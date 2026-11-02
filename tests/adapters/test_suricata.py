from __future__ import annotations

import ipaddress
import json
import random
from datetime import UTC, timedelta
from pathlib import Path
from typing import Any

import pytest

from tuisku.adapters import (
    AdapterError,
    Authorship,
    DetectionDraft,
    LimitExceeded,
    ObservationDraft,
    ParseResult,
    RawRecord,
    Severity,
    registry,
)
from tuisku.adapters.suricata import ADAPTER
from tuisku.adapters.testing import FIXED_RECEIVED_AT, assert_golden, run_fixture_file

FIXTURES = Path(__file__).parent.parent / "fixtures" / "suricata"
FIXTURE_FILES = sorted(FIXTURES.glob("*.ndjson"))

TS = "2023-09-18T06:13:41.532140+0000"


def parse(record: dict[str, Any] | str, options: dict[str, Any] | None = None) -> ParseResult:
    body = record if isinstance(record, str) else json.dumps(record)
    raw = RawRecord(source="t", body=body.encode(), received_at=FIXED_RECEIVED_AT)
    return ADAPTER.parse(raw, options or {})


def alert(sid: int = 2045001, **alert_fields: Any) -> dict[str, Any]:
    return {
        "timestamp": TS,
        "flow_id": 1676750115612680,
        "event_type": "alert",
        "src_ip": "203.0.113.10",
        "src_port": 443,
        "dest_ip": "10.0.0.5",
        "dest_port": 49175,
        "proto": "TCP",
        "alert": {"gid": 1, "signature_id": sid, "rev": 1, "signature": "x", "severity": 1}
        | alert_fields,
    }


def fixture_lines() -> list[str]:
    return [ln for p in FIXTURE_FILES for ln in p.read_text().splitlines() if ln.strip()]


@pytest.mark.parametrize("path", FIXTURE_FILES, ids=lambda p: p.stem)
def test_golden(path: Path) -> None:
    assert_golden(run_fixture_file(ADAPTER, path), path.with_suffix(".expected.json"))


def test_registered() -> None:
    assert registry.get("suricata") is ADAPTER
    assert ADAPTER.version == "1.0.0"


class TestLayerSplit:
    def test_alert_is_one_observation_and_one_detection_referencing_it(self) -> None:
        result = parse(alert())
        assert len(result.observations) == 1 and len(result.detections) == 1
        obs, det = result.observations[0], result.detections[0]
        assert det.observation_refs == (0,)
        assert obs.kind == "network.flow" and det.kind == "suricata.alert"
        assert det.identity == "suricata:1:2045001"
        # the verdict lives only on the detection, the 5-tuple only on the observation
        assert "alert" not in obs.unmapped and "alert" not in obs.attributes
        assert "src_endpoint" not in det.attributes
        assert obs.attributes["src_endpoint"] == {"ip": "203.0.113.10", "port": 443}
        assert obs.correlation == {"suricata.flow_id": "1676750115612680"}

    def test_rule_ref_is_verbatim(self) -> None:
        meta = {"signature_severity": ["Major"], "created_at": ["2023_04_17"]}
        det = parse(
            alert(rev=7, signature="ET X", category="c", action="allowed", metadata=meta)
        ).detections[0]
        assert det.rule_ref == {
            "engine": "suricata",
            "gid": 1,
            "sid": 2045001,
            "rev": 7,
            "signature": "ET X",
            "category": "c",
            "action": "allowed",
            "metadata": meta,
            "attack_version": None,
        }
        assert det.explanation["signature_severity"] == ["Major"]

    def test_attack_version_option(self) -> None:
        det = parse(alert(), {"attack_version": "v15"}).detections[0]
        assert det.rule_ref["attack_version"] == "v15"

    @pytest.mark.parametrize("bad", ["", "latest", "v15\n", 15, "v1.2.3.4"])
    def test_attack_version_option_validated(self, bad: object) -> None:
        with pytest.raises(AdapterError, match="attack_version"):
            parse(alert(), {"attack_version": bad})

    @pytest.mark.parametrize("value", [["x" * 65], ["Major"] * 9, "Major", [1]])
    def test_oversized_signature_severity_not_copied_to_explanation(self, value: object) -> None:
        det = parse(alert(metadata={"signature_severity": value})).detections[0]
        assert "signature_severity" not in det.explanation
        assert det.rule_ref["metadata"] == {"signature_severity": value}  # verbatim there

    def test_signature_severity_at_bounds_is_copied(self) -> None:
        value = ["x" * 64] * 8
        det = parse(alert(metadata={"signature_severity": value})).detections[0]
        assert det.explanation["signature_severity"] == value

    def test_alert_with_app_layer_takes_app_kind(self) -> None:
        rec = alert() | {"http": {"hostname": "c2.example.com", "url": "/"}}
        assert parse(rec).observations[0].kind == "http.request"
        rec = alert() | {
            "dns": {"version": 3, "type": "request", "queries": [{"rrname": "a.example"}]}
        }
        assert parse(rec).observations[0].kind == "dns.query"
        rec = alert() | {"tls": {"sni": "a.example"}}
        assert parse(rec).observations[0].kind == "tls.handshake"

    def test_anomaly_is_builtin_detection_with_facts_on_observation(self) -> None:
        anomaly = {
            "app_proto": "http",
            "type": "applayer",
            "event": "INVALID_RECORD",
            "layer": "proto_parser",
        }
        result = parse({"timestamp": TS, "event_type": "anomaly", "anomaly": anomaly})
        obs, det = result.observations[0], result.detections[0]
        assert det.authorship is Authorship.BUILTIN
        assert det.identity == "suricata:anomaly:applayer:http:INVALID_RECORD"
        assert det.observation_refs == (0,)
        assert obs.attributes["anomaly"] == anomaly
        assert "anomaly" not in obs.unmapped
        assert "reported" not in det.explanation and "anomaly" not in det.attributes

    def test_anomaly_scope_falls_back_to_layer_then_dash(self) -> None:
        rec = {"event_type": "anomaly", "anomaly": {"type": "applayer", "event": "E", "layer": "L"}}
        assert parse(rec).detections[0].identity == "suricata:anomaly:applayer:L:E"
        rec = {"event_type": "anomaly", "anomaly": {"type": "decode", "event": "decoder.x"}}
        assert parse(rec).detections[0].identity == "suricata:anomaly:decode:-:decoder.x"

    @pytest.mark.parametrize(
        "anomaly",
        [
            {"type": "decode", "event": "a b\nc"},
            {"type": "a:b", "event": "E"},
            {"type": "decode", "app_proto": "x:y", "event": "E"},
            {"type": "decode", "event": "E" * 129},
        ],
    )
    def test_hostile_anomaly_parts_do_not_enter_identity(self, anomaly: dict[str, Any]) -> None:
        identity = parse({"event_type": "anomaly", "anomaly": anomaly}).detections[0].identity
        assert identity.count(":") == 4
        assert "-" in identity.split(":")[2:]


class TestAuthorshipAndSeverity:
    @pytest.mark.parametrize(
        ("sid", "expected"),
        [
            (999_999, Authorship.COMMUNITY),
            (1_000_000, Authorship.LOCAL),
            (1_999_999, Authorship.LOCAL),
            (2_000_000, Authorship.COMMUNITY),
            (2_045_001, Authorship.COMMUNITY),
            (2_199_999, Authorship.COMMUNITY),
            (2_200_000, Authorship.BUILTIN),
            (2_299_999, Authorship.BUILTIN),
            (2_300_000, Authorship.COMMUNITY),
        ],
    )
    def test_default_ranges(self, sid: int, expected: Authorship) -> None:
        assert parse(alert(sid)).detections[0].authorship is expected

    @pytest.mark.parametrize("sid", [1_000_001, 2_200_001])
    def test_ranges_apply_only_to_gid_1(self, sid: int) -> None:
        rec = alert(sid, gid=3)
        det = parse(rec).detections[0]
        assert det.authorship is Authorship.COMMUNITY
        assert det.identity == f"suricata:3:{sid}"

    def test_builtin_option(self) -> None:
        opts = {"builtin_sid_ranges": [[2_500_000, 2_500_010]]}
        assert parse(alert(2_500_005), opts).detections[0].authorship is Authorship.BUILTIN
        assert parse(alert(2_200_000), opts).detections[0].authorship is Authorship.COMMUNITY

    def test_local_wins_over_builtin_on_overlap(self) -> None:
        opts = {"local_sid_ranges": [[2_200_000, 2_200_000]]}
        assert parse(alert(2_200_000), opts).detections[0].authorship is Authorship.LOCAL

    @pytest.mark.parametrize("name", ["local_sid_ranges", "builtin_sid_ranges"])
    def test_range_count_capped(self, name: str) -> None:
        parse(alert(), {name: [[1, 1]] * 64})
        with pytest.raises(AdapterError, match=name):
            parse(alert(), {name: [[1, 1]] * 65})

    def test_option_overrides_local_range(self) -> None:
        opts = {"local_sid_ranges": [[9_000_000, 9_000_100]]}
        assert parse(alert(9_000_050), opts).detections[0].authorship is Authorship.LOCAL
        assert parse(alert(1_000_001), opts).detections[0].authorship is Authorship.COMMUNITY
        empty = {"local_sid_ranges": []}
        assert parse(alert(1_000_001), empty).detections[0].authorship is Authorship.COMMUNITY

    @pytest.mark.parametrize(
        "bad", ["1-2", [[5, 1]], [[1]], [["1", 2]], [[True, 2]], [[0, 2**40]], {"a": 1}]
    )
    def test_invalid_option_is_adapter_error(self, bad: object) -> None:
        with pytest.raises(AdapterError, match="local_sid_ranges"):
            parse(alert(), {"local_sid_ranges": bad})

    @pytest.mark.parametrize(
        ("raw", "expected"),
        [
            (1, Severity.HIGH),
            (2, Severity.MEDIUM),
            (3, Severity.LOW),
            (4, Severity.INFORMATIONAL),
            (0, Severity.INFORMATIONAL),
            (255, Severity.INFORMATIONAL),
            ("1", Severity.UNKNOWN),
            (True, Severity.UNKNOWN),
            (None, Severity.UNKNOWN),
            (1.0, Severity.UNKNOWN),
            (-1, Severity.UNKNOWN),
        ],
    )
    def test_severity(self, raw: object, expected: Severity) -> None:
        assert parse(alert(severity=raw)).detections[0].severity is expected

    def test_missing_severity_is_unknown(self) -> None:
        rec = alert()
        del rec["alert"]["severity"]
        assert parse(rec).detections[0].severity is Severity.UNKNOWN

    def test_attack_ids_validated(self) -> None:
        meta = {
            "mitre_technique_id": ["T1071", "T1071.001", "t1059", "T12345", "T1071\n", "T１２３４"],
            "mitre_tactic_id": ["TA0011"],
            "other": ["T1003"],
        }
        assert parse(alert(metadata=meta)).detections[0].attack == ("T1071", "T1071.001")

    def test_attack_ids_capped(self) -> None:
        ids = [f"T{1000 + i}" for i in range(40)]
        attack = parse(alert(metadata={"mitre_technique_id": ids})).detections[0].attack
        assert attack == tuple(ids[:32])

    def test_no_attack_without_metadata(self) -> None:
        assert parse(alert()).detections[0].attack == ()


class TestEntityKeys:
    def test_endpoints_and_domains(self) -> None:
        rec = alert() | {
            "http": {"hostname": "C2.Example.com"},
            "tls": {"sni": "sni.example.org."},
        }
        result = parse(rec)
        keys = result.observations[0].entity_keys
        assert keys == (
            "ip:203.0.113.10",
            "ip:10.0.0.5",
            "domain:sni.example.org",
            "domain:c2.example.com",
        )
        assert result.detections[0].entity_keys == keys

    def test_ip_literal_hostname_is_not_a_domain(self) -> None:
        rec = alert() | {"http": {"hostname": "198.51.100.1"}}
        assert not any(k.startswith("domain:") for k in parse(rec).observations[0].entity_keys)

    def test_dns_rrname_and_file_sha256(self) -> None:
        dns = {
            "event_type": "dns",
            "dns": {"version": 3, "type": "request", "queries": [{"rrname": "Q.Example.NET"}]},
        }
        assert parse(dns).observations[0].entity_keys == ("domain:q.example.net",)
        digest = "AB" * 32
        fileinfo = {"event_type": "fileinfo", "fileinfo": {"sha256": digest}}
        assert parse(fileinfo).observations[0].entity_keys == (f"sha256:{digest.lower()}",)

    def test_cname_targets_are_domain_keys(self) -> None:
        rec = {
            "event_type": "dns",
            "dns": {
                "version": 3,
                "type": "response",
                "queries": [{"rrname": "a.example.net", "rrtype": "A"}],
                "answers": [
                    {"rrname": "a.example.net", "rrtype": "CNAME", "rdata": "B.example.org."},
                    {"rrname": "b.example.org", "rrtype": "A", "rdata": "192.0.2.1"},
                ],
            },
        }
        obs = parse(rec).observations[0]
        assert obs.entity_keys == ("domain:a.example.net", "domain:b.example.org")
        assert [a["rrname"] for a in obs.attributes["answers"]] == [
            "a.example.net",
            "b.example.org",
        ]
        assert obs.unmapped["dns"] == {"version": 3}  # answers fully mapped, rrnames kept

    def test_ipv6_compressed(self) -> None:
        rec = {
            "event_type": "flow",
            "src_ip": "2001:DB8:0:0:0:0:0:1",
            "dest_ip": "2001:db8::2",
            "proto": "UDP",
        }
        obs = parse(rec).observations[0]
        assert obs.entity_keys == ("ip:2001:db8::1", "ip:2001:db8::2")
        assert obs.attributes["connection_info"]["protocol_ver_id"] == 6

    def test_scoped_ipv6_is_invalid(self) -> None:
        rec = {"event_type": "flow", "src_ip": "fe80::1%eth0", "dest_ip": "fe80::2"}
        obs = parse(rec).observations[0]
        assert "invalid_src_ip" in obs.flags
        assert obs.unmapped["src_ip"] == "fe80::1%eth0"
        assert obs.entity_keys == ("ip:fe80::2",)

    def test_ip_length_is_capped_before_parsing(self, monkeypatch: pytest.MonkeyPatch) -> None:
        real = ipaddress.ip_address

        def guarded(value: Any) -> Any:
            assert len(str(value)) <= 64, "long input reached ipaddress"
            return real(value)

        monkeypatch.setattr(ipaddress, "ip_address", guarded)
        rec = {"event_type": "flow", "src_ip": "1" * 65, "dest_ip": "10.0.0.1"}
        assert "invalid_src_ip" in parse(rec).observations[0].flags

    @pytest.mark.parametrize("value", ["::ffff:192.0.2.1", "::FFFF:c000:201", "0::ffff:192.0.2.1"])
    def test_ipv4_mapped_ipv6_is_rendered_stably(self, value: str) -> None:
        rec = {"event_type": "flow", "src_ip": value, "dest_ip": "10.0.0.1"}
        obs = parse(rec).observations[0]
        assert obs.entity_keys[0] == "ip:192.0.2.1"
        assert obs.attributes["src_endpoint"] == {"ip": "::ffff:192.0.2.1"}


class TestCommunityId:
    # Reference vectors from the Community ID spec README / baseline (corelight/community-id-spec).
    def test_tcp_spec_vector(self) -> None:
        rec = {
            "event_type": "flow",
            "src_ip": "128.232.110.120",
            "src_port": 34855,
            "dest_ip": "66.35.250.204",
            "dest_port": 80,
            "proto": "TCP",
        }
        assert parse(rec).observations[0].community_id == "1:LQU9qZlK+B5F3KDmev6m5PMibrg="

    def test_icmp_uses_type_and_code(self) -> None:
        rec = {
            "event_type": "flow",
            "src_ip": "192.168.0.89",
            "dest_ip": "192.168.0.1",
            "proto": "ICMP",
            "icmp_type": 8,
            "icmp_code": 0,
        }
        obs = parse(rec).observations[0]
        assert obs.community_id == "1:X0snYXpgwiv9TZtqg64sgzUn6Dk="
        assert "community_id_mismatch" not in obs.flags

    def test_matching_reported_value_is_consumed(self) -> None:
        rec = alert() | {"community_id": "1:1WGJD3/A+XuRifa7N17irB4R6ZQ="}
        obs = parse(rec).observations[0]
        assert "community_id_mismatch" not in obs.flags and "community_id" not in obs.unmapped

    def test_mismatch_is_flagged_and_reported_value_kept(self) -> None:
        rec = alert() | {"community_id": "1:AAAA"}
        obs = parse(rec).observations[0]
        assert "community_id_mismatch" in obs.flags
        assert obs.unmapped["community_id"] == "1:AAAA"
        assert obs.community_id == "1:1WGJD3/A+XuRifa7N17irB4R6ZQ="

    def test_icmp_hash_uses_packet_direction_even_when_reoriented(self) -> None:
        rec = alert() | {
            "proto": "ICMP",
            "icmp_type": 8,
            "icmp_code": 0,
            "src_ip": "192.168.0.89",
            "dest_ip": "192.168.0.1",
            "direction": "to_client",
        }
        del rec["src_port"], rec["dest_port"]
        obs = parse(rec).observations[0]
        assert obs.community_id == "1:X0snYXpgwiv9TZtqg64sgzUn6Dk="
        assert obs.attributes["src_endpoint"] == {"ip": "192.168.0.1"}

    def test_uncomputable_reported_id_is_unverified(self) -> None:
        reported = "1:" + "A" * 27 + "="
        rec = {"event_type": "flow", "src_ip": "10.0.0.1", "community_id": reported}
        obs = parse(rec).observations[0]
        assert "community_id_unverified" in obs.flags
        assert obs.community_id == reported
        assert obs.unmapped["community_id"] == reported

    def test_uncomputable_malformed_reported_id_is_invalid(self) -> None:
        rec = {"event_type": "flow", "src_ip": "10.0.0.1", "community_id": "1:abc"}
        obs = parse(rec).observations[0]
        assert "community_id_invalid" in obs.flags
        assert obs.community_id is None
        assert obs.unmapped["community_id"] == "1:abc"


class TestOrientation:
    FLOW = {"pkts_toserver": 1, "bytes_toserver": 10, "pkts_toclient": 2, "bytes_toclient": 20}
    TRAFFIC = {"packets_out": 1, "bytes_out": 10, "packets_in": 2, "bytes_in": 20}
    CLIENT = {"ip": "10.0.0.5", "port": 49175}
    SERVER = {"ip": "203.0.113.10", "port": 443}

    def _flow_tuple(self) -> dict[str, Any]:
        return {
            "src_ip": "10.0.0.5",
            "dest_ip": "203.0.113.10",
            "src_port": 49175,
            "dest_port": 443,
        }

    @pytest.mark.parametrize(
        "extra",
        [
            {"direction": "to_client"},
            {"flow": "tuple"},
            {"flow": "tuple", "direction": "to_server"},  # flow object wins over direction
        ],
    )
    def test_alert_reoriented_to_client_server(self, extra: dict[str, Any]) -> None:
        flow = dict(self.FLOW) | (self._flow_tuple() if extra.get("flow") == "tuple" else {})
        rec = alert() | {k: v for k, v in extra.items() if k != "flow"} | {"flow": flow}
        obs = parse(rec).observations[0]
        assert obs.attributes["src_endpoint"] == self.CLIENT
        assert obs.attributes["dst_endpoint"] == self.SERVER
        assert obs.attributes["traffic"] == self.TRAFFIC
        assert obs.entity_keys[:2] == ("ip:10.0.0.5", "ip:203.0.113.10")
        assert "orientation_unknown" not in obs.flags
        assert "flow" not in obs.unmapped  # the consumed flow tuple is not repeated

    def test_alert_already_client_server(self) -> None:
        rec = alert() | {
            "src_ip": "10.0.0.5",
            "src_port": 49175,
            "dest_ip": "203.0.113.10",
            "dest_port": 443,
            "flow": dict(self.FLOW) | self._flow_tuple(),
        }
        obs = parse(rec).observations[0]
        assert obs.attributes["src_endpoint"] == self.CLIENT
        assert obs.attributes["traffic"] == self.TRAFFIC

    @pytest.mark.parametrize(
        "flow_tuple",
        [
            {},
            {"src_ip": "198.51.100.1", "dest_ip": "198.51.100.2"},  # unrelated
            {"src_ip": "10.0.0.5", "dest_ip": "203.0.113.10", "src_port": True, "dest_port": 443},
        ],
    )
    def test_unknown_orientation_keeps_packet_direction(self, flow_tuple: dict[str, Any]) -> None:
        rec = alert() | {"direction": "sideways", "flow": dict(self.FLOW) | flow_tuple}
        obs = parse(rec).observations[0]
        if flow_tuple.get("src_port") is True:  # bool is not a port: tuple ignored, IPs settle it
            assert "orientation_unknown" not in obs.flags
            return
        assert "orientation_unknown" in obs.flags
        assert obs.attributes["src_endpoint"] == self.SERVER

    def test_bool_port_in_flow_tuple_is_not_consumed(self) -> None:
        rec = alert() | {"src_port": 1}
        rec["flow"] = {"src_ip": "10.0.0.5", "dest_ip": "203.0.113.10", "dest_port": True}
        obs = parse(rec).observations[0]
        assert obs.attributes["src_endpoint"] == {"ip": "10.0.0.5", "port": 49175}
        assert obs.unmapped["flow"] == {"dest_port": True}

    def test_symmetric_tuple_is_unknown(self) -> None:
        rec = alert() | {"src_ip": "10.0.0.5", "dest_ip": "10.0.0.5", "src_port": 1, "dest_port": 1}
        rec["flow"] = {"src_ip": "10.0.0.5", "dest_ip": "10.0.0.5", "src_port": 1, "dest_port": 1}
        assert "orientation_unknown" in parse(rec).observations[0].flags

    @pytest.mark.parametrize(
        ("dns", "client_is_src"),
        [
            ({"type": "query", "rrname": "a.example"}, True),
            ({"version": 2, "type": "answer", "rrname": "a.example"}, True),
            ({"version": 3, "type": "request", "queries": []}, True),
            ({"version": 3, "type": "response", "queries": []}, False),
            ({"version": 3, "type": "answer", "queries": []}, False),
        ],
    )
    def test_dns_orientation(self, dns: dict[str, Any], client_is_src: bool) -> None:
        rec = {"event_type": "dns", "src_ip": "10.0.0.5", "dest_ip": "10.0.0.2", "dns": dns}
        obs = parse(rec).observations[0]
        expected = "10.0.0.5" if client_is_src else "10.0.0.2"
        assert obs.attributes["src_endpoint"]["ip"] == expected
        assert "orientation_unknown" not in obs.flags

    @pytest.mark.parametrize(
        ("etype", "unknown"),
        [("flow", False), ("http", False), ("tls", False), ("fileinfo", True), ("anomaly", True)],
    )
    def test_event_type_orientation(self, etype: str, unknown: bool) -> None:
        rec = {"event_type": etype, "src_ip": "10.0.0.5", "dest_ip": "10.0.0.2", etype: {}}
        assert ("orientation_unknown" in parse(rec).observations[0].flags) is unknown

    def test_no_endpoints_no_orientation_flag(self) -> None:
        rec = {"event_type": "fileinfo", "fileinfo": {}}
        assert "orientation_unknown" not in parse(rec).observations[0].flags


class TestDns:
    def test_source_lists_are_not_mutated(self) -> None:
        queries = [{"rrname": "a.example", "rrtype": "A"}, {"rrname": "b.example", "rrtype": "A"}]
        rec = {
            "event_type": "dns",
            "dns": {"version": 3, "type": "request", "queries": json.loads(json.dumps(queries))},
        }
        obs = parse(rec).observations[0]
        assert obs.attributes["query"] == {"hostname": "a.example", "type": "A"}
        assert obs.unmapped["dns"]["queries"] == queries

    def test_v2_wrapped_query_partially_mapped_stays_verbatim(self) -> None:
        wrapped = [{"rrname": "a.example", "rrtype": "A", "tx_id": 0}, {"rrname": "b.example"}]
        rec = alert() | {"dns": {"query": json.loads(json.dumps(wrapped))}}
        obs = parse(rec).observations[0]
        assert obs.kind == "dns.query"
        assert obs.unmapped["dns"]["query"] == wrapped

    def test_rcode_only_for_responses(self) -> None:
        req = {"event_type": "dns", "dns": {"version": 3, "type": "request", "rcode": "NOERROR"}}
        obs = parse(req).observations[0]
        assert "rcode" not in obs.attributes and obs.unmapped["dns"]["rcode"] == "NOERROR"
        resp = {"event_type": "dns", "dns": {"version": 3, "type": "response", "rcode": "REFUSED"}}
        obs = parse(resp).observations[0]
        assert obs.attributes["rcode"] == "REFUSED" and obs.attributes["rcode_id"] == 5

    @pytest.mark.parametrize(
        ("opcode", "mapped"), [(0, True), (15, True), (16, False), (-1, False)]
    )
    def test_opcode_bound(self, opcode: int, mapped: bool) -> None:
        rec = {
            "event_type": "dns",
            "dns": {"type": "query", "rrname": "a.example", "opcode": opcode},
        }
        obs = parse(rec).observations[0]
        assert ("opcode_id" in obs.attributes["query"]) is mapped
        assert ("opcode" in obs.unmapped.get("dns", {})) is not mapped


class TestFlagsAndTls:
    @pytest.mark.parametrize(
        ("field", "value"),
        [
            ("flow_id", "12"),
            ("flow_id", -1),
            ("flow_id", 2**64),
            ("src_port", 70000),
            ("dest_port", "80"),
            ("src_port", True),
            ("src_ip", "10.0.0.256"),
            ("dest_ip", 167772161),
        ],
    )
    def test_invalid_common_fields_flagged(self, field: str, value: object) -> None:
        rec = alert() | {field: value}
        obs = parse(rec).observations[0]
        assert f"invalid_{field}" in obs.flags
        assert obs.unmapped[field] == value

    @pytest.mark.parametrize(
        "fingerprint",
        [
            "AA:bb:cc:dd:ee:ff:00:11:22:33:44:55:66:77:88:99:aa:bb:cc:dd",
            "aabbccddeeff00112233445566778899aabbccdd",
        ],
    )
    def test_fingerprint_normalised_original_kept(self, fingerprint: str) -> None:
        rec = {"event_type": "tls", "tls": {"fingerprint": fingerprint}}
        obs = parse(rec).observations[0]
        assert obs.attributes["tls"]["certificate"]["fingerprints"] == [
            {"algorithm": "SHA-1", "value": "aabbccddeeff00112233445566778899aabbccdd"}
        ]
        assert obs.unmapped["tls"]["fingerprint"] == fingerprint

    @pytest.mark.parametrize("fingerprint", ["aa:bb", "zz" * 20, "a" * 41, 5, "aa::bb" * 10])
    def test_bad_fingerprint_not_mapped(self, fingerprint: object) -> None:
        obs = parse({"event_type": "tls", "tls": {"fingerprint": fingerprint}}).observations[0]
        assert "tls" not in obs.attributes


class TestTimestampsAndFlow:
    def test_suricata_offset_format(self) -> None:
        rec = alert() | {"timestamp": "2023-09-18T08:13:41.532140+0200"}
        obs = parse(rec).observations[0]
        assert obs.event_time is not None
        assert obs.event_time.isoformat() == "2023-09-18T06:13:41.532140+00:00"

    def test_zone_less_timestamps_flagged(self) -> None:
        rec = alert() | {
            "timestamp": "2023-09-18T06:13:41.532140",
            "flow": {"start": "2023-09-18T06:13:40.000000+0000"},
        }
        obs = parse(rec).observations[0]
        assert obs.event_time is not None and obs.event_time.isoformat().endswith("+00:00")
        assert "timezone_assumed_utc" in obs.flags
        rec = alert() | {"flow": {"start": "2023-09-18T06:13:40.000000"}}
        assert "timezone_assumed_utc" in parse(rec).observations[0].flags
        assert "timezone_assumed_utc" not in parse(alert()).observations[0].flags

    @pytest.mark.parametrize("value", [1695017621, 1695017621.5, ["2023-09-18"]])
    def test_non_string_timestamps_rejected(self, value: object) -> None:
        assert "invalid_timestamp" in parse(alert() | {"timestamp": value}).observations[0].flags

    @pytest.mark.parametrize(("value", "flag"), [("yesterday", "invalid_timestamp"), (None, None)])
    def test_bad_or_missing_timestamp_is_flagged(self, value: object, flag: str | None) -> None:
        rec = alert()
        if value is None:
            del rec["timestamp"]
            flag = "missing_timestamp"
        else:
            rec["timestamp"] = value
        result = parse(rec)
        assert result.observations[0].event_time is None
        assert flag in result.observations[0].flags


class TestUnknownAndMalformed:
    @pytest.mark.parametrize("etype", ["stats", "ssh", "", None, 5, ["alert"]])
    def test_unknown_types_are_generic(self, etype: object) -> None:
        rec: dict[str, Any] = {"timestamp": TS, "x": {"y": 1}}
        if etype is not None:
            rec["event_type"] = etype
        result = parse(rec)
        assert result.detections == ()
        (obs,) = result.observations
        assert obs.kind == "suricata.unknown"
        assert obs.unmapped["x"] == {"y": 1}
        assert ("missing_event_type" in obs.flags) == (etype is None)

    def test_unmapped_keeps_everything_not_mapped(self) -> None:
        rec = alert() | {"in_iface": "eth0", "payload": "AAAA", "tx_id": 3}
        rec["alert"]["verdict"] = {"action": "drop"}
        result = parse(rec)
        assert result.observations[0].unmapped == {
            "in_iface": "eth0",
            "payload": "AAAA",
            "tx_id": 3,
        }
        assert result.detections[0].attributes["unmapped"] == {"verdict": {"action": "drop"}}

    @pytest.mark.parametrize(
        "body",
        [
            "not json",
            "[1]",
            '{"event_type":"alert"}',
            '{"event_type":"alert","alert":{"gid":1,"signature_id":"1"}}',
            '{"event_type":"alert","alert":{"gid":1}}',
            '{"event_type":"anomaly","anomaly":[]}',
            '{"a":' * 100 + "1" + "}" * 100,
            '{"event_type":"flow","x":Infinity}',
        ],
    )
    def test_malformed_is_adapter_error(self, body: str) -> None:
        with pytest.raises(AdapterError):
            parse(body)

    def test_error_message_does_not_echo_body(self) -> None:
        secret = "S3CRET-" + "q" * 100
        with pytest.raises(AdapterError) as exc:
            parse('{"event_type":"alert","alert":{"gid":"' + secret + '","signature_id":1}}')
        assert secret not in str(exc.value)

    def test_oversized_body(self) -> None:
        with pytest.raises(LimitExceeded, match="larger than") as exc:
            parse(json.dumps({"event_type": "flow", "x": "a" * 300_000}))
        assert exc.value.limit == "line_length"

    @pytest.mark.parametrize(
        ("body", "limit"),
        [
            ('{"a":' * 100 + "1" + "}" * 100, "json_depth"),
            ("{" + ",".join(f'"k{i}":1' for i in range(5000)) + "}", "json_keys"),
        ],
    )
    def test_structural_limits_propagate(self, body: str, limit: str) -> None:
        with pytest.raises(LimitExceeded) as exc:
            parse(body)
        assert exc.value.limit == limit

    def test_unicode_flag_on_unknown_and_alert(self) -> None:
        unknown = parse('{"event_type":"stats","note":"\\u0000"}').observations[0]
        assert "invalid_unicode_replaced" in unknown.flags
        body = json.dumps(alert() | {"payload": "x\udfff"})
        assert "invalid_unicode_replaced" in parse(body).observations[0].flags

    def test_invalid_utf8(self) -> None:
        raw = RawRecord(source="t", body=b'{"a":"\xff"}', received_at=FIXED_RECEIVED_AT)
        with pytest.raises(AdapterError, match="UTF-8"):
            ADAPTER.parse(raw, {})

    def test_non_ascii_digit_protocol_rejected(self) -> None:
        rec = {"event_type": "flow", "proto": "\u0661\u0667", "src_ip": "10.0.0.1"}
        assert parse(rec).observations[0].attributes["connection_info"].get("protocol_num") is None

    @pytest.mark.parametrize(
        "ts",
        [
            "\u0662\u0660\u0662\u0663-09-18T06:13:41.532140+0000",
            "2023-09-18T06:13:41.532140+2400",
            "2023-09-18T06:13:41.532140+0099",
        ],
    )
    def test_loose_timestamps_rejected(self, ts: str) -> None:
        obs = parse(alert() | {"timestamp": ts}).observations[0]
        assert "invalid_timestamp" in obs.flags

    @pytest.mark.parametrize("bad", ["\\u0000", "\\ud800", "\\udfff"])  # JSON escapes
    def test_nul_and_lone_surrogates_replaced_and_flagged(self, bad: str) -> None:
        body = '{"event_type":"http","http":{"hostname":"a' + bad + '.example"}}'
        obs = parse(body).observations[0]
        assert "invalid_unicode_replaced" in obs.flags
        assert obs.attributes["http_request"]["url"]["hostname"] == "a\ufffd.example"

    @pytest.mark.parametrize("bad", ["\\u0000", "\\ud800"])
    def test_nul_and_lone_surrogates_do_not_crash(self, bad: str) -> None:
        body = (
            '{"event_type":"http","src_ip":"10.0.0.1'
            + bad
            + '","http":{"hostname":"a'
            + bad
            + '"}}'
        )
        obs = parse(body).observations[0]
        assert "invalid_src_ip" in obs.flags
        assert not any(k.startswith("domain:") for k in obs.entity_keys)

    def test_huge_ints_do_not_crash(self) -> None:
        body = '{"event_type":"flow","flow_id":' + "9" * 4000 + ',"src_port":-' + "9" * 300 + "}"
        try:
            obs = parse(body).observations[0]
        except AdapterError:
            return  # Python's int-digit limit is a decode error, which is fine
        assert "invalid_flow_id" in obs.flags

    def test_huge_and_wrong_typed_fields_stay_unmapped(self) -> None:
        huge = "a" * 100_000
        rec = {
            "event_type": "http",
            "src_ip": "10.0.0.1" + huge,
            "src_port": "80",
            "http": {"hostname": huge, "status": "200", "url": ["/"]},
        }
        obs = parse(rec).observations[0]
        assert obs.unmapped["src_port"] == "80"
        assert obs.unmapped["http"] == rec["http"]
        assert "invalid_src_ip" in obs.flags
        assert obs.entity_keys == ()


def test_deterministic() -> None:
    for line in fixture_lines():
        try:
            first = parse(line)
        except AdapterError:
            continue
        assert parse(line) == first


def _mutate(value: Any, rng: random.Random) -> Any:
    choices: list[Any] = [
        None,
        True,
        -1,
        2**70,
        1.5,
        "",
        "x" * 5000,
        "T1059",
        "::1",
        "\u0000퟿",
        "\u0000",
        "\ud800",
        "a\udfffb",
        "\u0661\u0667",
        "\u0662\u0660\u0662\u0663-09-18T06:13:41+0000",
        "fe80::1%eth0",
        "::ffff:192.0.2.1",
        "to_client",
        "response",
        2**64,
        -(2**63),
        10**30,
        "T\u0661\u0660\u0665\u0669",
        [],
        {},
        [1, "a", None],
        {"k": [{}]},
    ]
    if isinstance(value, dict) and value and rng.random() < 0.7:
        out = dict(value)
        key = rng.choice(list(out))
        if rng.random() < 0.2:
            del out[key]
        else:
            out[key] = _mutate(out[key], rng)
        return out
    if isinstance(value, list) and value and rng.random() < 0.7:
        out_list = list(value)
        i = rng.randrange(len(out_list))
        out_list[i] = _mutate(out_list[i], rng)
        return out_list
    return rng.choice(choices)


def test_fuzz_only_adapter_error_escapes() -> None:
    rng = random.Random(20261101)
    records = []
    for line in fixture_lines():
        try:
            records.append(json.loads(line))
        except ValueError:
            continue
    assert len(records) > 20
    for _ in range(4000):
        rec = rng.choice(records)
        for _ in range(rng.randint(1, 4)):
            rec = _mutate(rec, rng)
        body = json.dumps(rec)
        if rng.random() < 0.1:  # byte-level damage too
            cut = rng.randrange(len(body) + 1)
            body = body[:cut] + rng.choice(["", "}", '"', "\\", "{"]) + body[cut + 1 :]
        try:
            result = parse(body)
        except AdapterError:
            continue
        _assert_valid(result)


KINDS = {
    "network.flow",
    "network.anomaly",
    "dns.query",
    "dns.answer",
    "http.request",
    "tls.handshake",
    "file.transfer",
    "suricata.unknown",
}
MAX_MAPPED_STR = 8192


def _strings(value: Any, skip: frozenset[str] = frozenset({"unmapped", "metadata"})) -> list[str]:
    """Every string in a mapped payload, skipping verbatim copies (``unmapped``, rule metadata)."""
    out: list[str] = []
    stack = [value]
    while stack:
        node = stack.pop()
        if isinstance(node, str):
            out.append(node)
        elif isinstance(node, dict):
            for k, v in node.items():
                out.append(k)
                if k not in skip:
                    stack.append(v)
        elif isinstance(node, list | tuple):
            stack.extend(node)
    return out


def _assert_valid(result: ParseResult) -> None:
    assert isinstance(result, ParseResult)
    assert len(result.observations) == 1 and len(result.detections) <= 1
    for obs in result.observations:
        assert isinstance(obs, ObservationDraft) and obs.kind in KINDS
        if obs.event_time is not None:
            assert obs.event_time.utcoffset() == timedelta(0) and obs.event_time.tzinfo is UTC
        assert all(len(k) <= 300 for k in obs.entity_keys)
        assert all(isinstance(v, str) and len(v) <= 32 for v in obs.correlation.values())
        assert all(len(s) <= MAX_MAPPED_STR for s in _strings(obs.attributes))
        assert all(isinstance(f, str) and len(f) <= 64 for f in obs.flags)
        assert isinstance(obs.unmapped, dict)
    for det in result.detections:
        assert isinstance(det, DetectionDraft)
        assert isinstance(det.severity, Severity) and isinstance(det.authorship, Authorship)
        assert det.observation_refs == (0,)
        assert len(det.identity) <= 300 and len(det.title) <= 1100
        assert det.identity.startswith(("suricata:anomaly:", "suricata:"))
        assert all(len(s) <= MAX_MAPPED_STR for s in _strings(det.rule_ref))
        assert all(len(s) <= MAX_MAPPED_STR for s in _strings(det.explanation))
        assert all(len(a) <= 9 for a in det.attack) and len(det.attack) <= 32
        assert det.entity_keys == result.observations[0].entity_keys
