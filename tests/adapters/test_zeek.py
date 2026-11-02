from __future__ import annotations

import json
import random
from datetime import timedelta
from pathlib import Path
from typing import Any

import pytest

from tuisku.adapters import (
    AdapterError,
    Authorship,
    LimitExceeded,
    ParseResult,
    RawRecord,
    Severity,
    registry,
)
from tuisku.adapters.flows import community_id
from tuisku.adapters.jsonsafe import loads_object
from tuisku.adapters.testing import (
    FIXED_RECEIVED_AT,
    assert_golden,
    result_to_jsonable,
    run_fixture_file,
)
from tuisku.adapters.zeek import ADAPTER, LOG_TYPES

FIXTURES = Path(__file__).parent.parent / "fixtures" / "zeek"

# fixture stem -> adapter options; every other fixture runs with type inference
OPTIONS: dict[str, dict[str, Any]] = {"option-path": {"log": "conn"}}


def parse(record: dict[str, Any] | str, **options: Any) -> ParseResult:
    body = record if isinstance(record, str) else json.dumps(record)
    raw = RawRecord(
        source="test",
        body=body.encode("utf-8"),
        received_at=FIXED_RECEIVED_AT,
        collector={"path": "/var/log/zeek/notice.log"},
    )
    return ADAPTER.parse(raw, options)


def fixture_lines(stem: str) -> list[dict[str, Any]]:
    path = FIXTURES / f"{stem}.ndjson"
    return [json.loads(ln) for ln in path.read_text(encoding="utf-8").splitlines() if ln.strip()]


CONN = fixture_lines("conn")[0]
NOTICE = fixture_lines("notice")[0]
WEIRD = fixture_lines("weird")[0]


def test_registered() -> None:
    assert registry.get("zeek") is ADAPTER
    assert ADAPTER.version == "1.0.0"


@pytest.mark.parametrize("path", sorted(FIXTURES.glob("*.ndjson")), ids=lambda p: p.stem)
def test_golden(path: Path) -> None:
    actual = run_fixture_file(ADAPTER, path, OPTIONS.get(path.stem))
    assert_golden(actual, path.with_suffix(".expected.json"))


class TestLogTypeSelection:
    @pytest.mark.parametrize(
        ("stem", "kind"),
        [
            ("conn", "network.flow"),
            ("dns", "dns.answer"),
            ("http", "http.request"),
            ("ssl", "tls.handshake"),
            ("files", "file.transfer"),
        ],
    )
    def test_inferred_observation_kinds(self, stem: str, kind: str) -> None:
        for record in fixture_lines(stem):
            result = parse(record)
            assert [o.kind for o in result.observations] == [kind]
            assert result.detections == ()

    def test_http_version_does_not_make_it_ssl(self) -> None:
        record = fixture_lines("http")[1]
        assert "version" in record
        assert parse(record).observations[0].kind == "http.request"

    def test_notice_fuid_does_not_make_it_files(self) -> None:
        record = fixture_lines("notice")[2]
        assert "fuid" in record
        assert parse(record).detections[0].kind == "zeek.notice"

    def test_ssh_count_version_is_not_ssl(self) -> None:
        record = fixture_lines("unknown")[0]
        assert parse(record).observations[0].kind == "zeek.unknown"

    def test_option_overrides_inference(self) -> None:
        record = fixture_lines("option-path")[1]  # conn + dns fields: ambiguous on its own
        assert parse(record).observations[0].kind == "zeek.unknown"
        assert parse(record).observations[0].flags == ("log_type_ambiguous",)
        assert parse(record, log="conn").observations[0].kind == "network.flow"
        assert parse(record, log="dns").observations[0].kind == "dns.answer"

    def test_option_on_record_with_no_characteristic_fields(self) -> None:
        record = fixture_lines("option-path")[0]
        assert parse(record).observations[0].kind == "zeek.unknown"
        assert parse(record, log="conn").observations[0].kind == "network.flow"

    def test_ambiguous_lists_candidates(self) -> None:
        obs = parse(fixture_lines("ambiguous")[0]).observations[0]
        assert obs.kind == "zeek.unknown"
        assert obs.flags == ("log_type_ambiguous",)
        assert obs.attributes["log_type_candidates"] == ["conn", "dns"]

    def test_notice_wins_over_ambiguity(self) -> None:
        result = parse(fixture_lines("ambiguous")[1])  # note + weird's name/addl
        assert result.observations == ()
        det = result.detections[0]
        assert det.identity == "zeek:notice:Weird::Activity"
        assert det.attributes["flags"] == ["log_type_ambiguous"]
        assert det.attributes["log_type_candidates"] == ["notice", "weird"]

    def test_site_extended_notice_is_still_a_notice(self) -> None:
        result = parse(fixture_lines("notice")[3])  # carries dns's ``query``
        det = result.detections[0]
        assert det.identity == "zeek:notice:Site::Suspicious_Query"
        assert det.observation_refs == (0,)
        assert "log_type_ambiguous" in result.observations[0].flags
        assert det.attributes["unmapped"]["query"] == "odd.example.com"

    def test_option_is_not_ambiguous(self) -> None:
        det = parse(fixture_lines("ambiguous")[1], log="notice").detections[0]
        assert "flags" not in det.attributes

    def test_weird_wins_over_ambiguity(self) -> None:
        record = dict(WEIRD, query="x.example.com")
        result = parse(record)
        assert result.detections[0].identity == "zeek:weird:inappropriate_FIN"
        assert "log_type_ambiguous" in result.observations[0].flags

    def test_invalid_note_does_not_force_notice(self) -> None:
        record = dict(fixture_lines("ambiguous")[1], note="bad note")
        assert parse(record).detections[0].kind == "zeek.weird"
        del record["name"]  # now only a (malformed) notice: fail loudly, never guess
        with pytest.raises(AdapterError, match="'note'"):
            parse(record)

    @pytest.mark.parametrize(("line", "what"), [(3, "krb"), (4, "snmp")])
    def test_krb_and_snmp_are_not_ssl(self, line: int, what: str) -> None:
        obs = parse(fixture_lines("unknown")[line]).observations[0]
        assert obs.kind == "zeek.unknown", what

    def test_ssl_needs_server_name_or_cipher_and_version(self) -> None:
        base = {"ts": 1695017614.0, "uid": "Cx", "id.orig_h": "10.0.0.5"}
        assert parse(dict(base, cipher="x")).observations[0].kind == "zeek.unknown"
        assert parse(dict(base, version="TLSv12")).observations[0].kind == "zeek.unknown"
        both = dict(base, cipher="x", version="TLSv12")
        assert parse(both).observations[0].kind == "tls.handshake"
        assert parse(dict(base, server_name="a.example")).observations[0].kind == "tls.handshake"
        # one krb or snmp marker is enough to veto
        assert parse(dict(both, request_type="AS")).observations[0].kind == "zeek.unknown"
        assert parse(dict(both, community="public")).observations[0].kind == "zeek.unknown"

    def test_signature_note_is_not_a_notice(self) -> None:
        record = fixture_lines("unknown")[5]
        assert "sig_id" in record
        result = parse(record)
        assert result.detections == ()
        assert result.observations[0].kind == "zeek.unknown"

    def test_path_is_authoritative_over_inference(self) -> None:
        record = fixture_lines("option-path")[2]  # conn fields, _path dns
        assert parse(record).observations[0].kind == "dns.answer"
        assert parse(record, log="conn").observations[0].kind == "network.flow"

    def test_unsupported_path(self) -> None:
        record = fixture_lines("unknown")[6]
        assert record["_path"] == "dhcp"
        obs = parse(record).observations[0]
        assert obs.kind == "zeek.unknown"
        assert obs.flags == ("log_type_unsupported",)
        # a signatures _path also beats a valid note
        assert parse(dict(NOTICE, _path="signatures")).detections == ()

    def test_notice_alarm_path(self) -> None:
        det = parse(fixture_lines("notice")[4]).detections[0]
        assert det.identity == "zeek:notice:Scan::Address_Scan"

    def test_unknown_keeps_every_field(self) -> None:
        record = fixture_lines("unknown")[0]
        obs = parse(record).observations[0]
        assert obs.flags == ("log_type_unknown",)
        assert dict(obs.unmapped) == record
        assert obs.correlation == {"zeek.uid": ("CsshUid0000000001",)}

    def test_collector_path_is_ignored(self) -> None:
        # parse() always says the line came from notice.log; a conn record stays a conn record.
        assert parse(CONN).observations[0].kind == "network.flow"

    @pytest.mark.parametrize("bad", ["Conn", "x509", 1, ["conn"]])
    def test_invalid_log_option(self, bad: Any) -> None:
        with pytest.raises(AdapterError, match="option 'log'"):
            parse(CONN, log=bad)


class TestLayerSplit:
    def test_notice_is_observation_plus_detection(self) -> None:
        result = parse(NOTICE)
        assert len(result.observations) == 1 and len(result.detections) == 1
        obs, det = result.observations[0], result.detections[0]
        assert obs.kind == "network.flow" and "connection_context" in obs.flags
        assert det.observation_refs == (0,)
        assert det.kind == "zeek.notice"
        assert det.authorship is Authorship.BUILTIN
        assert det.identity == "zeek:notice:SSH::Password_Guessing"
        assert det.severity is Severity.MEDIUM
        assert det.rule_ref == {"engine": "zeek", "log": "notice", "note": "SSH::Password_Guessing"}
        for field in ("msg", "sub", "src", "dst", "p", "actions"):
            assert det.explanation[field] == NOTICE[field]
        # verdict fields stay out of the fact
        assert "msg" not in obs.attributes and obs.unmapped == {}
        assert obs.correlation == {"zeek.uid": ("CHhAvVGS1DHFjwGM9",)}

    def test_notice_without_connection_has_no_observation(self) -> None:
        result = parse(fixture_lines("notice")[1])
        assert result.observations == ()
        det = result.detections[0]
        assert det.observation_refs == ()
        assert det.entity_keys == ("ip:198.51.100.9",)

    def test_notice_without_connection_keeps_uid_and_proto(self) -> None:
        record = dict(fixture_lines("notice")[1], uid="CnoTuple000000001", proto="tcp")
        det = parse(record).detections[0]
        assert det.attributes["unmapped"]["uid"] == "CnoTuple000000001"
        assert det.attributes["unmapped"]["proto"] == "tcp"

    def test_notice_fuid_correlates_context(self) -> None:
        obs = parse(fixture_lines("notice")[2]).observations[0]
        assert obs.correlation == {
            "zeek.uid": ("CfileNotice000001",),
            "zeek.fuid": ("F2xow8TIkvHG4Zz41",),
        }

    def test_local_notes_option(self) -> None:
        det = parse(NOTICE, local_notes=["SSH::Password_Guessing"]).detections[0]
        assert det.authorship is Authorship.LOCAL
        with pytest.raises(AdapterError, match="local_notes"):
            parse(NOTICE, local_notes="SSH::Password_Guessing")

    def test_weird(self) -> None:
        result = parse(WEIRD)
        det = result.detections[0]
        assert det.kind == "zeek.weird"
        assert det.identity == "zeek:weird:inappropriate_FIN"
        assert det.severity is Severity.INFORMATIONAL
        assert det.authorship is Authorship.BUILTIN
        assert det.observation_refs == (0,)
        assert det.explanation["notice"] is False
        assert result.observations[0].kind == "network.flow"

    def test_weird_without_connection(self) -> None:
        result = parse(fixture_lines("weird")[1])
        assert result.observations == ()
        assert result.detections[0].identity == "zeek:weird:truncated_header"

    def test_forced_notice_without_note_fails(self) -> None:
        with pytest.raises(AdapterError, match="'note'"):
            parse(CONN, log="notice")


class TestEntityKeysAndCorrelation:
    def test_conn(self) -> None:
        obs = parse(CONN).observations[0]
        assert obs.entity_keys == ("ip:192.0.2.10", "ip:203.0.113.20")
        assert obs.correlation == {"zeek.uid": ("CHhAvVGS1DHFjwGM9",)}

    def test_dns_query_domain_and_answer_ips(self) -> None:
        obs = parse(fixture_lines("dns")[0]).observations[0]
        assert obs.entity_keys == (
            "ip:10.0.0.5",
            "ip:10.0.0.2",
            "domain:www.example.com",
            "ip:192.0.2.80",
        )
        second = parse(fixture_lines("dns")[1]).observations[0]
        assert "domain:missing.example" in second.entity_keys

    def test_rcode_above_23_has_no_rcode_id(self) -> None:
        record = dict(fixture_lines("dns")[0], rcode=24, rcode_name="X")
        obs = parse(record).observations[0]
        assert "rcode_id" not in obs.attributes
        assert obs.unmapped["rcode"] == 24
        obs = parse(dict(record, rcode=23)).observations[0]
        assert obs.attributes["rcode_id"] == 23
        assert "rcode" not in obs.unmapped

    def test_invalid_domain_gives_no_key(self) -> None:
        obs = parse(fixture_lines("dns")[2]).observations[0]
        assert not any(k.startswith("domain:") for k in obs.entity_keys)

    def test_http_host_with_port(self) -> None:
        obs = parse(fixture_lines("http")[0]).observations[0]
        assert "domain:www.example.com" in obs.entity_keys
        url = obs.attributes["http_request"]["url"]
        assert url == {
            "hostname": "www.example.com",
            "port": 8080,
            "path": "/upload/form",
            "query_string": "id=7&x=y",
        }
        # exact values, never joined: resp_fuids then orig_fuids
        assert obs.correlation["zeek.fuid"] == (
            "F2xow8TIkvHG4Zz41",
            "F3second000000002",
            "FupLoad0000000001",
        )

    def test_http_ip_host_is_not_a_domain(self) -> None:
        obs = parse(fixture_lines("http")[1]).observations[0]
        assert obs.entity_keys == ("ip:192.0.2.10", "ip:203.0.113.20")

    def test_ssl_sni(self) -> None:
        obs = parse(fixture_lines("ssl")[0]).observations[0]
        assert "domain:calendar.example.com" in obs.entity_keys
        assert obs.attributes["tls"]["sni"] == "calendar.example.com"

    def test_files_sha256_and_fuid(self) -> None:
        obs = parse(fixture_lines("files")[0]).observations[0]
        assert (
            "sha256:ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb"
            in obs.entity_keys
        )
        assert obs.correlation == {
            "zeek.uid": ("CHhAvVGS1DHFjwGM9",),
            "zeek.fuid": ("F2xow8TIkvHG4Zz41",),
        }

    def test_files_invalid_hash_is_not_mapped(self) -> None:
        obs = parse(fixture_lines("files")[1]).observations[0]
        assert "hashes" not in obs.attributes["file"]
        assert obs.unmapped["sha256"] == "not-a-hash"
        assert not any(k.startswith("sha256:") for k in obs.entity_keys)

    def test_files_legacy_hosts(self) -> None:
        obs = parse(fixture_lines("files")[1]).observations[0]
        assert obs.entity_keys == ("ip:203.0.113.20", "ip:192.0.2.10")
        assert obs.correlation == {
            "zeek.fuid": ("FlegacyFile000001",),
            "zeek.uid": ("ClegacyConn000001",),
        }


class TestCommunityId:
    def test_reported_match(self) -> None:
        obs = parse(CONN).observations[0]
        assert obs.community_id == CONN["community_id"]
        assert obs.community_id == community_id("tcp", "192.0.2.10", 49175, "203.0.113.20", 80)
        assert "community_id_mismatch" not in obs.flags

    def test_reported_mismatch(self) -> None:
        obs = parse(fixture_lines("conn")[1]).observations[0]
        assert obs.community_id == "1:ktGSSHxVRGE5LR0LsXJNJxiLm9A="
        assert "community_id_mismatch" in obs.flags

    def test_reference_vector(self) -> None:
        record = dict(CONN, **{"id.orig_h": "127.0.0.1", "id.orig_p": 1234})
        record |= {"id.resp_h": "10.0.0.1", "id.resp_p": 80}
        del record["community_id"]
        # pycommunityid's documented example
        assert parse(record).observations[0].community_id == "1:mgRgpIZSu0KHDp/QrtcWZpkJpMU="

    def test_http_assumes_tcp(self) -> None:
        obs = parse(fixture_lines("http")[0]).observations[0]
        assert obs.community_id == community_id("tcp", "192.0.2.10", 49175, "203.0.113.20", 80)
        assert obs.flags == ("proto_assumed_tcp",)
        assert "protocol_name" not in obs.attributes["connection_info"]

    def test_explicit_proto_is_not_overridden(self) -> None:
        obs = parse(dict(fixture_lines("http")[0], proto="udp")).observations[0]
        assert obs.community_id is None
        assert "proto_assumed_tcp" not in obs.flags

    def test_tls_version_assumes_tcp(self) -> None:
        obs = parse(fixture_lines("ssl")[0]).observations[0]
        assert obs.community_id == community_id("tcp", "10.0.0.5", 50110, "198.51.100.43", 443)
        assert obs.flags == ("proto_assumed_tcp",)

    def test_dtls_does_not_assume_tcp(self) -> None:
        obs = parse(fixture_lines("ssl")[2]).observations[0]
        assert obs.community_id is None
        assert obs.flags == ()

    def test_no_version_keeps_reported_as_unverified(self) -> None:
        record = fixture_lines("ssl")[1]
        obs = parse(record).observations[0]
        assert obs.community_id == record["community_id"]
        assert obs.flags == ("community_id_unverified",)

    def test_malformed_reported_is_invalid_and_not_stored(self) -> None:
        line = (FIXTURES / "malformed.ndjson").read_text(encoding="utf-8").splitlines()[-1]
        obs = parse(line).observations[0]
        assert obs.community_id is None
        assert "community_id_invalid" in obs.flags

    def test_icmp(self) -> None:
        obs = parse(fixture_lines("conn")[2]).observations[0]
        assert obs.community_id == community_id("icmp", "192.0.2.10", 8, "203.0.113.20", 0)

    def test_notice_context(self) -> None:
        obs = parse(NOTICE).observations[0]
        assert obs.community_id == NOTICE["community_id"]
        assert "community_id_mismatch" not in obs.flags


class TestTimestamps:
    def test_epoch_float(self) -> None:
        t = parse(CONN).observations[0].event_time
        assert t is not None and t.isoformat() == "2023-09-18T06:13:33.324862+00:00"

    def test_iso(self) -> None:
        t = parse(fixture_lines("ssl")[1]).observations[0].event_time
        assert t is not None and t.isoformat() == "2023-09-18T08:13:46+00:00"

    def test_epoch_millis(self) -> None:
        t = parse(fixture_lines("conn")[3]).observations[0].event_time
        assert t is not None and t.isoformat() == "2023-09-18T06:16:40+00:00"

    def test_same_instant_both_formats(self) -> None:
        epoch, iso = fixture_lines("option-path")[:2]
        a = parse(epoch, log="conn").observations[0].event_time
        b = parse(iso, log="conn").observations[0].event_time
        assert a == b

    def test_invalid_ts_is_kept_and_flagged(self) -> None:
        obs = parse(dict(CONN, ts="yesterday")).observations[0]
        assert obs.event_time is None
        assert "invalid_ts" in obs.flags
        assert obs.unmapped["ts"] == "yesterday"

    @pytest.mark.parametrize(
        ("ts", "expected"),
        [
            (631152000000, "1990-01-01T00:00:00+00:00"),  # millis near the lower range bound
            (7258118399000, "2199-12-31T23:59:59+00:00"),  # millis near the upper range bound
            (1695017613, "2023-09-18T06:13:33+00:00"),  # integer seconds stay seconds
            (99999999999, None),  # just below the millis band: seconds, year 5138
            (10**11, None),  # first millis value: 1973, before the range
            (10**14, None),  # past the millis band: seconds, far future
            (1695017800000.0, None),  # TS_MILLIS writes integers; a float is seconds
        ],
    )
    def test_epoch_millis_boundaries(self, ts: float, expected: str | None) -> None:
        obs = parse(dict(CONN, ts=ts)).observations[0]
        got = obs.event_time.isoformat() if obs.event_time else None
        assert got == expected
        assert ("invalid_ts" in obs.flags) is (expected is None)

    def test_zoneless_iso_is_flagged(self) -> None:
        obs = parse(dict(CONN, ts="2023-09-18T06:13:33.324862")).observations[0]
        assert obs.event_time is not None
        assert obs.event_time.isoformat() == "2023-09-18T06:13:33.324862+00:00"
        assert "timezone_assumed_utc" in obs.flags
        assert "timezone_assumed_utc" not in parse(CONN).observations[0].flags
        zoned = parse(dict(CONN, ts="2023-09-18T06:13:33Z")).observations[0]
        assert "timezone_assumed_utc" not in zoned.flags

    def test_numeric_string_ts_is_invalid(self) -> None:
        obs = parse(dict(CONN, ts="1695017613.324862")).observations[0]
        assert obs.event_time is None
        assert "invalid_ts" in obs.flags
        assert obs.unmapped["ts"] == "1695017613.324862"

    def test_unknown_keeps_invalid_ts_flag(self) -> None:
        obs = parse(fixture_lines("unknown")[1]).observations[0]
        assert obs.flags == ("log_type_unknown", "invalid_ts")

    def test_out_of_range_ts(self) -> None:
        obs = parse(dict(CONN, ts=1e300)).observations[0]
        assert obs.event_time is None and "invalid_ts" in obs.flags


class TestHostileInput:
    def test_wrong_types_go_to_unmapped(self) -> None:
        obs = parse(fixture_lines("conn")[4]).observations[0]
        assert obs.unmapped["id.orig_h"] == "not-an-ip"
        assert obs.unmapped["id.orig_p"] == "80"
        assert obs.unmapped["id.resp_p"] == 70000
        assert obs.unmapped["orig_bytes"] == -5
        assert obs.unmapped["resp_bytes"] == "lots"
        assert obs.attributes["dst_endpoint"] == {"ip": "203.0.113.20"}
        assert obs.community_id is None

    def test_scoped_ipv6_is_rejected(self) -> None:
        line = (FIXTURES / "malformed.ndjson").read_text(encoding="utf-8").splitlines()[-1]
        obs = parse(line).observations[0]
        assert obs.unmapped["id.orig_h"] == "fe80::1%eth0"
        assert "ip" not in obs.attributes["src_endpoint"]
        assert obs.community_id is None
        assert not any("%" in k for k in obs.entity_keys)

    def test_huge_integer_is_an_adapter_error(self) -> None:
        body = json.dumps(CONN).replace('"orig_bytes": 3536', '"orig_bytes": ' + "9" * 5000)
        assert "9" * 5000 in body
        with pytest.raises(AdapterError) as exc:
            parse(body)
        assert "999" not in str(exc.value)

    def test_limit_exceeded_propagates(self) -> None:
        deep = '{"a":' * 70 + "1" + "}" * 70
        with pytest.raises(LimitExceeded) as exc:
            parse(deep)
        assert exc.value.limit == "json_depth"

    def test_nul_and_lone_surrogate_are_replaced_and_flagged(self) -> None:
        body = json.dumps(dict(CONN, service="ht\x00tp", history="Sh\ud800"))
        obs = parse(body).observations[0]
        assert obs.unmapped["service"] == "ht\ufffdtp"
        assert obs.attributes["connection_info"]["flag_history"] == "Sh\ufffd"
        assert "invalid_unicode_replaced" in obs.flags
        assert "invalid_unicode_replaced" not in parse(CONN).observations[0].flags

    def test_unicode_flag_reaches_detections(self) -> None:
        result = parse(json.dumps(dict(NOTICE, msg="a\x00b")))
        assert "invalid_unicode_replaced" in result.observations[0].flags
        assert "invalid_unicode_replaced" in result.detections[0].attributes["flags"]
        assert result.detections[0].explanation["msg"] == "a\ufffdb"
        unknown = parse(json.dumps({"x": "\x00"})).observations[0]
        assert unknown.flags == ("log_type_unknown", "invalid_unicode_replaced")

    def test_bool_is_not_a_port(self) -> None:
        obs = parse(dict(CONN, **{"id.resp_p": True})).observations[0]
        assert "port" not in obs.attributes["dst_endpoint"]

    def test_huge_string_is_bounded(self) -> None:
        big = "a" * 100_000
        obs = parse(dict(CONN, history=big, uid=big)).observations[0]
        assert "flag_history" not in obs.attributes["connection_info"]
        assert obs.correlation == {}
        assert obs.unmapped["history"] == big

    def test_oversize_body(self) -> None:
        with pytest.raises(AdapterError, match="larger than") as exc:
            parse(json.dumps(dict(CONN, pad="x" * 300_000)))
        assert "xxxx" not in str(exc.value)

    def test_error_never_echoes_body(self) -> None:
        secret = "S3CR3T-" * 10
        with pytest.raises(AdapterError) as exc:
            parse(json.dumps({"note": secret, "msg": secret}))
        assert "S3CR3T" not in str(exc.value)

    @pytest.mark.parametrize("body", ["", "null", "[]", '"x"', "{", '{"ts": NaN}'])
    def test_not_an_object(self, body: str) -> None:
        with pytest.raises(AdapterError):
            parse(body)

    def test_invalid_utf8(self) -> None:
        raw = RawRecord(source="t", body=b'{"note":"\xff"}', received_at=FIXED_RECEIVED_AT)
        with pytest.raises(AdapterError, match="UTF-8"):
            ADAPTER.parse(raw, {})

    def test_ignores_receipt_metadata(self) -> None:
        # Same bytes, different receipt time, source and collector: identical drafts.
        other = RawRecord(
            source="elsewhere",
            body=json.dumps(NOTICE).encode("utf-8"),
            received_at=FIXED_RECEIVED_AT.replace(year=2030),
            collector={"path": "/var/log/zeek/conn.log", "host": "sensor-2"},
        )
        assert ADAPTER.parse(other, {}) == parse(NOTICE)


BIG_INT = "9" * 5000  # longer than Python's 4300-digit int parsing limit
SCOPED_IPV6 = "fe80::1%eth0"
VOCABULARY: list[Any] = [
    None,
    True,
    -1,
    2**70,
    1.5,
    1e308,
    "",
    "x" * 5000,
    "::",
    SCOPED_IPV6,
    [],
    ["a", 1],
    [SCOPED_IPV6],
    {"k": "v"},
    "1:abc",
    "Scan::Port_Scan",
    "TLSv12",
    "signatures",
    "nul\x00byte",
    "lone\ud800surrogate",
]
FUZZ_KEYS = ["note", "name", "addl", "fuid", "query", "trans_depth", "_path", "server_name"]
KINDS = {
    "network.flow",
    "dns.answer",
    "http.request",
    "tls.handshake",
    "file.transfer",
    "zeek.unknown",
}


def _mutate(rng: random.Random, record: dict[str, Any], big_int: bool) -> str:
    out = dict(record)
    for _ in range(rng.randint(1, 4)):
        key = rng.choice([*out, *FUZZ_KEYS])
        if rng.random() < 0.15:
            out.pop(key, None)
        elif big_int and rng.random() < 0.2:
            out[key] = "__BIG_INT__"
        else:
            out[key] = rng.choice(VOCABULARY)
    body = json.dumps(out).replace('"__BIG_INT__"', BIG_INT)
    if rng.random() < 0.1:  # byte-level damage
        cut = rng.randrange(len(body) + 1)
        body = body[:cut] + rng.choice(["", "}", '"', "\\", "\x00"]) + body[cut:]
    return body


def _check_result(result: ParseResult, body: str) -> None:
    """Invariants every successful parse must satisfy."""
    assert isinstance(result, ParseResult)
    assert result.observations or result.detections
    record = loads_object(body)  # the same sanitized view the adapter saw
    for obs in result.observations:
        assert obs.kind in KINDS
        assert obs.event_time is None or obs.event_time.utcoffset() == timedelta(0)
        assert set(obs.unmapped) <= set(record)  # unmapped only holds source fields, verbatim
        for key, value in obs.unmapped.items():
            assert value == record[key]
        for key in obs.entity_keys:
            assert key.split(":", 1)[0] in {"ip", "domain", "sha256"} and "%" not in key
        for key, ids in obs.correlation.items():
            assert key in {"zeek.uid", "zeek.fuid"}
            assert isinstance(ids, tuple) and ids
            assert all(isinstance(v, str) and "," not in v for v in ids)
    for det in result.detections:
        assert det.kind in {"zeek.notice", "zeek.weird"}
        assert det.authorship in {Authorship.BUILTIN, Authorship.LOCAL}
        assert det.identity.startswith(det.kind.replace(".", ":") + ":")
        assert len(det.identity) < 300
    json.dumps(result_to_jsonable(result))  # storable


def _fuzz(big_int: bool) -> tuple[int, int]:
    rng = random.Random(1234)
    seeds: list[dict[str, Any]] = []
    for path in sorted(FIXTURES.glob("*.ndjson")):
        for ln in path.read_text(encoding="utf-8").splitlines():
            try:
                value = json.loads(ln)
            except ValueError:
                continue
            if isinstance(value, dict):
                seeds.append(value)
    options: list[dict[str, Any]] = [{}, *({"log": t} for t in LOG_TYPES)]
    ok = failed = 0
    for _ in range(3000):
        body = _mutate(rng, rng.choice(seeds), big_int)
        try:
            result = parse(body, **rng.choice(options))
        except AdapterError:
            failed += 1
            continue
        _check_result(result, body)
        ok += 1
    return ok, failed


def test_fuzz_only_adapter_error_escapes() -> None:
    ok, failed = _fuzz(big_int=False)
    # both paths are exercised, so the invariants above actually ran
    assert ok > 1000 and failed > 100


def test_fuzz_with_huge_integers() -> None:
    _fuzz(big_int=True)
