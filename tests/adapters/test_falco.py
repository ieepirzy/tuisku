from __future__ import annotations

import hashlib
import json
import random
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from tuisku.adapters import registry
from tuisku.adapters.base import (
    AdapterError,
    Authorship,
    DetectionDraft,
    LimitExceeded,
    ObservationDraft,
    ParseResult,
    RawRecord,
    Severity,
)
from tuisku.adapters.falco import ADAPTER, MAX_LOCAL_RULES
from tuisku.adapters.flows import community_id
from tuisku.adapters.testing import (
    FIXED_RECEIVED_AT,
    assert_golden,
    result_to_jsonable,
    run_fixture_file,
)

FIXTURES = Path(__file__).parent.parent / "fixtures" / "falco"
LOCAL_OPTIONS = {"local_rules": ["Example estate tool executed"]}
# Inputs that once crashed shared contract helpers (flows.protocol_number, jsonsafe).
CONTRACT_CRASH_LINES = [
    '{"rule":"x","output_fields":{"fd.l4proto":"\u00b2","fd.cip":"10.0.0.1","fd.cport":1,'
    '"fd.sip":"10.0.0.2","fd.sport":2}}',
    '{"rule":"x","output_fields":{"fd.l4proto":"' + "9" * 5000 + '","fd.cip":"10.0.0.1",'
    '"fd.cport":1,"fd.sip":"10.0.0.2","fd.sport":2}}',
    '{"rule":"x","n":' + "9" * 4400 + "}",
]


def _options_for(path: Path) -> dict[str, Any]:
    return LOCAL_OPTIONS if path.stem == "local_rule" else {}


def _first(name: str) -> dict[str, Any]:
    return json.loads((FIXTURES / f"{name}.ndjson").read_text().splitlines()[0])


def _parse(record: dict[str, Any] | str, options: dict[str, Any] | None = None):
    body = record if isinstance(record, str) else json.dumps(record)
    raw = RawRecord(source="t", body=body.encode(), received_at=FIXED_RECEIVED_AT)
    return ADAPTER.parse(raw, options or {})


@pytest.mark.parametrize("path", sorted(FIXTURES.glob("*.ndjson")), ids=lambda p: p.stem)
def test_golden(path: Path) -> None:
    actual = run_fixture_file(ADAPTER, path, _options_for(path))
    assert_golden(actual, path.with_suffix(".expected.json"))


def test_registered() -> None:
    assert registry.get("falco") is ADAPTER
    assert ADAPTER.version == "1.0.0"


class TestLayerSplit:
    def test_one_observation_one_detection(self) -> None:
        result = _parse(_first("shell_in_container"))
        assert len(result.observations) == 1
        assert len(result.detections) == 1
        det = result.detections[0]
        assert det.observation_refs == (0,)
        assert det.kind == "falco.rule"
        assert det.identity == "falco:Terminal shell in container"
        assert det.rule_ref["engine"] == "falco"
        assert det.rule_ref["priority"] == "Notice"
        assert det.rule_ref["source"] == "syscall"
        assert det.attack == ("T1059",)
        assert det.explanation["mitre_tactics"] == ["mitre_execution"]

    def test_process_exec_attributes(self) -> None:
        obs = _parse(_first("shell_in_container")).observations[0]
        assert obs.kind == "process.exec"
        assert obs.ocsf_class_uid == 1007
        assert obs.attributes["process"] == {
            "name": "sh",
            "pid": 4242,
            "cmd_line": "sh",
            "file": {"path": "/bin/sh"},
            "parent_process": {"name": "runc", "pid": 4200},
        }
        assert obs.attributes["actor"] == {"user": {"name": "root", "uid": "0"}}
        assert obs.attributes["container"]["uid"] == "3ad7b26ded6d"
        assert obs.attributes["container"]["image"]["name"] == "docker.io/library/nginx"
        assert obs.attributes["k8s"] == {"namespace": "default", "pod": "web-1"}
        assert obs.attributes["device"] == {"hostname": "node-1"}
        assert obs.correlation == {"falco.uuid": "5d0b0f8e-1b7a-4c1e-9d2a-2f0e6c1a9b01"}
        # Unmapped fields are kept verbatim; mapped ones are not duplicated there.
        assert obs.unmapped["output_fields"] == {
            "container.image.digest": "sha256:" + "ab" * 32,
            "evt.time": 1793361600123456789,
            "evt.type": "execve",
            "proc.pid.ts": 1793361590000000000,
            "proc.tty": 34816,
            "user.loginuid": -1,
        }

    def test_rendered_output_is_interpretation(self) -> None:
        result = _parse(_first("shell_in_container"))
        assert "output" not in result.observations[0].unmapped
        out = result.detections[0].explanation["output"]
        assert out.startswith("12:00:00.123456789: Notice A shell")

    def test_non_exec_process_event_is_generic(self) -> None:
        rec = _first("shell_in_container")
        rec["output_fields"]["evt.type"] = "ptrace"
        obs = _parse(rec).observations[0]
        assert obs.kind == "falco.event"
        assert obs.ocsf_class_uid is None

    def test_exec_without_process_attributes_claims_no_class(self) -> None:
        rec = _first("shell_in_container")
        rec["output_fields"] = {"evt.time": 1793361600123456789, "evt.type": "execve"}
        obs = _parse(rec).observations[0]
        assert obs.kind == "falco.event"
        assert obs.ocsf_class_uid is None

    def test_file_fields_without_file_syscall_is_generic(self) -> None:
        rec = _first("sensitive_file_read")
        rec["output_fields"]["evt.type"] = "ptrace"
        assert _parse(rec).observations[0].kind == "falco.event"

    def test_fd_path_with_endpoints_is_not_a_file(self) -> None:
        rec = _first("outbound_connection")
        rec["output_fields"]["fd.name"] = "/tmp/looks-like-a-path"
        rec["output_fields"]["evt.type"] = "openat"
        obs = _parse(rec).observations[0]
        assert "file" not in obs.attributes
        assert obs.kind == "falco.event"
        assert obs.unmapped["output_fields"]["fd.name"] == "/tmp/looks-like-a-path"

    def test_file_access(self) -> None:
        obs = _parse(_first("sensitive_file_read")).observations[0]
        assert obs.kind == "file.access"
        assert obs.ocsf_class_uid == 1001
        assert obs.attributes["file"] == {"path": "/etc/shadow"}
        # container.id "host" is not a container; it stays unmapped verbatim.
        assert "container" not in obs.attributes
        assert obs.unmapped["output_fields"]["container.id"] == "host"
        assert obs.unmapped["output_fields"]["container.image.repository"] is None

    def test_outbound_connection_is_not_file_access(self) -> None:
        obs = _parse(_first("outbound_connection")).observations[0]
        assert obs.kind == "falco.event"
        assert obs.ocsf_class_uid is None
        assert "file" not in obs.attributes
        assert obs.attributes["src_endpoint"] == {"ip": "10.0.0.5", "port": 51234}
        assert obs.attributes["dst_endpoint"] == {"ip": "203.0.113.7", "port": 443}
        assert obs.unmapped["output_fields"]["fd.name"] == "10.0.0.5:51234->203.0.113.7:443"

    def test_non_syscall_source_is_generic(self) -> None:
        result = _parse(_first("k8s_audit"))
        obs = result.observations[0]
        assert obs.kind == "falco.event"
        assert obs.unmapped["output_fields"]["ka.verb"] == "create"
        assert result.detections[0].rule_ref["source"] == "k8s_audit"
        assert result.detections[0].attack == ("T1609",)

    def test_plugin_hostname_is_collector_not_asset(self) -> None:
        obs = _parse(_first("k8s_audit")).observations[0]
        assert "device" not in obs.attributes
        assert obs.attributes["metadata"] == {"collector": "falco-k8saudit-0"}
        assert not any(k.startswith("host:") for k in obs.entity_keys)

    @pytest.mark.parametrize("source", [None, 7, "s" * 65], ids=["missing", "int", "long"])
    def test_missing_or_invalid_source_is_not_syscall(self, source: object) -> None:
        rec = _first("shell_in_container")
        if source is None:
            del rec["source"]
        else:
            rec["source"] = source
        obs = _parse(rec).observations[0]
        assert obs.kind == "falco.event"
        assert obs.ocsf_class_uid is None
        assert "device" not in obs.attributes
        assert obs.attributes["metadata"] == {"collector": "node-1"}
        assert not any(k.startswith(("host:", "process:")) for k in obs.entity_keys)

    @pytest.mark.parametrize(
        ("fd_type", "evt_type"),
        [("unix", "openat"), ("file", "connect"), ("file", "sendto"), ("ipv4", "openat")],
    )
    def test_socket_fd_name_is_not_a_file(self, fd_type: str, evt_type: str) -> None:
        rec = _first("sensitive_file_read")
        rec["output_fields"]["fd.name"] = "/run/containerd/containerd.sock"
        rec["output_fields"]["fd.type"] = fd_type
        rec["output_fields"]["evt.type"] = evt_type
        obs = _parse(rec).observations[0]
        assert "file" not in obs.attributes
        assert obs.kind == "falco.event"
        assert obs.unmapped["output_fields"]["fd.name"] == "/run/containerd/containerd.sock"

    def test_regular_file_fd_is_still_a_file(self) -> None:
        rec = _first("sensitive_file_read")
        rec["output_fields"]["fd.type"] = "file"
        obs = _parse(rec).observations[0]
        assert obs.attributes["file"] == {"path": "/etc/shadow"}
        assert obs.kind == "file.access"


class TestInternal:
    def test_metrics_snapshot_is_observation_only(self) -> None:
        result = _parse(_first("internal"))
        assert result.detections == ()
        assert len(result.observations) == 1
        obs = result.observations[0]
        assert obs.kind == "falco.internal"
        assert obs.ocsf_class_uid is None
        assert obs.unmapped["output_fields"]["scap.n_drops"] == 0
        assert obs.unmapped["record"]["rule"] == "Falco internal: metrics snapshot"
        assert obs.unmapped["record"]["priority"] == "Informational"
        assert obs.attributes["device"] == {"hostname": "node-1"}

    def test_internal_source_is_observation_only(self) -> None:
        rec = _first("shell_in_container")
        rec["source"] = "internal"
        result = _parse(rec, {"local_rules": ["Terminal shell in container"]})
        assert result.detections == ()
        assert result.observations[0].kind == "falco.internal"

    def test_similar_rule_name_still_detects(self) -> None:
        rec = _first("shell_in_container")
        rec["rule"] = "Falco internal: metrics snapshot "
        assert len(_parse(rec).detections) == 1


class TestContractFlags:
    def test_invalid_unicode_replaced_and_flagged(self) -> None:
        rec = _first("shell_in_container")
        rec["output_fields"]["proc.cmdline"] = "sh\x00-c \ud800"
        obs = _parse(json.dumps(rec)).observations[0]
        assert obs.attributes["process"]["cmd_line"] == "sh\ufffd-c \ufffd"
        assert "invalid_unicode_replaced" in obs.flags

    def test_invalid_unicode_flag_on_unknown_records(self) -> None:
        obs = _parse('{"msg":"a\\u0000b"}').observations[0]
        assert obs.kind == "falco.unknown"
        assert obs.flags == ("no_rule", "invalid_unicode_replaced")

    def test_zone_less_time_flagged(self) -> None:
        rec = _first("missing_output_fields")
        rec["time"] = "2026-10-30T12:40:00.5"
        obs = _parse(rec).observations[0]
        assert obs.event_time == datetime(2026, 10, 30, 12, 40, 0, 500000, tzinfo=UTC)
        assert "timezone_assumed_utc" in obs.flags

    def test_zone_given_or_evt_time_not_flagged(self) -> None:
        for name in ("missing_output_fields", "shell_in_container"):
            assert "timezone_assumed_utc" not in _parse(_first(name)).observations[0].flags
        rec = _first("shell_in_container")
        rec["time"] = "2026-10-30T12:00:00"  # ignored: evt.time wins
        assert "timezone_assumed_utc" not in _parse(rec).observations[0].flags

    @pytest.mark.parametrize(
        ("line", "limit"),
        [
            ('{"rule":"x","a":' + "[" * 100 + "]" * 100 + "}", "json_depth"),
            ('{"rule":"x","output_fields":{' + ",".join(f'"k{i}":1' for i in range(5000)) + "}}",
             "json_keys"),
        ],
    )  # fmt: skip
    def test_limit_exceeded_propagates(self, line: str, limit: str) -> None:
        with pytest.raises(LimitExceeded) as exc:
            _parse(line)
        assert exc.value.limit == limit


class TestCommunityId:
    def test_computed_from_fd_tuple(self) -> None:
        obs = _parse(_first("outbound_connection")).observations[0]
        expected = community_id("tcp", "10.0.0.5", 51234, "203.0.113.7", 443)
        assert expected is not None
        assert obs.community_id == expected

    def test_absent_without_tuple(self) -> None:
        assert _parse(_first("shell_in_container")).observations[0].community_id is None


class TestEntityKeys:
    def test_container_keys(self) -> None:
        obs = _parse(_first("outbound_connection")).observations[0]
        assert obs.entity_keys == (
            "host:node-2",
            "k8s:payments/api-7d9f8c6b5-x2x9q",
            "k8s-ns:payments",
            "image:registry.example.com/team/api",
            "ip:10.0.0.5",
            "ip:203.0.113.7",
        )

    def test_detection_carries_same_keys(self) -> None:
        result = _parse(_first("shell_in_container"))
        assert result.detections[0].entity_keys == result.observations[0].entity_keys
        assert "k8s:default/web-1" in result.detections[0].entity_keys

    def test_process_and_image_digest_keys(self) -> None:
        keys = _parse(_first("shell_in_container")).observations[0].entity_keys
        assert "process:node-1/4242/1793361590000000000" in keys
        assert "sha256:" + "ab" * 32 in keys

    def test_no_process_key_without_start_or_asset_host(self) -> None:
        rec = _first("shell_in_container")
        rec["output_fields"]["proc.pid.ts"] = 17933615  # not ns magnitude
        assert not any(k.startswith("process:") for k in _parse(rec).observations[0].entity_keys)
        rec = _first("shell_in_container")
        rec["source"] = "k8s_audit"  # hostname is the collector, not the process's host
        assert not any(k.startswith("process:") for k in _parse(rec).observations[0].entity_keys)

    def test_k8s_audit_keys(self) -> None:
        obs = _parse(_first("k8s_audit")).observations[0]
        assert obs.entity_keys == ("k8s:default/web-1", "k8s-ns:default", "ip:192.0.2.10")

    def test_only_last_source_ip_is_trusted(self) -> None:
        rec = _first("k8s_audit")
        sourceips = ["203.0.113.66", "198.51.100.77", "192.0.2.10"]  # XFF, X-Real-Ip, remote
        rec["output_fields"]["ka.sourceips"] = sourceips
        obs = _parse(rec).observations[0]
        ips = [k for k in obs.entity_keys if k.startswith("ip:")]
        assert ips == ["ip:192.0.2.10"]
        assert "source_ips_forwarded" in obs.flags
        assert obs.unmapped["output_fields"]["ka.sourceips"] == sourceips

    def test_single_source_ip_not_flagged(self) -> None:
        obs = _parse(_first("k8s_audit")).observations[0]
        assert "ip:192.0.2.10" in obs.entity_keys
        assert "source_ips_forwarded" not in obs.flags

    def test_long_source_ip_list_still_uses_real_last_entry(self) -> None:
        rec = _first("k8s_audit")
        forged = [f"203.0.113.{i}" for i in range(1, 20)]  # more than 16 forwarded entries
        rec["output_fields"]["ka.sourceips"] = [*forged, "192.0.2.10"]
        obs = _parse(rec).observations[0]
        ips = [k for k in obs.entity_keys if k.startswith("ip:")]
        assert ips == ["ip:192.0.2.10"]
        assert obs.unmapped["output_fields"]["ka.sourceips"] == [*forged, "192.0.2.10"]
        assert "source_ips_forwarded" in obs.flags

    def test_invalid_last_source_ip_gives_no_key(self) -> None:
        rec = _first("k8s_audit")
        rec["output_fields"]["ka.sourceips"] = ["192.0.2.10", "not-an-ip"]
        obs = _parse(rec).observations[0]
        assert not any(k.startswith("ip:") for k in obs.entity_keys)

    def test_k8s_audit_non_pod_target_has_no_pod_key(self) -> None:
        rec = _first("k8s_audit")
        rec["output_fields"]["ka.target.resource"] = "secrets"
        rec["output_fields"]["ka.sourceips"] = "198.51.100.9"
        keys = _parse(rec).observations[0].entity_keys
        assert keys == ("k8s-ns:default", "ip:198.51.100.9")

    def test_cloudtrail_source_ip_key(self) -> None:
        line = (FIXTURES / "k8s_audit.ndjson").read_text().splitlines()[1]
        assert _parse(line).observations[0].entity_keys == ("ip:198.51.100.23",)

    def test_invalid_plugin_values_never_become_keys(self) -> None:
        rec = _first("k8s_audit")
        rec["output_fields"]["ka.target.namespace"] = "Bad_NS"
        rec["output_fields"]["ka.sourceips"] = ["not-an-ip", 7]
        assert _parse(rec).observations[0].entity_keys == ()

    def test_invalid_values_never_become_keys(self) -> None:
        rec = _first("outbound_connection")
        rec["hostname"] = "bad host!"
        rec["output_fields"]["fd.cip"] = "10.0.0.999"
        rec["output_fields"]["k8s.ns.name"] = "Bad_NS"
        keys = _parse(rec).observations[0].entity_keys
        assert not any(k.startswith(("host:", "k8s")) for k in keys)
        assert "ip:10.0.0.999" not in keys


class TestAuthorshipAndSeverity:
    def test_community_by_default(self) -> None:
        assert _parse(_first("local_rule")).detections[0].authorship is Authorship.COMMUNITY

    def test_local_when_listed(self) -> None:
        det = _parse(_first("local_rule"), LOCAL_OPTIONS).detections[0]
        assert det.authorship is Authorship.LOCAL

    def test_bad_option_type_fails_loudly(self) -> None:
        with pytest.raises(AdapterError, match="local_rules"):
            _parse(_first("local_rule"), {"local_rules": "Example estate tool executed"})

    def test_local_rules_cap(self) -> None:
        rule = "Example estate tool executed"
        ok = [rule] + [f"r{i}" for i in range(MAX_LOCAL_RULES - 1)]
        det = _parse(_first("local_rule"), {"local_rules": ok}).detections[0]
        assert det.authorship is Authorship.LOCAL
        with pytest.raises(AdapterError, match="local_rules"):
            _parse(_first("local_rule"), {"local_rules": [*ok, "one too many"]})

    def test_local_match_uses_full_rule_name_only(self) -> None:
        rec = _first("local_rule")
        rec["rule"] = "L" * 300
        prefix_only = {"local_rules": ["L" * 256]}
        assert _parse(rec, prefix_only).detections[0].authorship is Authorship.COMMUNITY
        full = {"local_rules": ["L" * 300]}
        assert _parse(rec, full).detections[0].authorship is Authorship.LOCAL

    def test_attack_version_option(self) -> None:
        det = _parse(_first("shell_in_container")).detections[0]
        assert det.rule_ref["attack_version"] is None
        det = _parse(_first("shell_in_container"), {"attack_version": "v16"}).detections[0]
        assert det.rule_ref["attack_version"] == "v16"
        for bad in (16, "", "v" * 40):
            with pytest.raises(AdapterError, match="attack_version"):
                _parse(_first("shell_in_container"), {"attack_version": bad})

    @pytest.mark.parametrize(
        ("priority", "severity"),
        [
            ("Emergency", Severity.CRITICAL),
            ("Alert", Severity.CRITICAL),
            ("Critical", Severity.CRITICAL),
            ("Error", Severity.HIGH),
            ("Warning", Severity.MEDIUM),
            ("Notice", Severity.LOW),
            ("Informational", Severity.INFORMATIONAL),
            ("info", Severity.INFORMATIONAL),
            ("INFO", Severity.INFORMATIONAL),
            ("Debug", Severity.INFORMATIONAL),
            ("debug", Severity.INFORMATIONAL),
            ("Spicy", Severity.UNKNOWN),
            (3, Severity.UNKNOWN),
        ],
    )
    def test_priority_mapping(self, priority: object, severity: Severity) -> None:
        rec = _first("shell_in_container")
        rec["priority"] = priority
        assert _parse(rec).detections[0].severity is severity


class TestAttack:
    def test_only_strict_technique_ids(self) -> None:
        rec = _first("shell_in_container")
        rec["tags"] = ["T1059", "T1059.004", "T１０５９", "T1059\n", "t1059", "T10590", "TA0002"]
        det = _parse(rec).detections[0]
        assert det.attack == ("T1059", "T1059.004")

    def test_invalid_tag_entries_kept_verbatim(self) -> None:
        rec = _first("shell_in_container")
        rec["tags"] = ["T1059", 7, None, "x" * 500]
        result = _parse(rec)
        assert result.detections[0].rule_ref["tags"] == ["T1059"]
        assert result.observations[0].unmapped["record"]["tags"] == rec["tags"]

    def test_tactic_tags_only_in_explanation(self) -> None:
        rec = _first("shell_in_container")
        rec["tags"] = ["mitre_execution"]
        det = _parse(rec).detections[0]
        assert det.attack == ()
        assert det.explanation["mitre_tactics"] == ["mitre_execution"]

    def test_tags_deduplicated(self) -> None:
        rec = _first("shell_in_container")
        rec["tags"] = ["mitre_execution", "T1059", "mitre_execution", "T1059", "mitre_persistence"]
        det = _parse(rec).detections[0]
        assert det.attack == ("T1059",)
        assert det.explanation["mitre_tactics"] == ["mitre_execution", "mitre_persistence"]


class TestTimestamps:
    def test_evt_time_preferred(self) -> None:
        rec = _first("shell_in_container")
        rec["time"] = "2026-01-01T00:00:00Z"
        obs = _parse(rec).observations[0]
        assert obs.event_time == datetime(2026, 10, 30, 12, 0, 0, 123456, tzinfo=UTC)
        assert obs.attributes["event_time_ns"] == 1793361600123456789
        assert obs.unmapped["output_fields"]["evt.time"] == 1793361600123456789
        assert obs.unmapped["record"]["time"] == "2026-01-01T00:00:00Z"

    def test_falls_back_to_time(self) -> None:
        rec = _first("shell_in_container")
        del rec["output_fields"]["evt.time"]
        rec["time"] = "2026-10-30T12:00:01.5Z"
        obs = _parse(rec).observations[0]
        assert obs.event_time == datetime(2026, 10, 30, 12, 0, 1, 500000, tzinfo=UTC)
        assert "event_time_ns" not in obs.attributes
        assert obs.unmapped["record"]["time"] == "2026-10-30T12:00:01.5Z"

    def test_small_evt_time_is_not_seconds(self) -> None:
        rec = _first("shell_in_container")
        rec["output_fields"]["evt.time"] = 1793361600  # seconds, not ns: not trusted
        rec["time"] = "2026-10-30T12:00:02Z"
        obs = _parse(rec).observations[0]
        assert obs.event_time == datetime(2026, 10, 30, 12, 0, 2, tzinfo=UTC)
        assert obs.unmapped["output_fields"]["evt.time"] == 1793361600
        assert "event_time_ns" not in obs.attributes

    def test_no_time_at_all(self) -> None:
        rec = _first("missing_output_fields")
        del rec["time"]
        obs = _parse(rec).observations[0]
        assert obs.event_time is None
        assert "event_time_missing" in obs.flags


class TestMalformed:
    @pytest.mark.parametrize(
        "line",
        [
            "{not json",
            "[1,2]",
            '{"rule":42}',
            '{"rule":""}',
            '{"rule":"x","time":NaN}',
            "\xff",
            "[" * 200 + "]" * 200,
        ],
    )
    def test_adapter_error(self, line: str) -> None:
        with pytest.raises(AdapterError):
            _parse(line)

    @pytest.mark.parametrize(
        ("line", "error"),
        [
            (CONTRACT_CRASH_LINES[0], None),
            (CONTRACT_CRASH_LINES[1], None),
            (CONTRACT_CRASH_LINES[2], "JSON number out of range"),
        ],
        ids=["superscript", "digits", "bigint"],
    )
    def test_contract_crash_inputs(self, line: str, error: str | None) -> None:
        if error is not None:
            with pytest.raises(AdapterError, match=error):
                _parse(line)
            return
        result = _parse(line)
        _check_result(result)
        obs = result.observations[0]
        # An unusable protocol yields no Community ID; the record has no time at all.
        assert obs.community_id is None
        assert obs.flags == ("event_time_missing",)
        assert obs.attributes["src_endpoint"] == {"ip": "10.0.0.1", "port": 1}
        proto = json.loads(line)["output_fields"]["fd.l4proto"]
        if len(proto) <= 16:
            assert obs.attributes["connection_info"] == {"protocol_name": proto}
        else:
            assert "connection_info" not in obs.attributes
            assert obs.unmapped["output_fields"]["fd.l4proto"] == proto

    SECRET = "SECRET-" + "z" * 100

    @pytest.mark.parametrize(
        ("body", "options"),
        [
            ('{"rule":"' + SECRET, {}),  # jsonsafe: invalid JSON
            ('{"rule":["' + SECRET + '"]}', {}),  # adapter: rule type
            ('{"rule":"x"}', {"local_rules": SECRET}),  # adapter: option type
            ('{"rule":"x"}', {"local_rules": [SECRET, 1]}),
            ('{"rule":"x"}', {"attack_version": SECRET}),
            ('{"rule":"x"}', {"attack_version": [SECRET]}),
        ],
    )
    def test_error_message_never_echoes_input(self, body: str, options: dict[str, Any]) -> None:
        with pytest.raises(AdapterError) as exc:
            _parse(body, options)
        assert "SECRET" not in str(exc.value)
        assert len(str(exc.value)) < 120

    def test_no_rule_key_is_unknown_observation(self) -> None:
        result = _parse({"time": "2026-10-30T12:00:00Z", "msg": "hi"})
        assert result.detections == ()
        assert result.observations[0].kind == "falco.unknown"
        assert result.observations[0].unmapped == {"time": "2026-10-30T12:00:00Z", "msg": "hi"}

    def test_wrong_types_go_to_unmapped(self) -> None:
        rec = _first("shell_in_container")
        rec["output_fields"]["proc.pid"] = "4242"
        rec["output_fields"]["user.uid"] = -5
        rec["output_fields"]["proc.ppid"] = True
        obs = _parse(rec).observations[0]
        assert "pid" not in obs.attributes["process"]
        assert "pid" not in obs.attributes["process"]["parent_process"]
        assert "uid" not in obs.attributes["actor"]["user"]
        assert obs.unmapped["output_fields"]["proc.pid"] == "4242"
        assert obs.unmapped["output_fields"]["user.uid"] == -5

    def test_huge_strings_bounded(self) -> None:
        rec = _first("shell_in_container")
        rec["rule"] = "R" * 1000
        rec["output"] = "A" * 100_000
        det = _parse(rec).detections[0]
        digest = hashlib.sha256(("R" * 1000).encode()).hexdigest()[:16]
        assert det.identity == "falco:" + "R" * 200 + "#" + digest
        assert det.rule_ref["rule"] == "R" * 256
        assert det.explanation["rule_truncated"] is True
        assert len(det.explanation["output"]) == 4096
        assert det.explanation["output_truncated"] is True

    def test_long_rules_sharing_a_prefix_do_not_collide(self) -> None:
        rec = _first("shell_in_container")
        identities = set()
        for suffix in ("a", "b"):
            rec["rule"] = "R" * 300 + suffix
            identities.add(_parse(rec).detections[0].identity)
        assert len(identities) == 2

    def test_rule_at_limit_is_not_hashed(self) -> None:
        rec = _first("shell_in_container")
        rec["rule"] = "R" * 256
        det = _parse(rec).detections[0]
        assert det.identity == "falco:" + "R" * 256
        assert "rule_truncated" not in det.explanation

    def test_backslash_escaped_so_escaping_is_unambiguous(self) -> None:
        rec = _first("shell_in_container")
        identities = []
        for rule in ("A\\x01", "A\x01"):
            rec["rule"] = rule
            result = _parse(rec)
            identities.append(result.detections[0].identity)
        assert identities == ["falco:A\\\\x01", "falco:A\\x01"]
        rec["rule"] = "C:\\path"
        result = _parse(rec)
        assert result.detections[0].identity == "falco:C:\\\\path"
        assert "control_chars" not in result.observations[0].flags

    @pytest.mark.parametrize(
        ("rule", "escaped"),
        [
            ("evil\u202ecod.exe", "evil\\u202ecod.exe"),
            ("zero\u200bwidth", "zero\\u200bwidth"),
            ("tag\U000e0041", "tag\\U000e0041"),
        ],
    )
    def test_format_chars_escaped_and_flagged(self, rule: str, escaped: str) -> None:
        rec = _first("shell_in_container")
        rec["rule"] = rule
        result = _parse(rec)
        det = result.detections[0]
        assert det.identity == "falco:" + escaped
        assert det.title == escaped
        assert "control_chars" in result.observations[0].flags

    def test_control_chars_escaped_and_flagged(self) -> None:
        rec = _first("shell_in_container")
        rec["rule"] = "Bad\nrule\x1b[31m\u0085"
        result = _parse(rec)
        det, obs = result.detections[0], result.observations[0]
        assert det.identity == "falco:Bad\\x0arule\\x1b[31m\\x85"
        assert det.title == det.rule_ref["rule"] == "Bad\\x0arule\\x1b[31m\\x85"
        assert "control_chars" in obs.flags
        assert det.explanation["rule_control_chars_escaped"] is True

    def test_uuid_must_be_canonical(self) -> None:
        rec = _first("shell_in_container")
        for bad in (
            "5d0b0f8e1b7a4c1e9d2a2f0e6c1a9b01",
            "-" * 36,
            "5d0b0f8e-1b7a-4c1e-9d2a-2f0e6c1a9b0g",
        ):
            rec["uuid"] = bad
            obs = _parse(rec).observations[0]
            assert obs.correlation == {}
            assert obs.unmapped["record"]["uuid"] == bad

    def test_output_fields_not_object(self) -> None:
        rec = _first("shell_in_container")
        rec["output_fields"] = ["proc.name"]
        obs = _parse(rec).observations[0]
        assert obs.kind == "falco.event"
        assert obs.unmapped["record"]["output_fields"] == ["proc.name"]
        assert "output_fields_invalid" in obs.flags


FUZZ_VALUES: list[Any] = [
    None,
    True,
    -1,
    2**70,
    1.5,
    "",
    "x" * 5000,
    "T1059",
    "10.0.0.1",
    "/etc/passwd",
    "execve",
    "openat",
    "internal",
    "pods",
    [],
    {},
    [None, {"a": [1]}],
    "\u202e\x00\x1b",
]
# Values that once crashed contract helpers (see CONTRACT_CRASH_LINES).
CONTRACT_FUZZ_VALUES: list[Any] = ["\u00b2", "9" * 5000]


def _mutate(value: Any, rng: random.Random, vocab: list[Any]) -> Any:
    if isinstance(value, dict) and value and rng.random() < 0.7:
        key = rng.choice(list(value))
        out = dict(value)
        if rng.random() < 0.2:
            del out[key]
        else:
            out[key] = _mutate(value[key], rng, vocab)
        return out
    if isinstance(value, list) and value and rng.random() < 0.5:
        out_list = list(value)
        i = rng.randrange(len(out_list))
        out_list[i] = _mutate(out_list[i], rng, vocab)
        return out_list
    return rng.choice(vocab)


def _seeds() -> list[dict[str, Any]]:
    return [
        json.loads(line)
        for path in sorted(FIXTURES.glob("*.ndjson"))
        for line in path.read_text().splitlines()
        if _is_json(line)
    ]


def _check_result(result: object) -> None:
    """Only a well-formed ParseResult may come back."""
    assert isinstance(result, ParseResult)
    assert len(result.observations) == 1
    assert len(result.detections) <= 1
    for obs in result.observations:
        assert isinstance(obs, ObservationDraft)
        assert obs.event_time is None or obs.event_time.tzinfo is not None
        assert all(isinstance(k, str) and k for k in obs.entity_keys)
        assert all(isinstance(v, str) for v in obs.correlation.values())
    for det in result.detections:
        assert isinstance(det, DetectionDraft)
        assert det.observation_refs == (0,)
        assert det.identity.startswith("falco:") and len(det.identity) <= 6 + 256
        assert isinstance(det.severity, Severity)
        assert det.authorship in (Authorship.COMMUNITY, Authorship.LOCAL)
        assert len(det.explanation.get("output", "")) <= 4096
    json.dumps(result_to_jsonable(result))


def _fuzz(vocab: list[Any], seed: int, rounds: int) -> int:
    rng = random.Random(seed)
    seeds = _seeds()
    assert len(seeds) >= 10
    parsed = 0
    for _ in range(rounds):
        rec = _mutate(rng.choice(seeds), rng, vocab)
        for _ in range(rng.randrange(3)):
            rec = _mutate(rec, rng, vocab)
        line = json.dumps(rec)
        if rng.random() < 0.1:
            line = line[: rng.randrange(len(line) + 1)]
        try:
            result = _parse(line, LOCAL_OPTIONS)
        except AdapterError:
            continue
        _check_result(result)
        parsed += 1
    return parsed


def test_fuzz_only_adapter_error_escapes() -> None:
    parsed = _fuzz(FUZZ_VALUES, 1234, 3000)
    assert parsed > 1000  # the fuzzer must mostly reach the parser, not just the JSON check


def test_fuzz_with_contract_crash_values() -> None:
    rng = random.Random(99)
    base = _first("outbound_connection")
    for _ in range(200):
        rec = _mutate(base, rng, FUZZ_VALUES)
        if isinstance(rec, dict) and isinstance(rec.get("output_fields"), dict):
            rec["output_fields"]["fd.l4proto"] = rng.choice(CONTRACT_FUZZ_VALUES)
        try:
            _check_result(_parse(json.dumps(rec), LOCAL_OPTIONS))
        except AdapterError:
            pass


def _is_json(line: str) -> bool:
    try:
        return isinstance(json.loads(line, parse_constant=_reject), dict)
    except ValueError:
        return False


def _reject(name: str) -> Any:
    raise ValueError(name)
