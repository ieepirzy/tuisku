from __future__ import annotations

from datetime import UTC, datetime

import pytest

from tuisku.adapters import (
    AdapterError,
    Authorship,
    DetectionDraft,
    ObservationDraft,
    ParseResult,
    RawRecord,
    Severity,
    registry,
)
from tuisku.adapters.entities import (
    caller_key,
    domain_key,
    host_key,
    image_key,
    ip_key,
    k8s_namespace_key,
    k8s_pod_key,
    sha256_key,
    unique,
)
from tuisku.adapters.flows import check_reported, community_id, protocol_number
from tuisku.adapters.jsonsafe import loads_object
from tuisku.adapters.timeparse import parse_timestamp, parse_timestamp_or_none

T0 = datetime(2026, 11, 1, tzinfo=UTC)


def _obs() -> ObservationDraft:
    return ObservationDraft(kind="network.flow", event_time=T0, attributes={})


def _det(**kw: object) -> DetectionDraft:
    values: dict[str, object] = {
        "kind": "suricata.alert",
        "authorship": Authorship.COMMUNITY,
        "identity": "suricata:1:1",
        "title": "x",
        "severity": Severity.HIGH,
        "event_time": T0,
        "rule_ref": {"engine": "suricata"},
        "observation_refs": (0,),
    }
    values.update(kw)
    return DetectionDraft(**values)  # type: ignore[arg-type]


class TestParseResult:
    def test_valid_reference(self) -> None:
        ParseResult(observations=(_obs(),), detections=(_det(),))

    def test_dangling_reference_rejected(self) -> None:
        with pytest.raises(ValueError, match="references observation 1"):
            ParseResult(observations=(_obs(),), detections=(_det(observation_refs=(1,)),))

    def test_negative_reference_rejected(self) -> None:
        with pytest.raises(ValueError):
            ParseResult(observations=(_obs(),), detections=(_det(observation_refs=(-1,)),))

    def test_adapters_cannot_emit_tuisku_authored_detections(self) -> None:
        with pytest.raises(ValueError, match="worker"):
            ParseResult(observations=(_obs(),), detections=(_det(authorship=Authorship.TUISKU),))


class TestRawRecord:
    def test_text_decodes_utf8(self) -> None:
        raw = RawRecord(source="s", body="ä".encode(), received_at=T0)
        assert raw.text() == "ä"

    def test_invalid_utf8_is_adapter_error(self) -> None:
        raw = RawRecord(source="s", body=b"\xff\xfe", received_at=T0)
        with pytest.raises(AdapterError, match="UTF-8"):
            raw.text()


class _Dummy:
    name = "dummy-test"
    version = "0.0.1"

    def parse(self, raw: RawRecord, options: object) -> ParseResult:
        return ParseResult()


class TestRegistry:
    def test_register_and_get(self) -> None:
        a = _Dummy()
        registry.register(a)
        assert registry.get("dummy-test") is a
        assert "dummy-test" in registry.names()
        registry.register(a)  # idempotent for the same instance

    def test_conflicting_name_rejected(self) -> None:
        registry.register(_Dummy()) if "dummy-test" not in registry.names() else None
        with pytest.raises(ValueError, match="already registered"):
            registry.register(_Dummy())

    def test_non_adapter_rejected(self) -> None:
        with pytest.raises(TypeError):
            registry.register(object())  # type: ignore[arg-type]

    def test_unknown(self) -> None:
        with pytest.raises(KeyError):
            registry.get("no-such-adapter")


class TestEntities:
    @pytest.mark.parametrize(
        ("value", "expected"),
        [
            ("203.0.113.5", "ip:203.0.113.5"),
            ("2001:DB8:0:0::1", "ip:2001:db8::1"),
            ("not-an-ip", None),
            ("1.2.3.4.5", None),
            (12345, None),
        ],
    )
    def test_ip(self, value: object, expected: str | None) -> None:
        assert ip_key(value) == expected

    @pytest.mark.parametrize(
        ("value", "expected"),
        [
            ("WWW.Example.COM.", "domain:www.example.com"),
            ("bücher.example", "domain:xn--bcher-kva.example"),
            ("localhost", None),  # single label is a host, not a domain
            ("203.0.113.5", None),
            ("bad_label.example", None),
            ("-x.example", None),
            ("a" * 64 + ".example", None),
            ("ex ample.com", None),
            ("evil.com\nInjected: 1", None),
        ],
    )
    def test_domain(self, value: str, expected: str | None) -> None:
        assert domain_key(value) == expected

    def test_host(self) -> None:
        assert host_key("Node-1") == "host:node-1"
        assert host_key("node 1") is None

    def test_k8s(self) -> None:
        assert k8s_pod_key("default", "web-1") == "k8s:default/web-1"
        assert k8s_pod_key("Default", "web-1") is None
        assert k8s_pod_key("default", "../etc") is None
        assert k8s_namespace_key("kube-system") == "k8s-ns:kube-system"

    def test_image_sha_caller(self) -> None:
        assert image_key("ghcr.io/org/app") == "image:ghcr.io/org/app"
        assert image_key("bad image") is None
        h = "A" * 64
        assert sha256_key("sha256:" + h) == "sha256:" + "a" * 64
        assert sha256_key("abc") is None
        assert caller_key("harava", "agents") == "caller:harava/agents"
        assert caller_key("har/ava", "agents") is None

    def test_unique(self) -> None:
        assert unique("a", None, "b", "a") == ("a", "b")


class TestCommunityId:
    def test_reference_vector(self) -> None:
        # Vector from the reference implementation's documentation.
        assert community_id("tcp", "127.0.0.1", 1234, "10.0.0.1", 80) == (
            "1:mgRgpIZSu0KHDp/QrtcWZpkJpMU="
        )

    def test_direction_independent(self) -> None:
        a = community_id("udp", "10.0.0.5", 53211, "10.0.0.2", 53)
        b = community_id("UDP", "10.0.0.2", 53, "10.0.0.5", 53211)
        assert a is not None and a == b

    def test_invalid_inputs(self) -> None:
        assert community_id("tcp", "x", 1, "10.0.0.1", 2) is None
        assert community_id("tcp", "10.0.0.1", 70000, "10.0.0.2", 2) is None
        assert community_id("tcp", "10.0.0.1", None, "10.0.0.2", 2) is None
        assert community_id("tcp", "10.0.0.1", 1, "2001:db8::1", 2) is None
        assert community_id("bogus", "10.0.0.1", 1, "10.0.0.2", 2) is None
        assert community_id("tcp", "10.0.0.1", True, "10.0.0.2", 2) is None

    def test_protocol_number(self) -> None:
        assert protocol_number("TCP") == 6
        assert protocol_number("17") == 17
        assert protocol_number(300) is None

    def test_check_reported(self) -> None:
        assert check_reported("1:a", None) == ("1:a", ())
        assert check_reported("1:a", "1:a") == ("1:a", ())
        assert check_reported("1:a", "1:b") == ("1:a", ("community_id_mismatch",))
        assert check_reported(None, "1:b") == (None, ("community_id_mismatch",))


class TestTimestamps:
    @pytest.mark.parametrize(
        ("value", "expected"),
        [
            ("2023-09-18T06:13:41.532140+0000", datetime(2023, 9, 18, 6, 13, 41, 532140, UTC)),
            ("2023-09-18T08:13:41.5+02:00", datetime(2023, 9, 18, 6, 13, 41, 500000, UTC)),
            ("2026-10-30T12:00:00.123456789Z", datetime(2026, 10, 30, 12, 0, 0, 123456, UTC)),
            ("2026-11-01 09:14:03,512", datetime(2026, 11, 1, 9, 14, 3, 512000, UTC)),
            (1695017613.324862, datetime(2023, 9, 18, 6, 13, 33, 324862, UTC)),
            (1761825600123456789, datetime(2025, 10, 30, 12, 0, 0, 123456, UTC)),
            (1761825600, datetime(2025, 10, 30, 12, 0, 0, tzinfo=UTC)),
        ],
    )
    def test_formats(self, value: object, expected: datetime) -> None:
        got = parse_timestamp(value)
        assert got == expected
        assert got.tzinfo is not None

    @pytest.mark.parametrize(
        "value",
        [
            "yesterday",
            "2023-13-01T00:00:00Z",
            "1850-01-01T00:00:00Z",
            float("nan"),
            True,
            None,
            "2023-09-18T06:13:41" + "1" * 50,
        ],
    )
    def test_rejects(self, value: object) -> None:
        assert parse_timestamp_or_none(value) is None


class TestJsonSafe:
    def test_object(self) -> None:
        assert loads_object('{"a": [1, 2]}') == {"a": [1, 2]}

    @pytest.mark.parametrize(
        "text",
        ["[1]", "not json", '{"a": NaN}', '{"a": Infinity}', "[" * 100 + "]" * 100],
    )
    def test_rejects(self, text: str) -> None:
        with pytest.raises(AdapterError):
            loads_object(text)

    def test_depth_limit(self) -> None:
        deep = '{"a":' * 70 + "1" + "}" * 70
        with pytest.raises(AdapterError, match="nesting"):
            loads_object(deep)
        ok = '{"a":' * 10 + "1" + "}" * 10
        assert loads_object(ok)

    def test_very_deep_does_not_crash(self) -> None:
        deep = '{"a":' * 100_000 + "1" + "}" * 100_000
        with pytest.raises(AdapterError):
            loads_object(deep)

    def test_key_limit(self) -> None:
        text = "{" + ",".join(f'"k{i}": 1' for i in range(5000)) + "}"
        with pytest.raises(AdapterError, match="keys"):
            loads_object(text)
