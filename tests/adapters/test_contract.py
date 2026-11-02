from __future__ import annotations

from collections.abc import Iterator
from datetime import UTC, datetime, timedelta, timezone

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
from tuisku.adapters.entities import (
    caller_key,
    domain_key,
    host_key,
    image_digest_key,
    image_key,
    ip_key,
    k8s_namespace_key,
    k8s_pod_key,
    process_key,
    sha256_key,
    unique,
)
from tuisku.adapters.flows import check_reported, community_id, protocol_number
from tuisku.adapters.jsonsafe import loads_object, loads_object_flagged, sanitize_text
from tuisku.adapters.testing import result_to_jsonable
from tuisku.adapters.timeparse import (
    parse_timestamp,
    parse_timestamp_or_none,
    parse_timestamp_with_zone_flag,
)

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


@pytest.fixture
def isolated_registry() -> Iterator[None]:
    """Snapshot the global registry and restore it, so tests neither see nor leak adapters."""
    saved = dict(registry._ADAPTERS)
    registry._ADAPTERS.clear()
    try:
        yield
    finally:
        registry._ADAPTERS.clear()
        registry._ADAPTERS.update(saved)


@pytest.mark.usefixtures("isolated_registry")
class TestRegistry:
    def test_register_and_get(self) -> None:
        a = _Dummy()
        registry.register(a)
        assert registry.get("dummy-test") is a
        assert "dummy-test" in registry.names()
        registry.register(a)  # idempotent for the same instance

    def test_conflicting_name_rejected(self) -> None:
        registry.register(_Dummy())
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
        assert protocol_number("006") == 6
        assert protocol_number(True) is None

    def test_check_reported(self) -> None:
        assert check_reported("1:a", None) == ("1:a", ())
        assert check_reported("1:a", "1:a") == ("1:a", ())
        assert check_reported("1:a", "1:b") == ("1:a", ("community_id_mismatch",))
        assert check_reported("1:a", 5) == ("1:a", ("community_id_mismatch",))
        assert check_reported(None, None) == (None, ())
        cid = "1:dGHyGvjMfljg6Bppwm3bg0LO8TY="
        assert check_reported(None, cid) == (cid, ("community_id_unverified",))
        assert check_reported(None, "1:b\n") == (None, ("community_id_invalid",))
        assert check_reported(None, 5) == (None, ("community_id_invalid",))


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
        ["[1]", "not json", '{"a": NaN}', '{"a": Infinity}', '{"a": 1e999}', '"x"', "null"],
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


class TestLimitExceeded:
    def test_is_adapter_error_with_limit(self) -> None:
        exc = LimitExceeded("datapoints")
        assert isinstance(exc, AdapterError) and isinstance(exc, ValueError)
        assert exc.limit == "datapoints"


class TestCorrelation:
    def test_multiple_values_per_key(self) -> None:
        obs = ObservationDraft(
            kind="zeek.http",
            event_time=T0,
            attributes={},
            correlation={"zeek.uid": "C1", "zeek.fuid": ("Fa1", "Fb2")},
        )
        out = result_to_jsonable(ParseResult(observations=(obs,)))
        assert out["observations"][0]["correlation"] == {
            "zeek.uid": "C1",
            "zeek.fuid": ["Fa1", "Fb2"],
        }


# Values that must never pass a validator: trailing/embedded newline, NUL, CR.
_CONTROL_SUFFIXES = ["\n", "\nx", "\x00", "\r", " "]


class TestHostileEntities:
    @pytest.mark.parametrize("bad", _CONTROL_SUFFIXES)
    def test_control_characters_rejected(self, bad: str) -> None:
        h = "a" * 64
        assert ip_key("203.0.113.5" + bad) is None
        assert domain_key("example.com" + bad) is None
        assert domain_key("exa" + bad + "mple.com") is None
        assert host_key("node-1" + bad) is None
        assert sha256_key(h + bad) is None
        assert k8s_namespace_key("default" + bad) is None
        assert k8s_pod_key("default", "web-1" + bad) is None
        assert k8s_pod_key("default" + bad, "web-1") is None
        assert image_key("ghcr.io/org/app" + bad) is None
        assert caller_key("harava" + bad, "agents") is None
        assert caller_key("harava", "agents" + bad) is None
        assert process_key("node-1" + bad, 1, T0) is None

    def test_ip_scope_and_mapped(self) -> None:
        assert ip_key("fe80::1%eth0") is None
        assert ip_key("fe80::1") == "ip:fe80::1"
        assert ip_key("::ffff:1.2.3.4") == "ip:1.2.3.4"
        assert ip_key("::FFFF:102:304") == "ip:1.2.3.4"

    @pytest.mark.parametrize(
        ("value", "expected"),
        [
            ("faß.de", "domain:xn--fa-hia.de"),  # UTS 46 non-transitional
            ("fass.de", "domain:fass.de"),
            ("FASS.de", "domain:fass.de"),
            ("xn--fa-hia.de", "domain:xn--fa-hia.de"),
            ("XN--BCHER-KVA.example", "domain:xn--bcher-kva.example"),
            ("xn--zz.example", None),  # invalid punycode
            ("xn--a.example", None),  # decodes to a disallowed code point
            ("so­ft.example", None),  # soft hyphen: rejected, not dropped
            ("a‍b.example", None),  # ZWJ outside a joining context
            ("a​b.example", None),  # zero-width space
            ("a️b.example", None),  # variation selector
            ("example.123", None),
            ("", None),
            (".", None),
        ],
    )
    def test_domain_idna(self, value: str, expected: str | None) -> None:
        assert domain_key(value) == expected

    def test_host_rejects_ip_literals(self) -> None:
        assert host_key("203.0.113.5") is None
        assert host_key("2001:db8::1") is None
        assert host_key("::ffff:1.2.3.4") is None
        assert host_key("node-1.") == "host:node-1"

    def test_k8s_namespace_is_a_label(self) -> None:
        assert k8s_namespace_key("a.b") is None
        assert k8s_namespace_key("a" * 63) == "k8s-ns:" + "a" * 63
        assert k8s_namespace_key("a" * 64) is None
        assert k8s_pod_key("a.b", "web") is None
        assert k8s_pod_key("default", "web.v1.x") == "k8s:default/web.v1.x"
        assert k8s_pod_key("default", "web..x") is None
        assert k8s_pod_key("default", ".web") is None
        assert k8s_pod_key("default", "web-") is None

    def test_process_key(self) -> None:
        start = datetime(2025, 10, 30, 12, 0, 0, 123456, UTC)
        assert process_key("Node-1", 4242, start) == "process:node-1/4242/1761825600123456000"
        eet = timezone(timedelta(hours=2))
        assert process_key("node-1", 0, start.astimezone(eet)) == (
            "process:node-1/0/1761825600123456000"
        )
        assert process_key("node-1", 1, datetime(2025, 10, 30)) is None  # naive
        assert process_key("node-1", -1, start) is None
        assert process_key("node-1", True, start) is None
        assert process_key("node-1", "1", start) is None
        assert process_key("node-1", 2**40, start) is None
        assert process_key("10.0.0.1", 1, start) is None
        assert process_key("bad host", 1, start) is None
        assert process_key("node-1", 1, "2025-10-30T12:00:00Z") is None

    def test_image_keys(self) -> None:
        h = "ab" * 32
        assert image_key("ghcr.io/org/app:1.2") == "image:ghcr.io/org/app"
        assert image_key(f"ghcr.io/org/app@sha256:{h}") == "image:ghcr.io/org/app"
        assert image_key(f"ghcr.io/org/app:1.2@sha256:{h}") == "image:ghcr.io/org/app"
        assert image_key("registry:5000/app") == "image:registry:5000/app"
        assert image_key("registry:5000/app:v1") == "image:registry:5000/app"
        assert image_key("app@sha256:xyz") is None
        assert image_key("app:bad tag") is None
        assert image_key("app@") is None
        assert image_digest_key(f"ghcr.io/org/app:1.2@sha256:{h}") == f"sha256:{h}"
        assert image_digest_key(f"sha256:{h.upper()}") == f"sha256:{h}"
        assert image_digest_key("ghcr.io/org/app:1.2") is None
        assert image_digest_key(h) is None  # a bare hex string is not an image digest
        assert image_digest_key(f"app@sha512:{'a' * 128}") is None


class TestCommunityIdBaseline:
    """Vectors from corelight/community-id-spec baseline/baseline_deflt.json (seed 0)."""

    @pytest.mark.parametrize(
        ("proto", "saddr", "sport", "daddr", "dport", "expected"),
        [
            # ICMP echo request and its reply hash the same.
            (1, "192.168.0.89", 8, "192.168.0.1", 0, "1:X0snYXpgwiv9TZtqg64sgzUn6Dk="),
            (1, "192.168.0.1", 0, "192.168.0.89", 8, "1:X0snYXpgwiv9TZtqg64sgzUn6Dk="),
            # ICMPv6 neighbour solicitation/advertisement.
            (
                58,
                "fe80::200:86ff:fe05:80da",
                135,
                "fe80::260:97ff:fe07:69ea",
                136,
                "1:dGHyGvjMfljg6Bppwm3bg0LO8TY=",
            ),
            # SCTP.
            (132, "192.168.170.8", 7, "192.168.170.56", 7, "1:MP2EtRCAUIZvTw6MxJHLV7N7JDs="),
            # A port-less protocol (46, RSVP): ports are ignored.
            (46, "10.1.12.1", None, "10.1.12.2", None, "1:KHlLkgoJW7ifUTyTSgyVfkFHzKw="),
            (46, "10.1.12.2", 9, "10.1.12.1", 9, "1:KHlLkgoJW7ifUTyTSgyVfkFHzKw="),
        ],
    )
    def test_vectors(
        self, proto: int, saddr: str, sport: object, daddr: str, dport: object, expected: str
    ) -> None:
        assert community_id(proto, saddr, sport, daddr, dport) == expected

    def test_zeek_icmp_label_for_icmpv6(self) -> None:
        # Zeek logs proto "icmp" for ICMPv6; over IPv6 addresses it must hash as 58.
        got = community_id("icmp", "fe80::200:86ff:fe05:80da", 135, "fe80::260:97ff:fe07:69ea", 136)
        assert got == "1:dGHyGvjMfljg6Bppwm3bg0LO8TY="

    @pytest.mark.parametrize(
        "args",
        [
            ("icmp", "10.0.0.1", 300, "10.0.0.2", 0),  # ICMP type above 255
            ("tcp", "10.0.0.1", 1, "2001:db8::1", 2),  # v4/v6 mix
            ("tcp", "fe80::1%eth0", 1, "fe80::2", 2),  # scoped
        ],
    )
    def test_failed_computation_keeps_sensor_value(self, args: tuple[object, ...]) -> None:
        computed = community_id(*args)
        assert computed is None
        reported = "1:dGHyGvjMfljg6Bppwm3bg0LO8TY="
        assert check_reported(computed, reported) == (reported, ("community_id_unverified",))
        assert check_reported(computed, None) == (None, ())

    def test_scoped_ipv6_rejected(self) -> None:
        assert community_id("tcp", "fe80::1%eth0", 1, "fe80::2", 2) is None
        assert community_id("tcp", "fe80::1", 1, "fe80::2%1", 2) is None

    def test_icmp_type_code_bound(self) -> None:
        assert community_id("icmp", "10.0.0.1", 255, "10.0.0.2", 0) is not None
        assert community_id("icmp", "10.0.0.1", 256, "10.0.0.2", 0) is None
        assert community_id("icmp", "10.0.0.1", 8, "10.0.0.2", 256) is None

    @pytest.mark.parametrize(
        "proto", ["²", "١٢", "6" * 5000, "0006", "-1", " ", "", "\x00", 2**100, 6.0, None]
    )
    def test_protocol_number_hostile(self, proto: object) -> None:
        assert protocol_number(proto) is None


class TestHostileJson:
    def test_huge_integer(self) -> None:
        digits = "7" * 5000
        with pytest.raises(AdapterError) as info:
            loads_object('{"a": ' + digits + "}")
        assert digits[:20] not in str(info.value)

    def test_duplicate_keys(self) -> None:
        with pytest.raises(AdapterError, match="duplicate") as info:
            loads_object('{"secret-key": 1, "secret-key": 2}')
        assert "secret-key" not in str(info.value)

    @pytest.mark.parametrize(
        ("text", "expected"),
        [
            ('{"a": "x\\u0000y"}', {"a": "x\ufffdy"}),
            ('{"a\\u0000": 1}', {"a\ufffd": 1}),
            ('{"a": "\\ud800"}', {"a": "\ufffd"}),
            ('{"\\udc00": 1}', {"\ufffd": 1}),
            ('{"a": ["ok", "\\ud83d"]}', {"a": ["ok", "\ufffd"]}),
            (
                '{"a": [["\\u0000"]], "b": {"c": "\\udfff!"}}',
                {"a": [["\ufffd"]], "b": {"c": "\ufffd!"}},
            ),
        ],
    )
    def test_nul_and_lone_surrogates_replaced(self, text: str, expected: object) -> None:
        # Replaced, not rejected: a hostile User-Agent must not make a record unparseable.
        assert loads_object_flagged(text) == (expected, ("invalid_unicode_replaced",))
        assert loads_object(text) == expected

    def test_clean_text_has_no_flag(self) -> None:
        assert loads_object_flagged('{"a": "\\ud83d\\ude00", "b": ["x"]}') == (
            {"a": "\U0001f600", "b": ["x"]},
            (),
        )

    def test_keys_colliding_after_replacement_are_duplicates(self) -> None:
        with pytest.raises(AdapterError, match="duplicate"):
            loads_object('{"a\\u0000": 1, "a\\ud800": 2}')

    def test_sanitize_text(self) -> None:
        assert sanitize_text("plain ä \U0001f600") == ("plain ä \U0001f600", False)
        assert sanitize_text("a\x00b\ud800c") == ("a\ufffdb\ufffdc", True)

    def test_depth_boundary(self) -> None:
        def nested(n: int) -> str:
            return '{"a":' * n + "1" + "}" * n

        assert loads_object(nested(64))
        with pytest.raises(LimitExceeded) as info:
            loads_object(nested(65))
        assert info.value.limit == "json_depth"

    def test_deep_array_inside_object(self) -> None:
        with pytest.raises(LimitExceeded) as info:
            loads_object('{"a":' + "[" * 100 + "]" * 100 + "}")
        assert info.value.limit == "json_depth"

    def test_recursion_is_depth_limit(self) -> None:
        with pytest.raises(LimitExceeded) as info:
            loads_object('{"a":' * 100_000 + "1" + "}" * 100_000)
        assert info.value.limit == "json_depth"

    def test_key_boundary(self) -> None:
        def flat(n: int) -> str:
            return "{" + ",".join(f'"k{i}": 1' for i in range(n)) + "}"

        assert len(loads_object(flat(4096))) == 4096
        with pytest.raises(LimitExceeded) as info:
            loads_object(flat(4097))
        assert info.value.limit == "json_keys"

    def test_keys_counted_across_nested_objects(self) -> None:
        inner = "{" + ",".join(f'"k{i}": 1' for i in range(3000)) + "}"
        with pytest.raises(LimitExceeded):
            loads_object('{"a": ' + inner + ', "b": ' + inner + "}")

    def test_not_text(self) -> None:
        with pytest.raises(AdapterError):
            loads_object(b'{"a": 1}')  # type: ignore[arg-type]


class TestHostileTimestamps:
    @pytest.mark.parametrize(
        "value",
        [
            10**30,
            -(10**30),
            2**63,
            1e300,
            -1e300,
            "9999-12-31T23:59:59-23:59",
            "0001-01-01T00:00:00+23:59",
            "0000-01-01T00:00:00Z",
            "2023-02-30T00:00:00Z",
            "2023-09-18T25:00:00Z",
            "2023-09-18T06:13:41+24:00",
            "2023-09-18T06:13:41+14:01",
            "2023-09-18T06:13:41-1401",
            "2023-09-18T06:13:41+15:00",
            "2023-09-18T06:13:41+05:60",
            "2023-09-18T06:13:41+99:99",
            "２０２３-09-18T06:13:41Z",
            "2023-09-18T06:13:41Z\n",
            "2023-09-18T06:13:41Z\nx",
            "2023-09-18T06:13:41\x00Z",
            "2023-09-18T06:13:41Z\r",
            " 2023-09-18T06:13:41Z",
            "2023-09-18T06:13:41ZZ",
        ],
    )
    def test_only_adapter_error(self, value: object) -> None:
        with pytest.raises(AdapterError) as info:
            parse_timestamp(value)
        assert str(value) not in str(info.value)
        assert parse_timestamp_or_none(value) is None

    def test_offset_bounds_accepted(self) -> None:
        assert parse_timestamp("2023-09-18T14:00:00+14:00") == datetime(2023, 9, 18, tzinfo=UTC)
        assert parse_timestamp("2023-09-18T00:00:00-1400") == datetime(2023, 9, 18, 14, tzinfo=UTC)
        assert parse_timestamp("2023-09-18T00:00:00-0059") == datetime(
            2023, 9, 18, 0, 59, tzinfo=UTC
        )

    def test_lowercase_t_and_z(self) -> None:
        assert parse_timestamp("2023-09-18t06:13:41z") == datetime(
            2023, 9, 18, 6, 13, 41, tzinfo=UTC
        )

    def test_leap_second(self) -> None:
        assert parse_timestamp("2016-12-31T23:59:60Z") == datetime(
            2016, 12, 31, 23, 59, 59, 999999, UTC
        )

    def test_zone_flag(self) -> None:
        assert parse_timestamp_with_zone_flag("2026-11-01 09:14:03,512") == (
            datetime(2026, 11, 1, 9, 14, 3, 512000, UTC),
            False,
        )
        assert parse_timestamp_with_zone_flag("2026-11-01T09:14:03Z")[1] is True
        assert parse_timestamp_with_zone_flag("2026-11-01T09:14:03+0200")[1] is True
        assert parse_timestamp_with_zone_flag(1761825600)[1] is True
        assert parse_timestamp_with_zone_flag(1761825600.5)[1] is True

    def test_nanosecond_threshold(self) -> None:
        # Ints above 10**17 are epoch nanoseconds. 1990-01-01 in ns (6.3e17) must be read as ns;
        # a threshold moved above it would read it as seconds and reject it.
        assert parse_timestamp(631152000 * 10**9) == datetime(1990, 1, 1, tzinfo=UTC)
        assert parse_timestamp(631152000 * 10**9 + 1500) == datetime(1990, 1, 1, 0, 0, 0, 1, UTC)
        # A seconds value just below the threshold is far out of range, not silently ns.
        with pytest.raises(AdapterError):
            parse_timestamp(10**17)

    def test_range_bounds(self) -> None:
        assert parse_timestamp("1990-01-01T00:00:00Z") == datetime(1990, 1, 1, tzinfo=UTC)
        with pytest.raises(AdapterError):
            parse_timestamp("1989-12-31T23:59:59.999999Z")
        assert parse_timestamp("2199-12-31T23:59:59.999999Z") == datetime(
            2199, 12, 31, 23, 59, 59, 999999, UTC
        )
        with pytest.raises(AdapterError):
            parse_timestamp("2200-01-01T00:00:00Z")
        with pytest.raises(AdapterError):
            parse_timestamp("2199-12-31T23:30:00-01:00")
