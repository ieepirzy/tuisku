from __future__ import annotations

import json
import random
from datetime import UTC, datetime
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
from tuisku.adapters.harava import (
    ADAPTER,
    MAX_DATAPOINTS,
    MAX_MESSAGE,
    MAX_REASON,
    MAX_REFUSAL_MESSAGE,
    _finite_float,
)
from tuisku.adapters.testing import FIXED_RECEIVED_AT, assert_golden, run_fixture_file

FIXTURES = Path(__file__).parent.parent / "fixtures" / "harava"
FIXTURE_FILES = sorted(p for p in FIXTURES.iterdir() if p.suffix in (".log", ".ndjson"))


def parse(line: str | bytes) -> ParseResult:
    body = line.encode("utf-8", "surrogatepass") if isinstance(line, str) else line
    return ADAPTER.parse(RawRecord("fixture", body, FIXED_RECEIVED_AT), {})


def line(message: str, logger: str = "harava.api", level: str = "WARNING") -> str:
    return f"2026-11-01 09:14:03,512 {level} {logger} {message}"


def docker(log: str, **extra: Any) -> str:
    return json.dumps({"log": log, "stream": "stderr", "time": "2026-11-01T09:14:04Z"} | extra)


OUTBOUND = line("outbound data refused: caller=agents urls=2 findings=email/query/percent")
DESTINATION = line("destination refused: caller=agents classes=ip_literal,tunnel")


def all_strings(value: Any) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, dict):
        return [s for k, v in value.items() for s in (*all_strings(k), *all_strings(v))]
    if isinstance(value, list | tuple):
        return [s for v in value for s in all_strings(v)]
    return []


@pytest.mark.parametrize("path", FIXTURE_FILES, ids=lambda p: p.name)
def test_golden(path: Path) -> None:
    assert_golden(run_fixture_file(ADAPTER, path), path.with_name(path.name + ".expected.json"))


def test_registered() -> None:
    assert registry.get("harava") is ADAPTER
    assert ADAPTER.version == "1.1.0"


class TestRefusals:
    def test_outbound_layer_split(self) -> None:
        r = parse(OUTBOUND)
        assert len(r.observations) == 1 and len(r.detections) == 1
        obs, det = r.observations[0], r.detections[0]
        assert obs.kind == "harava.refusal"
        assert obs.attributes["type"] == "outbound"
        assert obs.attributes["caller"] == "agents"
        assert obs.attributes["urls"] == 2
        assert obs.attributes["findings"] == [
            {"detector": "email", "location": "query", "encoding": "percent"}
        ]
        assert det.kind == "harava.outbound_refused"
        assert det.authorship is Authorship.BUILTIN
        assert det.identity == "harava:outbound_refused"
        assert det.severity is Severity.HIGH
        assert det.observation_refs == (0,)
        assert det.entity_keys == obs.entity_keys == ("caller:harava/agents",)

    def test_destination_layer_split(self) -> None:
        r = parse(DESTINATION)
        obs, det = r.observations[0], r.detections[0]
        assert obs.attributes["classes"] == ["ip_literal", "tunnel"]
        assert obs.attributes["stage"] == "admission"
        assert det.kind == "harava.destination_refused"
        assert det.identity == "harava:destination_refused"
        assert det.authorship is Authorship.BUILTIN
        assert det.entity_keys == ("caller:harava/agents",)

    @pytest.mark.parametrize("record", [OUTBOUND, DESTINATION])
    def test_detection_carries_only_the_verdict(self, record: str) -> None:
        other = record.replace("caller=agents", "caller=sidos").replace("urls=2", "urls=7")
        a, b = parse(record).detections[0], parse(other).detections[0]
        assert a.attributes == {}
        # Nothing taken from the line except the caller's entity key.
        assert (a.title, a.explanation, a.rule_ref) == (b.title, b.explanation, b.rule_ref)
        text = json.dumps([a.title, a.explanation, a.rule_ref])
        for fact in ("agents", "sidos", "email", "query", "percent", "ip_literal"):
            assert fact not in text

    @pytest.mark.parametrize(
        "record",
        [
            OUTBOUND,
            DESTINATION,
            docker(OUTBOUND + "\n", attrs={"tag": "harava-api"}),
            line(
                "outbound data refused: caller=agents urls=1 findings=email/body/plain",
            ),
        ],
    )
    def test_no_url_fields_invented(self, record: str) -> None:
        r = parse(record)
        stored = [
            r.observations[0].attributes,
            r.observations[0].unmapped,
            r.detections[0].attributes,
            r.detections[0].explanation,
            r.detections[0].rule_ref,
        ]
        keys = json.dumps(stored)
        for forbidden in ('"url"', '"urls_list"', "hostname", '"value"', "hash", "dst_endpoint"):
            assert forbidden not in keys
        assert not any("://" in s for s in all_strings(stored))

    @pytest.mark.parametrize(
        ("findings", "flag"),
        [
            ("ssn/query/plain", "unknown_detector"),
            ("email/body/plain", "unknown_location"),
            ("email/query/rot13", "unknown_encoding"),
            ("email/query", "malformed_finding"),
        ],
    )
    def test_unknown_finding_values(self, findings: str, flag: str) -> None:
        r = parse(line(f"outbound data refused: caller=agents urls=1 findings={findings}"))
        obs = r.observations[0]
        assert flag in obs.flags
        assert obs.attributes["findings"] == []
        assert obs.unmapped["findings_unrecognised"] == [findings]
        assert len(r.detections) == 1  # Harava still refused

    def test_findings_dedup(self) -> None:
        r = parse(
            line(
                "outbound data refused: caller=agents urls=1 "
                "findings=email/query/plain,email/query/plain,phone/host/plain"
            )
        )
        assert r.observations[0].attributes["findings"] == [
            {"detector": "email", "location": "query", "encoding": "plain"},
            {"detector": "phone", "location": "host", "encoding": "plain"},
        ]

    def test_unknown_class(self) -> None:
        r = parse(line("destination refused: caller=agents classes=overlay,wormhole"))
        obs = r.observations[0]
        assert obs.attributes["classes"] == ["overlay"]
        assert obs.unmapped["classes_unrecognised"] == ["wormhole"]
        assert "unknown_class" in obs.flags

    @pytest.mark.parametrize(
        "caller",
        [
            "../../x$",
            "a b",
            "agents urls=9",
            "agents classes=x",
            "",
            "x" * 129,
            "y" * 300,
            "z " * 2000,
            "agénts",
            "-lead",
            "a\x00b",
            "a\tb",
        ],
    )
    @pytest.mark.parametrize("kind", ["outbound", "destination"])
    def test_invalid_caller_is_withheld(self, caller: str, kind: str) -> None:
        if kind == "outbound":
            msg = f"outbound data refused: caller={caller} urls=1 findings=email/query/plain"
        else:
            msg = f"destination refused: caller={caller} classes=tunnel"
        r = parse(line(msg))
        obs = r.observations[0]
        assert "caller" not in obs.attributes
        assert obs.entity_keys == () and r.detections[0].entity_keys == ()
        assert "caller_invalid" in obs.flags
        assert len(r.detections) == 1
        stored = all_strings([obs.attributes, obs.unmapped, r.detections[0].explanation])
        assert caller == "" or not any(caller in s for s in stored if len(caller) > 3)

    @pytest.mark.parametrize(
        "message",
        [
            "outbound data refused: caller=agents urls=x findings=email/query/plain",
            "outbound data refused: caller=agents urls=\u0661 findings=email/query/plain",
            "outbound data refused: caller=agents findings=email/query/plain",
            "outbound data refused: caller=agents urls=1 findings=email/query/plain ",
            "destination refused: caller=agents",
            "destination refused: caller=agents classes=tunnel\x0b",
        ],
    )
    def test_malformed_refusal_is_loud(self, message: str) -> None:
        with pytest.raises(AdapterError):
            parse(line(message))

    def test_refusal_length_guard(self) -> None:
        # Valid up to the cut, so only the length guard can refuse it.
        findings = ",".join(["email/query/plain"] * (MAX_REFUSAL_MESSAGE // 18 + 10))
        msg = f"outbound data refused: caller=agents urls=1 findings={findings}"
        assert len(msg) > MAX_REFUSAL_MESSAGE
        with pytest.raises(AdapterError, match="longer than"):
            parse(line(msg))

    def test_refusal_text_from_other_logger_is_generic(self) -> None:
        r = parse(line("destination refused: caller=agents classes=tunnel", logger="x.y"))
        assert r.observations[0].kind == "harava.log"
        assert r.detections == ()

    def test_mcp_refused_to_serve(self) -> None:
        r = parse(line("MCP refuses to serve: " + "z" * 5000, "harava.mcp", "ERROR"))
        obs = r.observations[0]
        assert obs.kind == "harava.mcp_refused_to_serve"
        assert r.detections == ()
        assert len(obs.attributes["reason"]) == MAX_REASON
        assert "reason_truncated" in obs.flags

    def test_generic_log(self) -> None:
        r = parse(line("applied migration 0001", "harava.api", "INFO"))
        assert r.observations[0].kind == "harava.log"
        assert r.observations[0].attributes["message"] == "applied migration 0001"

    def test_generic_message_bounded(self) -> None:
        obs = parse(line("m" * (MAX_MESSAGE + 1), level="INFO")).observations[0]
        assert len(obs.attributes["message"]) == MAX_MESSAGE
        assert "message_truncated" in obs.flags


class TestControlCharacters:
    def test_message_escaped(self) -> None:
        obs = parse(docker(line("a\x00b\x1bc\x85d", level="INFO") + "\n")).observations[0]
        # NUL is replaced by the shared decoder; other C0/C1 characters are escaped here.
        assert obs.attributes["message"] == "a\ufffdb\\x1bc\\x85d"
        assert {"control_chars", "invalid_unicode_replaced"} <= set(obs.flags)

    def test_bare_line_nul_replaced(self) -> None:
        obs = parse(line("MCP refuses to serve: x\x00\x07", "harava.mcp", "ERROR")).observations[0]
        assert obs.attributes["reason"] == "x\ufffd\\x07"
        assert {"control_chars", "invalid_unicode_replaced"} <= set(obs.flags)

    def test_unmapped_escaped(self) -> None:
        obs = parse(
            line("outbound data refused: caller=agents urls=1 findings=em\x01ail/query/plain")
        ).observations[0]
        assert obs.unmapped["findings_unrecognised"] == ["em\\x01ail/query/plain"]
        assert "control_chars" in obs.flags
        env = parse(docker(OUTBOUND + "\n", **{"k\x02": "v\x9b", "s": "\ud800"})).observations[0]
        assert env.unmapped["envelope"]["k\\x02"] == "v\\x9b"
        assert env.unmapped["envelope"]["s"] == "\ufffd"
        assert {"control_chars", "invalid_unicode_replaced"} <= set(env.flags)

    @pytest.mark.parametrize(
        ("raw", "escaped"),
        [
            ("a\\x01", "a\\\\x01"),  # a literal backslash cannot pass for an escape
            ("a\x7fb", "a\\x7fb"),
            ("a\u2028b\u2029", "a\\u2028b\\u2029"),
            ("ab\u202ecd", "ab\\u202ecd"),
            ("x\u200by\ufeff", "x\\u200by\\ufeff"),
            ("tag\U000e0041", "tag\\U000e0041"),
        ],
    )
    def test_escaping_is_unambiguous(self, raw: str, escaped: str) -> None:
        obs = parse(docker(line(raw, level="INFO") + "\n")).observations[0]
        assert obs.attributes["message"] == escaped

    def test_backslash_alone_is_escaped_unflagged(self) -> None:
        obs = parse(docker(line("C:\\x", level="INFO") + "\n")).observations[0]
        assert obs.attributes["message"] == "C:\\\\x"
        assert "control_chars" not in obs.flags

    def test_otlp_unicode_flag(self) -> None:
        obs = parse(otlp([dp(detector="a\x00")])).observations[0]
        assert obs.attributes["labels"]["detector"] == "a\ufffd"
        assert "invalid_unicode_replaced" in obs.flags

    def test_no_nul_survives_anywhere(self) -> None:
        nul_metric = otlp([dp(detector="a\x00")]).replace("harava.outbound", "harava.\\u0000")
        for record in (docker(line("\x00", level="INFO") + "\n"), nul_metric):
            r = parse(record)
            for o in r.observations:
                assert not any("\x00" in s for s in all_strings([o.attributes, o.unmapped]))

    def test_clean_strings_unflagged(self) -> None:
        assert "control_chars" not in parse(OUTBOUND).observations[0].flags


class TestOtherLines:
    @pytest.mark.parametrize(
        ("text", "line_type"),
        [
            ("INFO:     Started server process [1]", "uvicorn"),
            ('INFO:     192.0.2.1:5000 - "GET /v1/fetch?e=a@example.com HTTP/1.1" 422', "uvicorn"),
            ("ERROR:    Exception in ASGI application", "uvicorn"),
            ("Traceback (most recent call last):", "traceback"),
            ('  File "/app/harava/api/app.py", line 355, in _refuse', "traceback"),
            ("ValueError: bad https://example.com/?x=1", "traceback"),
            ("httpx2.ConnectError:", "traceback"),
            ("KeyError", "traceback"),
            ("asyncio.exceptions.CancelledError", "traceback"),
        ],
    )
    def test_kept_withheld(self, text: str, line_type: str) -> None:
        for record in (text, docker(text + "\n")):
            r = parse(record)
            (obs,) = r.observations
            assert r.detections == ()
            assert obs.kind == "harava.unknown"
            assert obs.attributes["line_type"] == line_type
            assert "message_withheld" in obs.flags
            assert not any("example.com" in s for s in all_strings([obs.attributes, obs.unmapped]))

    def test_wrapped_fragment_flagged(self) -> None:
        obs = parse(docker("ail/query/plain urls=1\n")).observations[0]
        assert obs.kind == "harava.unknown"
        assert "possible_continuation" in obs.flags
        obs = parse("2026-11-01T09:14:04Z stderr F tail of a long line").observations[0]
        assert "possible_continuation" in obs.flags

    def test_bare_fragment_is_a_failure(self) -> None:
        with pytest.raises(AdapterError):
            parse("tail of a long line")


class TestTimestampsAndWrappers:
    def test_bare_line_is_utc(self) -> None:
        obs = parse(OUTBOUND).observations[0]
        assert obs.event_time == datetime(2026, 11, 1, 9, 14, 3, 512000, tzinfo=UTC)
        assert obs.attributes["asctime"] == "2026-11-01 09:14:03,512"
        assert "timezone_assumed_utc" in obs.flags

    def test_docker_time_without_zone_flagged(self) -> None:
        wrapped = json.dumps({"log": OUTBOUND + "\n", "time": "2026-11-01T09:14:04.5"})
        obs = parse(wrapped).observations[0]
        assert obs.event_time == datetime(2026, 11, 1, 9, 14, 4, 500000, tzinfo=UTC)
        assert "timezone_assumed_utc" in obs.flags

    def test_docker_time_preferred(self) -> None:
        wrapped = json.dumps(
            {"log": OUTBOUND + "\n", "stream": "stderr", "time": "2026-11-01T09:14:04.000001999Z"}
        )
        obs = parse(wrapped).observations[0]
        assert obs.event_time == datetime(2026, 11, 1, 9, 14, 4, 1, tzinfo=UTC)
        assert obs.attributes["asctime"] == "2026-11-01 09:14:03,512"
        assert obs.unmapped["stream"] == "stderr"
        assert obs.flags == ()

    def test_cri_time_preferred(self) -> None:
        obs = parse("2026-11-01T11:14:04.5+02:00 stderr F " + OUTBOUND).observations[0]
        assert obs.event_time == datetime(2026, 11, 1, 9, 14, 4, 500000, tzinfo=UTC)

    def test_partial_lines_flagged(self) -> None:
        cri = parse("2026-11-01T09:14:04Z stderr P " + line("x", level="INFO"))
        assert "cri_partial" in cri.observations[0].flags
        dock = parse(json.dumps({"log": line("x", level="INFO"), "time": "2026-11-01T09:14:04Z"}))
        assert "docker_partial" in dock.observations[0].flags

    def test_embedded_newline_guard(self) -> None:
        # Both halves are valid lines: only the embedded-newline guard can refuse this.
        with pytest.raises(AdapterError, match="embedded newline"):
            parse(docker(line("hello", level="INFO") + "\n" + OUTBOUND + "\n"))

    def test_docker_extra_keys_bounded(self) -> None:
        long_a, long_b = "k" * 200 + "a", "k" * 200 + "b"
        obs = parse(
            docker(OUTBOUND + "\n", **{long_a: 1, long_b: 2, "big": list(range(1000)), "ok": [1]})
        ).observations[0]
        assert obs.unmapped == {"stream": "stderr", "envelope": {"ok": [1]}}
        assert {"unmapped_key_too_long", "unmapped_dropped"} <= set(obs.flags)

    @pytest.mark.parametrize(
        "record",
        [
            '{"log": 5, "time": "2026-11-01T09:14:04Z"}',
            '{"log": "' + OUTBOUND + '\\n", "time": 17}',
            '{"log": "' + OUTBOUND + '\\n", "stream": "stdin"}',
            '{"log": "x", "n": ' + "9" * 5000 + "}",
            "not a log line",
            "",
            line("x", level="TRACE"),
            "2026-02-30 09:14:03,512 INFO harava.api x",
            "\u0662026-11-01 09:14:03,512 INFO harava.api x",
        ],
    )
    def test_malformed_lines(self, record: str) -> None:
        with pytest.raises(AdapterError):
            parse(record)

    def test_error_message_does_not_echo_body(self) -> None:
        secret = "SECRET-" + "q" * 100
        with pytest.raises(AdapterError) as exc:
            parse("GET /?email=" + secret)
        assert secret not in str(exc.value)

    def test_invalid_utf8(self) -> None:
        with pytest.raises(AdapterError):
            parse(b"\xff\xfe" + OUTBOUND.encode())


def _attr(k: str, v: Any, kind: str = "stringValue") -> dict[str, Any]:
    return {"key": k, "value": {kind: v}}


def otlp(datapoints: list[Any], **sum_kw: Any) -> str:
    data = {"aggregationTemporality": 2, "isMonotonic": True, "dataPoints": datapoints} | sum_kw
    return json.dumps(
        {
            "resourceMetrics": [
                {
                    "resource": {
                        "attributes": [_attr("service.name", "harava"), _attr("harava.role", "api")]
                    },
                    "scopeMetrics": [
                        {
                            "scope": {"name": "harava"},
                            "metrics": [{"name": "harava.outbound.refused", "sum": data}],
                        }
                    ],
                }
            ]
        }
    )


def dp(value: Any = "1", **labels: str) -> dict[str, Any]:
    return {
        "attributes": [_attr(k, v) for k, v in labels.items()],
        "startTimeUnixNano": "1793520000000000000",
        "timeUnixNano": "1793524443512000000",
        "asInt": value,
    }


GOOD = dp("3", detector="email", location="query", encoding="percent")


class TestOtlp:
    def test_sample(self) -> None:
        r = parse(otlp([GOOD]))
        (obs,) = r.observations
        assert r.detections == ()
        assert obs.kind == "metric.sample"
        assert obs.attributes["metric"] == "harava.outbound.refused"
        assert obs.attributes["value"] == 3
        assert obs.attributes["labels"] == {
            "detector": "email",
            "location": "query",
            "encoding": "percent",
        }
        assert obs.attributes["resource"] == {"service.name": "harava", "harava.role": "api"}
        assert obs.attributes["temporality"] == "cumulative"
        assert obs.attributes["is_monotonic"] is True
        assert obs.event_time == datetime(2026, 11, 1, 9, 14, 3, 512000, tzinfo=UTC)
        assert obs.flags == ()

    @pytest.mark.parametrize("value", ["-1", "-1000000000000000"])
    def test_negative_counter_is_not_a_sample(self, value: str) -> None:
        good = dp("2", detector="email", location="query", encoding="percent")
        bad = dp(value, detector="phone", location="host", encoding="plain")
        r = parse(otlp([good, bad]))
        assert [o.kind for o in r.observations] == ["metric.sample", "harava.unknown"]
        assert "negative_counter" in r.observations[1].flags

    def test_negative_double_is_not_a_sample(self) -> None:
        point = {k: v for k, v in GOOD.items() if k != "asInt"} | {"asDouble": -0.5}
        (obs,) = parse(otlp([point])).observations
        assert obs.kind == "harava.unknown" and "negative_counter" in obs.flags

    @pytest.mark.parametrize("monotonic", [{"isMonotonic": False}, {"isMonotonic": None}])
    def test_non_monotonic_sum_is_not_a_sample(self, monotonic: dict[str, Any]) -> None:
        body = json.loads(otlp([GOOD], **monotonic))
        if monotonic["isMonotonic"] is None:  # absent: OTLP's default is false
            del body["resourceMetrics"][0]["scopeMetrics"][0]["metrics"][0]["sum"]["isMonotonic"]
        (obs,) = parse(json.dumps(body)).observations
        assert obs.kind == "harava.unknown"
        assert "non_monotonic_sum" in obs.flags and "non_cumulative_sum" not in obs.flags

    def test_temporality_enum_name(self) -> None:
        r = parse(otlp([GOOD], aggregationTemporality="AGGREGATION_TEMPORALITY_CUMULATIVE"))
        assert r.observations[0].kind == "metric.sample"
        r = parse(otlp([GOOD], aggregationTemporality="AGGREGATION_TEMPORALITY_DELTA"))
        assert r.observations[0].kind == "harava.unknown"

    def test_asint_json_number(self) -> None:
        assert parse(otlp([dp(42)])).observations[0].attributes["value"] == 42

    def test_typed_labels(self) -> None:
        point = dp()
        point["attributes"] = [
            _attr("i", "7", "intValue"),
            _attr("j", 8, "intValue"),
            _attr("b", True, "boolValue"),
            _attr("d", 1.5, "doubleValue"),
            _attr("x", "y", "bytesValue"),
        ]
        obs = parse(otlp([point])).observations[0]
        assert obs.attributes["labels"] == {"i": 7, "j": 8, "b": True, "d": 1.5, "x": None}
        assert "label_unsupported_value" in obs.flags

    def test_unknown_label_value_flagged(self) -> None:
        obs = parse(otlp([dp(detector="ssn", location="query", encoding="plain")])).observations[0]
        assert "unknown_label_value" in obs.flags

    def test_label_values_bounded(self) -> None:
        obs = parse(otlp([dp(detector="x" * 10_000)])).observations[0]
        assert len(obs.attributes["labels"]["detector"]) == 256
        assert "label_truncated" in obs.flags

    def test_label_count_bounded(self) -> None:
        labels = {f"k{i}": "v" for i in range(100)}
        obs = parse(otlp([dp(**labels)])).observations[0]
        assert len(obs.attributes["labels"]) == 32
        assert "labels_truncated" in obs.flags

    def test_delta_sum_is_unknown(self) -> None:
        obs = parse(otlp([dp()], aggregationTemporality=1)).observations[0]
        assert obs.kind == "harava.unknown"
        assert "non_cumulative_sum" in obs.flags

    def test_datapoint_cap(self) -> None:
        assert len(parse(otlp([dp()] * MAX_DATAPOINTS)).observations) == MAX_DATAPOINTS
        with pytest.raises(LimitExceeded) as exc:
            parse(otlp([dp()] * (MAX_DATAPOINTS + 1)))
        assert exc.value.limit == "datapoints"

    def test_json_key_limit_propagates(self) -> None:
        point = dp() | {f"x{i}": 1 for i in range(300_000)}
        with pytest.raises(LimitExceeded) as exc:
            parse(otlp([point]))
        assert exc.value.limit == "json_keys"

    @pytest.mark.parametrize(
        ("bad", "flag"),
        [
            (dp("many"), "invalid_value"),
            (dp("\u0664"), "invalid_value"),
            (dp(str(2**63)), "invalid_value"),
            (dp(True), "invalid_value"),
            (
                {k: v for k, v in dp().items() if k != "asInt"} | {"asDouble": "NaN"},
                "invalid_value",
            ),
            ({k: v for k, v in dp().items() if k != "asInt"}, "missing_value"),
            (dp() | {"asDouble": 1.0}, "invalid_value"),
            (dp() | {"flags": 1}, "no_recorded_value"),
            (dp() | {"flags": "1"}, "invalid_datapoint"),
            (dp() | {"timeUnixNano": "12"}, "invalid_time"),
            (dp() | {"timeUnixNano": ["x"]}, "invalid_time"),
            (dp() | {"attributes": "x"}, "invalid_datapoint"),
            ("x", "invalid_datapoint"),
        ],
    )
    def test_bad_datapoint_is_kept_and_rest_survives(self, bad: Any, flag: str) -> None:
        r = parse(otlp([GOOD, bad, GOOD]))
        kinds = [o.kind for o in r.observations]
        assert kinds == ["metric.sample", "harava.unknown", "metric.sample"]
        assert flag in r.observations[1].flags
        assert r.observations[1].attributes["metric"] == "harava.outbound.refused"

    def test_dp_with_flags_zero_is_a_sample(self) -> None:
        assert parse(otlp([GOOD | {"flags": 0}])).observations[0].kind == "metric.sample"

    @pytest.mark.parametrize(
        "body",
        [
            otlp([dp()], dataPoints="x"),
            otlp([dp()], isMonotonic="yes"),
            '{"resourceMetrics": [{"scopeMetrics": [{"metrics": [{"sum": {}}]}]}]}',
            '{"resourceMetrics": [{"scopeMetrics": [{"metrics": ["x"]}]}]}',
            '{"resourceMetrics": [{"scopeMetrics": [{"metrics": [{"name": "m", "sum": {},'
            ' "gauge": {}}]}]}]}',
        ],
    )
    def test_bad_metric_is_kept(self, body: str) -> None:
        (obs,) = parse(body).observations
        assert obs.kind == "harava.unknown"
        assert "invalid_metric" in obs.flags

    @pytest.mark.parametrize(
        "body",
        [
            '{"resourceMetrics": 5}',
            '{"resourceMetrics": [5]}',
            '{"resourceMetrics": [{"scopeMetrics": 5}]}',
            '{"resourceMetrics": [], "x": NaN}',
        ],
    )
    def test_malformed_request(self, body: str) -> None:
        with pytest.raises(AdapterError):
            parse(body)

    def test_unhashable_temporality_does_not_crash(self) -> None:
        obs = parse(otlp([dp()], aggregationTemporality=[2])).observations[0]
        assert obs.kind == "harava.unknown"


def _mutations(rng: random.Random, text: str) -> str:
    chars = list(text)
    for _ in range(rng.randint(1, 8)):
        op = rng.random()
        pos = rng.randrange(len(chars) + 1)
        if op < 0.4 and chars:
            del chars[min(pos, len(chars) - 1)]
        elif op < 0.8:
            chars.insert(pos, rng.choice('{}[]",:/=, \\n0aZ\x00\x85é\u0661' + "9" * 3))
        else:
            chars[pos:pos] = list(text[rng.randrange(len(text)) :][:20])
    return "".join(chars)


def test_fuzz_only_adapter_errors_escape() -> None:
    rng = random.Random(20261101)
    seeds = [
        ln
        for path in FIXTURE_FILES
        for ln in path.read_text(encoding="utf-8").splitlines()
        if ln.strip()
    ] + FUZZ_EXTRA_SEEDS
    for seed in FUZZ_EXTRA_SEEDS:
        try:
            parse(seed)
        except AdapterError:
            pass
    for _ in range(4000):
        mutated = _mutations(rng, rng.choice(seeds))
        try:
            r = parse(mutated)
        except AdapterError:
            continue
        for o in r.observations:
            assert not any("\x00" in s for s in all_strings([o.attributes, o.unmapped]))


HUGE = int("9" * 400)


class TestOtlpRoundTwo:
    def test_huge_asdouble_skips_only_that_datapoint(self) -> None:
        bad = {k: v for k, v in dp().items() if k != "asInt"} | {"asDouble": HUGE}
        r = parse(otlp([GOOD, bad, GOOD]))
        assert [o.kind for o in r.observations] == [
            "metric.sample",
            "harava.unknown",
            "metric.sample",
        ]
        assert "invalid_value" in r.observations[1].flags

    def test_huge_double_label_flagged(self) -> None:
        point = dp()
        point["attributes"] = [_attr("d", HUGE, "doubleValue")]
        obs = parse(otlp([point])).observations[0]
        assert obs.kind == "metric.sample"
        assert obs.attributes["labels"] == {"d": None}
        assert "label_unsupported_value" in obs.flags

    @pytest.mark.parametrize("flags", [2**32, -1])
    def test_datapoint_flags_bounded_to_uint32(self, flags: int) -> None:
        obs = parse(otlp([GOOD | {"flags": flags}])).observations[0]
        assert obs.kind == "harava.unknown"
        assert "invalid_datapoint" in obs.flags

    def test_uint32_flags_without_no_value_bit_is_sample(self) -> None:
        assert parse(otlp([GOOD | {"flags": 2**32 - 2}])).observations[0].kind == "metric.sample"

    def _request(self, **over: Any) -> dict[str, Any]:
        req = json.loads(otlp([GOOD | {"exemplars": [], "description": "dp-level"}]))
        rm = req["resourceMetrics"][0]
        rm["schemaUrl"] = "https://opentelemetry.io/schemas/1.26.0"
        rm["resource"]["droppedAttributesCount"] = 2
        sm = rm["scopeMetrics"][0]
        sm["schemaUrl"] = "https://opentelemetry.io/schemas/1.25.0"
        sm["scope"] |= {
            "version": "0.9.2",
            "attributes": [_attr("a", "b")],
            "droppedAttributesCount": 1,
        }
        sm["metrics"][0]["description"] = "metric-level"
        req["description"] = "request-level"
        for path, value in over.items():
            target: Any = req
            *parents, last = path.split(".")
            for part in parents:
                target = target[int(part)] if part.isdigit() else target[part]
            target[last] = value
        return req

    def test_everything_kept_without_collisions(self) -> None:
        obs = parse(json.dumps(self._request())).observations[0]
        assert obs.kind == "metric.sample"
        u = obs.unmapped
        assert u["request"] == {"description": "request-level"}
        assert u["resource_metrics"] == {"schemaUrl": "https://opentelemetry.io/schemas/1.26.0"}
        assert u["resource"] == {"droppedAttributesCount": 2}
        assert u["scope_metrics"] == {"schemaUrl": "https://opentelemetry.io/schemas/1.25.0"}
        assert u["scope"] == {"attributes": [_attr("a", "b")], "droppedAttributesCount": 1}
        assert u["metric"] == {"description": "metric-level"}
        assert u["datapoint"] == {"exemplars": [], "description": "dp-level"}
        assert obs.attributes["scope"] == {"name": "harava", "version": "0.9.2"}

    def test_docker_extras_cannot_overwrite_adapter_fields(self) -> None:
        obs = parse(
            docker(
                line("outbound data refused: caller=agents urls=1 findings=x/y/z") + "\n",
                findings_unrecognised=["forged"],
            )
        ).observations[0]
        assert obs.unmapped["findings_unrecognised"] == ["x/y/z"]
        assert obs.unmapped["envelope"] == {"findings_unrecognised": ["forged"]}

    @pytest.mark.parametrize("attrs", ["x", [5], [{"key": 1}]])
    def test_malformed_resource_attributes_keep_datapoints(self, attrs: Any) -> None:
        req = self._request(**{"resourceMetrics.0.resource.attributes": attrs})
        obs = parse(json.dumps(req)).observations[0]
        assert obs.kind == "metric.sample"
        assert obs.attributes["resource"] == {}
        assert "invalid_resource_attributes" in obs.flags
        assert obs.unmapped["resource"]["attributes"] == attrs

    def test_repeated_sections_bounded(self) -> None:
        req = self._request(description="d" * 5000)
        obs = parse(json.dumps(req)).observations[0]
        assert "request" not in obs.unmapped
        assert "unmapped_dropped" in obs.flags

    def test_repeated_section_total_bounded(self) -> None:
        req = self._request(description="d" * 600, other="o" * 600)
        obs = parse(json.dumps(req)).observations[0]
        assert obs.unmapped["request"] == {"description": "d" * 600}
        assert "unmapped_dropped" in obs.flags

    def test_finite_float_guard(self) -> None:
        assert _finite_float(float("inf")) is None
        assert _finite_float(float("nan")) is None
        assert _finite_float(HUGE) is None
        assert _finite_float(True) is None
        assert _finite_float(2) == 2.0


FUZZ_EXTRA_SEEDS = [
    otlp([{k: v for k, v in dp().items() if k != "asInt"} | {"asDouble": HUGE}]),
    otlp([dp() | {"attributes": [_attr("d", HUGE, "doubleValue")]}]),
]
