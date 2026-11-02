"""Harava adapter: plain-text log lines and OTLP JSON metrics (ADR 0005).

Log lines come from Python logging with Harava's format
``%(asctime)s %(levelname)s %(name)s %(message)s`` (``harava.cli.configure_logging``); asctime is
``YYYY-MM-DD HH:MM:SS,mmm`` in the container's zone, UTC. A line arrives bare, wrapped by Docker's
json-file driver (``{"log": "<line>\\n", "stream": "stderr", "time": "<RFC3339Nano>"}``) or in the
CRI format used by Kubernetes (``<RFC3339Nano> <stream> <P|F> <line>``). The wrapper's timestamp,
when there is one, is the event time; the inner asctime is kept in the attributes.

Recognised messages (``harava.api.app`` and ``harava.mcp``):

- ``outbound data refused: caller=%s urls=%d findings=det/loc/enc,...`` (harava.api, WARNING)
- ``destination refused: caller=%s classes=a,b`` (harava.api, WARNING; only the admission stage
  logs, so ``stage = admission`` is implied)
- ``MCP refuses to serve: %s`` (harava.mcp, ERROR)

Refusals become a ``harava.refusal`` observation (the facts) plus a sensor detection (only the
verdict, authorship ``builtin``). Any other line in the logging format becomes ``harava.log``.
Uvicorn's own lines, traceback continuation lines and, inside a wrapper, chunks that do not start
with a timestamp (the tail of a line Docker or the CRI runtime split) become ``harava.unknown``
with the text withheld: uvicorn access lines and exception messages can carry request URLs, which
Harava itself never logs. Anything else is a parse failure.

OTLP: an ``ExportMetricsServiceRequest`` in OTLP/JSON encoding, detected by a top-level
``resourceMetrics``. Each datapoint of a cumulative sum becomes a ``metric.sample``. Other metrics
(gauges, histograms, non-cumulative sums), malformed metrics and datapoints that cannot be read
become flagged ``harava.unknown`` observations; the rest of the request is kept.

Privacy: Harava never logs the refused URL, the matched value or a hash of either, and its
metrics never carry caller, host or URL. This adapter adds no field for any of them.

U+0000 and lone surrogates are replaced with U+FFFD by the shared decoders
(``invalid_unicode_replaced``); every other C0/C1 control character in a stored string is escaped
as ``\\xNN`` and flagged ``control_chars``.
"""

from __future__ import annotations

import json
import re
from collections.abc import Mapping
from datetime import datetime
from typing import Any

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
from tuisku.adapters.entities import caller_key, unique
from tuisku.adapters.jsonsafe import INVALID_UNICODE_FLAG, loads_object_flagged, sanitize_text
from tuisku.adapters.registry import register
from tuisku.adapters.timeparse import parse_timestamp, parse_timestamp_with_zone_flag

# --- limits -------------------------------------------------------------------------------------

MAX_LINE = 256 * 1024  # ADR 0005 line limit; log records longer than this are refused
MAX_INNER_LINE = 64 * 1024  # a Harava log line; the regexes never see more than this
MAX_OTLP_BYTES = 5 * 1024 * 1024  # ADR 0005 body limit
MAX_OTLP_KEYS = 262_144  # ~13 keys per datapoint at the 10,000-datapoint cap, plus headroom
MAX_DATAPOINTS = 10_000  # ADR 0005
MAX_MESSAGE = 2048  # generic harava.log message, truncated beyond this
MAX_REFUSAL_MESSAGE = 8192  # 240 possible findings x ~30 characters; longer is not Harava's
MAX_REASON = 512
MAX_CALLER_FIELD = 256
MAX_LABELS = 32
MAX_LABEL_KEY = 128
MAX_LABEL_VALUE = 256
MAX_METRIC_NAME = 255
MAX_UNMAPPED_KEYS = 64
MAX_UNMAPPED_ENVELOPE = 1024  # JSON size of one extra docker envelope value
MAX_UNMAPPED_OTLP = 64 * 1024  # JSON size of one unmapped OTLP value (e.g. a histogram)
INT64_MIN, INT64_MAX = -(2**63), 2**63 - 1
UINT64_MAX = 2**64 - 1
NO_RECORDED_VALUE = 1  # DataPointFlags.DATA_POINT_FLAGS_NO_RECORDED_VALUE_MASK

# --- Harava's closed sets (harava.outbound, harava.destinations, harava.telemetry) --------------

DETECTORS = frozenset(
    {
        "userinfo",
        "email",
        "phone",
        "personal_id",
        "iban",
        "payment_card",
        "credential",
        "sensitive_value",
    }
)
LOCATIONS = frozenset({"userinfo", "host", "path", "query", "fragment", "crawl_scope"})
ENCODINGS = frozenset({"plain", "percent", "idna", "base64", "hex"})
DESTINATION_CLASSES = frozenset(
    {
        "overlay",
        "overlay_gateway",
        "capture_sink",
        "tunnel",
        "ip_mapping",
        "special_use",
        "operator",
        "ip_literal",
        "dynamic_dns",
    }
)
DESTINATION_STAGES = frozenset({"admission", "side_request", "hop", "discovery", "render"})
VERDICTS = frozenset({"none", "suspected", "likely"})
LEVELS = frozenset({"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"})

# Label value sets for Harava's security metrics, checked so a forged sample is flagged.
KNOWN_LABELS: dict[str, dict[str, frozenset[str]]] = {
    "harava.outbound.refused": {
        "detector": DETECTORS,
        "location": LOCATIONS,
        "encoding": ENCODINGS,
    },
    "harava.destination.refused": {"class": DESTINATION_CLASSES, "stage": DESTINATION_STAGES},
    "harava.content.signals": {"verdict": VERDICTS},
}

# --- patterns (fullmatch, ASCII classes, no nested quantifiers, applied to capped input) --------

_A = re.ASCII
_LINE = re.compile(
    r"(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2},\d{3}) ([A-Z]{1,10}) ([A-Za-z0-9_.-]{1,128}) (.*)",
    _A | re.DOTALL,
)
_STARTS_WITH_ASCTIME = re.compile(r"\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}", _A)
_CRI = re.compile(
    r"(\d{4}-\d{2}-\d{2}T[0-9:.]{8,18}(?:Z|[+-]\d{2}:\d{2})) (stdout|stderr) ([PF]) ", _A
)
_OUTBOUND = re.compile(
    r"outbound data refused: caller=(.{0,256}?) urls=(\d{1,7}) findings=(\S{1,8192})", _A
)
_DESTINATION = re.compile(r"destination refused: caller=(.{0,256}?) classes=(\S{1,8192})", _A)
_CALLER = re.compile(r"[A-Za-z0-9._:@+-]{1,128}", _A)
_OUTBOUND_PREFIX = "outbound data refused:"
_DESTINATION_PREFIX = "destination refused:"
_MCP_PREFIX = "MCP refuses to serve: "
_DIGITS = re.compile(r"-?\d{1,20}", _A)
_UVICORN = re.compile(r"(?:INFO|WARNING|ERROR|DEBUG|CRITICAL):\s", _A)
_EXCEPTION_LINE = re.compile(r"[A-Za-z_][A-Za-z0-9_.]{0,255}:(?: .*)?", _A | re.DOTALL)
_TRACEBACK_HEADERS = frozenset(
    {
        "Traceback (most recent call last):",
        "During handling of the above exception, another exception occurred:",
        "The above exception was the direct cause of the following exception:",
    }
)
_CONTROL = re.compile(r"[\x00-\x1f\x80-\x9f]")

_TEMPORALITY = {
    0: "unspecified",
    1: "delta",
    2: "cumulative",
    "AGGREGATION_TEMPORALITY_UNSPECIFIED": "unspecified",
    "AGGREGATION_TEMPORALITY_DELTA": "delta",
    "AGGREGATION_TEMPORALITY_CUMULATIVE": "cumulative",
}
_METRIC_TYPES = ("sum", "gauge", "histogram", "exponentialHistogram", "summary")


# --- shared helpers -----------------------------------------------------------------------------


def _escape_char(m: re.Match[str]) -> str:
    return f"\\x{ord(m.group(0)):02x}"


def _clean(value: Any, flags: list[str]) -> Any:
    """Escape C0/C1 control characters in every string, keys included.

    Input depth is bounded by ``loads_object`` (64), so the recursion is bounded too.
    """
    if isinstance(value, str):
        if _CONTROL.search(value):
            flags.append("control_chars")
            return _CONTROL.sub(_escape_char, value)
        return value
    if isinstance(value, dict):
        return {_clean(k, flags): _clean(v, flags) for k, v in value.items()}
    if isinstance(value, list):
        return [_clean(v, flags) for v in value]
    return value


def _observation(
    kind: str,
    event_time: datetime | None,
    attributes: dict[str, Any],
    flags: list[str],
    unmapped: dict[str, Any] | None = None,
    entity_keys: tuple[str, ...] = (),
) -> ObservationDraft:
    flags = list(flags)
    return ObservationDraft(
        kind=kind,
        event_time=event_time,
        attributes=_clean(attributes, flags),
        unmapped=_clean(unmapped or {}, flags),
        entity_keys=entity_keys,
        flags=tuple(dict.fromkeys(flags)),
    )


def _bound_unmapped(source: Mapping[Any, Any], max_value: int, flags: list[str]) -> dict[str, Any]:
    """Keep extra source fields verbatim but bounded: no long keys, no huge values."""
    out: dict[str, Any] = {}
    for key, value in source.items():
        if not isinstance(key, str) or len(key) > MAX_LABEL_KEY:
            flags.append("unmapped_key_too_long")
            continue
        if len(out) >= MAX_UNMAPPED_KEYS:
            flags.append("unmapped_dropped")
            break
        try:
            size = len(json.dumps(value))
        except (TypeError, ValueError):
            size = max_value + 1
        if size > max_value:
            flags.append("unmapped_dropped")
            continue
        out[key] = value
    return out


def _temporality(data: dict[str, Any]) -> str:
    value = data.get("aggregationTemporality", 0)
    if isinstance(value, bool) or not isinstance(value, int | str):
        return "invalid"
    return _TEMPORALITY.get(value, "invalid")


def _truncate(value: str, limit: int, flag: str, flags: list[str]) -> str:
    if len(value) > limit:
        flags.append(flag)
        return value[:limit]
    return value


# --- log lines ----------------------------------------------------------------------------------


class _Envelope:
    """What the wrapper (if any) said about the line."""

    __slots__ = ("line", "wrapped", "wrapper_time", "unmapped", "flags")

    def __init__(
        self,
        line: str,
        wrapped: bool,
        wrapper_time: datetime | None,
        unmapped: dict[str, Any],
        flags: list[str],
    ) -> None:
        self.line = line
        self.wrapped = wrapped
        self.wrapper_time = wrapper_time
        self.unmapped = unmapped
        self.flags = flags


def _wrapper_time(value: object) -> datetime:
    try:
        return parse_timestamp(value)
    except (ValueError, OverflowError, OSError):
        raise AdapterError("wrapper time is not a valid RFC 3339 timestamp") from None


def _docker_envelope(obj: dict[str, Any], json_flags: tuple[str, ...]) -> _Envelope:
    log = obj.get("log")
    if not isinstance(log, str):
        raise AdapterError("docker json-file record has no string 'log'")
    flags: list[str] = list(json_flags)
    unmapped: dict[str, Any] = {}
    stream = obj.get("stream")
    if stream is not None:
        if stream not in ("stdout", "stderr"):
            raise AdapterError("docker json-file 'stream' is not stdout or stderr")
        unmapped["stream"] = stream
    time_value = obj.get("time")
    wrapper_time = None
    if time_value is not None:
        try:
            wrapper_time, zone_given = parse_timestamp_with_zone_flag(time_value)
        except (ValueError, OverflowError, OSError):
            raise AdapterError("wrapper time is not a valid RFC 3339 timestamp") from None
        if not zone_given:
            flags.append("timezone_assumed_utc")
    extras = {k: v for k, v in obj.items() if k not in ("log", "stream", "time")}
    unmapped |= _bound_unmapped(extras, MAX_UNMAPPED_ENVELOPE, flags)
    if log.endswith("\n"):
        log = log[:-1]
    else:
        # Docker splits lines over 16 KiB; a chunk without the newline is a partial line.
        flags.append("docker_partial")
    return _Envelope(log, True, wrapper_time, unmapped, flags)


def _cri_envelope(text: str) -> _Envelope | None:
    m = _CRI.match(text[:64])
    if m is None:
        return None
    flags = ["cri_partial"] if m.group(3) == "P" else []
    return _Envelope(
        text[m.end() :], True, _wrapper_time(m.group(1)), {"stream": m.group(2)}, flags
    )


class _Line:
    __slots__ = ("asctime", "level", "logger", "message", "event_time", "env")

    def __init__(self, env: _Envelope, m: re.Match[str]) -> None:
        self.asctime, self.level, self.logger, self.message = m.groups()
        if self.level not in LEVELS:
            raise AdapterError("unknown log level")
        try:
            # No zone: UTC, as in Harava's containers.
            inner_time, zone_given = parse_timestamp_with_zone_flag(self.asctime)
        except (ValueError, OverflowError, OSError):
            raise AdapterError("log asctime is not a valid date") from None
        if env.wrapper_time is not None:
            self.event_time = env.wrapper_time
        else:
            self.event_time = inner_time
            if not zone_given:
                env.flags.append("timezone_assumed_utc")
        self.env = env

    def base(self) -> dict[str, Any]:
        return {"logger": self.logger, "level": self.level, "asctime": self.asctime}


def _caller(raw_caller: str, flags: list[str]) -> tuple[dict[str, str], tuple[str, ...]]:
    """The caller attribute and entity key, or neither (flagged) when the name is not plain."""
    key = caller_key("harava", raw_caller) if _CALLER.fullmatch(raw_caller) else None
    if key is None:
        flags.append("caller_invalid")
        return {}, ()
    return {"caller": raw_caller}, (key,)


def _refusal_match(pattern: re.Pattern[str], ln: _Line, what: str) -> re.Match[str]:
    if len(ln.message) > MAX_REFUSAL_MESSAGE:
        raise AdapterError(f"{what} refusal line longer than {MAX_REFUSAL_MESSAGE} characters")
    m = pattern.fullmatch(ln.message)
    if m is None:
        raise AdapterError(f"malformed {what} refusal line")
    return m


def _outbound(ln: _Line) -> ParseResult:
    m = _refusal_match(_OUTBOUND, ln, "outbound")
    flags = list(ln.env.flags)
    caller, keys = _caller(m.group(1), flags)
    urls = int(m.group(2))
    findings: list[dict[str, str]] = []
    unrecognised: list[str] = []
    seen: set[tuple[str, str, str]] = set()
    for entry in m.group(3).split(","):
        parts = entry.split("/")
        if len(parts) != 3:
            unrecognised.append(entry)
            flags.append("malformed_finding")
            continue
        detector, location, encoding = parts
        ok = True
        for value, allowed, flag in (
            (detector, DETECTORS, "unknown_detector"),
            (location, LOCATIONS, "unknown_location"),
            (encoding, ENCODINGS, "unknown_encoding"),
        ):
            if value not in allowed:
                flags.append(flag)
                ok = False
        if not ok:
            unrecognised.append(entry)
            continue
        if (detector, location, encoding) in seen:
            continue
        seen.add((detector, location, encoding))
        findings.append({"detector": detector, "location": location, "encoding": encoding})
    unmapped = dict(ln.env.unmapped)
    if unrecognised:
        unmapped["findings_unrecognised"] = unrecognised
    entity_keys = unique(*keys)
    observation = _observation(
        "harava.refusal",
        ln.event_time,
        {"type": "outbound", **caller, "urls": urls, "findings": findings, **ln.base()},
        flags,
        unmapped,
        entity_keys,
    )
    detection = DetectionDraft(
        kind="harava.outbound_refused",
        authorship=Authorship.BUILTIN,
        identity="harava:outbound_refused",
        title="Harava refused outbound data",
        severity=Severity.HIGH,
        event_time=ln.event_time,
        rule_ref={"engine": "harava", "name": "outbound_refused"},
        entity_keys=entity_keys,
        observation_refs=(0,),
        explanation={
            "sensor": "harava",
            "check": "outbound guard (harava.outbound)",
            "why": (
                "Harava found what looks like personal or secret data in URLs the caller asked "
                "it to fetch, and refused the request. Harava does not log the URL or the value; "
                "the findings are on the referenced observation."
            ),
        },
    )
    return ParseResult(observations=(observation,), detections=(detection,))


def _destination(ln: _Line) -> ParseResult:
    m = _refusal_match(_DESTINATION, ln, "destination")
    flags = list(ln.env.flags)
    caller, keys = _caller(m.group(1), flags)
    classes: list[str] = []
    unrecognised: list[str] = []
    for cls in m.group(2).split(","):
        if cls in DESTINATION_CLASSES:
            if cls not in classes:
                classes.append(cls)
        else:
            unrecognised.append(cls)
            flags.append("unknown_class")
    unmapped = dict(ln.env.unmapped)
    if unrecognised:
        unmapped["classes_unrecognised"] = unrecognised
    entity_keys = unique(*keys)
    observation = _observation(
        "harava.refusal",
        ln.event_time,
        {
            "type": "destination",
            **caller,
            "classes": classes,
            # Only the admission stage logs this line (harava.api.app._refuse_destinations).
            "stage": "admission",
            **ln.base(),
        },
        flags,
        unmapped,
        entity_keys,
    )
    detection = DetectionDraft(
        kind="harava.destination_refused",
        authorship=Authorship.BUILTIN,
        identity="harava:destination_refused",
        title="Harava refused a destination",
        severity=Severity.HIGH,
        event_time=ln.event_time,
        rule_ref={"engine": "harava", "name": "destination_refused"},
        entity_keys=entity_keys,
        observation_refs=(0,),
        explanation={
            "sensor": "harava",
            "check": "destination policy (harava.destinations), admission stage",
            "why": (
                "The caller asked Harava to fetch a destination in a refused class (overlay "
                "networks and gateways, request catchers, tunnels, local-network names). Harava "
                "logs the classes only, never the destination; they are on the referenced "
                "observation."
            ),
        },
    )
    return ParseResult(observations=(observation,), detections=(detection,))


def _mcp_refused(ln: _Line) -> ParseResult:
    flags = list(ln.env.flags)
    reason = _truncate(ln.message[len(_MCP_PREFIX) :], MAX_REASON, "reason_truncated", flags)
    return ParseResult(
        observations=(
            _observation(
                "harava.mcp_refused_to_serve",
                ln.event_time,
                {"reason": reason, **ln.base()},
                flags,
                dict(ln.env.unmapped),
            ),
        )
    )


def _generic(ln: _Line) -> ParseResult:
    flags = list(ln.env.flags)
    message = _truncate(ln.message, MAX_MESSAGE, "message_truncated", flags)
    return ParseResult(
        observations=(
            _observation(
                "harava.log",
                ln.event_time,
                {"message": message, **ln.base()},
                flags,
                dict(ln.env.unmapped),
            ),
        )
    )


def _other_line_type(line: str) -> str | None:
    if _UVICORN.match(line):
        return "uvicorn"
    if line in _TRACEBACK_HEADERS or line[:1] in (" ", "\t") or _EXCEPTION_LINE.fullmatch(line):
        return "traceback"
    return None


def _unknown_line(env: _Envelope, line: str, line_type: str, extra_flags: list[str]) -> ParseResult:
    attributes: dict[str, Any] = {"line_type": line_type, "length": len(line)}
    if line_type == "uvicorn":
        attributes["level"] = line.split(":", 1)[0]
    return ParseResult(
        observations=(
            _observation(
                "harava.unknown",
                env.wrapper_time,
                attributes,
                [*env.flags, *extra_flags, "message_withheld"],
                dict(env.unmapped),
            ),
        )
    )


def _parse_line(env: _Envelope) -> ParseResult:
    line = env.line.rstrip("\r\n")
    if len(line) > MAX_INNER_LINE:
        raise AdapterError(f"log line longer than {MAX_INNER_LINE} characters")
    if "\n" in line:
        raise AdapterError("log line contains an embedded newline")
    m = _LINE.fullmatch(line)
    if m is None:
        line_type = _other_line_type(line)
        if line_type is not None:
            return _unknown_line(env, line, line_type, [])
        if env.wrapped and not _STARTS_WITH_ASCTIME.match(line):
            # The tail of a line the runtime split (Docker at 16 KiB, CRI ``P`` chunks): the
            # chunk itself does not say so, so it is kept, withheld and flagged.
            return _unknown_line(env, line, "fragment", ["possible_continuation"])
        raise AdapterError("not a Harava log line (asctime levelname name message)")
    ln = _Line(env, m)
    if ln.logger == "harava.api":
        if ln.message.startswith(_OUTBOUND_PREFIX):
            return _outbound(ln)
        if ln.message.startswith(_DESTINATION_PREFIX):
            return _destination(ln)
    if ln.logger == "harava.mcp" and ln.message.startswith(_MCP_PREFIX):
        return _mcp_refused(ln)
    return _generic(ln)


# --- OTLP metrics -------------------------------------------------------------------------------


class _Skip(Exception):
    """A datapoint or metric that cannot be read; kept as a flagged ``harava.unknown``."""

    def __init__(self, flag: str, reason: str) -> None:
        super().__init__(reason)
        self.flag = flag
        self.reason = reason


def _int64(value: object, what: str, *, unsigned: bool = False) -> int:
    """OTLP/JSON encodes (u)int64 as a decimal string; plain JSON integers are accepted too."""
    if isinstance(value, bool):
        raise AdapterError(f"{what} is not an integer")
    if isinstance(value, str):
        if not _DIGITS.fullmatch(value):
            raise AdapterError(f"{what} is not an integer")
        value = int(value)
    if not isinstance(value, int):
        raise AdapterError(f"{what} is not an integer")
    low, high = (0, UINT64_MAX) if unsigned else (INT64_MIN, INT64_MAX)
    if not low <= value <= high:
        raise AdapterError(f"{what} is out of range")
    return value


def _nanos_time(value: object, what: str) -> datetime:
    nanos = _int64(value, what, unsigned=True)
    if nanos <= 10**17:
        raise AdapterError(f"{what} is not a nanosecond epoch timestamp")
    try:
        return parse_timestamp(nanos)
    except (ValueError, OverflowError, OSError):
        raise AdapterError(f"{what} is out of range") from None


def _any_value(value: object, flags: list[str]) -> Any:
    """An OTLP AnyValue as a plain, bounded value. Unsupported shapes return None and flag."""
    if not isinstance(value, dict) or len(value) != 1:
        flags.append("label_unsupported_value")
        return None
    ((kind, inner),) = value.items()
    if kind == "stringValue" and isinstance(inner, str):
        return _truncate(inner, MAX_LABEL_VALUE, "label_truncated", flags)
    if kind == "boolValue" and isinstance(inner, bool):
        return inner
    if kind == "intValue":
        try:
            return _int64(inner, "intValue")
        except AdapterError:
            flags.append("label_unsupported_value")
            return None
    if kind == "doubleValue" and isinstance(inner, int | float) and not isinstance(inner, bool):
        return float(inner)
    flags.append("label_unsupported_value")
    return None


def _attributes(value: object, flags: list[str], what: str) -> dict[str, Any]:
    if value is None:
        return {}
    if not isinstance(value, list):
        raise AdapterError(f"{what} attributes are not a list")
    out: dict[str, Any] = {}
    for item in value:
        if not isinstance(item, dict) or not isinstance(item.get("key"), str):
            raise AdapterError(f"{what} attribute is not a key/value object")
        key = item["key"]
        if len(key) > MAX_LABEL_KEY:
            flags.append("label_key_too_long")
            continue
        if len(out) >= MAX_LABELS:
            flags.append("labels_truncated")
            break
        out[key] = _any_value(item.get("value"), flags)
    return out


def _list(value: object, what: str) -> list[Any]:
    if value is None:
        return []
    if not isinstance(value, list):
        raise AdapterError(f"{what} is not a list")
    return value


def _dict(value: object, what: str) -> dict[str, Any]:
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise AdapterError(f"{what} is not an object")
    return value


def _metric_data(metric: dict[str, Any]) -> tuple[str | None, dict[str, Any]]:
    found = [t for t in _METRIC_TYPES if t in metric]
    if len(found) > 1:
        raise AdapterError("metric has more than one data type")
    if not found:
        return None, {}
    return found[0], _dict(metric[found[0]], "metric data")


def _count_datapoints(resource_metrics: list[Any]) -> None:
    """Enforce the datapoint cap over every datapoint list, readable or not."""
    total = 0
    for rm in resource_metrics:
        for sm in _list(_dict(rm, "resourceMetrics item").get("scopeMetrics"), "scopeMetrics"):
            for metric in _list(_dict(sm, "scopeMetrics item").get("metrics"), "metrics"):
                if not isinstance(metric, dict):
                    continue
                for t in _METRIC_TYPES:
                    data = metric.get(t)
                    if isinstance(data, dict) and isinstance(data.get("dataPoints"), list):
                        total += len(data["dataPoints"])
                if total > MAX_DATAPOINTS:
                    raise LimitExceeded("datapoints", f"more than {MAX_DATAPOINTS} OTLP datapoints")


def _value(dp: dict[str, Any]) -> int | float:
    has_int, has_double = "asInt" in dp, "asDouble" in dp
    if not has_int and not has_double:
        raise _Skip("missing_value", "datapoint has no value")
    if has_int and has_double:
        raise _Skip("invalid_value", "datapoint has both asInt and asDouble")
    if has_int:
        try:
            return _int64(dp["asInt"], "asInt")
        except AdapterError as exc:
            raise _Skip("invalid_value", str(exc)) from None
    value = dp["asDouble"]
    if isinstance(value, bool) or not isinstance(value, int | float):
        raise _Skip("invalid_value", "asDouble is not a finite number")
    return float(value)


_DP_MAPPED = ("attributes", "timeUnixNano", "startTimeUnixNano", "asInt", "asDouble")


def _sample(
    name: str,
    dp: dict[str, Any],
    common: dict[str, Any],
    flags: list[str],
    labels: dict[str, Any],
    temporality: str,
    is_monotonic: bool,
    metric_unmapped: dict[str, Any],
) -> ObservationDraft:
    point_flags = dp.get("flags", 0)
    if isinstance(point_flags, bool) or not isinstance(point_flags, int) or point_flags < 0:
        raise _Skip("invalid_datapoint", "datapoint flags are not an unsigned integer")
    if point_flags & NO_RECORDED_VALUE:
        raise _Skip("no_recorded_value", "datapoint has the no-recorded-value flag")
    try:
        time = _nanos_time(dp.get("timeUnixNano"), "timeUnixNano")
        start = dp.get("startTimeUnixNano")
        start_time = (
            _nanos_time(start, "startTimeUnixNano").isoformat()
            if start not in (None, "0", 0)
            else None
        )
    except AdapterError as exc:
        raise _Skip("invalid_time", str(exc)) from None
    value = _value(dp)
    for label, allowed in KNOWN_LABELS.get(name, {}).items():
        if labels.get(label) not in allowed:
            flags.append("unknown_label_value")
    unmapped = metric_unmapped | _bound_unmapped(
        {k: v for k, v in dp.items() if k not in _DP_MAPPED}, MAX_UNMAPPED_OTLP, flags
    )
    return _observation(
        "metric.sample",
        time,
        {
            "metric": name,
            "labels": labels,
            **common,
            "value": value,
            "start_time": start_time,
            "time": time.isoformat(),
            "temporality": temporality,
            "is_monotonic": is_monotonic,
        },
        flags,
        unmapped,
    )


def _samples(
    name: str,
    data: dict[str, Any],
    common: dict[str, Any],
    common_flags: list[str],
    metric_unmapped: dict[str, Any],
) -> list[ObservationDraft]:
    is_monotonic = data.get("isMonotonic", False)
    if not isinstance(is_monotonic, bool):
        raise _Skip("invalid_metric", "isMonotonic is not a boolean")
    datapoints = _list(data.get("dataPoints"), "dataPoints")
    out: list[ObservationDraft] = []
    for dp in datapoints:
        flags = list(common_flags)
        labels: dict[str, Any] = {}
        try:
            if not isinstance(dp, dict):
                raise _Skip("invalid_datapoint", "datapoint is not an object")
            try:
                labels = _attributes(dp.get("attributes"), flags, "datapoint")
            except AdapterError as exc:
                raise _Skip("invalid_datapoint", str(exc)) from None
            out.append(
                _sample(
                    name, dp, common, flags, labels, "cumulative", is_monotonic, metric_unmapped
                )
            )
        except _Skip as skip:
            kept = dp if isinstance(dp, dict) else {"datapoint": dp}
            try:
                event_time = _nanos_time(kept.get("timeUnixNano"), "timeUnixNano")
            except AdapterError:
                event_time = None
            out.append(
                _observation(
                    "harava.unknown",
                    event_time,
                    {
                        "metric": name,
                        "type": "sum",
                        "labels": labels,
                        **common,
                        "error": skip.reason,
                    },
                    [*flags, skip.flag],
                    _bound_unmapped(
                        {k: v for k, v in kept.items() if k != "attributes"},
                        MAX_UNMAPPED_OTLP,
                        flags,
                    ),
                )
            )
    return out


def _metric(
    metric: object, common: dict[str, Any], rflags: list[str], top_unmapped: dict[str, Any]
) -> list[ObservationDraft]:
    flags = list(rflags)
    name: str | None = None
    try:
        if not isinstance(metric, dict):
            raise _Skip("invalid_metric", "metric is not an object")
        raw_name = metric.get("name")
        if not isinstance(raw_name, str) or not 0 < len(raw_name) <= MAX_METRIC_NAME:
            raise _Skip("invalid_metric", "metric name is missing or too long")
        name = raw_name
        unit = metric.get("unit")
        common = common | {"unit": unit if isinstance(unit, str) and len(unit) <= 63 else None}
        try:
            mtype, data = _metric_data(metric)
        except AdapterError as exc:
            raise _Skip("invalid_metric", str(exc)) from None
        temporality = _temporality(data)
        if mtype == "sum" and temporality == "cumulative":
            extra = {k: v for k, v in metric.items() if k not in ("name", "unit", "sum")}
            extra = _bound_unmapped(extra | top_unmapped, MAX_UNMAPPED_OTLP, flags)
            try:
                return _samples(name, data, common, flags, extra)
            except AdapterError as exc:
                raise _Skip("invalid_metric", str(exc)) from None
        if mtype == "sum":
            flags.append("non_cumulative_sum")
        else:
            flags.append("unsupported_metric_type")
        return [
            _observation(
                "harava.unknown",
                None,
                {"metric": name, "type": mtype, **common},
                flags,
                _bound_unmapped(
                    {k: v for k, v in metric.items() if k not in ("name", "unit")} | top_unmapped,
                    MAX_UNMAPPED_OTLP,
                    flags,
                ),
            )
        ]
    except _Skip as skip:
        kept = metric if isinstance(metric, dict) else {"metric": metric}
        return [
            _observation(
                "harava.unknown",
                None,
                {"metric": name, "type": None, **common, "error": skip.reason},
                [*flags, skip.flag],
                _bound_unmapped(kept, MAX_UNMAPPED_OTLP, flags),
            )
        ]


def _parse_otlp(obj: dict[str, Any], json_flags: tuple[str, ...]) -> ParseResult:
    resource_metrics = _list(obj["resourceMetrics"], "resourceMetrics")
    _count_datapoints(resource_metrics)  # enforce the cap before building anything
    observations: list[ObservationDraft] = []
    top_unmapped = {k: v for k, v in obj.items() if k != "resourceMetrics"}
    for rm in resource_metrics:
        rm = _dict(rm, "resourceMetrics item")
        rflags: list[str] = list(json_flags)
        resource_obj = _dict(rm.get("resource"), "resource")
        resource = _attributes(resource_obj.get("attributes"), rflags, "resource")
        for sm in _list(rm.get("scopeMetrics"), "scopeMetrics"):
            sm = _dict(sm, "scopeMetrics item")
            scope_obj = _dict(sm.get("scope"), "scope")
            scope = {
                k: _truncate(scope_obj[k], MAX_METRIC_NAME, "scope_truncated", rflags)
                for k in ("name", "version")
                if isinstance(scope_obj.get(k), str)
            }
            common: dict[str, Any] = {"resource": resource, "scope": scope}
            for metric in _list(sm.get("metrics"), "metrics"):
                observations.extend(_metric(metric, common, rflags, top_unmapped))
    return ParseResult(observations=tuple(observations))


# --- adapter ------------------------------------------------------------------------------------


class HaravaAdapter:
    name = "harava"
    version = "1.0.0"

    def parse(self, raw: RawRecord, options: Mapping[str, Any]) -> ParseResult:
        if len(raw.body) > MAX_OTLP_BYTES:
            raise LimitExceeded("body_bytes", f"record larger than {MAX_OTLP_BYTES} bytes")
        text = raw.text()
        stripped = text.strip()
        if stripped.startswith("{"):
            # LimitExceeded (json_depth, json_keys) propagates for ingest to record.
            obj, json_flags = loads_object_flagged(stripped, max_keys=MAX_OTLP_KEYS)
            if "resourceMetrics" in obj:
                return _parse_otlp(obj, json_flags)
            if len(text) > MAX_LINE:
                raise LimitExceeded("line_length", f"log record longer than {MAX_LINE} characters")
            return _parse_line(_docker_envelope(obj, json_flags))
        if len(text) > MAX_LINE:
            raise LimitExceeded("line_length", f"log record longer than {MAX_LINE} characters")
        text, replaced = sanitize_text(text.rstrip("\r\n"))
        env = _cri_envelope(text) or _Envelope(text, False, None, {}, [])
        if replaced:
            env.flags.append(INVALID_UNICODE_FLAG)
        return _parse_line(env)


ADAPTER = HaravaAdapter()
register(ADAPTER)
