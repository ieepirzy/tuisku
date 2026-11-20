"""Decoding OTLP/HTTP JSON logs requests (``ExportLogsServiceRequest``) into raw records.

Each ``logRecord`` becomes one raw record, exactly as one NDJSON envelope does
(ADR 0005):

- ``raw`` is the record's ``body.stringValue``, byte for byte. Shippers ship raw lines, they
  do not parse. A body of any other ``AnyValue`` kind (a ``kvlistValue`` from a collector-side
  ``json_parser``, say) is **refused** (``body_not_string``) rather than re-serialized, because
  a re-serialization is not what the sensor wrote.
- ``collector`` keeps the resource attributes and the record's own attributes **apart**:
  ``{"resource": {...}, "attributes": {...}}``, keyed by their OpenTelemetry names
  (``k8s.node.name``, ``log.file.path``...), with values flattened from ``AnyValue`` to plain
  JSON, plus ``observed_time_unix_nano`` and ``time_unix_nano`` when the record sets them.
  Record attributes can be derived from log content (a collector operator that parses the
  line), so they must never be able to pose as the resource that describes the shipper's own
  node or pod. Like any ``collector``, it is untrusted receipt metadata, never evidence about
  the event, and no adapter reads it.
- Metadata never costs evidence. Attributes that are malformed (a bad ``intValue``, two kinds
  in one ``AnyValue``, a repeated key) or over a limit (``AnyValue`` nesting, key count, the
  collector byte cap) replace the record's ``collector`` with a ``tuisku_collector_dropped*``
  marker and name the breach; the record itself is stored and parsed. A malformed *envelope*
  for NDJSON is rejected instead, because there the envelope and the line are one JSON value.

Everything is decoded once, off the event loop, in :func:`decode_request`: each resource's
attributes are converted, bounded and sized once, however many records share them, and each
record's collector is sized as the resource's size plus its own. Decoding stops as soon as the
record count passes the limit.

Field names follow the OTLP/JSON encoding (lowerCamelCase); unknown fields are ignored, as the
OTLP specification requires of receivers. A request whose structure down to the log records is
malformed is refused as a whole (:class:`InvalidRequest`); a malformed log record is rejected
on its own. Error messages never echo the input.
"""

from __future__ import annotations

import json
import math
import re
from dataclasses import dataclass
from typing import Any

from tuisku.adapters.jsonsafe import MAX_KEYS, sanitize_text

BODY_NOT_STRING = "body_not_string"
INVALID_LOG_RECORD = "invalid_log_record"
OBSERVED_TIME_KEY = "observed_time_unix_nano"
TIME_KEY = "time_unix_nano"

# Why a record's collector was replaced by a marker: the subject of the breach it raises.
COLLECTOR_BYTES = "collector_bytes"
COLLECTOR_DEPTH = "collector_depth"
COLLECTOR_KEYS = "collector_keys"
COLLECTOR_INVALID = "collector_invalid"
DROPPED_BYTES_KEY = "tuisku_collector_dropped_bytes"
DROPPED_KEY = "tuisku_collector_dropped"

MAX_ANY_VALUE_DEPTH = 32
# Keys in one collector, over both parts and all nesting (the jsonsafe per-record limit, less
# the collector's own top-level keys).
MAX_COLLECTOR_KEYS = MAX_KEYS - 4
# Rejected records listed by number in a response, so it stays far below the 64 KiB an OTLP
# exporter reads of it.
MAX_LISTED_REJECTIONS = 100

_ANY_VALUE_KINDS = (
    "stringValue",
    "boolValue",
    "intValue",
    "doubleValue",
    "arrayValue",
    "kvlistValue",
    "bytesValue",
)
_INT = re.compile(r"-?[0-9]{1,19}")
_UINT64 = re.compile(r"[0-9]{1,20}")
# A JSON number, or proto3 JSON's spellings of the non-finite doubles.
_DOUBLE = re.compile(r"-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?")
_NON_FINITE = frozenset({"NaN", "Infinity", "-Infinity"})
_INT64_MIN, _INT64_MAX = -(2**63), 2**63 - 1
_UINT64_MAX = 2**64 - 1


class InvalidRequest(ValueError):
    """The request is not an OTLP/JSON logs request. The message never contains input."""


class TooManyRecords(ValueError):
    """The request holds more log records than allowed; decoding stopped there."""


class _Malformed(ValueError):
    pass


class _OverLimit(ValueError):
    def __init__(self, limit: str) -> None:
        super().__init__(limit)
        self.limit = limit


def _reject_constant(name: str) -> Any:
    raise ValueError("non-standard JSON constant")


def _unique_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    # As for NDJSON envelopes: {"stringValue": "a", "stringValue": "b"} is ambiguous. Refuse it.
    obj = dict(pairs)
    if len(obj) != len(pairs):
        raise ValueError("duplicate key")
    return obj


def _list(value: object) -> list[Any]:
    if value is None:
        return []
    if not isinstance(value, list):
        raise _Malformed
    return value


def _object(value: object) -> dict[str, Any]:
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise _Malformed
    return value


def _int64(value: object) -> int:
    if isinstance(value, bool):
        raise _Malformed
    if isinstance(value, int):
        number = value
    elif isinstance(value, str) and _INT.fullmatch(value):
        number = int(value)
    else:
        raise _Malformed
    if not _INT64_MIN <= number <= _INT64_MAX:
        raise _Malformed
    return number


def _double(value: object) -> float | str:
    if isinstance(value, bool):
        raise _Malformed
    if isinstance(value, str):
        if value in _NON_FINITE:
            return value  # jsonb has no NaN or infinity: keep proto3 JSON's spelling
        if not _DOUBLE.fullmatch(value):
            raise _Malformed
    elif not isinstance(value, int | float):
        raise _Malformed
    try:
        number = float(value)
    except (OverflowError, ValueError):  # an integer literal of hundreds of digits
        raise _Malformed from None
    if not math.isfinite(number):  # 1e999 overflows to infinity
        raise _Malformed
    return number


class _Converter:
    """Converts ``AnyValue``s and ``KeyValue`` lists to plain JSON under the collector limits:
    ``AnyValue`` nesting, a key budget shared by everything one converter converts, and U+0000
    or lone surrogates (which Postgres cannot store) replaced with U+FFFD, as jsonsafe does."""

    def __init__(self, key_budget: int = MAX_COLLECTOR_KEYS) -> None:
        self.keys_left = key_budget

    def text(self, value: str) -> str:
        return sanitize_text(value)[0]

    def value(self, value: object, depth: int = 0) -> Any:
        if depth > MAX_ANY_VALUE_DEPTH:
            raise _OverLimit(COLLECTOR_DEPTH)
        if not isinstance(value, dict):
            raise _Malformed
        kinds = [k for k in _ANY_VALUE_KINDS if k in value]
        if not kinds:
            return None
        if len(kinds) > 1:  # a oneof
            raise _Malformed
        kind = kinds[0]
        inner = value[kind]
        if kind in ("stringValue", "bytesValue"):
            if not isinstance(inner, str):
                raise _Malformed
            return self.text(inner)
        if kind == "boolValue":
            if not isinstance(inner, bool):
                raise _Malformed
            return inner
        if kind == "intValue":
            return _int64(inner)
        if kind == "doubleValue":
            return _double(inner)
        if kind == "arrayValue":
            return [self.value(v, depth + 1) for v in _list(_object(inner).get("values"))]
        return self.key_values(_object(inner).get("values"), depth + 1)

    def key_values(self, value: object, depth: int = 0) -> dict[str, Any]:
        """A repeated ``KeyValue`` (attributes, ``kvlistValue``) as an object. A repeated key
        is malformed: which of the values did the sender mean?"""
        items = _list(value)
        self.keys_left -= len(items)
        if self.keys_left < 0:
            raise _OverLimit(COLLECTOR_KEYS)
        out: dict[str, Any] = {}
        for item in items:
            if not isinstance(item, dict) or not isinstance(item.get("key"), str):
                raise _Malformed
            key = self.text(item["key"])
            if key in out:
                raise _Malformed
            out[key] = self.value(item.get("value", {}), depth)
        return out


def plain_value(value: object) -> Any:
    """An OTLP ``AnyValue`` as plain JSON. An empty ``AnyValue`` is None; ``bytesValue`` stays
    base64 text. Raises ValueError for anything that is not an ``AnyValue`` or is over a
    limit."""
    return _Converter().value(value)


def _nanos(value: object) -> str | None:
    """A fixed64 timestamp as decimal text; None when unset (zero) or not a timestamp."""
    if isinstance(value, bool):
        return None
    text = str(value) if isinstance(value, int) else value
    if not isinstance(text, str) or not _UINT64.fullmatch(text):
        return None
    number = int(text)
    return str(number) if 0 < number <= _UINT64_MAX else None


def _size(value: Any) -> int:
    """Bytes of ``value`` as the store serializes it (compact, UTF-8)."""
    text = json.dumps(value, ensure_ascii=False, allow_nan=False, separators=(",", ":"))
    return len(text.encode("utf-8"))


@dataclass(frozen=True, slots=True)
class _Part:
    """A converted attribute set and its serialized size, or why it was dropped."""

    value: dict[str, Any] | None
    size: int
    keys: int  # keys it used from the collector's budget
    dropped: str | None


def _part(attributes: object, key_budget: int) -> _Part:
    converter = _Converter(key_budget)
    try:
        value = converter.key_values(attributes)
    except _OverLimit as exc:
        return _Part(None, 0, 0, exc.limit)
    except (ValueError, RecursionError):  # _Malformed, OverflowError is caught in _double
        return _Part(None, 0, 0, COLLECTOR_INVALID)
    return _Part(value, _size(value), key_budget - converter.keys_left, None)


_EMPTY = _Part({}, 2, 0, None)


@dataclass(frozen=True, slots=True)
class DecodedRecord:
    """One log record: its raw bytes, or the reason it is rejected; its bounded collector, and
    the breach (one of the ``COLLECTOR_*`` subjects) when the collector was dropped."""

    number: int
    raw: bytes | None
    reason: str | None = None
    collector: dict[str, Any] | None = None
    collector_dropped: str | None = None


def _raw_body(record: dict[str, Any]) -> bytes | str:
    """The record's body bytes, or the reason it is rejected."""
    body = record.get("body")
    if not isinstance(body, dict):
        return INVALID_LOG_RECORD
    kinds = [k for k in _ANY_VALUE_KINDS if k in body]
    if len(kinds) != 1:  # no body, or not one AnyValue
        return INVALID_LOG_RECORD
    if kinds[0] != "stringValue":
        return BODY_NOT_STRING
    text = body["stringValue"]
    if not isinstance(text, str) or not text:
        return INVALID_LOG_RECORD
    try:
        return text.encode("utf-8")  # fails on lone surrogates such as "\ud800"
    except UnicodeEncodeError:
        return INVALID_LOG_RECORD


def _collector(
    record: dict[str, Any], resource: _Part, max_bytes: int
) -> tuple[dict[str, Any], str | None]:
    """The record's bounded collector, sized as the resource's size plus its own, so a large
    resource shared by many records is never serialized again per record."""
    if resource.dropped is not None and resource.dropped != COLLECTOR_BYTES:
        return {DROPPED_KEY: resource.dropped}, resource.dropped
    attributes = _part(record.get("attributes"), MAX_COLLECTOR_KEYS - resource.keys)
    if attributes.dropped is not None:
        return {DROPPED_KEY: attributes.dropped}, attributes.dropped
    times = {
        key: nanos
        for key, field in ((OBSERVED_TIME_KEY, "observedTimeUnixNano"), (TIME_KEY, "timeUnixNano"))
        if (nanos := _nanos(record.get(field))) is not None
    }
    # {"resource":R,"attributes":A,"observed_time_unix_nano":"1",...}: keys and digits are ASCII.
    size = (
        len('{"resource":,"attributes":}')
        + resource.size
        + attributes.size
        + sum(len(f',"{key}":"{nanos}"') for key, nanos in times.items())
    )
    if size > max_bytes:
        return {DROPPED_BYTES_KEY: size}, COLLECTOR_BYTES
    assert resource.value is not None and attributes.value is not None
    return {"resource": resource.value, "attributes": attributes.value, **times}, None


def decode_request(
    body: bytes, *, max_records: int, max_collector_bytes: int
) -> list[DecodedRecord]:
    """Decode the whole request into records, in request order, numbered from 1.

    Raises :class:`InvalidRequest` for a body that is not an OTLP/JSON logs request, and
    :class:`TooManyRecords` as soon as more than ``max_records`` records are seen. An empty
    request (no ``resourceLogs``) is valid and has no records. Runs in a worker thread.
    """
    try:
        request = json.loads(
            body.decode("utf-8"), parse_constant=_reject_constant, object_pairs_hook=_unique_pairs
        )
    except (UnicodeDecodeError, ValueError, RecursionError):
        raise InvalidRequest("body is not valid JSON") from None
    if not isinstance(request, dict):
        raise InvalidRequest("body is not a JSON object")
    try:
        return _records(request, max_records, max_collector_bytes)
    except _Malformed:
        raise InvalidRequest("body is not an OTLP/JSON ExportLogsServiceRequest") from None


def _records(
    request: dict[str, Any], max_records: int, max_collector_bytes: int
) -> list[DecodedRecord]:
    out: list[DecodedRecord] = []
    for resource_logs in _list(request.get("resourceLogs")):
        resource_logs = _object(resource_logs)
        resource_obj = _object(resource_logs.get("resource"))
        resource: _Part | None = None  # converted once, when its first record needs it
        for scope_logs in _list(resource_logs.get("scopeLogs")):
            for record in _list(_object(scope_logs).get("logRecords")):
                number = len(out) + 1
                if number > max_records:
                    raise TooManyRecords(f"more than {max_records} log records")
                if not isinstance(record, dict):
                    out.append(DecodedRecord(number, None, INVALID_LOG_RECORD))
                    continue
                raw = _raw_body(record)
                if isinstance(raw, str):
                    out.append(DecodedRecord(number, None, raw))
                    continue
                if resource is None:
                    resource = _resource(resource_obj.get("attributes"), max_collector_bytes)
                collector, dropped = _collector(record, resource, max_collector_bytes)
                out.append(DecodedRecord(number, raw, None, collector, dropped))
    return out


def _resource(attributes: object, max_collector_bytes: int) -> _Part:
    if attributes is None:
        return _EMPTY
    part = _part(attributes, MAX_COLLECTOR_KEYS)
    if part.dropped is None and part.size > max_collector_bytes:
        # Over the cap on its own: every record's collector is dropped, sized from here.
        return _Part(part.value, part.size, part.keys, COLLECTOR_BYTES)
    return part


def summary(results: list[dict[str, Any]]) -> dict[str, Any]:
    """Counts of the records' outcomes, and the first rejected records by number and reason.
    Its size does not grow with the number of records."""
    counts: dict[str, int] = {}
    parse: dict[str, int] = {}
    rejected: list[dict[str, Any]] = []
    for result in results:
        status = result["status"]
        counts[status] = counts.get(status, 0) + 1
        if "parse" in result:
            parse[result["parse"]] = parse.get(result["parse"], 0) + 1
        if status == "rejected" and len(rejected) < MAX_LISTED_REJECTIONS:
            rejected.append({"record": result["record"], "reason": result.get("reason")})
    out: dict[str, Any] = {"counts": counts, "parse": parse}
    if rejected:
        out["rejected"] = rejected
    return out


def export_response(results: list[dict[str, Any]]) -> dict[str, Any]:
    """An ``ExportLogsServiceResponse``, plus the ``tuisku`` :func:`summary`, which OTLP clients
    ignore. ``partialSuccess`` is set only when a record was rejected. An OTLP exporter reads at
    most 64 KiB of the answer and counts a failure to decode it as a failed export, so the
    answer never lists every record."""
    content: dict[str, Any] = {}
    refused = [r for r in results if r["status"] == "rejected"]
    if refused:
        reasons = sorted({str(r.get("reason")) for r in refused})
        content["partialSuccess"] = {
            # OTLP/JSON encodes 64-bit integers as decimal strings.
            "rejectedLogRecords": str(len(refused)),
            "errorMessage": f"{len(refused)} log records rejected: {', '.join(reasons)}",
        }
    content["tuisku"] = summary(results)
    return content
