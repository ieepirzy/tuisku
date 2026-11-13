"""Decoding OTLP/HTTP JSON logs requests (``ExportLogsServiceRequest``) into raw records.

Each ``logRecord`` becomes one raw record, exactly as one NDJSON envelope does
(ADR 0005):

- ``raw`` is the record's ``body.stringValue``, byte for byte. Shippers ship raw lines, they
  do not parse. A body of any other ``AnyValue`` kind (a ``kvlistValue`` from a collector-side
  ``json_parser``, say) is **refused** (``body_not_string``) rather than re-serialized, because
  a re-serialization is not what the sensor wrote.
- ``collector`` is the resource attributes merged with the record's own attributes (the record
  wins on a clash), keyed by their OpenTelemetry names (``k8s.node.name``, ``k8s.pod.name``,
  ``log.file.path``...), with values flattened from ``AnyValue`` to plain JSON. The record's
  ``observedTimeUnixNano`` and ``timeUnixNano``, when set, are added as
  ``otlp.observed_time_unix_nano`` and ``otlp.time_unix_nano``. Like any ``collector``, it is
  untrusted receipt metadata, never evidence about the event, and no adapter reads it.

Field names follow the OTLP/JSON encoding (lowerCamelCase); unknown fields are ignored, as the
OTLP specification requires of receivers. A request whose structure above the log record is
malformed is refused as a whole (:class:`InvalidRequest`); a malformed log record is rejected
on its own. Error messages never echo the input.
"""

from __future__ import annotations

import json
import math
import re
from collections.abc import Iterator
from dataclasses import dataclass
from typing import Any

BODY_NOT_STRING = "body_not_string"
INVALID_LOG_RECORD = "invalid_log_record"
OBSERVED_TIME_KEY = "otlp.observed_time_unix_nano"
TIME_KEY = "otlp.time_unix_nano"

MAX_ANY_VALUE_DEPTH = 32
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
_INT64_MIN, _INT64_MAX = -(2**63), 2**63 - 1


class InvalidRequest(ValueError):
    """The request is not an OTLP/JSON logs request. The message never contains input."""


class _Malformed(ValueError):
    pass


def _reject_constant(name: str) -> Any:
    raise ValueError("non-standard JSON constant")


def _unique_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
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
    if isinstance(value, int | float):
        number = float(value)
    elif isinstance(value, str):
        try:
            number = float(value)
        except ValueError:
            raise _Malformed from None
    else:
        raise _Malformed
    # jsonb has no NaN or infinity: keep proto3 JSON's spelling of them as a string.
    return number if math.isfinite(number) else str(value)


def plain_value(value: object, depth: int = 0) -> Any:
    """An OTLP ``AnyValue`` as plain JSON. An empty ``AnyValue`` is None; ``bytesValue`` stays
    base64 text. Raises ValueError for anything that is not an ``AnyValue``."""
    if depth > MAX_ANY_VALUE_DEPTH or not isinstance(value, dict):
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
        return inner
    if kind == "boolValue":
        if not isinstance(inner, bool):
            raise _Malformed
        return inner
    if kind == "intValue":
        return _int64(inner)
    if kind == "doubleValue":
        return _double(inner)
    if kind == "arrayValue":
        return [plain_value(v, depth + 1) for v in _list(_object(inner).get("values"))]
    return _key_values(_object(inner).get("values"), depth + 1)


def _key_values(value: object, depth: int = 0) -> dict[str, Any]:
    """A repeated ``KeyValue`` (attributes, ``kvlistValue``) as an object; the last of
    repeated keys wins."""
    out: dict[str, Any] = {}
    for item in _list(value):
        if not isinstance(item, dict) or not isinstance(item.get("key"), str):
            raise _Malformed
        out[item["key"]] = plain_value(item.get("value", {}), depth)
    return out


def _nanos(value: object) -> str | None:
    """A fixed64 timestamp as decimal text; None when unset (zero) or not a timestamp."""
    if isinstance(value, bool):
        return None
    text = str(value) if isinstance(value, int) else value
    if not isinstance(text, str) or not _UINT64.fullmatch(text) or int(text) == 0:
        return None
    return str(int(text))


@dataclass(frozen=True, slots=True)
class LogRecordEnvelope:
    """One log record: the raw bytes and the (not yet size-capped) collector metadata."""

    raw: bytes
    collector: dict[str, Any]


@dataclass(frozen=True, slots=True)
class PendingLogRecord:
    """One log record of the request, decoded on demand (so a request that runs out of time
    budget stops decoding too)."""

    record: object
    resource: dict[str, Any]

    def decode(self) -> LogRecordEnvelope | str:
        """The record's envelope, or the reason it is rejected."""
        record = self.record
        if not isinstance(record, dict):
            return INVALID_LOG_RECORD
        body = record.get("body")
        try:
            value = plain_value(body)  # also checks that it is one AnyValue
        except ValueError:
            return INVALID_LOG_RECORD
        if value is None:  # no body at all
            return INVALID_LOG_RECORD
        if not isinstance(body, dict) or "stringValue" not in body:
            return BODY_NOT_STRING
        if not value:
            return INVALID_LOG_RECORD
        try:
            raw = value.encode("utf-8")  # fails on lone surrogates such as "\ud800"
            attributes = _key_values(record.get("attributes"))
        except (UnicodeEncodeError, ValueError):
            return INVALID_LOG_RECORD
        collector = self.resource | attributes
        for key, field in ((OBSERVED_TIME_KEY, "observedTimeUnixNano"), (TIME_KEY, "timeUnixNano")):
            nanos = _nanos(record.get(field))
            if nanos is not None:
                collector[key] = nanos
        return LogRecordEnvelope(raw=raw, collector=collector)


def decode_request(body: bytes) -> list[PendingLogRecord]:
    """Validate the request down to its log records and list them in request order.

    Raises :class:`InvalidRequest` for a body that is not an OTLP/JSON logs request. An empty
    request (no ``resourceLogs``) is valid and has no records.
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
        return list(_records(request))
    except (ValueError, RecursionError):
        raise InvalidRequest("body is not an OTLP/JSON ExportLogsServiceRequest") from None


def _records(request: dict[str, Any]) -> Iterator[PendingLogRecord]:
    for resource_logs in _list(request.get("resourceLogs")):
        resource_logs = _object(resource_logs)
        resource = _key_values(_object(resource_logs.get("resource")).get("attributes"))
        for scope_logs in _list(resource_logs.get("scopeLogs")):
            for record in _list(_object(scope_logs).get("logRecords")):
                yield PendingLogRecord(record=record, resource=resource)


def export_response(results: list[dict[str, Any]]) -> dict[str, Any]:
    """An ``ExportLogsServiceResponse``, plus Tuisku's per-record ``results`` (OTLP clients
    ignore unknown fields). ``partialSuccess`` is set only when a record was rejected."""
    refused = [r for r in results if r["status"] == "rejected"]
    content: dict[str, Any] = {}
    if refused:
        reasons = sorted({str(r.get("reason")) for r in refused})
        content["partialSuccess"] = {
            # OTLP/JSON encodes 64-bit integers as decimal strings.
            "rejectedLogRecords": str(len(refused)),
            "errorMessage": f"{len(refused)} log records rejected: {', '.join(reasons)}",
        }
    content["results"] = results
    return content
