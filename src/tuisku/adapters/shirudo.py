"""Shirudo adapter: the status keepalive (ADR 0005, ADR 0013).

Shirudo (https://github.com/shirudo-dev/shirudo) is an eBPF runtime that loads signed
"shields" (upatches) on Linux targets. Each target sends a keepalive about once a minute: one
OTLP log record, event name ``shirudo.keepalive``, whose ``body.stringValue`` is a compact JSON
object (``shirudo status --keepalive``, schema ``shirudo.keepalive/1``, at most 4095 bytes) and
whose one attribute ``shirudo.quote`` is a TPM quote of those bytes. Tuisku's OTLP logs
endpoint hands this adapter the body, byte for byte; the same body also arrives as a bare
NDJSON line. The format is documented in Shirudo's ``Documentation/reference/formats/
keepalive.rst``.

A valid keepalive becomes:

- one ``shirudo.keepalive`` observation: identity (boot, build, config, kernel, image),
  health (verdict, the seven conditions decoded from ``cond``, the ``flags`` bits, the tamper
  and integrity counters), the upatch tree position and the loaded set;
- two ``metric.sample`` observations, ``shirudo.tamper`` and ``shirudo.integrity``: the sum of
  each counter array as a cumulative counter, labelled with the ``boot_id``. The counters start
  at zero at every boot and only grow within one, so each boot is its own series and the first
  keepalive of a boot is a baseline (ADR 0006 "Metric samples": a first sample with no
  ``start_time`` has delta 0). A rise within a boot is a refusal by Shirudo's guards. The
  non-zero counters are named in the sample's ``counters``;
- when the verdict is not ``ok``, one sensor detection ``shirudo.status`` (authorship
  ``builtin``: Shirudo's own ``status`` evaluation) referencing the keepalive observation.

The body names no host and carries no time: Shirudo identifies a node by the attestation key in
the quote, which is an OTLP attribute, and adapters never read ``collector``. The event time of
every row is therefore the record's ``received_at`` (``time_source: received_at``), which keeps
samples of one boot in arrival order. A keepalive body with schema ``shirudo.keepalive/1`` that
breaks the format becomes ``shirudo.unknown`` with ``reason: invalid_keepalive``; another
schema, any other JSON object (a decoded map snapshot sent as a string) and an OTLP metrics
request become ``shirudo.unknown`` with ``unsupported_schema``, ``not_a_keepalive`` or
``otlp_metrics_not_interpreted``. Map snapshots and decoder metrics are kept as raw records but
not interpreted: their fields are per upatch.

Tuisku does not check the quote. It stays in the raw record's ``collector``, where
``shirudo-quote-check`` can verify it offline. Shirudo's own documentation says telemetry is the
target's account of itself, not evidence: root on a target can stop or forge it. Only
``shirudo attest verify`` proves what a target runs.
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
from tuisku.adapters.jsonsafe import loads_object_flagged
from tuisku.adapters.registry import register

SCHEMA = "shirudo.keepalive/1"
SCHEMA_PREFIX = "shirudo.keepalive/"

MAX_BODY_BYTES = 5 * 1024 * 1024  # ADR 0005 body limit (an OTLP metrics request)
MAX_OTLP_KEYS = 262_144  # as the harava adapter: a metrics request at the datapoint cap
MAX_KEEPALIVE_BYTES = 4095  # the format's own cap
MAX_COUNTERS = 256  # 43 tamper and 22 integrity counters in /1; new ones are appended
MAX_UNMAPPED = 16 * 1024  # JSON size of what an unknown record keeps
MAX_ERROR = 256
UINT64_MAX = 2**64 - 1

# Shirudo's Documentation/security/tamper-counters.rst, in array order.
TAMPER_COUNTERS: tuple[str, ...] = (
    "LoadNotLoader", "LoadUnsigned", "LoadUnverified", "LoadKeyringKind", "LoadKeyring",
    "MapCreate", "MapWrite", "MapFdWrite", "ProgRun", "ProgAttach", "ObjPin", "BpfCommand",
    "ExeIdentity", "KeyringWrite", "PinUnlink", "PinRename", "PinXattr", "BpffsUmount",
    "BpffsUmountAbove", "BpffsMount", "SealWrite", "SealUnlink", "SealRename", "SealSetattr",
    "SealXattr", "SealLabel", "SealPtrace", "SealPerf", "ExecTraced", "SealEntry",
    "PerfAttach", "PinEntry", "SealCopyUp", "Kexec", "TpmExtend", "TpmWrite", "ObjGet",
    "SealSignal", "SealCoreDump", "SealUprobe", "XattrHandle", "ExecShared", "SealRlimit",
)  # fmt: skip
# Shirudo's Documentation/security/integrity-counters.rst, in array order.
INTEGRITY_COUNTERS: tuple[str, ...] = (
    "ModuleSignature", "DevMem", "EfiTest", "KexecSignature", "PciAccess", "IoPort", "Msr",
    "AcpiTables", "DeviceTree", "PcmciaCis", "Tiocsserial", "ModuleParameters", "Mmiotrace",
    "Debugfs", "XmonWrite", "BpfWriteUser", "DbgWriteKernel", "RtasErrorInjection",
    "XenUserActions", "Kcore", "HibernateLocation", "Other",
)  # fmt: skip
# ``cond``: condition i at bits 2i and 2i+1.
CONDITIONS: tuple[str, ...] = (
    "LsmAttached", "KeyringSealed", "ChainIntact", "UpatchesMeasured", "TpmMeasured",
    "ConfigActive", "XdpCovered",
)  # fmt: skip
CONDITION_STATES = ("not_evaluated", "ok", "warn", "alert")
FLAGS: tuple[str, ...] = (
    "register_rebound", "bound_late", "tree_log_mismatch", "tamper_unavailable",
    "tree_op_pending", "snapshot_unsettled", "integrity_unavailable",
)  # fmt: skip

KNOWN_VERDICTS = frozenset(
    {"ok", "degraded", "init-pending", "reboot-pending", "lsm-off", "tampered"}
)
# The keepalive's own severity follows the verdict: INFO ok, WARN degraded and the two pending
# states, ERROR every other verdict (tampered, lsm-off, and any verdict a newer Shirudo adds).
_SEVERITY = {
    "tampered": Severity.CRITICAL,
    "lsm-off": Severity.CRITICAL,
    "degraded": Severity.MEDIUM,
    "init-pending": Severity.LOW,
    "reboot-pending": Severity.LOW,
}
_UNKNOWN_VERDICT_SEVERITY = Severity.HIGH

# The 23 keys of /1, in order.
KEYS: tuple[str, ...] = (
    "schema", "boot_id", "version_id", "config_root", "kernel_release", "image_id",
    "image_version", "image_root", "verdict", "cond", "flags", "tamper", "integrity",
    "tree_id", "generation", "base_seq", "last_seq", "base_root", "projection_root", "mask",
    "set_sha256", "count", "not_ok",
)  # fmt: skip

_A = re.ASCII
_UUID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", _A)
_HASH = re.compile(r"[0-9a-f]{64}", _A)
_VERDICT = re.compile(r"[a-z][a-z0-9-]{0,31}", _A)
# Printable ASCII without blanks at the ends: a kernel release, an os-release value, a tree id.
_PRINTABLE = re.compile(r"[!-~](?:[ -~]{0,254}[!-~])?", _A)
_BASE64 = re.compile(r"(?:[A-Za-z0-9+/]{4}){0,64}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?", _A)


class _Invalid(Exception):
    """A ``shirudo.keepalive/1`` body that breaks the format."""


def _uint(value: object, key: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= UINT64_MAX:
        raise _Invalid(f"{key} is not an unsigned 64-bit integer")
    return value


def _uint_or_null(value: object, key: str) -> int | None:
    return None if value is None else _uint(value, key)


def _match(value: object, pattern: re.Pattern[str], key: str, *, nullable: bool) -> str | None:
    if value is None and nullable:
        return None
    if not isinstance(value, str) or not pattern.fullmatch(value):
        raise _Invalid(f"{key} is not valid")
    return value


def _counters(value: object, key: str) -> list[int] | None:
    if value is None:
        return None
    if not isinstance(value, list) or len(value) > MAX_COUNTERS:
        raise _Invalid(f"{key} is not a list of at most {MAX_COUNTERS} counters")
    return [_uint(v, f"{key}[{i}]") for i, v in enumerate(value)]


def _named(values: list[int] | None, names: tuple[str, ...]) -> dict[str, int]:
    """The non-zero counters by name; positions a newer Shirudo appended are ``counter_<i>``."""
    if values is None:
        return {}
    return {(names[i] if i < len(names) else f"counter_{i}"): v for i, v in enumerate(values) if v}


def _conditions(cond: int) -> dict[str, str]:
    out = {name: CONDITION_STATES[(cond >> (2 * i)) & 3] for i, name in enumerate(CONDITIONS)}
    rest, i = cond >> (2 * len(CONDITIONS)), len(CONDITIONS)
    while rest:
        if rest & 3:
            out[f"condition_{i}"] = CONDITION_STATES[rest & 3]
        rest, i = rest >> 2, i + 1
    return out


def _flag_names(flags: int) -> list[str]:
    return [
        FLAGS[bit] if bit < len(FLAGS) else f"bit_{bit}"
        for bit in range(flags.bit_length())
        if flags >> bit & 1
    ]


def _keepalive(body: dict[str, Any]) -> dict[str, Any]:
    """The checked fields of a /1 body. Raises :class:`_Invalid`."""
    missing = [k for k in KEYS if k not in body]
    if missing:
        raise _Invalid(f"missing keys: {', '.join(missing[:8])}")
    out: dict[str, Any] = {"schema": SCHEMA}
    out["boot_id"] = _match(body["boot_id"], _UUID, "boot_id", nullable=False)
    out["version_id"] = _match(body["version_id"], _HASH, "version_id", nullable=False)
    out["config_root"] = _match(body["config_root"], _HASH, "config_root", nullable=True)
    out["kernel_release"] = _match(
        body["kernel_release"], _PRINTABLE, "kernel_release", nullable=False
    )
    out["image_id"] = _match(body["image_id"], _PRINTABLE, "image_id", nullable=True)
    out["image_version"] = _match(body["image_version"], _PRINTABLE, "image_version", nullable=True)
    out["image_root"] = _match(body["image_root"], _HASH, "image_root", nullable=True)
    out["verdict"] = _match(body["verdict"], _VERDICT, "verdict", nullable=False)
    out["cond"] = _uint(body["cond"], "cond")
    out["flags"] = _uint(body["flags"], "flags")
    out["tamper"] = _counters(body["tamper"], "tamper")
    out["integrity"] = _counters(body["integrity"], "integrity")
    out["tree"] = {
        "tree_id": _match(body["tree_id"], _PRINTABLE, "tree_id", nullable=True),
        "generation": _uint_or_null(body["generation"], "generation"),
        "base_seq": _uint_or_null(body["base_seq"], "base_seq"),
        "last_seq": _uint_or_null(body["last_seq"], "last_seq"),
        "base_root": _match(body["base_root"], _HASH, "base_root", nullable=True),
        "projection_root": _match(body["projection_root"], _HASH, "projection_root", nullable=True),
        "mask": _match(body["mask"], _BASE64, "mask", nullable=True),
    }
    out["loaded"] = {
        "set_sha256": _match(body["set_sha256"], _HASH, "set_sha256", nullable=False),
        "count": _uint(body["count"], "count"),
        "not_ok": _uint(body["not_ok"], "not_ok"),
    }
    return out


def _bounded(record: Mapping[str, Any], flags: list[str]) -> dict[str, Any]:
    """Keep an unknown record verbatim when it is small, else only its top-level keys."""
    try:
        size = len(json.dumps(record))
    except (TypeError, ValueError):
        size = MAX_UNMAPPED + 1
    if size <= MAX_UNMAPPED:
        return dict(record)
    flags.append("unmapped_dropped")
    return {"keys": sorted(str(k)[:128] for k in list(record)[:64])}


def _unknown(
    reason: str,
    received_at: datetime,
    flags: list[str],
    unmapped: Mapping[str, Any] | None = None,
    error: str | None = None,
) -> ParseResult:
    attributes: dict[str, Any] = {"reason": reason, "time_source": "received_at"}
    if error is not None:
        attributes["error"] = error[:MAX_ERROR]
    return ParseResult(
        observations=(
            ObservationDraft(
                kind="shirudo.unknown",
                event_time=received_at,
                attributes=attributes,
                unmapped=dict(unmapped or {}),
                flags=tuple(dict.fromkeys([*flags, reason])),
            ),
        )
    )


def _sample(
    metric: str, total: int, counters: dict[str, int], boot_id: str, time: datetime
) -> ObservationDraft:
    return ObservationDraft(
        kind="metric.sample",
        event_time=time,
        attributes={
            "metric": metric,
            "labels": {"boot_id": boot_id},
            "resource": {},
            "scope": {"name": "shirudo.keepalive"},
            "unit": "{refusal}",
            "value": total,
            "start_time": None,
            "time": time.isoformat(),
            "temporality": "cumulative",
            "is_monotonic": True,
            "counters": counters,
            "time_source": "received_at",
        },
    )


def _parse_keepalive(
    body: dict[str, Any], json_flags: tuple[str, ...], received_at: datetime
) -> ParseResult:
    flags = list(json_flags)
    try:
        ka = _keepalive(body)
    except _Invalid as exc:
        return _unknown("invalid_keepalive", received_at, flags, _bounded(body, flags), str(exc))
    extra = {k: v for k, v in body.items() if k not in KEYS}
    if extra:
        flags.append("unknown_keys")
    verdict: str = ka["verdict"]
    if verdict not in KNOWN_VERDICTS:
        flags.append("unknown_verdict")
    conditions = _conditions(ka["cond"])
    flag_names = _flag_names(ka["flags"])
    tamper, integrity = ka["tamper"], ka["integrity"]
    tamper_named = _named(tamper, TAMPER_COUNTERS)
    integrity_named = _named(integrity, INTEGRITY_COUNTERS)
    if (tamper and len(tamper) > len(TAMPER_COUNTERS)) or (
        integrity and len(integrity) > len(INTEGRITY_COUNTERS)
    ):
        flags.append("unknown_counter")
    boot_id: str = ka["boot_id"]

    attributes = ka | {
        "conditions": conditions,
        "flag_names": flag_names,
        "tamper_total": sum(tamper) if tamper is not None else None,
        "integrity_total": sum(integrity) if integrity is not None else None,
        "tamper_nonzero": tamper_named,
        "integrity_nonzero": integrity_named,
        "time_source": "received_at",
    }
    observations = [
        ObservationDraft(
            kind="shirudo.keepalive",
            event_time=received_at,
            attributes=attributes,
            unmapped=_bounded(extra, flags) if extra else {},
            flags=tuple(dict.fromkeys(flags)),
        )
    ]
    # No sample when the target could not read its counters: a missing value is not a zero.
    if tamper is not None:
        observations.append(
            _sample("shirudo.tamper", sum(tamper), tamper_named, boot_id, received_at)
        )
    if integrity is not None:
        observations.append(
            _sample("shirudo.integrity", sum(integrity), integrity_named, boot_id, received_at)
        )

    detections: list[DetectionDraft] = []
    if verdict != "ok":
        severity = _SEVERITY.get(verdict, _UNKNOWN_VERDICT_SEVERITY)
        alerting = [name for name, state in conditions.items() if state == "alert"]
        warning = [name for name, state in conditions.items() if state == "warn"]
        detections.append(
            DetectionDraft(
                kind="shirudo.status",
                authorship=Authorship.BUILTIN,
                identity=f"shirudo:verdict:{verdict}",
                title=f"Shirudo target reports verdict {verdict}",
                severity=severity,
                event_time=received_at,
                rule_ref={"engine": "shirudo", "check": "status", "verdict": verdict},
                attributes={
                    "verdict": verdict,
                    "boot_id": boot_id,
                    "conditions_alert": alerting,
                    "conditions_warn": warning,
                },
                observation_refs=(0,),
                explanation={
                    "verdict": verdict,
                    "conditions": conditions,
                    "flag_names": flag_names,
                    "known_verdict": verdict in KNOWN_VERDICTS,
                },
            )
        )
    return ParseResult(observations=tuple(observations), detections=tuple(detections))


class ShirudoAdapter:
    name = "shirudo"
    version = "1.0.0"

    def parse(self, raw: RawRecord, options: Mapping[str, Any]) -> ParseResult:
        if len(raw.body) > MAX_BODY_BYTES:
            raise LimitExceeded("body_bytes", f"record larger than {MAX_BODY_BYTES} bytes")
        text = raw.text().strip()
        if not text.startswith("{"):
            raise AdapterError("expected a JSON object")
        record, json_flags = loads_object_flagged(text, max_keys=MAX_OTLP_KEYS)
        flags = list(json_flags)
        if "resourceMetrics" in record:
            # Upatch decoders define their own metrics; the raw record keeps them.
            return _unknown("otlp_metrics_not_interpreted", raw.received_at, flags)
        schema = record.get("schema")
        if schema == SCHEMA:
            if len(text.encode("utf-8")) > MAX_KEEPALIVE_BYTES:
                return _unknown(
                    "invalid_keepalive",
                    raw.received_at,
                    flags,
                    _bounded(record, flags),
                    f"keepalive body longer than {MAX_KEEPALIVE_BYTES} bytes",
                )
            return _parse_keepalive(record, json_flags, raw.received_at)
        if isinstance(schema, str) and schema.startswith(SCHEMA_PREFIX):
            return _unknown("unsupported_schema", raw.received_at, flags, _bounded(record, flags))
        return _unknown("not_a_keepalive", raw.received_at, flags, _bounded(record, flags))


ADAPTER = ShirudoAdapter()
register(ADAPTER)
