"""The source adapter contract (ADR 0005).

An adapter turns one raw record (L0) into drafts of observations (L1) and detections (L2). It is
pure and deterministic: no I/O, no clock, no randomness, no enrichment. The same bytes and
options always give the same drafts. Mixed records are split: sensor facts become observations,
sensor verdicts become detections that reference them (ADR 0002).

Everything an adapter reads is attacker-controlled. Adapters bound string sizes, check types and
raise :class:`AdapterError` for input they cannot parse (:class:`LimitExceeded` when a
structural limit is breached); the ingest path records that failure on
the raw record and carries on with the rest of the batch.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import datetime
from enum import IntEnum, StrEnum
from typing import Any, Protocol, runtime_checkable

OCSF_VERSION = "1.9.0"


class Evaluator(StrEnum):
    """Who ran the logic that produced a detection (ADR 0002)."""

    SENSOR = "sensor"  # Suricata, Zeek, Falco, Harava decided; adapters only ever emit this
    TUISKU = "tuisku"  # a Tuisku rule pack rule fired in the worker


class Authorship(StrEnum):
    """Who wrote that logic (ADR 0002)."""

    BUILTIN = "builtin"  # shipped with the sensor as its own logic (Zeek notice, Harava checks)
    COMMUNITY = "community"  # a third-party rule set (ET Open, Falco default rules)
    LOCAL = "local"  # written by the deploying estate
    TUISKU = "tuisku"  # a pack shipped in this repository


class Severity(IntEnum):
    """OCSF ``severity_id``."""

    UNKNOWN = 0
    INFORMATIONAL = 1
    LOW = 2
    MEDIUM = 3
    HIGH = 4
    CRITICAL = 5
    FATAL = 6


class AdapterError(ValueError):
    """The record cannot be parsed. The message must never contain the raw body."""


class LimitExceeded(AdapterError):
    """The record breaches a structural limit (ADR 0005), e.g. JSON depth or key count.

    ``limit`` names the limit (``"json_depth"``, ``"json_keys"``, ``"datapoints"``) so the ingest
    path can record the breach as a ``tuisku.meta.*`` meta-detection instead of absorbing it.
    """

    def __init__(self, limit: str, message: str | None = None) -> None:
        super().__init__(message or f"limit exceeded: {limit}")
        self.limit = limit


@dataclass(frozen=True, slots=True)
class RawRecord:
    """One L0 record as received: the exact bytes plus receipt metadata.

    ``collector`` is what the shipper says about where the line came from (host, path, offset,
    container). It is receipt metadata, not evidence about the event, and is also untrusted.
    """

    source: str
    body: bytes
    received_at: datetime
    collector: Mapping[str, Any] = field(default_factory=dict)

    def text(self) -> str:
        """The body as UTF-8. Invalid UTF-8 is a parse failure, not something to guess at."""
        try:
            return self.body.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise AdapterError(f"body is not valid UTF-8 (byte {exc.start})") from None


@dataclass(frozen=True, slots=True)
class ObservationDraft:
    """An L1 fact derived from the raw record.

    ``attributes`` is the OCSF-shaped payload; ``unmapped`` keeps source fields with no OCSF home,
    exactly as received. ``correlation`` holds sensor-scoped join keys (e.g.
    ``{"suricata.flow_id": "1676750115612680"}``), which the store qualifies by source. A key
    may carry several values as a tuple, e.g. ``{"zeek.fuid": ("Fa1", "Fb2")}`` for a Zeek http
    record that references more than one file; order is kept as reported.
    ``flags`` are short machine-readable notes such as ``community_id_mismatch``.
    """

    kind: str
    event_time: datetime | None
    attributes: Mapping[str, Any]
    ocsf_class_uid: int | None = None
    unmapped: Mapping[str, Any] = field(default_factory=dict)
    entity_keys: tuple[str, ...] = ()
    community_id: str | None = None
    correlation: Mapping[str, str | tuple[str, ...]] = field(default_factory=dict)
    flags: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class DetectionDraft:
    """An L2 verdict reported by the sensor (evaluator ``sensor``), referencing observations from
    the same result by index.

    ``rule_ref`` identifies the mechanism verbatim, e.g. ``{"engine": "suricata", "gid": 1,
    "sid": 2045001, "rev": 1, "name": "ET ..."}`` or ``{"engine": "harava", "name":
    "outbound_refused"}``. ``identity`` is the stable string used for finding fingerprints
    (``suricata:1:2045001``, ``falco:Terminal shell in container``,
    ``zeek:notice:Scan::Port_Scan``).
    ``explanation`` answers "why did this fire" with what the sensor reported.
    """

    kind: str
    authorship: Authorship
    identity: str
    title: str
    severity: Severity
    event_time: datetime | None
    rule_ref: Mapping[str, Any]
    attributes: Mapping[str, Any] = field(default_factory=dict)
    attack: tuple[str, ...] = ()
    entity_keys: tuple[str, ...] = ()
    observation_refs: tuple[int, ...] = ()
    explanation: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class ParseResult:
    observations: tuple[ObservationDraft, ...] = ()
    detections: tuple[DetectionDraft, ...] = ()

    def __post_init__(self) -> None:
        if any(d.authorship is Authorship.TUISKU for d in self.detections):
            raise ValueError(
                "adapters report sensor verdicts; tuisku-authored rules run in the worker"
            )
        n = len(self.observations)
        for d in self.detections:
            for ref in d.observation_refs:
                if not 0 <= ref < n:
                    raise ValueError(f"detection references observation {ref}, have {n}")


@runtime_checkable
class Adapter(Protocol):
    """A versioned, pure parser for one source format.

    Bump ``version`` (semver) on any change to the output for the same input; golden tests
    enforce this.
    """

    name: str
    version: str

    def parse(self, raw: RawRecord, options: Mapping[str, Any]) -> ParseResult: ...
