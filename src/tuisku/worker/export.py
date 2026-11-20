"""Export of finding and incident events to an append-only sink (ADR 0012).

When export is on (``export_state.enabled``, set by ``tuisku migrate``), an owner trigger
enqueues every ``finding_events`` and ``incident_events`` row in ``export_queue`` at the commit
of the event's transaction, with the event and the finding or incident as that transaction left
them (times already rendered as UTC text by the database).

The exporter runs as its own asyncio task on its own connection, beside the evaluation loop, so
a slow sink never delays evaluation or paging. A round takes a short lease on the worker-only
``worker_locks`` row ``export`` (renewed per batch, never held across a request in a
transaction), then sends batches, oldest first, as OTLP/HTTP JSON ``ExportLogsServiceRequest``s
until the queue is empty or the round's time budget is spent, and deletes each batch's rows
after a 2xx, in a statement of its own. Delivery is at least once: a crash between the POST and
the delete sends the batch again, and consumers deduplicate on ``record_uid`` (the event's uid).

- A 5xx, 429, other 4xx, timeout, connection error or redirect leaves the rows queued and backs
  off: 5 s doubling to 5 minutes, in this process's memory (it restarts from zero with the
  process; the worker role cannot write the queue).
- A 400 or 413 halves the batch, down to one record. A record refused on its own is the
  record's fault only if the sink accepts others: up to 4 other records, smallest first, are
  sent alone as probes, and the record is resent right after one is accepted. Refused that way
  twice, it is replaced by a stub that names it, and ``tuisku.meta.export_failed`` (subject
  ``refused``) pages. If no probe is accepted, or the stub is refused, the sink is at fault:
  every row is kept and delivery backs off. No row is ever dropped because the sink refuses it.
- A row that cannot be encoded is sent as such a stub (subject ``unencodable``); it never holds
  up the rows behind it.
- An OTLP partial success (``partialSuccess.rejectedLogRecords``) is not retried, as OTLP
  requires; the rows are deleted and ``export_failed`` (subject ``partial_success``) pages.
- An export row older than the backlog limit raises ``tuisku.meta.backlog`` (subject
  ``export``).

The record (``tuisku.export.v1``) carries ids, kinds, statuses, severities, times and entity
keys, never free text a person typed. Under the deployment's key (ADR 0008):

- entity keys of the pseudonymised kinds (default ``ip``, ``caller``, ``identity``) become
  ``<kind>:hmac:<HMAC-SHA-256 of the value after the first ':'>``;
- an event's reason becomes ``reason_hmac`` and ``reason_length``;
- in payloads and old or new values, any key not known to hold structured values is exported
  as ``{"hmac", "length"}``, so a future free-text field cannot leak by accident.

Titles come from rule packs, never from telemetry.
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import logging
import os
import socket
import time
import urllib.error
import urllib.request
import uuid
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

from psycopg import AsyncConnection

from tuisku import db
from tuisku.adapters import Severity
from tuisku.store import meta

log = logging.getLogger("tuisku.export")

SCHEMA = "tuisku.export.v1"
SERVICE = "tuisku"
SCOPE = "tuisku.export"
MAX_RESPONSE_BYTES = 64 * 1024
DISCARD_LIMIT = 1000  # leftover rows deleted per round once export is off
REFUSED = (400, 413)  # the sink refuses this content: halve the batch, then isolate the row
PROBES = 4  # other records sent alone to show the sink works, before blaming the sink
REFUSALS_TO_STUB = 2  # refusals of a record alone, each right after a proof, before a stub
DEFAULT_KINDS = frozenset({"ip", "caller", "identity"})

# OTLP SeverityNumber for each severity_id (OCSF: 0 Unknown ... 6 Fatal).
OTLP_SEVERITY: dict[int, int] = {0: 0, 1: 9, 2: 13, 3: 14, 4: 17, 5: 21, 6: 22}
SEVERITY_TEXT: dict[int, str] = {int(s): s.name.capitalize() for s in Severity}

# Keys of event payloads and old/new values known to hold structured values (ids, enums,
# numbers, times): exported as they are. Any other key's text or nested value is exported as
# {"hmac", "length"} (ADR 0012).
STRUCTURED_KEYS = frozenset(
    {
        "count",
        "detection_uid",
        "disposition",
        "finding_uid",
        "firing_detection_id",
        "from",
        "incident_uid",
        "late",
        "overflow",
        "previous_incident_uid",
        "row_uid",
        "rule",
        "severity_from",
        "severity_id",
        "severity_to",
        "status",
        "suppressed_until",
        "to",
    }
)

Post = Callable[[str, bytes, Mapping[str, str], float], Awaitable[tuple[int, bytes]]]


@dataclass(frozen=True, slots=True)
class ExportConfig:
    url: str | None = None  # None: this worker does not export
    # Secrets: never in repr (logs, tracebacks).
    pseudonym_key: bytes = field(default=b"", repr=False)
    pseudonymize_kinds: frozenset[str] = DEFAULT_KINDS
    headers: Mapping[str, str] = field(default_factory=dict, repr=False)
    batch_size: int = 100
    timeout_seconds: float = 10.0
    build_revision: str = "unknown"
    backoff_base_seconds: float = 5.0
    backoff_cap_seconds: float = 300.0
    round_budget_seconds: float = 30.0  # a round sends batches for at most this long
    # The export connection's statement timeout (TUISKU_WORKER_STATEMENT_TIMEOUT_SECONDS) and
    # lock timeout (as the evaluation connection's).
    statement_timeout_seconds: float = 10.0
    lock_timeout_seconds: float = 5.0

    @property
    def lease_seconds(self) -> float:
        """Long enough for two requests (a record refused on its own is followed by a probe or
        a stub), renewed before each request."""
        return 2 * self.timeout_seconds + 30.0


# --- the record ---------------------------------------------------------------------------------


class Pseudonyms:
    """HMAC-SHA-256 under the deployment's key (ADR 0008)."""

    def __init__(self, key: bytes, kinds: frozenset[str]) -> None:
        if not key:
            raise ValueError("a pseudonym key is required to export (ADR 0008)")
        self._key = key
        self.kinds = kinds

    def mac(self, text: str) -> str:
        return hmac.new(self._key, text.encode(), hashlib.sha256).hexdigest()

    def digest(self, text: str) -> dict[str, Any]:
        return {"hmac": self.mac(text), "length": len(text)}

    def entity_key(self, key: str) -> str:
        kind, sep, value = key.partition(":")
        if sep and kind in self.kinds:
            return f"{kind}:hmac:{self.mac(value)}"
        return key

    def scrub(self, value: Any) -> Any:
        """Keep structured keys; replace any other key's text or nested value by its digest."""
        if not isinstance(value, dict):
            return value
        out: dict[str, Any] = {}
        for key, item in value.items():
            if key in STRUCTURED_KEYS or item is None or isinstance(item, bool | int | float):
                out[key] = item
            elif isinstance(item, str):
                out[key] = self.digest(item)
            else:
                out[key] = self.digest(json.dumps(item, separators=(",", ":"), sort_keys=True))
        return out


def _finding(state: Mapping[str, Any], p: Pseudonyms) -> dict[str, Any]:
    ref = state.get("rule_ref") or {}
    return {
        "uid": state.get("uid"),
        "rule_id": state.get("rule_id"),
        "rule_rev": state.get("rule_rev"),
        "rule_name": ref.get("name"),
        "pack_id": ref.get("pack"),
        "pack_version": ref.get("pack_version"),
        "pack_sha256": ref.get("pack_sha256"),
        "overflow": state.get("overflow"),
        "title": state.get("title"),
        "severity_id": state.get("severity_id"),
        "status": state.get("status"),
        "count": state.get("count"),
        "entity_keys": [p.entity_key(k) for k in state.get("entity_keys") or []],
        "first_seen_at": state.get("first_seen"),
        "last_seen_at": state.get("last_seen"),
        "suppressed_until": state.get("suppressed_until"),
        "incident_uid": state.get("incident_uid"),
        "updated_at": state.get("updated_at"),
    }


def _incident(state: Mapping[str, Any], p: Pseudonyms) -> dict[str, Any]:
    return {
        "uid": state.get("uid"),
        "title": state.get("title"),
        "severity_id": state.get("severity_id"),
        "status": state.get("status"),
        "disposition": state.get("disposition"),
        "rule_id": state.get("rule_id"),
        "rule_rev": state.get("rule_rev"),
        "overflow": state.get("overflow"),
        "entity_keys": [p.entity_key(k) for k in state.get("entity_keys") or []],
        "finding_count": state.get("finding_count"),
        "opened_at": state.get("opened_at"),
        "updated_at": state.get("updated_at"),
        "previous_incident_uid": state.get("previous_incident_uid"),
    }


def build_record(
    stream: str, event: Mapping[str, Any], state: Mapping[str, Any], p: Pseudonyms, revision: str
) -> dict[str, Any]:
    """The ``tuisku.export.v1`` record for one queued event and its snapshot."""
    payload = dict(event.get("payload") or {})
    reason = event.get("reason")
    if reason is None and isinstance(payload.get("reason"), str):
        reason = payload["reason"]  # an incident event keeps its reason in the payload
    payload.pop("reason", None)
    if reason is not None and not isinstance(reason, str):
        reason = json.dumps(reason, sort_keys=True)
    uid = str(event["uid"])
    return {
        "schema": SCHEMA,
        "record_uid": uid,
        "stream": stream,
        "event": {
            "uid": uid,
            "at": event.get("at"),
            "actor": event.get("actor"),
            "kind": event.get("kind"),
            "old_value": p.scrub(event.get("old_value")),
            "new_value": p.scrub(event.get("new_value")),
            "payload": p.scrub(payload),
            "reason_hmac": None if reason is None else p.mac(reason),
            "reason_length": None if reason is None else len(reason),
        },
        stream: _finding(state, p) if stream == "finding" else _incident(state, p),
        "exporter": {"service": SERVICE, "build_revision": revision},
    }


def _event_of(row: Mapping[str, Any]) -> dict[str, Any]:
    event = row.get("event")
    return event if isinstance(event, dict) else {}


def stub_record(row: Mapping[str, Any], error: str, revision: str) -> dict[str, Any]:
    """What is sent in place of a record that cannot be encoded or that the sink refuses: it
    names the event, so the gap is visible in the sink too."""
    event = _event_of(row)
    uid = str(event.get("uid") or f"export_queue:{row['id']}")
    return {
        "schema": SCHEMA,
        "record_uid": uid,
        "stream": str(row.get("stream")),
        "error": error,
        "event": {"uid": uid, "at": str(event.get("at")), "kind": str(event.get("kind"))},
        "exporter": {"service": SERVICE, "build_revision": revision},
    }


@dataclass(frozen=True, slots=True)
class Encoded:
    queue_id: int
    record_uid: str
    stream: str
    body: str  # the record as compact JSON
    severity_id: int
    at_unix_nano: str
    stub: bool


def _dumps(record: Mapping[str, Any]) -> str:
    return json.dumps(record, separators=(",", ":"), sort_keys=True, ensure_ascii=False)


def _nano(value: Any) -> str:
    text = str(value)
    return text if text.isdigit() else "0"


def encode(row: Mapping[str, Any], p: Pseudonyms, revision: str) -> Encoded:
    """Encode one queue row; never raises for what the row holds (a stub replaces it)."""
    event = _event_of(row)
    try:
        record = build_record(row["stream"], event, row["state"], p, revision)
        severity = record[row["stream"]].get("severity_id")
        return Encoded(
            row["id"],
            record["record_uid"],
            row["stream"],
            _dumps(record),
            severity if isinstance(severity, int) else 0,
            _nano(event.get("at_unix_nano")),
            stub=False,
        )
    except Exception as exc:
        log.error("export queue row %s cannot be encoded: %s", row.get("id"), type(exc).__name__)
        return to_stub(row, f"unencodable: {type(exc).__name__}", revision)


def to_stub(row: Mapping[str, Any], error: str, revision: str) -> Encoded:
    stub = stub_record(row, error, revision)
    event = _event_of(row)
    return Encoded(
        row["id"],
        stub["record_uid"],
        stub["stream"],
        _dumps(stub),
        0,
        _nano(event.get("at_unix_nano")),
        stub=True,
    )


def _attr(key: str, value: str) -> dict[str, Any]:
    return {"key": key, "value": {"stringValue": value}}


def envelope(records: list[Encoded], build_revision: str) -> bytes:
    """One OTLP ``ExportLogsServiceRequest`` (JSON): one resource, one scope, one log record per
    exported record, its body the record as compact JSON."""
    log_records = [
        {
            "timeUnixNano": r.at_unix_nano,
            "severityNumber": OTLP_SEVERITY.get(r.severity_id, 0),
            "severityText": SEVERITY_TEXT.get(r.severity_id, "Unknown"),
            "body": {"stringValue": r.body},
            "attributes": [
                _attr("tuisku.stream", r.stream),
                _attr("tuisku.record_uid", r.record_uid),
                _attr("tuisku.schema", SCHEMA),
            ],
        }
        for r in records
    ]
    request = {
        "resourceLogs": [
            {
                "resource": {
                    "attributes": [
                        _attr("service.name", SERVICE),
                        _attr("service.version", build_revision),
                    ]
                },
                "scopeLogs": [{"scope": {"name": SCOPE}, "logRecords": log_records}],
            }
        ]
    }
    return json.dumps(request, separators=(",", ":"), ensure_ascii=False).encode()


# --- HTTP ---------------------------------------------------------------------------------------


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Audit records go to the configured URL only: a redirect is a failed delivery."""

    def redirect_request(self, *args: Any, **kwargs: Any) -> None:
        return None


def _opener() -> urllib.request.OpenerDirector:
    # No environment proxies: records go straight to the configured sink.
    return urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect)


def _post_blocking(
    url: str, body: bytes, headers: Mapping[str, str], timeout: float
) -> tuple[int, bytes]:
    request = urllib.request.Request(
        url, data=body, method="POST", headers={**headers, "Content-Type": "application/json"}
    )
    try:
        with _opener().open(request, timeout=timeout) as response:
            return response.status, response.read(MAX_RESPONSE_BYTES)
    except urllib.error.HTTPError as exc:
        with exc:
            return exc.code, b""


async def post_json(
    url: str, body: bytes, headers: Mapping[str, str], timeout: float
) -> tuple[int, bytes]:
    """POST off the event loop, bounded in total by ``timeout`` (a thread cannot be killed: one
    that overruns is abandoned and ends at its socket timeout)."""
    work = asyncio.to_thread(_post_blocking, url, body, headers, timeout)
    return await asyncio.wait_for(work, timeout)


def _rejected(body: bytes) -> int:
    """``partialSuccess.rejectedLogRecords`` of an OTLP response, 0 when absent."""
    try:
        parsed = json.loads(body) if body else {}
        return int(((parsed or {}).get("partialSuccess") or {}).get("rejectedLogRecords") or 0)
    except (ValueError, TypeError, AttributeError):
        return 0


# --- the exporter -------------------------------------------------------------------------------


@dataclass(slots=True)
class Round:
    delivered: int = 0
    discarded: int = 0
    stubs: int = 0
    more: bool = False  # the round's budget ran out with rows left


def _holder() -> str:
    return f"{socket.gethostname()}:{os.getpid()}:{uuid.uuid4().hex[:8]}"[:200]


@dataclass
class Exporter:
    config: ExportConfig = field(default_factory=ExportConfig)
    post: Post = post_json
    monotonic: Callable[[], float] = time.monotonic
    clock: Callable[[], datetime] = lambda: datetime.now(UTC)
    holder: str = field(default_factory=_holder)
    failures: int = field(default=0, init=False)
    _retry_at: float = field(default=0.0, init=False)
    _batch: int = field(default=0, init=False)
    _pseudonyms: Pseudonyms | None = field(default=None, init=False, repr=False)
    isolated: int = field(default=0, init=False)  # records replaced by stubs, since start

    def __post_init__(self) -> None:
        self._batch = self.config.batch_size
        if self.enabled:
            self._pseudonyms = Pseudonyms(self.config.pseudonym_key, self.config.pseudonymize_kinds)

    @property
    def enabled(self) -> bool:
        return self.config.url is not None

    # -- the task --------------------------------------------------------------------------

    async def run_forever(
        self,
        connect: Callable[[], Awaitable[AsyncConnection[Any]]],
        backlog_after: timedelta,
        poll_seconds: float,
    ) -> None:
        """The export task: rounds on a connection of its own, until cancelled. An error ends
        the round, never the task; the next round reconnects after a backoff."""
        errors_in_a_row = 0
        while True:
            try:
                conn = await connect()
                async with conn:
                    await conn.execute(
                        "SELECT set_config('lock_timeout', %s, false), "
                        "set_config('statement_timeout', %s, false)",
                        (
                            f"{int(self.config.lock_timeout_seconds * 1000)}ms",
                            f"{int(self.config.statement_timeout_seconds * 1000)}ms",
                        ),
                    )
                    while True:
                        done = await self.round(conn, backlog_after)
                        errors_in_a_row = 0
                        if not done.more:
                            await asyncio.sleep(poll_seconds)
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                errors_in_a_row += 1
                delay = min(60.0, poll_seconds * 2**errors_in_a_row)
                log.error("export round failed (%s); retrying in %.0fs", type(exc).__name__, delay)
                await asyncio.sleep(delay)

    async def round(self, conn: AsyncConnection[Any], backlog_after: timedelta) -> Round:
        """One export round on an autocommit connection: deliver (or, export off, discard),
        then check the backlog."""
        done = Round()
        state = await db.fetch_one(conn, "SELECT enabled FROM export_state")
        enqueueing = bool(state and state["enabled"])
        if not self.enabled:
            if enqueueing:
                # The database enqueues, but this worker does not export. Another replica may;
                # if none does, the backlog pages. Never discard what is meant to be exported.
                await self.check_backlog(conn, backlog_after)
            else:
                done.discarded = await self.discard(conn)
            return done
        if not enqueueing:
            if await self._meta(conn, "not_enqueued", {"export_state": "disabled"}):
                log.error(
                    "export is configured on the worker but the database does not enqueue "
                    "events: run TUISKU_EXPORT_ENQUEUE=on tuisku migrate (ADR 0012)"
                )
        due = self.monotonic() >= self._retry_at
        if due and await self._pending(conn) and await self._lease(conn):
            try:
                await self._deliver(conn, done)
            finally:
                await conn.execute(
                    "UPDATE worker_locks SET holder = NULL, lease_until = NULL "
                    "WHERE name = 'export' AND holder = %s",
                    (self.holder,),
                )
        await self.check_backlog(conn, backlog_after)
        return done

    async def _pending(self, conn: AsyncConnection[Any]) -> bool:
        """Anything queued? An idle round then writes no lease at all."""
        row = await db.fetch_one(conn, "SELECT EXISTS (SELECT 1 FROM export_queue) AS any")
        if row is None or not row["any"]:
            self.failures, self._retry_at = 0, 0.0  # caught up
            return False
        return True

    async def _lease(self, conn: AsyncConnection[Any]) -> bool:
        """Take or renew the export lease: one exporter at a time, without a lock held across a
        request. A holder that dies loses it when it expires."""
        row = await db.fetch_one(
            conn,
            "UPDATE worker_locks SET holder = %s, "
            "lease_until = now() + make_interval(secs => %s) "
            "WHERE name = 'export' AND (lease_until IS NULL OR lease_until < now() "
            "OR holder = %s) RETURNING name",
            (self.holder, self.config.lease_seconds, self.holder),
        )
        return row is not None

    def _failed(self, why: str) -> None:
        self.failures += 1
        delay = min(
            self.config.backoff_cap_seconds,
            self.config.backoff_base_seconds * 2 ** min(self.failures - 1, 30),
        )
        self._retry_at = self.monotonic() + delay
        log.warning("%s; %d consecutive failures, retrying in %.0fs", why, self.failures, delay)

    async def _deliver(self, conn: AsyncConnection[Any], done: Round) -> None:
        assert self.config.url is not None and self._pseudonyms is not None
        deadline = self.monotonic() + self.config.round_budget_seconds
        while True:
            if self.monotonic() >= deadline:
                done.more = True
                return
            rows = await db.fetch_all(
                conn,
                "SELECT id, stream, event, state FROM export_queue ORDER BY id LIMIT %s",
                (self._batch,),
            )
            if not rows:
                self.failures, self._retry_at = 0, 0.0  # caught up
                return
            encoded = [encode(r, self._pseudonyms, self.config.build_revision) for r in rows]
            status = await self._send(conn, encoded, done)
            if status is None:
                return  # failed: backing off
            if not await self._lease(conn):
                return  # the lease was lost (expired and taken): leave the rest to its holder

    async def _send(
        self, conn: AsyncConnection[Any], encoded: list[Encoded], done: Round
    ) -> int | None:
        """Send one batch. Returns the status once the batch is settled (sent, or split), None
        after a failure that backs off."""
        assert self.config.url is not None
        try:
            status, answer = await self.post(
                self.config.url,
                envelope(encoded, self.config.build_revision),
                self.config.headers,
                self.config.timeout_seconds,
            )
        except (TimeoutError, OSError) as exc:  # never log the URL: it may carry a secret
            self._failed(f"export of {len(encoded)} records failed: {type(exc).__name__}")
            return None
        if status in REFUSED and len(encoded) > 1:
            self._batch = max(1, len(encoded) // 2)
            log.warning("export sink refused %d records (HTTP %d); halving", len(encoded), status)
            return status
        if status in REFUSED:
            return await self._isolate(conn, encoded[0], status, done)
        if not 200 <= status < 300:
            self._failed(f"export of {len(encoded)} records failed: HTTP {status}")
            return None
        await self._settle(conn, encoded, answer, done)
        self._batch = min(self.config.batch_size, self._batch * 2)
        return status

    async def _settle(
        self, conn: AsyncConnection[Any], encoded: list[Encoded], answer: bytes, done: Round
    ) -> None:
        stubs = [e for e in encoded if e.stub]
        for e in stubs:
            await self._meta(
                conn, "unencodable", {"queue_id": e.queue_id, "record_uid": e.record_uid}
            )
        rejected = _rejected(answer)
        if rejected:
            # OTLP: a partial success must not be retried; the sink refused them for good.
            log.error("export sink rejected %d of %d records", rejected, len(encoded))
            await self._meta(conn, "partial_success", {"rejected": rejected, "sent": len(encoded)})
        await conn.execute(
            "DELETE FROM export_queue WHERE id = ANY(%s)", ([e.queue_id for e in encoded],)
        )
        done.delivered += len(encoded) - rejected
        done.stubs += len(stubs)

    async def _post_one(self, conn: AsyncConnection[Any], one: Encoded) -> int | None:
        """Send one record on its own, under a renewed lease. None after a failure (backing off)
        or a lost lease."""
        if not await self._lease(conn):
            return None
        try:
            status, _ = await self.post(
                self.config.url or "",
                envelope([one], self._rev),
                self.config.headers,
                self.config.timeout_seconds,
            )
        except (TimeoutError, OSError) as exc:
            self._failed(f"export of one record failed: {type(exc).__name__}")
            return None
        return status

    async def _prove(self, conn: AsyncConnection[Any], one: Encoded, done: Round) -> bool:
        """Show that the sink accepts records other than ``one``: send up to ``PROBES`` other
        queued records alone, smallest first (a size limit refuses big records, and the events of
        one transaction share one big snapshot), and stop at the first it accepts, which is then
        delivered. False when none is accepted (the sink is at fault, delivery backs off), or
        after a failure or a lost lease."""
        rows = await db.fetch_all(
            conn,
            "SELECT id, stream, event, state FROM export_queue WHERE id <> %s "
            "ORDER BY pg_column_size(event) + pg_column_size(state), id LIMIT %s",
            (one.queue_id, PROBES),
        )
        if not rows:
            self._failed(
                "the export sink refuses the only queued record; nothing else can show "
                "whether the record or the sink is at fault"
            )
            return False
        assert self._pseudonyms is not None
        for row in rows:
            probe = encode(row, self._pseudonyms, self._rev)
            status = await self._post_one(conn, probe)
            if status is None:
                return False
            if 200 <= status < 300:
                await self._settle(conn, [probe], b"", done)
                return True
            if status not in REFUSED:
                self._failed(f"export of one record failed: HTTP {status}")
                return False
        self._failed(f"the export sink refuses {len(rows)} distinct records on their own")
        return False

    async def _isolate(
        self, conn: AsyncConnection[Any], one: Encoded, status: int, done: Round
    ) -> int | None:
        """The sink refuses this one record. That is the record's fault only if the sink accepts
        others: the record is sent again, alone, right after the sink accepted another record
        (``_prove``), and must be refused that way twice before a stub replaces it (and pages).
        So a flaky sink does not stub sound records. A sink that accepts none of the probes, or
        refuses the stub, is at fault: every row is kept and delivery backs off. A row is never
        dropped because the sink refuses it."""
        log.error("export sink refused queue row %s on its own (HTTP %d)", one.queue_id, status)
        for _ in range(REFUSALS_TO_STUB):
            if not await self._prove(conn, one, done):
                return None
            if one.stub:
                # Already the smallest form, and refused while the sink takes other records:
                # still the sink's to fix (its schema, its limits); keep the row and back off.
                self._failed(f"the export sink refuses a stub (HTTP {status})")
                return None
            again = await self._post_one(conn, one)
            if again is None:
                return None
            if 200 <= again < 300:  # a flaky sink: delivered after all
                await self._settle(conn, [one], b"", done)
                return again
            if again not in REFUSED:
                self._failed(f"export of one record failed: HTTP {again}")
                return None
            status = again
        row = await db.fetch_one(
            conn, "SELECT id, stream, event FROM export_queue WHERE id = %s", (one.queue_id,)
        )
        stub = to_stub(row or {"id": one.queue_id}, f"refused: HTTP {status}", self._rev)
        sent = await self._post_one(conn, stub)
        if sent is None:
            return None
        if not 200 <= sent < 300:
            self._failed(f"the export sink refuses a stub (HTTP {sent})")
            return None
        self.isolated += 1
        log.error(
            "export queue row %s (record %s) was replaced by a stub; %d so far",
            one.queue_id,
            one.record_uid,
            self.isolated,
        )
        await self._meta(
            conn,
            "refused",
            {
                "queue_id": one.queue_id,
                "record_uid": one.record_uid,
                "status": status,
                "isolated_since_start": self.isolated,
            },
        )
        await conn.execute("DELETE FROM export_queue WHERE id = %s", (one.queue_id,))
        done.stubs += 1
        self._batch = self.config.batch_size
        return sent

    @property
    def _rev(self) -> str:
        return self.config.build_revision

    async def _meta(self, conn: AsyncConnection[Any], subject: str, details: dict) -> bool:
        """Raise ``tuisku.meta.export_failed``; True when this bucket had none for the subject
        yet (one per subject and 5-minute bucket, ADR 0005)."""
        async with conn.transaction():
            return await meta.record_export_failed(
                conn, subject=subject, details=details, now=self.clock()
            )

    async def discard(self, conn: AsyncConnection[Any]) -> int:
        """Export off: delete rows left from when it was on, bounded per round."""
        rows = await db.fetch_all(
            conn,
            "DELETE FROM export_queue WHERE id IN (SELECT id FROM export_queue ORDER BY id "
            "LIMIT %s) RETURNING id",
            (DISCARD_LIMIT,),
        )
        if rows:
            log.info("export off: discarded %d queued records", len(rows))
        return len(rows)

    async def check_backlog(self, conn: AsyncConnection[Any], limit: timedelta) -> int:
        """Raise ``tuisku.meta.backlog`` (subject ``export``) when the oldest queued export row
        is older than ``limit`` by the database clock, which set ``enqueued_at``."""
        async with conn.transaction():
            row = await db.fetch_one(
                conn,
                "SELECT min(enqueued_at) AS oldest, now() - min(enqueued_at) > %s AS late "
                "FROM export_queue",
                (limit,),
            )
            assert row is not None
            if not row["late"]:
                return 0
            counted = await db.fetch_one(conn, "SELECT count(*) AS n FROM export_queue")
            assert counted is not None
            raised = await meta.record_backlog(
                conn,
                subject="export",
                details={
                    "oldest_enqueued_at": row["oldest"].isoformat(),
                    "queued": counted["n"],
                    "limit_seconds": int(limit.total_seconds()),
                },
                now=self.clock(),
            )
        return int(raised)
