"""Export of finding and incident events to an append-only sink (ADR 0012).

Every ``finding_events`` and ``incident_events`` row is enqueued in ``export_queue`` by an owner
trigger at the commit of the event's transaction, with a snapshot of the finding or incident as
that transaction left it. After the notification drain, each worker pass sends at most one
batch, oldest first, as one OTLP/HTTP JSON ``ExportLogsServiceRequest`` (one log record per
event), and deletes the batch's queue rows only after a 2xx. Delivery is at least once: a crash
between the POST and the delete sends the batch again, and consumers deduplicate on
``record_uid`` (the event's uid). A non-2xx, a timeout or a connection error leaves the rows
queued and backs off (5 s doubling, capped at 5 minutes, kept in the worker's memory: the
worker role cannot update the queue). An export row older than the backlog limit raises
``tuisku.meta.backlog`` with subject ``export``, which pages like the evaluation queue and the
outbox do.

The record (``tuisku.export.v1``) carries ids, kinds, statuses, severities, times and entity
keys. It never carries free text a person typed: an event's reason (a triage reason, or an
incident event's ``payload.reason``) is exported as its SHA-256 and length only, and any
payload key not known to hold structured values is exported the same way, so a future
free-text field cannot leak by accident. Entity keys of the configured kinds become
``<kind>:sha256:<hex>``. Titles come from rule packs, never from telemetry.

With export disabled (no URL), the triggers still enqueue and the worker deletes queued rows
older than the backlog limit without sending them: the queue stays bounded and nothing pages.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import time
import urllib.error
import urllib.request
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

from psycopg import AsyncConnection, errors

from tuisku import db
from tuisku.adapters import Severity
from tuisku.store import meta

log = logging.getLogger("tuisku.export")

SCHEMA = "tuisku.export.v1"
SERVICE = "tuisku"
SCOPE = "tuisku.export"
MAX_RESPONSE_BYTES = 64 * 1024
DISCARD_LIMIT = 1000  # queue rows a disabled exporter deletes per pass

# OTLP SeverityNumber for each severity_id (OCSF: 0 Unknown ... 6 Fatal).
OTLP_SEVERITY: dict[int, int] = {0: 0, 1: 9, 2: 13, 3: 14, 4: 17, 5: 21, 6: 22}
SEVERITY_TEXT: dict[int, str] = {int(s): s.name.capitalize() for s in Severity}

# Keys of event payloads and old/new values known to hold structured values (ids, enums,
# numbers, times): exported as they are. Any other key's text or nested value is exported as
# {"sha256", "length"} (ADR 0012).
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

Post = Callable[[str, bytes, float], Awaitable[tuple[int, bytes]]]


@dataclass(frozen=True, slots=True)
class ExportConfig:
    url: str | None = None  # None: export disabled
    batch_size: int = 100
    timeout_seconds: float = 10.0
    redact_entity_kinds: frozenset[str] = frozenset({"user", "email"})
    build_revision: str = "unknown"
    backoff_base_seconds: float = 5.0
    backoff_cap_seconds: float = 300.0


# --- the record ---------------------------------------------------------------------------------


def _digest(text: str) -> dict[str, Any]:
    return {"sha256": hashlib.sha256(text.encode()).hexdigest(), "length": len(text)}


def _scrub(value: Any) -> Any:
    """Keep structured keys; replace any other key's text or nested value by its digest."""
    if not isinstance(value, dict):
        return value
    out: dict[str, Any] = {}
    for key, item in value.items():
        if key in STRUCTURED_KEYS or item is None or isinstance(item, bool | int | float):
            out[key] = item
        elif isinstance(item, str):
            out[key] = _digest(item)
        else:
            out[key] = _digest(json.dumps(item, separators=(",", ":"), sort_keys=True))
    return out


def redact_entity_key(key: str, kinds: frozenset[str]) -> str:
    kind, sep, value = key.partition(":")
    if sep and kind in kinds:
        return f"{kind}:sha256:{hashlib.sha256(value.encode()).hexdigest()}"
    return key


def _ts(value: Any) -> str | None:
    """An RFC 3339 UTC timestamp, whatever the session time zone rendered."""
    if value is None:
        return None
    t = value if isinstance(value, datetime) else datetime.fromisoformat(value)
    return t.astimezone(UTC).isoformat().replace("+00:00", "Z")


def _finding(state: Mapping[str, Any], kinds: frozenset[str]) -> dict[str, Any]:
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
        "entity_keys": [redact_entity_key(k, kinds) for k in state.get("entity_keys") or []],
        "first_seen_at": _ts(state.get("first_seen")),
        "last_seen_at": _ts(state.get("last_seen")),
        "suppressed_until": _ts(state.get("suppressed_until")),
        "incident_uid": state.get("incident_uid"),
        "updated_at": _ts(state.get("updated_at")),
    }


def _incident(state: Mapping[str, Any], kinds: frozenset[str]) -> dict[str, Any]:
    return {
        "uid": state.get("uid"),
        "title": state.get("title"),
        "severity_id": state.get("severity_id"),
        "status": state.get("status"),
        "disposition": state.get("disposition"),
        "rule_id": state.get("rule_id"),
        "rule_rev": state.get("rule_rev"),
        "overflow": state.get("overflow"),
        "entity_keys": [redact_entity_key(k, kinds) for k in state.get("entity_keys") or []],
        "finding_count": state.get("finding_count"),
        "opened_at": _ts(state.get("opened_at")),
        "updated_at": _ts(state.get("updated_at")),
        "previous_incident_uid": state.get("previous_incident_uid"),
    }


def build_record(row: Mapping[str, Any], config: ExportConfig) -> dict[str, Any]:
    """The ``tuisku.export.v1`` record for one queue row joined with its event."""
    payload = dict(row["payload"] or {})
    reason = row["reason"]
    if reason is None and isinstance(payload.get("reason"), str):
        reason = payload.pop("reason")  # an incident event keeps its reason in the payload
    payload.pop("reason", None)
    stream = row["stream"]
    state = row["state"]
    kinds = config.redact_entity_kinds
    return {
        "schema": SCHEMA,
        "record_uid": str(row["event_uid"]),
        "stream": stream,
        "event": {
            "uid": str(row["event_uid"]),
            "at": _ts(row["at"]),
            "actor": row["actor"],
            "kind": row["kind"],
            "old_value": _scrub(row["old_value"]),
            "new_value": _scrub(row["new_value"]),
            "payload": _scrub(payload),
            "reason_sha256": None if reason is None else _digest(reason)["sha256"],
            "reason_length": None if reason is None else len(reason),
        },
        stream: _finding(state, kinds) if stream == "finding" else _incident(state, kinds),
        "exporter": {"service": SERVICE, "build_revision": config.build_revision},
    }


def _attr(key: str, value: str) -> dict[str, Any]:
    return {"key": key, "value": {"stringValue": value}}


def _nanos(t: datetime) -> str:
    delta = t - datetime(1970, 1, 1, tzinfo=UTC)
    return str((delta.days * 86_400 + delta.seconds) * 1_000_000_000 + delta.microseconds * 1000)


def envelope(records: list[tuple[dict[str, Any], datetime]], build_revision: str) -> bytes:
    """One OTLP ``ExportLogsServiceRequest`` (JSON): one resource, one scope, one log record per
    exported record, its body the record as compact JSON."""
    log_records = []
    for record, at in records:
        severity = record[record["stream"]].get("severity_id") or 0
        log_records.append(
            {
                "timeUnixNano": _nanos(at),
                "severityNumber": OTLP_SEVERITY.get(severity, 0),
                "severityText": SEVERITY_TEXT.get(severity, "Unknown"),
                "body": {
                    "stringValue": json.dumps(
                        record, separators=(",", ":"), sort_keys=True, ensure_ascii=False
                    )
                },
                "attributes": [
                    _attr("tuisku.stream", record["stream"]),
                    _attr("tuisku.record_uid", record["record_uid"]),
                    _attr("tuisku.schema", SCHEMA),
                ],
            }
        )
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


# --- delivery -----------------------------------------------------------------------------------


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Audit records go to the configured URL only: a redirect is a failed delivery."""

    def redirect_request(self, *args: Any, **kwargs: Any) -> None:
        return None


_OPENER = urllib.request.build_opener(_NoRedirect)


def _post_blocking(url: str, body: bytes, timeout: float) -> tuple[int, bytes]:
    request = urllib.request.Request(
        url, data=body, method="POST", headers={"Content-Type": "application/json"}
    )
    try:
        with _OPENER.open(request, timeout=timeout) as response:
            return response.status, response.read(MAX_RESPONSE_BYTES)
    except urllib.error.HTTPError as exc:
        with exc:
            return exc.code, b""


async def post_json(url: str, body: bytes, timeout: float) -> tuple[int, bytes]:
    """POST off the event loop, bounded in total by ``timeout`` (a thread cannot be killed: one
    that overruns is abandoned and ends at its socket timeout)."""
    return await asyncio.wait_for(asyncio.to_thread(_post_blocking, url, body, timeout), timeout)


def _rejected(body: bytes) -> int:
    """``partialSuccess.rejectedLogRecords`` of an OTLP response, 0 when absent."""
    try:
        parsed = json.loads(body) if body else {}
        return int(((parsed or {}).get("partialSuccess") or {}).get("rejectedLogRecords") or 0)
    except (ValueError, TypeError, AttributeError):
        return 0


_BATCH_SQL = (
    "SELECT q.id, q.stream, q.state, "
    "coalesce(fe.uid, ie.uid) AS event_uid, coalesce(fe.at, ie.at) AS at, "
    "coalesce(fe.actor, ie.actor) AS actor, coalesce(fe.kind, ie.kind) AS kind, "
    "fe.old_value, fe.new_value, fe.reason, coalesce(fe.payload, ie.payload) AS payload "
    "FROM export_queue q "
    "LEFT JOIN finding_events fe ON fe.id = q.finding_event_id "
    "LEFT JOIN incident_events ie ON ie.id = q.incident_event_id "
    "ORDER BY q.id LIMIT %s"
)


@dataclass
class Exporter:
    config: ExportConfig = field(default_factory=ExportConfig)
    post: Post = post_json
    monotonic: Callable[[], float] = time.monotonic
    failures: int = field(default=0, init=False)
    _retry_at: float = field(default=0.0, init=False)

    @property
    def enabled(self) -> bool:
        return self.config.url is not None

    async def run(self, conn: AsyncConnection[Any], backlog_after: timedelta, now: datetime) -> int:
        """One bounded, isolated export step of a worker pass: deliver (or, disabled, discard)
        one batch, then check the backlog. Returns how many records were delivered. Lock and
        statement timeouts propagate (the worker skips the step); any other error is logged
        and backs off, so export never stops evaluation."""
        try:
            if not self.enabled:
                await self.discard(conn, backlog_after)
                return 0
            delivered = await self.deliver(conn)
        except (errors.LockNotAvailable, errors.QueryCanceled):
            raise
        except Exception as exc:
            self._failed(f"export step failed: {type(exc).__name__}")
            delivered = 0
        try:
            await self.check_backlog(conn, backlog_after, now)
        except (errors.LockNotAvailable, errors.QueryCanceled):
            raise
        except Exception as exc:
            log.error("export backlog check failed: %s", type(exc).__name__)
        return delivered

    def _failed(self, why: str) -> None:
        self.failures += 1
        delay = min(
            self.config.backoff_cap_seconds,
            self.config.backoff_base_seconds * 2 ** min(self.failures - 1, 30),
        )
        self._retry_at = self.monotonic() + delay
        log.warning("%s; %d consecutive failures, retrying in %.0fs", why, self.failures, delay)

    async def deliver(self, conn: AsyncConnection[Any]) -> int:
        if self.monotonic() < self._retry_at:
            return 0  # backing off after a failure
        assert self.config.url is not None
        async with conn.transaction():
            # One exporter at a time, by a row lock on the worker-only worker_locks table (as
            # the notification drain does, ADR 0011). Held across the POST, so two workers
            # never send the same batch; a crash still can, and consumers deduplicate.
            await conn.execute(
                "INSERT INTO worker_locks (name) VALUES ('export') ON CONFLICT (name) DO NOTHING"
            )
            got = await db.fetch_one(
                conn, "SELECT name FROM worker_locks WHERE name = 'export' FOR UPDATE SKIP LOCKED"
            )
            if got is None:
                return 0
            rows = await db.fetch_all(conn, _BATCH_SQL, (self.config.batch_size,))
            if not rows:
                return 0
            records = [(build_record(r, self.config), r["at"]) for r in rows]
            body = envelope(records, self.config.build_revision)
            try:
                status, answer = await self.post(self.config.url, body, self.config.timeout_seconds)
            except (TimeoutError, OSError) as exc:  # never log the URL: it may carry a secret
                self._failed(f"export of {len(rows)} records failed: {type(exc).__name__}")
                return 0
            if not 200 <= status < 300:
                self._failed(f"export of {len(rows)} records failed: HTTP {status}")
                return 0
            rejected = _rejected(answer)
            if rejected:
                # OTLP: a partial success must not be retried; the sink refused them for good.
                log.error("export sink rejected %d of %d records", rejected, len(rows))
            await conn.execute(
                "DELETE FROM export_queue WHERE id = ANY(%s)", ([r["id"] for r in rows],)
            )
        self.failures, self._retry_at = 0, 0.0
        return len(rows)

    async def discard(self, conn: AsyncConnection[Any], older_than: timedelta) -> int:
        """Export disabled: drop queued rows older than ``older_than`` (by the database clock),
        bounded per pass. Younger rows wait, so a replica with export enabled still gets them."""
        async with conn.transaction():
            rows = await db.fetch_all(
                conn,
                "DELETE FROM export_queue WHERE id IN (SELECT id FROM export_queue "
                "WHERE enqueued_at < now() - %s ORDER BY id LIMIT %s) RETURNING id",
                (older_than, DISCARD_LIMIT),
            )
        if rows:
            log.info("export disabled: discarded %d queued records", len(rows))
        return len(rows)

    async def check_backlog(
        self, conn: AsyncConnection[Any], limit: timedelta, now: datetime
    ) -> int:
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
                now=now,
            )
        return int(raised)
