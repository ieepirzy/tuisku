"""Meta-detections for ingest limit breaches (ADR 0005 "Breaches").

A breach is never silently absorbed. It becomes a detection with kind ``tuisku.meta.<name>``,
evaluator and authorship ``tuisku``, no raw record, and ``source:<name>`` as an entity key.
At most one is written per source and kind per 5 minutes.

ADR 0005 says repeats "increment a counter in its explanation", but detections are
append-only (ADR 0004), so a written detection is never updated. Instead each replica counts
breaches since its last write and puts those counts into the *next* meta-detection's
explanation (``counts_since_previous``). Counts held in memory are lost if the replica
restarts before the next write.
"""

from __future__ import annotations

import json
import time
from collections import Counter
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any

from psycopg import AsyncConnection

from tuisku import db
from tuisku.adapters import OCSF_VERSION, Severity
from tuisku.store.admin import Source
from tuisku.store.ingest import enqueue

WINDOW = timedelta(minutes=5)

LIMIT_EXCEEDED = "tuisku.meta.source_limit_exceeded"
RATE_LIMITED = "tuisku.meta.source_rate_limited"
INVALID_ENVELOPE = "tuisku.meta.invalid_envelope"

_TITLES = {
    LIMIT_EXCEEDED: ("Source exceeded an ingest limit", Severity.MEDIUM),
    RATE_LIMITED: ("Source was rate limited", Severity.LOW),
    INVALID_ENVELOPE: ("Source sent malformed ingest envelopes", Severity.LOW),
}


@dataclass(slots=True)
class _Pending:
    counts: Counter[str] = field(default_factory=Counter)
    last_attempt: float | None = None


class MetaDetectionGate:
    """In-process throttle in front of the database check, so a flood of breaches costs at most
    one database round trip per source and kind per window on each replica."""

    def __init__(self, monotonic: Callable[[], float] = time.monotonic) -> None:
        self._monotonic = monotonic
        self._pending: dict[tuple[int, str], _Pending] = {}

    def note(self, source_id: int, kind: str, limit: str, n: int = 1) -> dict[str, int] | None:
        """Count a breach. Returns the counts to write when a write is due, else None."""
        entry = self._pending.setdefault((source_id, kind), _Pending())
        entry.counts[limit] += n
        now = self._monotonic()
        if entry.last_attempt is not None and now - entry.last_attempt < WINDOW.total_seconds():
            return None
        entry.last_attempt = now
        return dict(entry.counts)

    def written(self, source_id: int, kind: str) -> None:
        entry = self._pending.get((source_id, kind))
        if entry is not None:
            entry.counts.clear()


async def write_meta_detection(
    conn: AsyncConnection[Any],
    source: Source,
    kind: str,
    *,
    counts: dict[str, int],
    details: dict[str, Any],
    now: datetime,
) -> bool:
    """Write one meta-detection unless one for this source and kind exists in the window.

    Runs in the caller's transaction. Returns True when a row was written.
    """
    # Serialize writers for this source and kind across replicas.
    await conn.execute(
        "SELECT pg_advisory_xact_lock(hashtextextended(%s, 0))", (f"{kind}/{source.id}",)
    )
    exists = await db.fetch_one(
        conn,
        "SELECT 1 AS x FROM detections WHERE kind = %s AND source_id = %s "
        "AND evaluator = 'tuisku' AND eval_time > %s LIMIT 1",
        (kind, source.id, now - WINDOW),
    )
    if exists is not None:
        return False
    title, severity = _TITLES[kind]
    explanation = {
        "counts_since_previous": counts,
        "window_seconds": int(WINDOW.total_seconds()),
        **details,
    }
    row = await db.fetch_one(
        conn,
        "INSERT INTO detections (source_id, evaluator, authorship, kind, identity, title, "
        "severity_id, event_time, received_at, eval_time, ocsf_version, rule_ref, "
        "entity_keys, explanation) "
        "VALUES (%s, 'tuisku', 'tuisku', %s, %s, %s, %s, %s, %s, %s, %s, %s::jsonb, %s, "
        "%s::jsonb) RETURNING id",
        (
            source.id,
            kind,
            kind,
            title,
            int(severity),
            now,
            now,
            now,
            OCSF_VERSION,
            json.dumps({"engine": "tuisku", "name": "ingest_limits"}),
            [f"source:{source.name}"],
            json.dumps(explanation),
        ),
    )
    assert row is not None
    await enqueue(conn, observation_ids=[], detection_ids=[row["id"]], enqueued_at=now)
    return True
