"""Meta-detections for ingest limit breaches (ADR 0005 "Breaches").

A breach is never silently absorbed. It becomes a detection with kind ``tuisku.meta.<name>``,
evaluator and authorship ``tuisku``, no raw record, and ``source:<name>`` as an entity key.

At most one is written per source, kind, subject and 5-minute bucket: the unique index on
``detections (source_id, kind, subject, bucket_start)`` with ``ON CONFLICT DO NOTHING``
enforces it across API replicas. The subject is the limit name, so a breach of one limit
cannot hide a breach of another. Every breach, the first included, increments
``meta_counters`` for that bucket; detections are append-only, so the count is never written
into the detection itself.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from typing import Any

from psycopg import AsyncConnection

from tuisku import db
from tuisku.adapters import OCSF_VERSION, Severity
from tuisku.store.admin import Source
from tuisku.store.ingest import enqueue

BUCKET = timedelta(minutes=5)
_EPOCH = datetime(2000, 1, 1, tzinfo=UTC)

LIMIT_EXCEEDED = "tuisku.meta.source_limit_exceeded"
RATE_LIMITED = "tuisku.meta.source_rate_limited"
INVALID_ENVELOPE = "tuisku.meta.invalid_envelope"
EVALUATION_FAILED = "tuisku.meta.evaluation_failed"
NOTIFICATION_UNDELIVERABLE = "tuisku.meta.notification_undeliverable"

_TITLES = {
    LIMIT_EXCEEDED: ("Source exceeded an ingest limit", Severity.MEDIUM),
    RATE_LIMITED: ("Source was rate limited", Severity.LOW),
    INVALID_ENVELOPE: ("Source sent malformed ingest envelopes", Severity.LOW),
    EVALUATION_FAILED: ("A rule failed to evaluate a row", Severity.MEDIUM),
    NOTIFICATION_UNDELIVERABLE: ("A notification keeps failing to deliver", Severity.HIGH),
}


def bucket_start(now: datetime) -> datetime:
    """The start of the 5-minute bucket containing ``now``."""
    return now - (now - _EPOCH) % BUCKET


async def record_breach(
    conn: AsyncConnection[Any],
    source: Source,
    kind: str,
    subject: str,
    *,
    n: int = 1,
    details: dict[str, Any],
    now: datetime,
) -> bool:
    """Count ``n`` breaches and write the bucket's meta-detection if it has none yet.

    Runs in the caller's transaction. Returns True when a detection row was written.
    """
    return await _record(
        conn,
        source.id,
        source.name,
        kind,
        subject,
        n=n,
        details=details,
        now=now,
        rule_name="ingest_limits",
    )


async def record_evaluation_failed(
    conn: AsyncConnection[Any],
    *,
    source_id: int | None,
    source_name: str | None,
    rule_id: str,
    details: dict[str, Any],
    now: datetime,
) -> bool:
    """A (row, rule) pair was dead-lettered (ADR 0006): the subject is the rule id, so one
    failing rule cannot hide another."""
    return await _record(
        conn,
        source_id,
        source_name,
        EVALUATION_FAILED,
        rule_id,
        n=1,
        details=details,
        now=now,
        rule_name="evaluation",
    )


async def record_notification_undeliverable(
    conn: AsyncConnection[Any], *, kind: str, details: dict[str, Any], now: datetime
) -> bool:
    """A notification failed ALERT_AFTER_FAILURES deliveries (ADR 0007). The subject is the
    notification's kind, so the meta-detection (and the page it causes) is at most one per
    kind per 5-minute bucket, even when the page about it fails in turn."""
    return await _record(
        conn,
        None,
        None,
        NOTIFICATION_UNDELIVERABLE,
        kind[:200],
        n=1,
        details=details,
        now=now,
        rule_name="notifications",
    )


async def _record(
    conn: AsyncConnection[Any],
    source_id: int | None,
    source_name: str | None,
    kind: str,
    subject: str,
    *,
    n: int,
    details: dict[str, Any],
    now: datetime,
    rule_name: str,
) -> bool:
    bucket = bucket_start(now)
    await conn.execute(
        "INSERT INTO meta_counters (source_id, kind, subject, bucket_start, count) "
        "VALUES (%s, %s, %s, %s, %s) ON CONFLICT ON CONSTRAINT meta_counters_key "
        "DO UPDATE SET count = meta_counters.count + EXCLUDED.count",
        (source_id, kind, subject, bucket, n),
    )
    title, severity = _TITLES[kind]
    explanation = {
        "bucket_start": bucket.isoformat(),
        "bucket_seconds": int(BUCKET.total_seconds()),
        "subject": subject,
        "counter": "meta_counters",  # repeats in this bucket are counted there
        **details,
    }
    row = await db.fetch_one(
        conn,
        "INSERT INTO detections (source_id, evaluator, authorship, kind, identity, title, "
        "severity_id, event_time, received_at, eval_time, ocsf_version, rule_ref, "
        "entity_keys, explanation, subject, bucket_start, attributes) "
        "VALUES (%s, 'tuisku', 'tuisku', %s, %s, %s, %s, %s, %s, %s, %s, %s::jsonb, %s, "
        "%s::jsonb, %s, %s, %s::jsonb) "
        "ON CONFLICT (source_id, kind, subject, bucket_start) WHERE bucket_start IS NOT NULL "
        "DO NOTHING RETURNING id",
        (
            source_id,
            kind,
            kind,
            title,
            int(severity),
            now,
            now,
            now,
            OCSF_VERSION,
            json.dumps({"engine": "tuisku", "name": rule_name}),
            [f"source:{source_name}"] if source_name else [],
            json.dumps(explanation),
            subject,
            bucket,
            # Selectable by rules (e.g. group_by attributes.subject): the limit or the rule id.
            json.dumps({"subject": subject}),
        ),
    )
    if row is None:
        return False
    await enqueue(conn, observation_ids=[], detection_ids=[row["id"]], enqueued_at=now)
    return True
