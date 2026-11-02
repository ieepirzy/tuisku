"""Notification events (ADR 0007 "Notifications").

Notifications are written to the ``notifications`` outbox inside the evaluation transaction,
keyed by a ``dedupe_key`` with ``ON CONFLICT DO NOTHING``: a notification exists only if the
insert actually happened, so a retried or re-claimed evaluation never pages twice. After the
transaction commits, :func:`drain` hands undelivered rows to the notifier and marks them
delivered. The first notifier writes structured log lines only; which channels page whom is a
deployment decision outside this repository.

Notifications carry ids, titles, severities and entity keys, never L0 bodies.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime
from typing import Any, Protocol

from psycopg import AsyncConnection
from psycopg.types.json import Jsonb

from tuisku import db

log = logging.getLogger("tuisku.notify")


class Notifier(Protocol):
    def deliver(self, notification: dict[str, Any]) -> None: ...


class LogNotifier:
    """Writes one JSON line per notification to the ``tuisku.notify`` logger."""

    def deliver(self, notification: dict[str, Any]) -> None:
        log.warning("notification %s", json.dumps(notification, default=str, sort_keys=True))


async def emit(
    conn: AsyncConnection[Any],
    *,
    dedupe_key: str,
    kind: str,
    severity_id: int,
    payload: dict[str, Any],
    now: datetime,
) -> bool:
    """Queue a notification; True only when this call inserted it."""
    row = await db.fetch_one(
        conn,
        "INSERT INTO notifications (dedupe_key, kind, severity_id, payload, created_at) "
        "VALUES (%s, %s, %s, %s, %s) ON CONFLICT (dedupe_key) DO NOTHING RETURNING id",
        (dedupe_key, kind, severity_id, Jsonb(payload), now),
    )
    return row is not None


MAX_DELIVERY_FAILURES = 10
_DRAIN_LOCK = 0x7475_6973_6B75_6E6F  # one drainer at a time; rows are never locked or updated


async def drain(
    conn: AsyncConnection[Any], notifier: Notifier, now: datetime, limit: int = 500
) -> int:
    """Deliver pending notifications in id order; returns how many were delivered.

    The outbox and the delivery log are append-only: delivery appends a ``delivered`` row, and
    a notifier error appends a ``failed`` row and moves on, so one bad notification never
    blocks the others. A notification is retried until it has failed
    ``MAX_DELIVERY_FAILURES`` times. Delivery is at-least-once: a crash after delivering and
    before committing re-delivers.
    """
    delivered = 0
    async with conn.transaction():
        got = await db.fetch_one(conn, "SELECT pg_try_advisory_xact_lock(%s) AS ok", (_DRAIN_LOCK,))
        if got is None or not got["ok"]:
            return 0  # another worker is draining
        rows = await db.fetch_all(
            conn,
            "SELECT n.id, n.uid, n.kind, n.severity_id, n.payload, n.created_at "
            "FROM notifications n WHERE NOT EXISTS (SELECT 1 FROM notification_deliveries d "
            "  WHERE d.notification_id = n.id AND d.status = 'delivered') "
            "AND (SELECT count(*) FROM notification_deliveries d WHERE d.notification_id = n.id "
            "  AND d.status = 'failed') < %s ORDER BY n.id LIMIT %s",
            (MAX_DELIVERY_FAILURES, limit),
        )
        for row in rows:
            message = {
                "uid": str(row["uid"]),
                "kind": row["kind"],
                "severity_id": row["severity_id"],
                "created_at": row["created_at"].isoformat(),
                **row["payload"],
            }
            try:
                notifier.deliver(message)
            except Exception as exc:  # isolate: record and carry on with the next one
                log.error("notifier failed for %s: %s", row["uid"], type(exc).__name__)
                status, error = "failed", type(exc).__name__
            else:
                status, error = "delivered", None
                delivered += 1
            await conn.execute(
                "INSERT INTO notification_deliveries (notification_id, status, error) "
                "VALUES (%s, %s, %s)",
                (row["id"], status, error),
            )
    return delivered
