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


async def drain(
    conn: AsyncConnection[Any], notifier: Notifier, now: datetime, limit: int = 500
) -> int:
    """Deliver undelivered notifications in id order; returns how many were delivered.

    Delivery is at-least-once: a crash after delivering and before committing re-delivers.
    """
    async with conn.transaction():
        rows = await db.fetch_all(
            conn,
            "SELECT id, uid, kind, severity_id, payload, created_at FROM notifications "
            "WHERE delivered_at IS NULL ORDER BY id LIMIT %s FOR UPDATE SKIP LOCKED",
            (limit,),
        )
        for row in rows:
            notifier.deliver(
                {
                    "uid": str(row["uid"]),
                    "kind": row["kind"],
                    "severity_id": row["severity_id"],
                    "created_at": row["created_at"].isoformat(),
                    **row["payload"],
                }
            )
        if rows:
            await conn.execute(
                "UPDATE notifications SET delivered_at = %s WHERE id = ANY(%s)",
                (now, [r["id"] for r in rows]),
            )
    return len(rows)
