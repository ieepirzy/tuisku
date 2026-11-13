"""Notification events (ADR 0007 "Notifications").

Notifications are written to the ``notifications`` outbox inside the evaluation transaction,
keyed by a ``dedupe_key`` with ``ON CONFLICT DO NOTHING``: a notification exists only if the
insert actually happened, so a retried or re-claimed evaluation never pages twice. After the
transaction commits, :func:`drain` hands undelivered rows to the notifier and marks them
delivered. :class:`LogNotifier` writes structured log lines and is always on;
``tuisku.worker.alertmanager`` adds an Alertmanager channel when one is configured. Which
receivers page whom is a deployment decision outside this repository.

Notifications carry ids, titles, severities and entity keys, never L0 bodies.
"""

from __future__ import annotations

import asyncio
import json
import logging
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Protocol

from psycopg import AsyncConnection
from psycopg.types.json import Jsonb

from tuisku import db
from tuisku.store import meta

log = logging.getLogger("tuisku.notify")


class Notifier(Protocol):
    def deliver(self, notification: dict[str, Any]) -> None: ...


class NotifierUnavailable(Exception):
    """Raised by a notifier whose channel is down as a whole (a timeout, a refused connection,
    a 5xx), rather than refusing this one notification. :func:`drain` records the failure for
    the notification as usual and ends the pass there, so a dead channel costs one timeout per
    pass, not one per due notification; the rest stay due for the next pass."""


class LogNotifier:
    """Writes one JSON line per notification to the ``tuisku.notify`` logger."""

    def deliver(self, notification: dict[str, Any]) -> None:
        log.warning("notification %s", json.dumps(notification, default=str, sort_keys=True))


@dataclass(frozen=True, slots=True)
class FanOutNotifier:
    """Delivers to each notifier in order. The first error fails the delivery (the earlier
    notifiers have already run, so a retry repeats them: put the log first)."""

    notifiers: Sequence[Notifier]

    def deliver(self, notification: dict[str, Any]) -> None:
        for notifier in self.notifiers:
            notifier.deliver(notification)


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


ALERT_AFTER_FAILURES = 10


@dataclass(frozen=True, slots=True)
class Backoff:
    """Retry spacing for failed deliveries, measured on the database clock from the last
    failed attempt: ``base * 2**(failures - 1)`` seconds, capped at ``cap``."""

    base_seconds: float = 5.0
    cap_seconds: float = 300.0
    alert_after: int = ALERT_AFTER_FAILURES


DEFAULT_BACKOFF = Backoff()


async def drain(
    conn: AsyncConnection[Any],
    notifier: Notifier,
    now: datetime,
    limit: int = 500,
    backoff: Backoff = DEFAULT_BACKOFF,
) -> int:
    """Deliver the notifications that are due, meta pages first, then most severe first and then
    oldest first; returns
    how many were delivered. Every notification is written by the worker or by an owner trigger
    (the API role has no INSERT on notifications, ADR 0011).

    The outbox and the delivery log are append-only: delivery appends a ``delivered`` row, and
    a notifier error appends a ``failed`` row and moves on, so one bad notification never
    blocks the others. A failed notification is due again after an exponential backoff from
    its last failure, capped at ``backoff.cap_seconds``, so a short outage costs a few retries
    however busy the queue is. Nothing is ever given up: at ``backoff.alert_after`` failures a
    ``tuisku.meta.notification_undeliverable`` meta-detection is raised (the ``tuisku-meta``
    pack pages on it, which a deployment routes to another channel) and retries continue at
    the capped interval. Delivery is at-least-once: a crash after delivering and before
    committing re-delivers.

    ``notifier.deliver`` runs in a thread (``asyncio.to_thread``), so a slow channel never
    blocks the event loop (the health listener keeps answering). A
    :class:`NotifierUnavailable` ends the pass after that notification's ``failed`` row; the
    notifications not yet tried get no row and stay due, as if beyond ``limit``.
    """
    delivered = 0
    async with conn.transaction():
        # One drainer at a time, by a row lock on the worker-only worker_locks table: an advisory
        # lock would be takeable by any role (ADR 0011).
        await conn.execute(
            "INSERT INTO worker_locks (name) VALUES ('drain') ON CONFLICT (name) DO NOTHING"
        )
        got = await db.fetch_one(
            conn,
            "SELECT name FROM worker_locks WHERE name = 'drain' FOR UPDATE SKIP LOCKED",
        )
        if got is None:
            return 0  # another worker is draining
        rows = await db.fetch_all(
            conn,
            "WITH pending AS (SELECT n.id, n.uid, n.kind, n.severity_id, n.payload, n.created_at, "
            "  n.meta, "
            "  (SELECT count(*) FROM notification_deliveries d WHERE d.notification_id = n.id "
            "   AND d.status = 'failed') AS failures, "
            "  (SELECT max(d.at) FROM notification_deliveries d WHERE d.notification_id = n.id "
            "   AND d.status = 'failed') AS last_failed "
            "  FROM notifications n WHERE NOT EXISTS (SELECT 1 FROM notification_deliveries d "
            "  WHERE d.notification_id = n.id AND d.status = 'delivered')) "
            "SELECT * FROM pending WHERE failures = 0 OR last_failed + make_interval(secs => "
            "  least(%s::float8, %s::float8 * power(2, least(failures - 1, 30)))) <= now() "
            # Pages about Tuisku itself first (backlog, dead letters, tuisku-meta findings: the
            # database marks them), so a flood of rule pages cannot hide that Tuisku is
            # failing. Then fair: the most severe first, then the oldest, so no backlog of
            # lesser pages (or of retries) can hold back a newer high-severity one.
            "ORDER BY meta DESC, severity_id DESC, created_at, id LIMIT %s",
            (backoff.cap_seconds, backoff.base_seconds, limit),
        )
        for row in rows:
            message = {
                "uid": str(row["uid"]),
                "kind": row["kind"],
                "severity_id": row["severity_id"],
                "created_at": row["created_at"].isoformat(),
                "meta": bool(row["meta"]),
                **row["payload"],
            }
            unavailable = False
            try:
                await asyncio.to_thread(notifier.deliver, message)
            except Exception as exc:  # isolate: record and carry on with the next one
                log.error("notifier failed for %s: %s", row["uid"], type(exc).__name__)
                status, error = "failed", type(exc).__name__
                unavailable = isinstance(exc, NotifierUnavailable)
            else:
                status, error = "delivered", None
                delivered += 1
            await conn.execute(
                "INSERT INTO notification_deliveries (notification_id, status, error) "
                "VALUES (%s, %s, %s)",
                (row["id"], status, error),
            )
            if status == "failed" and row["failures"] + 1 == backoff.alert_after:
                await meta.record_notification_undeliverable(
                    conn,
                    kind=row["kind"],
                    details={
                        "notification_uid": str(row["uid"]),
                        "failures": backoff.alert_after,
                        "error": error,
                    },
                    now=now,
                )
            if unavailable:
                break  # the channel is down: the rest wait for the next pass
    return delivered
