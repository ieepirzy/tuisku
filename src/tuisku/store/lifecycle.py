"""Finding and incident lifecycle (ADR 0007): states, transitions, histories.

Findings and incidents are mutable projections. Every change appends a ``finding_events`` or
``incident_events`` row whose ``actor`` the server sets (``system``, ``rule:<id>@<rev>``,
``operator:<token uid>``); it never comes from request content.
"""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any

from psycopg import AsyncConnection
from psycopg.types.json import Jsonb

from tuisku import db
from tuisku.worker import notify

ATTACHABLE = ("open", "acknowledged", "suppressed")
FINDING_STATUSES = ("open", "acknowledged", "resolved", "suppressed", "expired")
INCIDENT_STATES = ("open", "triaged", "investigating", "contained", "resolved", "closed")
DISPOSITIONS = (
    "true_positive",
    "benign_true_positive",
    "false_positive",
    "duplicate",
    "inconclusive",
)
REOPENABLE = ("contained", "resolved")
MAX_SUPPRESSION = timedelta(days=30)
THRESHOLDS = (10, 100, 1000)

# OCSF status_id (ADR 0007 "Status mapping"): New 1, In Progress 2, Suppressed 3, Resolved 4,
# Other 99.
OCSF_FINDING_STATUS = {
    "open": (1, "New"),
    "acknowledged": (2, "In Progress"),
    "suppressed": (3, "Suppressed"),
    "resolved": (4, "Resolved"),
    "expired": (99, "Expired"),
}


class TransitionError(ValueError):
    """The requested status change is not allowed from the current state."""


def incident_transition_allowed(old: str, new: str) -> bool:
    """ADR 0007: forward one step or skip forward; any state to closed; contained or resolved
    back to investigating (a reopen). Closed is final."""
    if old == "closed" or old == new:
        return False
    if new == "closed":
        return True
    if old in REOPENABLE and new == "investigating":
        return True
    return INCIDENT_STATES.index(new) > INCIDENT_STATES.index(old)


def finding_payload(finding: dict[str, Any], **extra: Any) -> dict[str, Any]:
    """Notification payload: ids, title, severity context and entity keys, never L0 bodies."""
    return {
        "finding_uid": str(finding["uid"]),
        "rule": f"{finding['rule_id']}@{finding['rule_rev']}",
        "title": finding["title"],
        "entity_keys": list(finding["entity_keys"])[:32],
        "count": finding["count"],
        **extra,
    }


async def notify_thresholds(
    conn: AsyncConnection[Any],
    finding: dict[str, Any],
    old_count: int,
    now: datetime,
    *,
    prefix: str = "finding_threshold",
) -> None:
    """One notification per threshold in (old_count, count] (ADR 0007: 10, 100, 1000).

    ``prefix`` keeps the keys apart by writer: the worker's ``finding_threshold`` keys are not
    writable by the API role, which uses ``triage_threshold`` when lifting a suppression, so it
    can never pre-claim and swallow a worker page (ADR 0011)."""
    for threshold in THRESHOLDS:
        if old_count < threshold <= finding["count"]:
            await notify.emit(
                conn,
                dedupe_key=f"{prefix}:{finding['uid']}:{threshold}",
                kind="finding_threshold",
                severity_id=finding["severity_id"],
                payload=finding_payload(finding, threshold=threshold),
                now=now,
            )


def operator_actor(token_uid: Any) -> str:
    return f"operator:{token_uid}"


def attachable_at(finding: dict[str, Any], t: datetime) -> bool:
    """ADR 0007 "Attach or open": an attachable status, ``last_seen`` within ``window`` and
    ``first_seen`` within ``max_lifetime`` of the evaluation time."""
    if finding["status"] not in ATTACHABLE:
        return False
    window = timedelta(seconds=finding["window_seconds"])
    lifetime = timedelta(seconds=finding["max_lifetime_seconds"])
    if t > finding["last_seen"] + window or t < finding["first_seen"] - window:
        return False
    return max(finding["last_seen"], t) - min(finding["first_seen"], t) <= lifetime


async def finding_event(
    conn: AsyncConnection[Any],
    finding_id: int,
    actor: str,
    kind: str,
    *,
    old: Any = None,
    new: Any = None,
    reason: str | None = None,
    payload: dict[str, Any] | None = None,
) -> None:
    await conn.execute(
        "INSERT INTO finding_events (finding_id, actor, kind, old_value, new_value, reason, "
        "payload) VALUES (%s, %s, %s, %s, %s, %s, %s)",
        (
            finding_id,
            actor,
            kind,
            None if old is None else Jsonb(old),
            None if new is None else Jsonb(new),
            reason,
            Jsonb(payload or {}),
        ),
    )


async def incident_event(
    conn: AsyncConnection[Any],
    incident_id: int,
    actor: str,
    kind: str,
    payload: dict[str, Any] | None = None,
) -> str:
    row = await db.fetch_one(
        conn,
        "INSERT INTO incident_events (incident_id, actor, kind, payload) "
        "VALUES (%s, %s, %s, %s) RETURNING uid",
        (incident_id, actor, kind, Jsonb(payload or {})),
    )
    assert row is not None
    return str(row["uid"])


async def set_finding_status(
    conn: AsyncConnection[Any],
    finding: dict[str, Any],
    new_status: str,
    *,
    actor: str,
    reason: str | None,
    now: datetime,
    suppressed_until: datetime | None = None,
    event_kind: str = "status_changed",
) -> None:
    """Change a finding's status and record it. The caller holds the row (FOR UPDATE).

    Entering suppression records when it began and the count then; re-suppressing keeps both.
    Leaving it for ``open`` or ``acknowledged`` pages for every threshold crossed meanwhile.
    """
    old = finding["status"]
    suppressing = new_status == "suppressed"
    was_suppressed = old == "suppressed"
    lifted_from = finding.get("count_at_suppression") if was_suppressed else None
    suppressed_at = count_then = None
    if suppressing:
        suppressed_at = finding["suppressed_at"] if was_suppressed else now
        count_then = finding["count_at_suppression"] if was_suppressed else finding["count"]
    new_value: dict[str, Any] = {"status": new_status}
    if suppressing:
        new_value["suppressed_until"] = suppressed_until.isoformat() if suppressed_until else None
    # The event first: for the API role the database accepts the update only with its operator
    # event already written in this transaction (ADR 0011).
    await finding_event(
        conn,
        finding["id"],
        actor,
        "suppressed" if suppressing else event_kind,
        old={"status": old},
        new=new_value,
        reason=reason,
    )
    if lifted_from is not None and new_status in ("open", "acknowledged"):
        # Before the update: the database refuses the API role's lift without these pages.
        prefix = "triage_threshold" if actor.startswith("operator:") else "finding_threshold"
        await notify_thresholds(conn, finding, lifted_from, now, prefix=prefix)
    row = await db.fetch_one(
        conn,
        "UPDATE findings SET status = %s, suppressed_until = %s, suppression_reason = %s, "
        "suppressed_at = %s, count_at_suppression = %s, updated_at = %s WHERE id = %s "
        "RETURNING suppressed_at, count_at_suppression",
        (
            new_status,
            suppressed_until if suppressing else None,
            reason if suppressing else None,
            suppressed_at,
            count_then,
            now,
            finding["id"],
        ),
    )
    assert row is not None
    finding.update(row)  # the database may set when the suppression began (ADR 0011)
    finding["status"] = new_status


async def lock_finding(conn: AsyncConnection[Any], uid: Any) -> dict[str, Any] | None:
    return await db.fetch_one(conn, "SELECT * FROM findings WHERE uid = %s FOR UPDATE", (uid,))


async def operator_finding_status(
    conn: AsyncConnection[Any],
    uid: Any,
    new_status: str,
    *,
    actor: str,
    reason: str | None,
    suppressed_until: datetime | None,
    now: datetime,
) -> dict[str, Any] | None:
    """Triage a finding: acknowledge, resolve, suppress (expiry and reason) or unsuppress.

    Only attachable findings can change; resolved and expired are final (a later match opens a
    new finding). An overflow finding cannot be suppressed, only resolved (ADR 0006).
    """
    finding = await lock_finding(conn, uid)
    if finding is None:
        return None
    if finding["status"] not in ATTACHABLE:
        raise TransitionError(f"finding is {finding['status']}; it can no longer change")
    if new_status not in ("open", "acknowledged", "resolved", "suppressed"):
        raise TransitionError(f"cannot set a finding to {new_status!r}")
    if new_status == finding["status"] and new_status != "suppressed":
        raise TransitionError(f"finding is already {new_status}")
    if reason is not None and not reason.strip():
        raise TransitionError("a reason must not be blank")
    if new_status == "suppressed":
        if finding["overflow"]:
            raise TransitionError("an overflow finding cannot be suppressed, only resolved")
        if suppressed_until is None or not reason:
            raise TransitionError("suppression needs an expiry and a reason")
        if suppressed_until.tzinfo is None:
            raise TransitionError("suppression expiry needs a UTC offset")
        # Never past 30 days from the finding's first suppression, even after a lift and a
        # re-suppression: the database enforces the same (ADR 0011).
        first = await db.fetch_one(
            conn,
            "SELECT min(at) AS at FROM finding_events "
            "WHERE finding_id = %s AND kind = 'suppressed'",
            (finding["id"],),
        )
        candidates = [now]
        if first is not None and first["at"] is not None:
            candidates.append(first["at"])
        if finding["status"] == "suppressed" and finding["suppressed_at"] is not None:
            candidates.append(finding["suppressed_at"])
        began = min(candidates)
        if not now < suppressed_until <= began + MAX_SUPPRESSION:
            raise TransitionError(
                "suppression expiry must be in the future and within 30 days of when the "
                "suppression began"
            )
    await set_finding_status(
        conn,
        finding,
        new_status,
        actor=actor,
        reason=reason,
        now=now,
        suppressed_until=suppressed_until,
    )
    return finding


async def resolve_incident_findings(
    conn: AsyncConnection[Any], incident_id: int, *, actor: str, reason: str, now: datetime
) -> int:
    """ADR 0007: closing or resolving an incident resolves every finding of it that is still
    attachable, so later activity opens a new finding instead of being absorbed silently."""
    rows = await db.fetch_all(
        conn,
        "SELECT f.* FROM findings f JOIN incident_findings l ON l.finding_id = f.id "
        "WHERE l.incident_id = %s AND f.status IN ('open', 'acknowledged', 'suppressed') "
        "ORDER BY f.id FOR UPDATE OF f",
        (incident_id,),
    )
    for finding in rows:
        await set_finding_status(conn, finding, "resolved", actor=actor, reason=reason, now=now)
    return len(rows)


async def operator_incident_status(
    conn: AsyncConnection[Any],
    uid: Any,
    new_status: str,
    *,
    actor: str,
    disposition: str | None,
    reason: str | None,
    now: datetime,
) -> dict[str, Any] | None:
    if reason is not None and not reason.strip():
        raise TransitionError("a reason must not be blank")
    found = await db.fetch_one(conn, "SELECT id FROM incidents WHERE uid = %s", (uid,))
    if found is None:
        return None
    # The worker's lock order: findings first, then the incident, so the two cannot deadlock.
    await conn.execute(
        "SELECT f.id FROM findings f JOIN incident_findings l ON l.finding_id = f.id "
        "WHERE l.incident_id = %s ORDER BY f.id FOR UPDATE OF f",
        (found["id"],),
    )
    incident = await db.fetch_one(
        conn, "SELECT * FROM incidents WHERE id = %s FOR UPDATE", (found["id"],)
    )
    assert incident is not None
    old = incident["status"]
    if new_status not in INCIDENT_STATES:
        raise TransitionError(f"unknown incident state {new_status!r}")
    if not incident_transition_allowed(old, new_status):
        raise TransitionError(f"an incident cannot go from {old} to {new_status}")
    if new_status == "closed":
        if disposition not in DISPOSITIONS:
            raise TransitionError(f"closing needs a disposition: {', '.join(DISPOSITIONS)}")
    elif disposition is not None:
        raise TransitionError("a disposition is given only when closing")
    kind = "reopened" if old in REOPENABLE and new_status == "investigating" else "status_changed"
    payload: dict[str, Any] = {"from": old, "to": new_status}
    if disposition is not None:
        payload["disposition"] = disposition
    if reason:
        payload["reason"] = reason
    # The event first: the database accepts the API role's update only with it (ADR 0011).
    await incident_event(conn, incident["id"], actor, kind, payload)
    await conn.execute(
        "UPDATE incidents SET status = %s, disposition = %s, updated_at = %s WHERE id = %s",
        (new_status, disposition, now, incident["id"]),
    )
    if new_status in ("resolved", "closed"):
        payload["findings_resolved"] = await resolve_incident_findings(
            conn, incident["id"], actor=actor, reason=f"incident {new_status}", now=now
        )
    if kind == "reopened":
        await notify.emit(
            conn,
            # A triage key: the worker's escalation: keys are not writable by the API role.
            dedupe_key=f"operator_escalation:{incident['uid']}:reopened:{now.isoformat()}",
            kind="incident_escalated",
            severity_id=incident["severity_id"],
            payload={
                "incident_uid": str(incident["uid"]),
                "title": incident["title"],
                "reason": "reopened",
                "entity_keys": incident["entity_keys"],
            },
            now=now,
        )
    incident.update(status=new_status, disposition=disposition)
    return incident
