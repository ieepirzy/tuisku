"""Fold firings and linked rows into findings and incidents (ADRs 0006 and 0007).

Every function here runs inside the caller's evaluation savepoint, after the caller took the
group and rule advisory locks, so two workers cannot both open a finding for a fingerprint or
overshoot a cap.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any

from psycopg import AsyncConnection
from psycopg.types.json import Jsonb

from tuisku import db
from tuisku.adapters import Severity
from tuisku.rules.fingerprint import finding_fingerprint, overflow_fingerprint
from tuisku.rules.packs import Rule
from tuisku.store.lifecycle import (
    ATTACHABLE,
    REOPENABLE,
    attachable_at,
    finding_event,
    incident_event,
    set_finding_status,
)
from tuisku.worker import notify

THRESHOLDS = (10, 100, 1000)
MAX_ENTITY_KEYS = 256


@dataclass(frozen=True, slots=True)
class Limits:
    max_open_findings: int = 1000
    max_live_incidents: int = 100


@dataclass(frozen=True, slots=True)
class Firing:
    """A detection just written for a rule firing."""

    rule: Rule
    detection_id: int
    detection_uid: str
    eval_time: datetime
    group_values: tuple[Any, ...]
    fingerprint: bytes
    entity_keys: list[str]
    explanation: dict[str, Any]


def _payload(finding: dict[str, Any], **extra: Any) -> dict[str, Any]:
    return {
        "finding_uid": str(finding["uid"]),
        "rule": f"{finding['rule_id']}@{finding['rule_rev']}",
        "title": finding["title"],
        "entity_keys": list(finding["entity_keys"])[:32],
        "count": finding["count"],
        **extra,
    }


async def _lock_attachable(conn: AsyncConnection[Any], fingerprint: bytes) -> dict | None:
    return await db.fetch_one(
        conn,
        "SELECT * FROM findings WHERE fingerprint = %s "
        "AND status IN ('open', 'acknowledged', 'suppressed') FOR UPDATE",
        (fingerprint,),
    )


async def _notify(
    conn: AsyncConnection[Any],
    key: str,
    kind: str,
    severity_id: int,
    payload: dict[str, Any],
    now: datetime,
) -> None:
    await notify.emit(
        conn, dedupe_key=key, kind=kind, severity_id=severity_id, payload=payload, now=now
    )


# --- incidents ----------------------------------------------------------------------------------


async def _open_incident(
    conn: AsyncConnection[Any],
    rule: Rule,
    fingerprint: bytes,
    *,
    title: str,
    severity_id: int,
    overflow: bool,
    now: datetime,
) -> dict[str, Any]:
    previous = await db.fetch_one(
        conn,
        "SELECT id, uid FROM incidents WHERE fingerprint = %s AND status = 'closed' "
        "ORDER BY id DESC LIMIT 1",
        (fingerprint,),
    )
    incident = await db.fetch_one(
        conn,
        "INSERT INTO incidents (fingerprint, title, severity_id, rule_id, rule_rev, overflow, "
        "previous_incident_id, opened_at, updated_at) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s) "
        "RETURNING *",
        (
            fingerprint,
            title,
            severity_id,
            rule.id,
            rule.rev,
            overflow,
            previous["id"] if previous else None,
            now,
            now,
        ),
    )
    assert incident is not None
    payload: dict[str, Any] = {"rule": rule.ref, "overflow": overflow}
    if previous is not None:
        payload["previous_incident_uid"] = str(previous["uid"])
    await incident_event(conn, incident["id"], rule.actor, "opened", payload)
    await _notify(
        conn,
        f"incident_opened:{incident['uid']}",
        "incident_opened",
        severity_id,
        {
            "incident_uid": str(incident["uid"]),
            "title": title,
            "rule": rule.ref,
            "overflow": overflow,
            **({"previous_incident_uid": str(previous["uid"])} if previous else {}),
        },
        now,
    )
    return incident


async def _link_incident(
    conn: AsyncConnection[Any],
    rule: Rule,
    incident: dict[str, Any],
    finding: dict[str, Any],
    now: datetime,
) -> None:
    await conn.execute(
        "INSERT INTO incident_findings (incident_id, finding_id, linked_at) VALUES (%s, %s, %s) "
        "ON CONFLICT DO NOTHING",
        (incident["id"], finding["id"], now),
    )
    await conn.execute(
        "UPDATE findings SET incident_id = %s, updated_at = %s WHERE id = %s",
        (incident["id"], now, finding["id"]),
    )
    finding["incident_id"] = incident["id"]
    await finding_event(
        conn,
        finding["id"],
        rule.actor,
        "incident_linked",
        new={"incident_uid": str(incident["uid"])},
    )
    updated = await db.fetch_one(
        conn,
        "UPDATE incidents SET finding_count = finding_count + 1, "
        "severity_id = greatest(severity_id, %s), "
        "entity_keys = (SELECT coalesce(array_agg(DISTINCT k ORDER BY k), '{}') FROM "
        "  (SELECT unnest(entity_keys || %s::text[]) AS k) u), updated_at = %s "
        "WHERE id = %s RETURNING severity_id",
        (finding["severity_id"], finding["entity_keys"], now, incident["id"]),
    )
    assert updated is not None
    await incident_event(
        conn,
        incident["id"],
        rule.actor,
        "finding_attached",
        {
            "finding_uid": str(finding["uid"]),
            "severity_from": incident["severity_id"],
            "severity_to": updated["severity_id"],
        },
    )
    await _maybe_severity_escalation(conn, incident, updated["severity_id"], now)


async def _maybe_severity_escalation(
    conn: AsyncConnection[Any], incident: dict[str, Any], new_severity: int, now: datetime
) -> None:
    if new_severity > incident["severity_id"]:
        await _notify(
            conn,
            f"escalation:{incident['uid']}:severity:{new_severity}",
            "incident_escalated",
            new_severity,
            {
                "incident_uid": str(incident["uid"]),
                "title": incident["title"],
                "reason": "severity_increased",
                "severity_from": incident["severity_id"],
                "severity_to": new_severity,
            },
            now,
        )
        incident["severity_id"] = new_severity


async def _live_incident(conn: AsyncConnection[Any], fingerprint: bytes) -> dict | None:
    return await db.fetch_one(
        conn,
        "SELECT * FROM incidents WHERE fingerprint = %s AND status <> 'closed' FOR UPDATE",
        (fingerprint,),
    )


async def incident_for_new_finding(
    conn: AsyncConnection[Any], rule: Rule, finding: dict[str, Any], limits: Limits, now: datetime
) -> None:
    """ADR 0007 "Opening" and "Uniqueness": attach to the live incident for the fingerprint, or
    open one (linked to the last closed one). At the live-incident cap, attach to the rule's
    overflow incident instead, so nothing is left without an incident."""
    fingerprint: bytes = finding["fingerprint"]
    overflow = bool(finding["overflow"])
    live = await _live_incident(conn, fingerprint)
    if live is None and not overflow:
        n = await db.fetch_one(
            conn,
            "SELECT count(*) AS n FROM incidents WHERE rule_id = %s AND NOT overflow "
            "AND status <> 'closed'",
            (rule.id,),
        )
        assert n is not None
        if n["n"] >= limits.max_live_incidents:
            overflow = True
            fingerprint = overflow_fingerprint(rule.id, rule.rev)
            live = await _live_incident(conn, fingerprint)
    if live is None:
        live = await _open_incident(
            conn,
            rule,
            fingerprint,
            title=f"Overflow: {rule.title}" if overflow else finding["title"],
            severity_id=(
                max(int(Severity.HIGH), finding["severity_id"])
                if overflow
                else finding["severity_id"]
            ),
            overflow=overflow,
            now=now,
        )
    else:
        await _new_evidence_on_incident(conn, rule, live, now)
    await _link_incident(conn, rule, live, finding, now)


async def _new_evidence_on_incident(
    conn: AsyncConnection[Any], rule: Rule, incident: dict[str, Any], now: datetime
) -> None:
    """ADR 0007: new evidence on a contained or resolved incident returns it to investigating,
    with a ``reopened`` event and an escalation notification."""
    if incident["status"] not in REOPENABLE:
        return
    old = incident["status"]
    await conn.execute(
        "UPDATE incidents SET status = 'investigating', updated_at = %s WHERE id = %s",
        (now, incident["id"]),
    )
    event_uid = await incident_event(
        conn,
        incident["id"],
        rule.actor,
        "reopened",
        {"from": old, "to": "investigating", "reason": "new evidence"},
    )
    incident["status"] = "investigating"
    await _notify(
        conn,
        f"escalation:{event_uid}",
        "incident_escalated",
        incident["severity_id"],
        {
            "incident_uid": str(incident["uid"]),
            "title": incident["title"],
            "reason": "reopened",
            "entity_keys": list(incident["entity_keys"])[:32],
        },
        now,
    )


async def evidence_reached_finding(
    conn: AsyncConnection[Any], rule: Rule, finding: dict[str, Any], limits: Limits, now: datetime
) -> None:
    """A detection or linked row reached an existing finding: update its incident."""
    if finding["incident_id"] is None:
        if rule.incident:
            await incident_for_new_finding(conn, rule, finding, limits, now)
        return
    incident = await db.fetch_one(
        conn, "SELECT * FROM incidents WHERE id = %s FOR UPDATE", (finding["incident_id"],)
    )
    assert incident is not None
    if incident["status"] == "closed":
        # Closing resolves attachable findings, so this is rare: open a new incident linked
        # to the closed one rather than touching it.
        await incident_for_new_finding(conn, rule, finding, limits, now)
        return
    await _new_evidence_on_incident(conn, rule, incident, now)
    if finding["severity_id"] > incident["severity_id"]:
        await conn.execute(
            "UPDATE incidents SET severity_id = %s, updated_at = %s WHERE id = %s",
            (finding["severity_id"], now, incident["id"]),
        )
        await _maybe_severity_escalation(conn, incident, finding["severity_id"], now)


# --- findings -----------------------------------------------------------------------------------


async def _open_finding(
    conn: AsyncConnection[Any],
    firing: Firing,
    *,
    fingerprint: bytes,
    overflow: bool,
    limits: Limits,
    now: datetime,
) -> dict[str, Any]:
    rule = firing.rule
    severity = max(int(Severity.HIGH), rule.severity_id) if overflow else rule.severity_id
    finding = await db.fetch_one(
        conn,
        "INSERT INTO findings (fingerprint, rule_id, rule_rev, overflow, title, severity_id, "
        "first_seen, last_seen, entity_keys, group_values, rule_ref, explanation, "
        "window_seconds, max_lifetime_seconds, notify, created_at, updated_at) "
        "VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s) RETURNING *",
        (
            fingerprint,
            rule.id,
            rule.rev,
            overflow,
            f"Overflow: {rule.title}" if overflow else rule.title,
            severity,
            firing.eval_time,
            firing.eval_time,
            firing.entity_keys[:MAX_ENTITY_KEYS],
            Jsonb([] if overflow else list(firing.group_values)),
            Jsonb(rule.rule_ref()),
            Jsonb(firing.explanation),
            int(rule.finding.window.total_seconds()),
            int(rule.finding.max_lifetime.total_seconds()),
            "thresholds" if overflow else rule.finding.notify,
            now,
            now,
        ),
    )
    assert finding is not None
    await conn.execute(
        "INSERT INTO finding_detections (finding_id, detection_id, linked_at) VALUES (%s, %s, %s)",
        (finding["id"], firing.detection_id, now),
    )
    await finding_event(
        conn,
        finding["id"],
        rule.actor,
        "opened",
        new={"status": "open", "severity_id": severity},
        payload={"detection_uid": firing.detection_uid},
    )
    if not overflow:  # an overflow finding notifies per folded group instead
        await _notify(
            conn,
            f"finding_opened:{finding['uid']}",
            "finding_opened",
            severity,
            _payload(finding, detection_uid=firing.detection_uid),
            now,
        )
    if rule.incident:
        await incident_for_new_finding(conn, rule, finding, limits, now)
    return finding


async def _bump(
    conn: AsyncConnection[Any],
    finding: dict[str, Any],
    *,
    t: datetime,
    severity_id: int,
    entity_keys: list[str],
    latest: dict[str, Any] | None,
    now: datetime,
) -> tuple[int, int]:
    """Increment count, move last_seen (and first_seen for a late row). Returns the old and new
    counts; updates ``finding`` in place."""
    row = await db.fetch_one(
        conn,
        "UPDATE findings SET count = count + 1, last_seen = greatest(last_seen, %s), "
        "first_seen = least(first_seen, %s), severity_id = greatest(severity_id, %s), "
        "entity_keys = (SELECT coalesce(array_agg(k ORDER BY k), '{}') FROM "
        "  (SELECT DISTINCT unnest(entity_keys || %s::text[]) AS k LIMIT %s) u), "
        "explanation = CASE WHEN %s::jsonb IS NULL THEN explanation "
        "  ELSE explanation || jsonb_build_object('latest', %s::jsonb) END, "
        "updated_at = %s WHERE id = %s RETURNING count, last_seen, first_seen, severity_id, "
        "entity_keys",
        (
            t,
            t,
            severity_id,
            entity_keys,
            MAX_ENTITY_KEYS,
            None if latest is None else Jsonb(latest),
            None if latest is None else Jsonb(latest),
            now,
            finding["id"],
        ),
    )
    assert row is not None
    old = finding["count"]
    old_severity = finding["severity_id"]
    finding.update(row)
    return old, old_severity


async def _after_attach(
    conn: AsyncConnection[Any],
    rule: Rule,
    finding: dict[str, Any],
    *,
    old_count: int,
    old_severity: int,
    each_key: str,
    each_extra: dict[str, Any],
    limits: Limits,
    now: datetime,
) -> None:
    quiet = finding["status"] == "suppressed"  # suppressed: collect, never notify
    if finding["severity_id"] > old_severity:
        await finding_event(
            conn,
            finding["id"],
            rule.actor,
            "severity_changed",
            old={"severity_id": old_severity},
            new={"severity_id": finding["severity_id"]},
        )
        if not quiet:
            await _notify(
                conn,
                f"finding_severity:{finding['uid']}:{finding['severity_id']}",
                "finding_severity_increased",
                finding["severity_id"],
                _payload(finding, severity_from=old_severity),
                now,
            )
    if not quiet:
        for threshold in THRESHOLDS:
            if old_count < threshold <= finding["count"]:
                await _notify(
                    conn,
                    f"finding_threshold:{finding['uid']}:{threshold}",
                    "finding_threshold",
                    finding["severity_id"],
                    _payload(finding, threshold=threshold),
                    now,
                )
        if finding["notify"] == "each" and not finding["overflow"]:
            await _notify(
                conn,
                each_key,
                "finding_occurrence",
                finding["severity_id"],
                _payload(finding, **each_extra),
                now,
            )
    await evidence_reached_finding(conn, rule, finding, limits, now)


async def _attach_detection(
    conn: AsyncConnection[Any],
    finding: dict[str, Any],
    firing: Firing,
    limits: Limits,
    now: datetime,
) -> None:
    rule = firing.rule
    await conn.execute(
        "INSERT INTO finding_detections (finding_id, detection_id, linked_at) VALUES (%s, %s, %s)",
        (finding["id"], firing.detection_id, now),
    )
    old_count, old_severity = await _bump(
        conn,
        finding,
        t=firing.eval_time,
        severity_id=rule.severity_id,
        entity_keys=firing.entity_keys,
        latest=firing.explanation.get("correlation"),
        now=now,
    )
    await finding_event(
        conn,
        finding["id"],
        rule.actor,
        "detection_attached",
        new={"count": finding["count"]},
        payload={"detection_uid": firing.detection_uid},
    )
    await _after_attach(
        conn,
        rule,
        finding,
        old_count=old_count,
        old_severity=old_severity,
        each_key=f"finding_detection:{firing.detection_uid}",
        each_extra={"detection_uid": firing.detection_uid},
        limits=limits,
        now=now,
    )


async def fold_firing(
    conn: AsyncConnection[Any], firing: Firing, limits: Limits, now: datetime
) -> dict[str, Any]:
    """Attach the firing's detection to its finding, or open one (ADR 0007), honouring the
    open-findings cap with an overflow finding (ADR 0006). Returns the finding."""
    rule = firing.rule
    existing = await _lock_attachable(conn, firing.fingerprint)
    if existing is not None:
        if attachable_at(existing, firing.eval_time):
            await _attach_detection(conn, existing, firing, limits, now)
            return existing
        await set_finding_status(
            conn,
            existing,
            "expired",
            actor="system",
            reason="window or max_lifetime passed",
            now=now,
        )
    n = await db.fetch_one(
        conn,
        "SELECT count(*) AS n FROM findings WHERE rule_id = %s AND NOT overflow "
        "AND status IN ('open', 'acknowledged', 'suppressed')",
        (rule.id,),
    )
    assert n is not None
    if n["n"] < limits.max_open_findings:
        return await _open_finding(
            conn, firing, fingerprint=firing.fingerprint, overflow=False, limits=limits, now=now
        )
    # At the cap: fold into the rule's overflow finding; detection keeps working.
    ofp = overflow_fingerprint(rule.id, rule.rev)
    overflow = await _lock_attachable(conn, ofp)
    if overflow is not None and attachable_at(overflow, firing.eval_time):
        await _attach_detection(conn, overflow, firing, limits, now)
    else:
        if overflow is not None:
            await set_finding_status(
                conn,
                overflow,
                "expired",
                actor="system",
                reason="window or max_lifetime passed",
                now=now,
            )
        overflow = await _open_finding(
            conn, firing, fingerprint=ofp, overflow=True, limits=limits, now=now
        )
    added = await db.fetch_one(
        conn,
        "INSERT INTO finding_overflow_groups (finding_id, group_key, group_values, detection_id, "
        "linked_at) VALUES (%s, %s, %s, %s, %s) ON CONFLICT DO NOTHING RETURNING finding_id",
        (
            overflow["id"],
            firing.fingerprint,
            Jsonb(list(firing.group_values)),
            firing.detection_id,
            now,
        ),
    )
    if added is not None:  # never suppressible: overflow findings cannot be suppressed
        await _notify(
            conn,
            f"overflow_group:{overflow['uid']}:{firing.fingerprint.hex()}",
            "finding_overflow_group",
            overflow["severity_id"],
            _payload(
                overflow,
                group_values=list(firing.group_values),
                detection_uid=firing.detection_uid,
                cap=limits.max_open_findings,
            ),
            now,
        )
    return overflow


async def link_row(
    conn: AsyncConnection[Any],
    rule: Rule,
    finding: dict[str, Any],
    *,
    firing_detection_id: int,
    link_id: int,
    row_uid: str,
    t: datetime,
    entity_keys: list[str],
    limits: Limits,
    now: datetime,
) -> None:
    """A row matched between firings while the finding is attachable: count it (ADR 0006)."""
    old_count, old_severity = await _bump(
        conn,
        finding,
        t=t,
        severity_id=finding["severity_id"],
        entity_keys=entity_keys,
        latest=None,
        now=now,
    )
    await finding_event(
        conn,
        finding["id"],
        rule.actor,
        "evidence_linked",
        new={"count": finding["count"]},
        payload={"row_uid": row_uid, "firing_detection_id": firing_detection_id},
    )
    await _after_attach(
        conn,
        rule,
        finding,
        old_count=old_count,
        old_severity=old_severity,
        each_key=f"finding_link:{link_id}",
        each_extra={"row_uid": row_uid},
        limits=limits,
        now=now,
    )


async def finding_of_detection(conn: AsyncConnection[Any], detection_id: int) -> dict | None:
    return await db.fetch_one(
        conn,
        "SELECT f.* FROM findings f JOIN finding_detections l ON l.finding_id = f.id "
        "WHERE l.detection_id = %s FOR UPDATE OF f",
        (detection_id,),
    )


def fingerprint_for(rule: Rule, group_values: tuple[Any, ...]) -> bytes:
    return finding_fingerprint(rule.id, rule.rev, group_values)


__all__ = ["ATTACHABLE", "Firing", "Limits", "fold_firing", "link_row"]
