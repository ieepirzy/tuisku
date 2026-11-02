"""Readers for findings and incidents (ADR 0007). Lists are newest first, keyset-paginated on id.

An incident's evidence is computed, never copied: the transitive closure of its findings
through their detections, the rows linked to them and their observations, down to L0.
"""

from __future__ import annotations

from typing import Any, LiteralString
from uuid import UUID

from psycopg import AsyncConnection
from psycopg.rows import dict_row

from tuisku import db
from tuisku.store.lifecycle import OCSF_FINDING_STATUS

MAX_LIMIT = 500

_FINDING_COLUMNS: LiteralString = (
    "f.id, f.uid, f.fingerprint, f.rule_id, f.rule_rev, f.overflow, f.title, f.severity_id, "
    "f.status, f.first_seen, f.last_seen, f.count, f.entity_keys, f.group_values, f.rule_ref, "
    "f.explanation, f.notify, f.suppressed_until, f.suppression_reason, i.uid AS incident_uid "
    "FROM findings f LEFT JOIN incidents i ON i.id = f.incident_id"
)
_INCIDENT_COLUMNS: LiteralString = (
    "t.id, t.uid, t.fingerprint, t.title, t.severity_id, t.status, t.disposition, t.rule_id, "
    "t.rule_rev, t.overflow, t.entity_keys, t.finding_count, p.uid AS previous_incident_uid, "
    "t.opened_at, t.updated_at FROM incidents t LEFT JOIN incidents p "
    "ON p.id = t.previous_incident_id"
)


def _finding_out(row: dict[str, Any]) -> dict[str, Any]:
    row["fingerprint"] = row["fingerprint"].hex()
    status_id, status_name = OCSF_FINDING_STATUS[row["status"]]
    row["ocsf_status_id"], row["ocsf_status"] = status_id, status_name
    return row


def _incident_out(row: dict[str, Any]) -> dict[str, Any]:
    row["fingerprint"] = row["fingerprint"].hex()
    return row


async def _page(
    conn: AsyncConnection[Any],
    columns: LiteralString,
    alias: LiteralString,
    filters: list[tuple[LiteralString, Any]],
    before: int | None,
    limit: int,
) -> tuple[list[dict[str, Any]], int | None]:
    if not 1 <= limit <= MAX_LIMIT:
        raise ValueError(f"limit must be between 1 and {MAX_LIMIT}")
    where: list[LiteralString] = ["TRUE"]
    params: list[Any] = []
    for clause, value in filters:
        if value is not None:
            where.append(clause)
            params.append(value)
    if before is not None:
        where.append(alias + ".id < %s")
        params.append(before)
    query: LiteralString = (
        "SELECT "
        + columns
        + " WHERE "
        + " AND ".join(where)
        + " ORDER BY "
        + alias
        + ".id DESC LIMIT %s"
    )
    params.append(limit)
    async with conn.cursor(row_factory=dict_row) as cur:
        await cur.execute(query, params)
        rows = await cur.fetchall()
    return rows, rows[-1]["id"] if len(rows) == limit else None


async def list_findings(
    conn: AsyncConnection[Any],
    *,
    status: str | None = None,
    rule_id: UUID | None = None,
    entity_key: str | None = None,
    before: int | None = None,
    limit: int = 100,
) -> tuple[list[dict[str, Any]], int | None]:
    rows, nxt = await _page(
        conn,
        _FINDING_COLUMNS,
        "f",
        [
            ("f.status = %s", status),
            ("f.rule_id = %s", rule_id),
            ("f.entity_keys @> ARRAY[%s]::text[]", entity_key),
        ],
        before,
        limit,
    )
    return [_finding_out(r) for r in rows], nxt


async def list_incidents(
    conn: AsyncConnection[Any],
    *,
    status: str | None = None,
    entity_key: str | None = None,
    before: int | None = None,
    limit: int = 100,
) -> tuple[list[dict[str, Any]], int | None]:
    rows, nxt = await _page(
        conn,
        _INCIDENT_COLUMNS,
        "t",
        [("t.status = %s", status), ("t.entity_keys @> ARRAY[%s]::text[]", entity_key)],
        before,
        limit,
    )
    return [_incident_out(r) for r in rows], nxt


async def get_incident(conn: AsyncConnection[Any], uid: UUID) -> dict[str, Any] | None:
    incident = await db.fetch_one(conn, "SELECT " + _INCIDENT_COLUMNS + " WHERE t.uid = %s", (uid,))
    if incident is None:
        return None
    incident_id = incident["id"]
    incident["timeline"] = await db.fetch_all(
        conn,
        "SELECT uid, at, actor, kind, payload FROM incident_events WHERE incident_id = %s "
        "ORDER BY id",
        (incident_id,),
    )
    incident["findings"] = [
        _finding_out(r)
        for r in await db.fetch_all(
            conn,
            "SELECT " + _FINDING_COLUMNS + " JOIN incident_findings l ON l.finding_id = f.id "
            "WHERE l.incident_id = %s ORDER BY f.id",
            (incident_id,),
        )
    ]
    incident["evidence"] = await db.fetch_one(
        conn,
        "WITH f AS (SELECT finding_id FROM incident_findings WHERE incident_id = %(id)s), "
        "d AS (SELECT detection_id FROM finding_detections WHERE finding_id IN "
        "  (SELECT finding_id FROM f)), "
        "e AS (SELECT detection_ref_id, observation_id FROM detection_evidence "
        "  WHERE detection_id IN (SELECT detection_id FROM d)), "
        "dets AS (SELECT detection_id AS id FROM d UNION "
        "  SELECT detection_ref_id FROM e WHERE detection_ref_id IS NOT NULL), "
        "obs AS (SELECT observation_id AS id FROM detection_observations WHERE detection_id IN "
        "  (SELECT id FROM dets) UNION SELECT observation_id FROM e "
        "  WHERE observation_id IS NOT NULL), "
        "raw AS (SELECT raw_record_id AS id FROM observations WHERE id IN (SELECT id FROM obs) "
        "  UNION SELECT raw_record_id FROM detections WHERE id IN (SELECT id FROM dets) "
        "  AND raw_record_id IS NOT NULL) "
        "SELECT (SELECT count(*) FROM f) AS findings, (SELECT count(*) FROM dets) AS detections, "
        "(SELECT count(*) FROM obs) AS observations, (SELECT count(*) FROM raw) AS raw_records, "
        "ARRAY(SELECT o.kind || ':' || count(*) FROM observations o WHERE o.id IN "
        "  (SELECT id FROM obs) GROUP BY o.kind ORDER BY o.kind) AS observation_kinds",
        {"id": incident_id},
    )
    return _incident_out(incident)
