"""Readers for observations, detections and raw records.

Lists are newest first with keyset pagination on id: pass the previous page's ``next_before``
as ``before`` to get the next page. Time filters apply to ``eval_time``.

By default only rows of the **current** derivation are returned: for each raw record, the rows
of its newest successful parse attempt (ADR 0002 rule 3). Rows without a parse attempt (Tuisku
rule output and meta-detections) are always current. ``all_attempts`` returns every row.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any, LiteralString
from uuid import UUID

from psycopg import AsyncConnection
from psycopg.rows import dict_row

from tuisku import db

MAX_LIMIT = 500


@dataclass(frozen=True, slots=True)
class Filters:
    kind: str | None = None
    source: str | None = None
    entity_key: str | None = None
    since: datetime | None = None
    until: datetime | None = None
    before: int | None = None
    limit: int = 100
    all_attempts: bool = False


# The newest successful attempt for the row's raw record (index parse_attempts_current_idx).
_CURRENT: LiteralString = (
    "t.parse_attempt_id = (SELECT c.id FROM parse_attempts c WHERE c.raw_record_id = "
    "t.raw_record_id AND c.status = 'ok' ORDER BY c.id DESC LIMIT 1)"
)


_OBSERVATION_COLUMNS: LiteralString = (
    "t.id, t.uid, r.uid AS raw_record_uid, p.uid AS parse_attempt_uid, s.name AS source, "
    "p.adapter, p.adapter_version, t.kind, t.event_time, t.received_at, t.eval_time, "
    "t.ocsf_class_uid, t.ocsf_version, t.attributes, t.unmapped, t.entity_keys, "
    "t.community_id, t.correlation, t.flags "
    "FROM observations t JOIN sources s ON s.id = t.source_id "
    "JOIN raw_records r ON r.id = t.raw_record_id "
    "JOIN parse_attempts p ON p.id = t.parse_attempt_id"
)

_DETECTION_COLUMNS: LiteralString = (
    "t.id, t.uid, r.uid AS raw_record_uid, p.uid AS parse_attempt_uid, s.name AS source, "
    "p.adapter, p.adapter_version, t.evaluator, t.authorship, t.kind, t.identity, t.title, "
    "t.severity_id, t.event_time, t.received_at, t.eval_time, t.ocsf_version, t.rule_ref, "
    "t.attack, t.attributes, t.entity_keys, t.explanation, t.flags, "
    "ARRAY(SELECT o.uid FROM detection_observations l JOIN observations o "
    "ON o.id = l.observation_id WHERE l.detection_id = t.id ORDER BY o.id) "
    "AS observation_uids, "
    "t.subject, (SELECT m.count FROM meta_counters m WHERE m.source_id IS NOT DISTINCT FROM "
    "t.source_id AND m.kind = t.kind AND m.subject = t.subject "
    "AND m.bucket_start = t.bucket_start) AS meta_count "
    "FROM detections t LEFT JOIN sources s ON s.id = t.source_id "
    "LEFT JOIN raw_records r ON r.id = t.raw_record_id "
    "LEFT JOIN parse_attempts p ON p.id = t.parse_attempt_id"
)


async def _list(
    conn: AsyncConnection[Any], columns: LiteralString, f: Filters
) -> tuple[list[dict[str, Any]], int | None]:
    if not 1 <= f.limit <= MAX_LIMIT:
        raise ValueError(f"limit must be between 1 and {MAX_LIMIT}")
    where: list[LiteralString] = ["TRUE"]
    params: list[Any] = []
    if f.kind is not None:
        where.append("t.kind = %s")
        params.append(f.kind)
    if f.source is not None:
        where.append("s.name = %s")
        params.append(f.source)
    if f.entity_key is not None:
        where.append("t.entity_keys @> ARRAY[%s]::text[]")
        params.append(f.entity_key)
    if f.since is not None:
        where.append("t.eval_time >= %s")
        params.append(f.since)
    if f.until is not None:
        where.append("t.eval_time < %s")
        params.append(f.until)
    if not f.all_attempts:
        where.append("(t.parse_attempt_id IS NULL OR " + _CURRENT + ")")
    if f.before is not None:
        where.append("t.id < %s")
        params.append(f.before)
    query: LiteralString = (
        "SELECT " + columns + " WHERE " + " AND ".join(where) + " ORDER BY t.id DESC LIMIT %s"
    )
    params.append(f.limit)
    async with conn.cursor(row_factory=dict_row) as cur:
        await cur.execute(query, params)
        rows = await cur.fetchall()
    next_before = rows[-1]["id"] if len(rows) == f.limit else None
    return rows, next_before


async def list_observations(
    conn: AsyncConnection[Any], filters: Filters
) -> tuple[list[dict[str, Any]], int | None]:
    return await _list(conn, _OBSERVATION_COLUMNS, filters)


async def list_detections(
    conn: AsyncConnection[Any], filters: Filters
) -> tuple[list[dict[str, Any]], int | None]:
    return await _list(conn, _DETECTION_COLUMNS, filters)


async def get_raw_record(conn: AsyncConnection[Any], uid: UUID) -> dict[str, Any] | None:
    row = await db.fetch_one(
        conn,
        "SELECT r.id, r.uid, s.name AS source, r.source_name AS source_name_at_ingest, "
        "t.uid AS token_uid, r.sha256, r.received_at, "
        "r.transport, r.collector, r.body, r.body_size, r.truncated, "
        "(SELECT count(*) FROM raw_duplicates d WHERE d.raw_record_id = r.id) AS duplicates "
        "FROM raw_records r JOIN sources s ON s.id = r.source_id "
        "JOIN source_tokens t ON t.id = r.token_id WHERE r.uid = %s",
        (uid,),
    )
    if row is None:
        return None
    row["parse_attempts"] = await db.fetch_all(
        conn,
        "SELECT uid, adapter, adapter_version, status, error, created_at "
        "FROM parse_attempts WHERE raw_record_id = %s ORDER BY id",
        (row.pop("id"),),
    )
    return row
