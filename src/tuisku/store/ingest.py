"""Ingest one raw record (ADR 0005 "Parsing runs inside the ingest transaction").

Each record runs inside its own SAVEPOINT, nested in the caller's transaction:

1. insert the raw record (``ON CONFLICT DO NOTHING``); on conflict record the duplicate
   receipt and stop;
2. run the adapter (pure, on already size-capped input) in a worker thread, off the event loop;
3. insert the parse attempt, observations, detections and their links;
4. enqueue every new observation and detection for rule evaluation.

If the database rejects the adapter's output (a CHECK, a bad value), the savepoint is rolled
back and the raw record is stored again on its own, with a failed parse attempt naming the
violated constraint. If even that fails, the record is reported ``rejected``. Either way the
rest of the batch continues.

A record longer than the line limit is stored truncated and never parsed (:func:`store_truncated`).
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from dataclasses import dataclass, replace
from datetime import datetime, timedelta
from enum import StrEnum
from typing import Any

import anyio.to_thread
import psycopg
from anyio import CapacityLimiter
from psycopg import AsyncConnection

from tuisku import adapters, db
from tuisku.adapters import OCSF_VERSION, AdapterError, LimitExceeded, ParseResult, RawRecord
from tuisku.store.admin import SourceCredential

CLOCK_SKEW = "clock_skew"
MAX_ERROR_CHARS = 500


class Transport(StrEnum):
    NDJSON = "ndjson"
    OTLP_JSON = "otlp_json"


@dataclass(frozen=True, slots=True)
class RecordOutcome:
    """``status``: accepted | duplicate | rejected. ``parse``: ok | failed | skipped when
    accepted. ``limit`` names a structural limit the record breached (adapter
    :class:`LimitExceeded`, or ``line_bytes`` for a truncated record), so the caller can raise
    the source's limit meta-detection."""

    status: str
    raw_uid: str | None = None
    parse: str | None = None
    reason: str | None = None
    limit: str | None = None


@dataclass(frozen=True, slots=True)
class IngestContext:
    """Per-request settings shared by every record of a batch."""

    received_at: datetime
    clock_skew_tolerance: timedelta
    parse_limiter: CapacityLimiter | None = None  # bounds the adapter worker threads
    # Each record's parse gets its own deadline (ADR 0005). None: no deadline.
    parse_timeout: float | None = None


def _dumps(value: Any) -> str:
    """Serialize adapter output to JSON text Postgres will take, or raise ValueError."""
    text = json.dumps(value, ensure_ascii=False, allow_nan=False, separators=(",", ":"))
    if "\\u0000" in text:
        raise ValueError("NUL character in JSON (Postgres jsonb cannot store it)")
    return text


def _times(
    event_time: datetime | None, received_at: datetime, tolerance: timedelta, flags: list[str]
) -> datetime:
    """Return eval_time, appending clock_skew to ``flags`` when event_time is in the future."""
    if event_time is None:
        return received_at
    if event_time.tzinfo is None:
        raise ValueError("adapter returned a naive event_time")
    if event_time > received_at + tolerance:
        flags.append(CLOCK_SKEW)
        return received_at
    return event_time


def _flags(adapter_flags: tuple[str, ...]) -> list[str]:
    # clock_skew is the store's verdict, computed from received_at; adapters cannot set it.
    out: list[str] = []
    for flag in adapter_flags:
        if flag != CLOCK_SKEW and flag not in out:
            out.append(str(flag))
    return out


def _qualify(source_id: int, value: str | tuple[str, ...]) -> str | list[str]:
    """Sensor-scoped ids are unique only per sensor: qualify them by source (ADR 0003 s7)."""
    if isinstance(value, tuple):
        return [f"{source_id}:{v}" for v in value]
    return f"{source_id}:{value}"


@dataclass(slots=True)
class _Prepared:
    observations: list[tuple[Any, ...]]
    detections: list[tuple[tuple[Any, ...], tuple[int, ...]]]


def _prepare(
    result: ParseResult, source_id: int, received_at: datetime, tolerance: timedelta
) -> _Prepared:
    """Validate and serialize drafts before touching the database (raises on bad output)."""
    observations: list[tuple[Any, ...]] = []
    for o in result.observations:
        flags = _flags(o.flags)
        eval_time = _times(o.event_time, received_at, tolerance, flags)
        correlation = {str(k): _qualify(source_id, v) for k, v in o.correlation.items()}
        observations.append(
            (
                o.kind,
                o.event_time,
                eval_time,
                o.ocsf_class_uid,
                _dumps(dict(o.attributes)),
                _dumps(dict(o.unmapped)),
                list(o.entity_keys),
                o.community_id,
                _dumps(correlation),
                flags,
            )
        )
    detections: list[tuple[tuple[Any, ...], tuple[int, ...]]] = []
    for d in result.detections:
        flags: list[str] = []
        eval_time = _times(d.event_time, received_at, tolerance, flags)
        detections.append(
            (
                (
                    d.authorship.value,
                    d.kind,
                    d.identity,
                    d.title,
                    int(d.severity),
                    d.event_time,
                    eval_time,
                    _dumps(dict(d.rule_ref)),
                    list(d.attack),
                    _dumps(dict(d.attributes)),
                    list(d.entity_keys),
                    _dumps(dict(d.explanation)),
                    flags,
                ),
                d.observation_refs,
            )
        )
    return _Prepared(observations=observations, detections=detections)


def _truncate(message: str) -> str:
    return message if len(message) <= MAX_ERROR_CHARS else message[: MAX_ERROR_CHARS - 1] + "…"


@dataclass(frozen=True, slots=True)
class _ParseOutput:
    version: str | None
    prepared: _Prepared | None = None
    error: str | None = None
    limit: str | None = None


def _parse(credential: SourceCredential, raw: RawRecord, ctx: IngestContext) -> _ParseOutput:
    """Run the adapter and prepare its rows. Never raises for adapter misbehaviour.

    Runs in a worker thread. It is pure CPU work on immutable inputs.
    """
    source = credential.source
    try:
        adapter = adapters.get(source.adapter)
    except KeyError:
        return _ParseOutput(None, error=f"adapter {source.adapter!r} is not available")
    try:
        result = adapter.parse(raw, source.adapter_options)
        if not isinstance(result, ParseResult):
            raise TypeError("adapter did not return a ParseResult")
        prepared = _prepare(result, source.id, ctx.received_at, ctx.clock_skew_tolerance)
        return _ParseOutput(adapter.version, prepared=prepared)
    except LimitExceeded as exc:
        return _ParseOutput(adapter.version, error=_truncate(str(exc)), limit=exc.limit)
    except AdapterError as exc:
        # AdapterError messages are written never to include the raw body (ADR 0005 rule 4).
        return _ParseOutput(adapter.version, error=_truncate(str(exc) or "parse failed"))
    except Exception as exc:  # any other failure is still a per-record parse failure
        # Other exception messages may echo input, so record the type only.
        return _ParseOutput(adapter.version, error=f"adapter error: {type(exc).__name__}")


PARSE_TIME_BUDGET = "time_budget"


async def _parse_with_deadline(
    credential: SourceCredential, raw: RawRecord, ctx: IngestContext
) -> _ParseOutput:
    """Run the adapter in a worker thread under the record's own deadline.

    A Python thread cannot be killed, so a parse that overruns is abandoned: its thread runs
    on, its result is discarded, and its slot in the parse limiter is released. The record
    stays accepted with a failed parse attempt (``time_budget``) and a ``parse_time`` limit
    breach, so the rest of the batch and the next requests are not held up.
    """
    try:
        with anyio.fail_after(ctx.parse_timeout):
            return await anyio.to_thread.run_sync(
                _parse, credential, raw, ctx, limiter=ctx.parse_limiter, abandon_on_cancel=True
            )
    except TimeoutError:
        adapter = _safe_adapter(credential.source.adapter)
        return _ParseOutput(
            adapter.version if adapter is not None else None,
            error=PARSE_TIME_BUDGET,
            limit="parse_time",
        )


async def _insert_raw(
    conn: AsyncConnection[Any],
    credential: SourceCredential,
    *,
    digest: bytes,
    body: bytes,
    body_size: int,
    truncated: bool,
    collector_json: str,
    transport: Transport,
    received_at: datetime,
) -> dict[str, Any] | None:
    return await db.fetch_one(
        conn,
        "INSERT INTO raw_records (source_id, source_name, token_id, sha256, received_at, "
        "transport, collector, body, body_size, truncated) "
        "VALUES (%s, %s, %s, %s, %s, %s, %s::jsonb, %s, %s, %s) "
        "ON CONFLICT (source_id, sha256) DO NOTHING RETURNING id, uid",
        (
            credential.source.id,
            credential.source.name,
            credential.token_id,
            digest,
            received_at,
            transport.value,
            collector_json,
            body,
            body_size,
            truncated,
        ),
    )


async def _record_duplicate(
    conn: AsyncConnection[Any], credential: SourceCredential, digest: bytes, received_at: datetime
) -> RecordOutcome:
    existing = await db.fetch_one(
        conn,
        "SELECT id, uid FROM raw_records WHERE source_id = %s AND sha256 = %s",
        (credential.source.id, digest),
    )
    assert existing is not None
    await conn.execute(
        "INSERT INTO raw_duplicates (raw_record_id, received_at, token_id) VALUES (%s, %s, %s)",
        (existing["id"], received_at, credential.token_id),
    )
    return RecordOutcome(status="duplicate", raw_uid=str(existing["uid"]))


async def _insert_attempt(
    conn: AsyncConnection[Any],
    raw_id: int,
    adapter: str,
    version: str | None,
    error: str | None,
    created_at: datetime,
) -> int:
    row = await db.fetch_one(
        conn,
        "INSERT INTO parse_attempts "
        "(raw_record_id, adapter, adapter_version, status, error, created_at) "
        "VALUES (%s, %s, %s, %s, %s, %s) RETURNING id",
        (raw_id, adapter, version, "failed" if error else "ok", error, created_at),
    )
    assert row is not None
    return row["id"]


async def _insert_derived(
    conn: AsyncConnection[Any],
    prepared: _Prepared,
    *,
    raw_id: int,
    attempt_id: int,
    source_id: int,
    received_at: datetime,
) -> None:
    obs_ids: list[int] = []
    for values in prepared.observations:
        row = await db.fetch_one(
            conn,
            "INSERT INTO observations (raw_record_id, parse_attempt_id, source_id, received_at, "
            "ocsf_version, kind, event_time, eval_time, ocsf_class_uid, attributes, unmapped, "
            "entity_keys, community_id, correlation, flags) "
            "VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s::jsonb, %s::jsonb, %s, %s, "
            "%s::jsonb, %s) RETURNING id",
            (raw_id, attempt_id, source_id, received_at, OCSF_VERSION, *values),
        )
        assert row is not None
        obs_ids.append(row["id"])
    det_ids: list[int] = []
    for values, refs in prepared.detections:
        row = await db.fetch_one(
            conn,
            "INSERT INTO detections (raw_record_id, parse_attempt_id, source_id, received_at, "
            "ocsf_version, evaluator, authorship, kind, identity, title, severity_id, "
            "event_time, eval_time, rule_ref, attack, attributes, entity_keys, explanation, "
            "flags) VALUES (%s, %s, %s, %s, %s, 'sensor', %s, %s, %s, %s, %s, %s, %s, "
            "%s::jsonb, %s, %s::jsonb, %s, %s::jsonb, %s) RETURNING id",
            (raw_id, attempt_id, source_id, received_at, OCSF_VERSION, *values),
        )
        assert row is not None
        det_ids.append(row["id"])
        linked = sorted({obs_ids[i] for i in refs})
        if linked:
            await conn.execute(
                "INSERT INTO detection_observations (detection_id, observation_id) "
                "SELECT %s, unnest(%s::bigint[])",
                (row["id"], linked),
            )
    await enqueue(conn, observation_ids=obs_ids, detection_ids=det_ids, enqueued_at=received_at)


async def enqueue(
    conn: AsyncConnection[Any],
    *,
    observation_ids: list[int],
    detection_ids: list[int],
    enqueued_at: datetime,
) -> None:
    """One evaluation_queue row per new observation and detection (ADR 0006)."""
    if observation_ids:
        await conn.execute(
            "INSERT INTO evaluation_queue (observation_id, enqueued_at) "
            "SELECT unnest(%s::bigint[]), %s",
            (observation_ids, enqueued_at),
        )
    if detection_ids:
        await conn.execute(
            "INSERT INTO evaluation_queue (detection_id, enqueued_at) "
            "SELECT unnest(%s::bigint[]), %s",
            (detection_ids, enqueued_at),
        )


def _in_error(conn: AsyncConnection[Any]) -> bool:
    return conn.info.transaction_status == psycopg.pq.TransactionStatus.INERROR


async def ingest_record(
    conn: AsyncConnection[Any],
    credential: SourceCredential,
    *,
    body: bytes,
    collector: Mapping[str, Any],
    transport: Transport,
    ctx: IngestContext,
) -> RecordOutcome:
    """Store and parse one record inside a savepoint of the caller's (open) transaction.

    ``collector`` must already be validated and size-capped; ``body`` is the record bytes
    whose SHA-256 is the idempotency key (ADR 0004 section 5).
    """
    digest = hashlib.sha256(body).digest()
    raw_args: dict[str, Any] = {
        "digest": digest,
        "body": body,
        "body_size": len(body),
        "truncated": False,
        "collector_json": _dumps(dict(collector)),
        "transport": transport,
        "received_at": ctx.received_at,
    }
    adapter_name = credential.source.adapter
    try:
        async with conn.transaction():
            raw = await _insert_raw(conn, credential, **raw_args)
            if raw is None:
                return await _record_duplicate(conn, credential, digest, ctx.received_at)
            record = RawRecord(
                source=credential.source.name,
                body=body,
                received_at=ctx.received_at,
                collector=dict(collector),
            )
            out = await _parse_with_deadline(credential, record, ctx)
            attempt_id = await _insert_attempt(
                conn, raw["id"], adapter_name, out.version, out.error, ctx.received_at
            )
            if out.prepared is not None:
                await _insert_derived(
                    conn,
                    out.prepared,
                    raw_id=raw["id"],
                    attempt_id=attempt_id,
                    source_id=credential.source.id,
                    received_at=ctx.received_at,
                )
            return RecordOutcome(
                status="accepted",
                raw_uid=str(raw["uid"]),
                parse="failed" if out.error else "ok",
                limit=out.limit,
            )
    except psycopg.Error as exc:
        if _in_error(conn):
            raise  # the outer transaction is gone; nothing more can be stored
        failure = exc
    # The database refused the adapter's output. Keep the evidence: store the raw record
    # alone with a failed parse attempt naming the constraint (never the values).
    diag = failure.diag
    detail = diag.constraint_name or diag.sqlstate or type(failure).__name__
    error = _truncate(f"store rejected adapter output: {detail}")
    try:
        async with conn.transaction():
            raw = await _insert_raw(conn, credential, **raw_args)
            if raw is None:
                # Another request stored the same record meanwhile: it is a duplicate.
                return await _record_duplicate(conn, credential, digest, ctx.received_at)
            adapter = _safe_adapter(adapter_name)
            version = adapter.version if adapter is not None else None
            await _insert_attempt(conn, raw["id"], adapter_name, version, error, ctx.received_at)
            return RecordOutcome(status="accepted", raw_uid=str(raw["uid"]), parse="failed")
    except psycopg.Error:
        if _in_error(conn):
            raise
        return RecordOutcome(status="rejected", reason="store_error")


async def store_truncated(
    conn: AsyncConnection[Any],
    credential: SourceCredential,
    *,
    body: bytes,
    limit: int,
    collector: Mapping[str, Any],
    ctx: IngestContext,
) -> RecordOutcome:
    """Store an over-long record cut to ``limit`` bytes, flagged ``truncated`` and unparsed.

    Its sha256 covers the full record, so a re-delivery is still a duplicate (ADR 0005).
    """
    digest = hashlib.sha256(body).digest()
    try:
        async with conn.transaction():
            raw = await _insert_raw(
                conn,
                credential,
                digest=digest,
                body=body[:limit],
                body_size=len(body),
                truncated=True,
                collector_json=_dumps(dict(collector)),
                transport=Transport.NDJSON,
                received_at=ctx.received_at,
            )
            if raw is None:
                duplicate = await _record_duplicate(conn, credential, digest, ctx.received_at)
                return replace(duplicate, limit="line_bytes")  # the breach still happened
            return RecordOutcome(
                status="accepted", raw_uid=str(raw["uid"]), parse="skipped", limit="line_bytes"
            )
    except psycopg.Error:
        if _in_error(conn):
            raise
        return RecordOutcome(status="rejected", reason="store_error")


def _safe_adapter(name: str) -> adapters.Adapter | None:
    try:
        return adapters.get(name)
    except KeyError:
        return None
