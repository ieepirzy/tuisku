"""Ingest endpoints (ADR 0005): NDJSON envelopes, OTLP/HTTP JSON logs and metrics.

Order of checks: token (401) -> content type and encoding (415) -> body size, compressed and
decompressed (413, before the whole body is read) -> line count (413) -> per-source rate (429)
-> per line. Per line, only a malformed envelope is ``rejected``; an over-long record is stored
truncated and unparsed, and an oversized ``collector`` is replaced by a marker. Every limit
breach also raises a meta-detection (:mod:`tuisku.store.meta`).

OTLP logs follow the same path with one ``logRecord`` per line (:mod:`tuisku.api.otlp_logs`):
a request that is not OTLP/JSON is refused with 400 before the record count is checked, and a
record whose body is not a string is ``rejected``.

The 2xx answer is sent only after the transaction commits. A request that runs past its
wall-clock budget stops before the next line, commits what it processed, and answers 503 with
Retry-After, listing the lines it did not process.
"""

from __future__ import annotations

import json
import logging
import time
import zlib
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import timedelta
from typing import Annotated, Any

import anyio.to_thread
from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import JSONResponse

from tuisku.adapters import AdapterError
from tuisku.adapters.jsonsafe import loads_object_flagged
from tuisku.api import otlp_logs
from tuisku.api.deps import Clock, authenticate_source, get_clock, get_pool
from tuisku.api.ratelimit import RateLimiter, RefusalCounter
from tuisku.config import Settings
from tuisku.store import meta
from tuisku.store.admin import Source, SourceCredential
from tuisku.store.ingest import (
    IngestContext,
    RecordOutcome,
    Transport,
    ingest_record,
    store_truncated,
)

log = logging.getLogger(__name__)
router = APIRouter()

NDJSON = "application/x-ndjson"
JSON = "application/json"
INVALID_ENVELOPE = "invalid_envelope"
NOT_PROCESSED = "not_processed"
BUDGET_RETRY_AFTER_SECONDS = 1


def _settings(request: Request) -> Settings:
    return request.app.state.settings


async def flush_refusals(app: Any) -> None:
    """Record every refusal still counted in process (at shutdown)."""
    limiter: RateLimiter = app.state.rate_limiter
    for source, count in app.state.refusals.drain():
        try:
            async with app.state.pool.connection() as conn, conn.transaction():
                await meta.record_breach(
                    conn,
                    source,
                    meta.RATE_LIMITED,
                    "records_per_second",
                    n=count,
                    details={
                        "limit": "records_per_second",
                        "rate": limiter.rate,
                        "burst": limiter.burst,
                    },
                    now=app.state.clock(),
                )
        except Exception as exc:
            log.warning("could not flush rate-limit refusals: %s", type(exc).__name__)


async def _record_breach(
    request: Request,
    source: Source,
    kind: str,
    limit: str,
    clock: Clock,
    *,
    n: int = 1,
    details: dict[str, Any] | None = None,
) -> None:
    """Count the breach and raise the bucket's meta-detection, in its own transaction."""
    try:
        async with get_pool(request).connection() as conn, conn.transaction():
            await meta.record_breach(
                conn,
                source,
                kind,
                limit,
                n=n,
                details={"limit": limit, **(details or {})},
                now=clock(),
            )
    except Exception as exc:  # a failed meta write must not change the ingest answer
        log.warning("could not record meta-detection %s: %s", kind, type(exc).__name__)


def _content_encoding(request: Request, expected_type: str) -> str:
    media = request.headers.get("content-type", "").split(";", 1)[0].strip().lower()
    if media != expected_type:
        raise HTTPException(status_code=415, detail=f"Content-Type must be {expected_type}")
    encoding = request.headers.get("content-encoding", "identity").strip().lower() or "identity"
    if encoding not in ("identity", "gzip"):
        raise HTTPException(status_code=415, detail="Content-Encoding must be identity or gzip")
    return encoding


class _TooLarge(Exception):
    pass


class _Inflater:
    """Streaming gzip decompression that never produces more than ``cap`` bytes (zip-bomb
    guard): each step asks zlib for at most the remaining allowance plus one byte."""

    def __init__(self, cap: int) -> None:
        self._d = zlib.decompressobj(16 + zlib.MAX_WBITS)  # gzip framing only
        self._cap = cap
        self.out = bytearray()

    def feed(self, data: bytes) -> None:
        while data:
            if self._d.eof:
                raise HTTPException(status_code=400, detail="data after the end of the gzip stream")
            try:
                chunk = self._d.decompress(data, self._cap - len(self.out) + 1)
            except zlib.error:
                raise HTTPException(status_code=400, detail="invalid gzip body") from None
            self.out += chunk
            if len(self.out) > self._cap:
                raise _TooLarge
            data = self._d.unconsumed_tail
        if self._d.eof and self._d.unused_data:
            raise HTTPException(status_code=400, detail="data after the end of the gzip stream")

    def finish(self) -> bytes:
        if not self._d.eof:
            raise HTTPException(status_code=400, detail="truncated gzip body")
        return bytes(self.out)


async def _read_body(
    request: Request, credential: SourceCredential, clock: Clock, encoding: str, max_bytes: int
) -> bytes:
    """Read (and gunzip) the body, refusing with 413 as soon as either the bytes on the wire or
    the decompressed bytes are known to exceed ``max_bytes``."""

    async def too_large() -> HTTPException:
        await _record_breach(
            request,
            credential.source,
            meta.LIMIT_EXCEEDED,
            "body_bytes",
            clock,
            details={"max": max_bytes, "content_encoding": encoding},
        )
        return HTTPException(status_code=413, detail=f"body larger than {max_bytes} bytes")

    declared = request.headers.get("content-length")
    if declared is not None:
        try:
            size = int(declared)
        except ValueError:
            raise HTTPException(status_code=400, detail="invalid Content-Length") from None
        if size > max_bytes:
            raise await too_large()
    wire = 0
    raw = bytearray()
    inflater = _Inflater(max_bytes) if encoding == "gzip" else None
    try:
        async for chunk in request.stream():
            wire += len(chunk)
            if wire > max_bytes:
                raise _TooLarge
            if inflater is None:
                raw += chunk
            else:
                inflater.feed(chunk)
    except _TooLarge:
        raise await too_large() from None
    return bytes(raw) if inflater is None else inflater.finish()


async def _admit(request: Request, credential: SourceCredential, clock: Clock, n: int) -> None:
    limiter: RateLimiter = request.app.state.rate_limiter
    retry_after = limiter.take(credential.source.id, n)
    if retry_after is not None:
        refusals: RefusalCounter = request.app.state.refusals
        due = refusals.add(credential.source.id, credential.source)
        if due is not None:  # batched: not one database write per refused request
            source, count = due
            await _record_breach(
                request,
                source,
                meta.RATE_LIMITED,
                "records_per_second",
                clock,
                n=count,
                details={"rate": limiter.rate, "burst": limiter.burst},
            )
        raise HTTPException(
            status_code=429,
            detail="source rate limit exceeded",
            headers={"Retry-After": str(retry_after)},
        )


def _reject_constant(name: str) -> Any:
    raise ValueError("non-standard JSON constant")


def _unique_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    # {"raw": "a", "raw": "b"} is ambiguous: which line did the shipper mean? Reject it.
    obj = dict(pairs)
    if len(obj) != len(pairs):
        raise ValueError("duplicate key")
    return obj


def bound_collector(
    collector: dict[str, Any], settings: Settings
) -> tuple[dict[str, Any], bool] | None:
    """Return ``(collector, dropped)``: the collector re-parsed under the JSON limits, or a
    marker when it is over its size limit. None when it cannot be stored at all."""
    try:
        # Bounded re-parse: depth and key limits; NUL and lone surrogates become U+FFFD.
        collector, _ = loads_object_flagged(json.dumps(collector))
    except (ValueError, RecursionError):  # AdapterError is a ValueError
        return None
    size = len(json.dumps(collector, ensure_ascii=False, separators=(",", ":")).encode("utf-8"))
    if size > settings.ingest_max_collector_bytes:
        return {"tuisku_collector_dropped_bytes": size}, True
    return collector, False


def parse_envelope(line: bytes, settings: Settings) -> tuple[bytes, dict[str, Any], bool] | None:
    """Return ``(raw bytes, collector, collector_dropped)``, or None for a malformed envelope.

    ``raw`` is kept exactly as sent; it is not size-checked here (over-long records are stored
    truncated). A ``collector`` over its limit is replaced by a marker, never fatal.
    """
    try:
        envelope = json.loads(
            line.decode("utf-8"), parse_constant=_reject_constant, object_pairs_hook=_unique_pairs
        )
    except (UnicodeDecodeError, ValueError, RecursionError):
        return None
    if not isinstance(envelope, dict) or not set(envelope) <= {"raw", "collector"}:
        return None
    raw = envelope.get("raw")
    collector = envelope.get("collector")
    if collector is None:
        collector = {}
    if not isinstance(raw, str) or not raw or not isinstance(collector, dict):
        return None
    try:
        body = raw.encode("utf-8")  # fails on lone surrogates such as "\ud800"
    except UnicodeEncodeError:
        return None
    bounded = bound_collector(collector, settings)
    if bounded is None:
        return None
    return body, *bounded


def _result(number: int, outcome: RecordOutcome, key: str = "line") -> dict[str, Any]:
    result: dict[str, Any] = {key: number, "status": outcome.status}
    if outcome.parse is not None:
        result["parse"] = outcome.parse
    if outcome.reason is not None:
        result["reason"] = outcome.reason
    return result


def _context(request: Request, clock: Clock) -> IngestContext:
    settings = _settings(request)
    return IngestContext(
        received_at=clock(),
        clock_skew_tolerance=timedelta(seconds=settings.clock_skew_tolerance_seconds),
        parse_limiter=request.app.state.parse_limiter,
        parse_timeout=settings.ingest_parse_timeout_seconds,
    )


# What one item of a batch decodes to: (raw bytes, collector, collector dropped), or the reason
# it is rejected.
_Decoded = tuple[bytes, dict[str, Any], bool] | str


@dataclass(slots=True)
class _Batch:
    results: list[dict[str, Any]] = field(default_factory=list)
    breaches: dict[tuple[str, str], int] = field(default_factory=dict)
    unprocessed: list[int] = field(default_factory=list)

    def breach(self, kind: str, limit: str) -> None:
        self.breaches[(kind, limit)] = self.breaches.get((kind, limit), 0) + 1


async def _store_batch(
    request: Request,
    credential: SourceCredential,
    clock: Clock,
    items: list[tuple[int, Callable[[], _Decoded]]],
    *,
    started: float,
    transport: Transport,
    key: str,
    reject_subject: str,
) -> _Batch:
    """Decode, store and parse each item in one transaction, then record the breaches.

    Items are decoded lazily, so a request that runs past its time budget stops before the next
    item and lists the rest as unprocessed. The 2xx is the caller's to send, after this returns.
    """
    settings = _settings(request)
    ctx = _context(request, clock)
    budget = settings.ingest_request_budget_seconds
    max_line = settings.ingest_max_line_bytes
    batch = _Batch()
    async with get_pool(request).connection() as conn, conn.transaction():
        for index, (number, decode) in enumerate(items):
            if time.monotonic() - started > budget:
                batch.unprocessed = [n for n, _ in items[index:]]
                break
            decoded = decode()
            if isinstance(decoded, str):
                batch.breach(meta.INVALID_ENVELOPE, reject_subject)
                batch.results.append(
                    _result(number, RecordOutcome(status="rejected", reason=decoded), key)
                )
                continue
            raw, collector, collector_dropped = decoded
            if collector_dropped:
                batch.breach(meta.LIMIT_EXCEEDED, "collector_bytes")
            if len(raw) > max_line:
                outcome = await store_truncated(
                    conn,
                    credential,
                    body=raw,
                    limit=max_line,
                    collector=collector,
                    ctx=ctx,
                    transport=transport,
                )
            else:
                outcome = await ingest_record(
                    conn, credential, body=raw, collector=collector, transport=transport, ctx=ctx
                )
            if outcome.limit is not None:
                batch.breach(meta.LIMIT_EXCEEDED, outcome.limit)
            batch.results.append(_result(number, outcome, key))
    # Committed. Breaches are recorded after the evidence, in their own transactions.
    for (kind, limit), count in batch.breaches.items():
        await _record_breach(request, credential.source, kind, limit, clock, n=count)
    return batch


def _budget_exceeded(batch: _Batch, key: str, what: str) -> JSONResponse:
    batch.results.extend(
        {key: n, "status": NOT_PROCESSED, "reason": "time_budget_exceeded"}
        for n in batch.unprocessed
    )
    return JSONResponse(
        status_code=503,
        headers={"Retry-After": str(BUDGET_RETRY_AFTER_SECONDS)},
        content={
            "detail": f"request time budget exceeded; {what} marked not_processed were not "
            f"stored, retry them (processed {what} are committed)",
            "results": batch.results,
        },
    )


async def _check_count(
    request: Request, credential: SourceCredential, clock: Clock, n: int, what: str
) -> None:
    settings = _settings(request)
    if n > settings.ingest_max_lines:
        await _record_breach(
            request,
            credential.source,
            meta.LIMIT_EXCEEDED,
            "lines",
            clock,
            details={"max": settings.ingest_max_lines},
        )
        raise HTTPException(status_code=413, detail=f"more than {settings.ingest_max_lines} {what}")


def _ndjson_decoder(line: bytes, settings: Settings) -> Callable[[], _Decoded]:
    return lambda: parse_envelope(line, settings) or INVALID_ENVELOPE


@router.post("/v1/sources/{source}/records")
async def ingest_records(
    source: str, request: Request, clock: Annotated[Clock, Depends(get_clock)]
) -> JSONResponse:
    settings = _settings(request)
    started = time.monotonic()
    credential = await authenticate_source(request, source)
    encoding = _content_encoding(request, NDJSON)
    body = await _read_body(request, credential, clock, encoding, settings.ingest_max_body_bytes)

    lines = [
        (number, line.removesuffix(b"\r"))
        for number, line in enumerate(body.split(b"\n"), start=1)
        if line.strip()
    ]
    await _check_count(request, credential, clock, len(lines), "lines")
    await _admit(request, credential, clock, len(lines))
    batch = await _store_batch(
        request,
        credential,
        clock,
        [(number, _ndjson_decoder(line, settings)) for number, line in lines],
        started=started,
        transport=Transport.NDJSON,
        key="line",
        reject_subject="envelope",
    )
    if batch.unprocessed:
        return _budget_exceeded(batch, "line", "lines")
    return JSONResponse(content={"results": batch.results})


def _log_record_decoder(
    pending: otlp_logs.PendingLogRecord, settings: Settings
) -> Callable[[], _Decoded]:
    def decode() -> _Decoded:
        envelope = pending.decode()
        if isinstance(envelope, str):
            return envelope
        bounded = bound_collector(envelope.collector, settings)
        if bounded is None:
            return otlp_logs.INVALID_LOG_RECORD
        return envelope.raw, *bounded

    return decode


@router.post("/v1/sources/{source}/otlp/v1/logs")
async def ingest_otlp_logs(
    source: str, request: Request, clock: Annotated[Clock, Depends(get_clock)]
) -> JSONResponse:
    """OTLP/HTTP JSON logs: each ``logRecord`` is one raw record, its ``body.stringValue``
    parsed by the source adapter exactly as an NDJSON line would be.

    The answer is an ``ExportLogsServiceResponse`` (``partialSuccess`` when records were
    rejected) plus a ``results`` entry per record, numbered from 1 in request order.
    """
    settings = _settings(request)
    started = time.monotonic()
    credential = await authenticate_source(request, source)
    encoding = _content_encoding(request, JSON)
    body = await _read_body(request, credential, clock, encoding, settings.ingest_max_body_bytes)
    try:
        # A 5 MiB body takes tens of milliseconds to decode: keep it off the event loop.
        pending = await anyio.to_thread.run_sync(otlp_logs.decode_request, body)
    except otlp_logs.InvalidRequest as exc:
        await _record_breach(
            request, credential.source, meta.INVALID_ENVELOPE, "otlp_logs_request", clock
        )
        raise HTTPException(status_code=400, detail=str(exc)) from None
    await _check_count(request, credential, clock, len(pending), "log records")
    if pending:
        await _admit(request, credential, clock, len(pending))
    batch = await _store_batch(
        request,
        credential,
        clock,
        [(n, _log_record_decoder(p, settings)) for n, p in enumerate(pending, start=1)],
        started=started,
        transport=Transport.OTLP_LOGS_JSON,
        key="record",
        reject_subject="log_record",
    )
    if batch.unprocessed:
        return _budget_exceeded(batch, "record", "log records")
    return JSONResponse(content=otlp_logs.export_response(batch.results))


@router.post("/v1/sources/{source}/otlp/v1/metrics")
async def ingest_otlp_metrics(
    source: str, request: Request, clock: Annotated[Clock, Depends(get_clock)]
) -> JSONResponse:
    """OTLP/HTTP JSON metrics: the whole body is one raw record, parsed by the source adapter.

    The response body is a JSON object; OTLP clients ignore its unknown fields.
    """
    settings = _settings(request)
    credential = await authenticate_source(request, source)
    encoding = _content_encoding(request, JSON)
    body = await _read_body(request, credential, clock, encoding, settings.ingest_max_body_bytes)
    if not body.strip():
        raise HTTPException(status_code=400, detail="empty body")
    await _admit(request, credential, clock, 1)
    async with get_pool(request).connection() as conn, conn.transaction():
        outcome = await ingest_record(
            conn,
            credential,
            body=body,
            collector={},
            transport=Transport.OTLP_JSON,
            ctx=_context(request, clock),
        )
    if outcome.limit is not None:
        await _record_breach(request, credential.source, meta.LIMIT_EXCEEDED, outcome.limit, clock)
    if outcome.status == "rejected":
        return JSONResponse(
            status_code=500, content={"status": "rejected", "reason": outcome.reason}
        )
    content: dict[str, Any] = {"status": outcome.status}
    if outcome.parse is not None:
        content["parse"] = outcome.parse
    return JSONResponse(content=content)


__all__ = ["AdapterError", "router"]
