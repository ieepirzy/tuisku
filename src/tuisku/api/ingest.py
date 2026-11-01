"""Ingest endpoints (ADR 0005): NDJSON envelopes and OTLP/HTTP JSON metrics.

Order of checks: token (401) -> content type (415) -> body size (413, before the whole body is
read) -> line count (413) -> per-source rate (429) -> per line envelope checks (``rejected``).
Every limit breach also becomes a meta-detection (see :mod:`tuisku.store.meta`). The 2xx
answer is sent only after the transaction commits.
"""

from __future__ import annotations

import json
import logging
from datetime import timedelta
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import JSONResponse

from tuisku.adapters import AdapterError
from tuisku.adapters.jsonsafe import loads_object
from tuisku.api.deps import Clock, authenticate_source, get_clock, get_pool
from tuisku.api.ratelimit import RateLimiter
from tuisku.config import Settings
from tuisku.store import meta
from tuisku.store.admin import Source, SourceCredential
from tuisku.store.ingest import RecordOutcome, Transport, ingest_record

log = logging.getLogger(__name__)
router = APIRouter()

NDJSON = "application/x-ndjson"
JSON = "application/json"

# Per-line rejection reasons, and the meta-detection each one raises.
LINE_TOO_LONG = "line_too_long"
COLLECTOR_TOO_LARGE = "collector_too_large"
INVALID_ENVELOPE = "invalid_envelope"
_REASON_META = {
    LINE_TOO_LONG: (meta.LIMIT_EXCEEDED, "line_bytes"),
    COLLECTOR_TOO_LARGE: (meta.LIMIT_EXCEEDED, "collector_bytes"),
    INVALID_ENVELOPE: (meta.INVALID_ENVELOPE, "envelope"),
}


def _settings(request: Request) -> Settings:
    return request.app.state.settings


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
    gate: meta.MetaDetectionGate = request.app.state.meta_gate
    counts = gate.note(source.id, kind, limit, n)
    if counts is None:
        return
    try:
        async with get_pool(request).connection() as conn, conn.transaction():
            wrote = await meta.write_meta_detection(
                conn,
                source,
                kind,
                counts=counts,
                details={"limit": limit, **(details or {})},
                now=clock(),
            )
        if wrote:
            gate.written(source.id, kind)
    except Exception as exc:  # a failed meta write must not change the ingest answer
        log.warning("could not record meta-detection %s: %s", kind, type(exc).__name__)


def _check_content_type(request: Request, expected: str) -> None:
    media = request.headers.get("content-type", "").split(";", 1)[0].strip().lower()
    if media != expected:
        raise HTTPException(status_code=415, detail=f"Content-Type must be {expected}")
    encoding = request.headers.get("content-encoding", "identity").strip().lower()
    if encoding not in ("", "identity"):
        raise HTTPException(status_code=415, detail="compressed bodies are not supported")


async def _read_capped(
    request: Request, credential: SourceCredential, clock: Clock, max_bytes: int
) -> bytes:
    """Read the body, refusing with 413 as soon as it is known to exceed ``max_bytes``."""

    async def too_large() -> HTTPException:
        await _record_breach(
            request,
            credential.source,
            meta.LIMIT_EXCEEDED,
            "body_bytes",
            clock,
            details={"max": max_bytes},
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
    body = bytearray()
    async for chunk in request.stream():
        body += chunk
        if len(body) > max_bytes:
            raise await too_large()
    return bytes(body)


async def _admit(request: Request, credential: SourceCredential, clock: Clock, n: int) -> None:
    limiter: RateLimiter = request.app.state.rate_limiter
    retry_after = limiter.take(credential.source.id, n)
    if retry_after is not None:
        await _record_breach(
            request,
            credential.source,
            meta.RATE_LIMITED,
            "records_per_second",
            clock,
            details={"rate": limiter.rate, "burst": limiter.burst},
        )
        raise HTTPException(
            status_code=429,
            detail="source rate limit exceeded",
            headers={"Retry-After": str(retry_after)},
        )


def parse_envelope(line: bytes, settings: Settings) -> tuple[bytes, dict[str, Any]] | str:
    """Return (raw bytes, collector) for a valid envelope, else a rejection reason."""
    if len(line) > settings.ingest_max_line_bytes:
        return LINE_TOO_LONG
    try:
        envelope = loads_object(line.decode("utf-8"))
    except (UnicodeDecodeError, AdapterError):
        return INVALID_ENVELOPE
    if not set(envelope) <= {"raw", "collector"}:
        return INVALID_ENVELOPE
    raw = envelope.get("raw")
    collector = envelope.get("collector")
    if collector is None:
        collector = {}
    if not isinstance(raw, str) or not raw or not isinstance(collector, dict):
        return INVALID_ENVELOPE
    try:
        body = raw.encode("utf-8")  # fails on lone surrogates such as "\ud800"
        serialized = json.dumps(collector, ensure_ascii=False, separators=(",", ":"))
        collector_size = len(serialized.encode("utf-8"))
    except (UnicodeEncodeError, ValueError):
        return INVALID_ENVELOPE
    if "\\u0000" in serialized:
        return INVALID_ENVELOPE  # Postgres jsonb cannot store NUL
    if collector_size > settings.ingest_max_collector_bytes:
        return COLLECTOR_TOO_LARGE
    return body, collector


def _result(line_no: int, outcome: RecordOutcome) -> dict[str, Any]:
    result: dict[str, Any] = {"line": line_no, "status": outcome.status}
    if outcome.parse is not None:
        result["parse"] = outcome.parse
    if outcome.reason is not None:
        result["reason"] = outcome.reason
    return result


@router.post("/v1/sources/{source}/records")
async def ingest_records(
    source: str, request: Request, clock: Annotated[Clock, Depends(get_clock)]
) -> dict[str, Any]:
    settings = _settings(request)
    credential = await authenticate_source(request, source)
    _check_content_type(request, NDJSON)
    body = await _read_capped(request, credential, clock, settings.ingest_max_body_bytes)

    lines = [
        (number, line.removesuffix(b"\r"))
        for number, line in enumerate(body.split(b"\n"), start=1)
        if line.strip()
    ]
    if len(lines) > settings.ingest_max_lines:
        await _record_breach(
            request,
            credential.source,
            meta.LIMIT_EXCEEDED,
            "lines",
            clock,
            details={"max": settings.ingest_max_lines},
        )
        raise HTTPException(status_code=413, detail=f"more than {settings.ingest_max_lines} lines")
    await _admit(request, credential, clock, len(lines))

    received_at = clock()
    tolerance = timedelta(seconds=settings.clock_skew_tolerance_seconds)
    results: list[dict[str, Any]] = []
    rejected: dict[str, int] = {}
    async with get_pool(request).connection() as conn, conn.transaction():
        for number, line in lines:
            parsed = parse_envelope(line, settings)
            if isinstance(parsed, str):
                rejected[parsed] = rejected.get(parsed, 0) + 1
                results.append(_result(number, RecordOutcome(status="rejected", reason=parsed)))
                continue
            raw, collector = parsed
            outcome = await ingest_record(
                conn,
                credential,
                body=raw,
                collector=collector,
                transport=Transport.NDJSON,
                received_at=received_at,
                clock_skew_tolerance=tolerance,
            )
            results.append(_result(number, outcome))
    # Committed. Breaches are recorded after the evidence, in their own transaction.
    for reason, count in rejected.items():
        kind, limit = _REASON_META[reason]
        await _record_breach(request, credential.source, kind, limit, clock, n=count)
    return {"results": results}


@router.post("/v1/sources/{source}/otlp/v1/metrics")
async def ingest_otlp_metrics(
    source: str, request: Request, clock: Annotated[Clock, Depends(get_clock)]
) -> JSONResponse:
    """OTLP/HTTP JSON metrics: the whole body is one raw record, parsed by the source adapter.

    The response body is a JSON object; OTLP clients ignore its unknown fields.
    """
    settings = _settings(request)
    credential = await authenticate_source(request, source)
    _check_content_type(request, JSON)
    body = await _read_capped(request, credential, clock, settings.ingest_max_body_bytes)
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
            received_at=clock(),
            clock_skew_tolerance=timedelta(seconds=settings.clock_skew_tolerance_seconds),
        )
    if outcome.status == "rejected":
        return JSONResponse(
            status_code=500, content={"status": "rejected", "reason": outcome.reason}
        )
    content: dict[str, Any] = {"status": outcome.status}
    if outcome.parse is not None:
        content["parse"] = outcome.parse
    return JSONResponse(content=content)
