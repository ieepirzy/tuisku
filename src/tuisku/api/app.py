"""FastAPI application factory.

The API never runs migrations: a separate `tuisku migrate` job does that.
"""

from __future__ import annotations

import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

import anyio
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from psycopg_pool import AsyncConnectionPool

from tuisku import __version__, db
from tuisku.adapters import builtin as _builtin_adapters  # noqa: F401  (registers adapters)
from tuisku.api import ingest, read, triage
from tuisku.api.deps import Clock, system_clock
from tuisku.api.ratelimit import RateLimiter, RefusalCounter
from tuisku.config import Settings

log = logging.getLogger(__name__)


def create_app(settings: Settings | None = None, *, clock: Clock | None = None) -> FastAPI:
    """Build the app. ``clock`` sets received_at on ingest; tests and replay inject one."""
    settings = settings if settings is not None else Settings()
    # Fail fast at construction when the database is not configured.
    settings.require_database_url()

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        pool = db.create_pool(settings)
        await db.open_pool(pool)
        app.state.pool = pool
        try:
            yield
        finally:
            await ingest.flush_refusals(app)
            await db.close_pool(pool)

    app = FastAPI(title="Tuisku", version=__version__, lifespan=lifespan)
    app.state.settings = settings
    app.state.clock = clock if clock is not None else system_clock
    app.state.rate_limiter = RateLimiter(
        settings.ingest_rate_per_second, settings.ingest_rate_burst
    )
    app.state.refusals = RefusalCounter(settings.ingest_rate_breach_flush_seconds)
    # Bounded worker threads for adapters, so parsing never blocks the event loop.
    app.state.parse_limiter = anyio.CapacityLimiter(settings.ingest_parse_threads)
    app.include_router(ingest.router)
    app.include_router(read.router)
    app.include_router(triage.router)

    @app.get("/v1/health")
    async def health() -> dict[str, str]:
        """Liveness: the process is up. Never touches the database."""
        return {"status": "ok", "revision": settings.build_revision}

    @app.get("/v1/worker/health")
    async def worker_health(request: Request) -> JSONResponse:
        """Unauthenticated, for an external monitor that does not depend on the worker (ADR
        0011 "Availability limits"): 503 when no worker heartbeat is fresh, or when the oldest
        undelivered notification is older than the backlog limit."""
        pool: AsyncConnectionPool = request.app.state.pool
        try:
            async with pool.connection(timeout=settings.ready_timeout_seconds) as conn:
                row = await db.fetch_one(
                    conn,
                    "SELECT extract(epoch FROM now() - max(beat_at)) AS heartbeat_age, "
                    "extract(epoch FROM now() - min(oldest_queued_at)) AS queued_age, "
                    "coalesce(sum(queued), 0) AS queued, "
                    "(SELECT extract(epoch FROM now() - min(n.created_at)) FROM notifications n "
                    " WHERE NOT EXISTS (SELECT 1 FROM notification_deliveries d "
                    " WHERE d.notification_id = n.id AND d.status = 'delivered')) "
                    "AS undelivered_age FROM worker_heartbeats "
                    "WHERE beat_at > now() - interval '1 day'",
                )
        except Exception as exc:
            log.warning("worker health check failed: %s", type(exc).__name__)
            return JSONResponse(status_code=503, content={"status": "unavailable"})
        assert row is not None
        age = None if row["heartbeat_age"] is None else float(row["heartbeat_age"])
        undelivered = None if row["undelivered_age"] is None else float(row["undelivered_age"])
        if age is None or age > settings.worker_heartbeat_stale_seconds:
            status = "no_worker"
        elif undelivered is not None and undelivered > settings.worker_backlog_seconds:
            status = "backlog"
        else:
            status = "ok"
        return JSONResponse(
            status_code=200 if status == "ok" else 503,
            content={
                "status": status,
                "heartbeat_age_seconds": age,
                "oldest_undelivered_seconds": undelivered,
                "oldest_queued_seconds": (
                    None if row["queued_age"] is None else float(row["queued_age"])
                ),
                "queued": int(row["queued"]),
            },
        )

    @app.get("/v1/ready")
    async def ready(request: Request) -> JSONResponse:
        """Readiness: the database answers `SELECT 1`; 503 otherwise."""
        pool: AsyncConnectionPool = request.app.state.pool
        try:
            async with pool.connection(timeout=settings.ready_timeout_seconds) as conn:
                row = await db.fetch_one(conn, "SELECT 1 AS ok")
            if row is None or row["ok"] != 1:
                raise RuntimeError("unexpected SELECT 1 result")
        except Exception as exc:  # any failure means not ready
            # Log the exception type only: messages may contain connection details.
            log.warning("readiness check failed: %s", type(exc).__name__)
            return JSONResponse(
                status_code=503,
                content={
                    "status": "unavailable",
                    "revision": settings.build_revision,
                    "database": "unreachable",
                },
            )
        return JSONResponse(
            content={"status": "ready", "revision": settings.build_revision, "database": "ok"}
        )

    return app
