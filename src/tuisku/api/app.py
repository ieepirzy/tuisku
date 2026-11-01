"""FastAPI application factory.

The API never runs migrations: a separate `tuisku migrate` job does that.
"""

from __future__ import annotations

import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from psycopg_pool import AsyncConnectionPool

from tuisku import __version__, db
from tuisku.adapters import builtin as _builtin_adapters  # noqa: F401  (registers adapters)
from tuisku.api import ingest, read
from tuisku.api.deps import Clock, system_clock
from tuisku.api.ratelimit import RateLimiter
from tuisku.config import Settings
from tuisku.store.meta import MetaDetectionGate

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
            await db.close_pool(pool)

    app = FastAPI(title="Tuisku", version=__version__, lifespan=lifespan)
    app.state.settings = settings
    app.state.clock = clock if clock is not None else system_clock
    app.state.rate_limiter = RateLimiter(
        settings.ingest_rate_per_second, settings.ingest_rate_burst
    )
    app.state.meta_gate = MetaDetectionGate()
    app.include_router(ingest.router)
    app.include_router(read.router)

    @app.get("/v1/health")
    async def health() -> dict[str, str]:
        """Liveness: the process is up. Never touches the database."""
        return {"status": "ok", "revision": settings.build_revision}

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
