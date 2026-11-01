"""Postgres access: an async connection pool and plain-SQL helpers (no ORM)."""

from __future__ import annotations

from typing import Any, LiteralString

from psycopg import AsyncConnection
from psycopg.rows import dict_row
from psycopg_pool import AsyncConnectionPool

from tuisku.config import Settings

Params = tuple[Any, ...] | dict[str, Any] | None


def create_pool(settings: Settings) -> AsyncConnectionPool:
    """Build an unopened pool; the caller opens and closes it (see the API lifespan)."""
    return AsyncConnectionPool(
        conninfo=settings.require_database_url(),
        min_size=settings.pool_min_size,
        max_size=settings.pool_max_size,
        kwargs={"connect_timeout": 5},
        open=False,
        name="tuisku",
    )


async def open_pool(pool: AsyncConnectionPool) -> None:
    # wait=False: the process must start (and answer liveness) even when the
    # database is down; readiness reports the database state.
    await pool.open(wait=False)


async def close_pool(pool: AsyncConnectionPool) -> None:
    await pool.close()


async def fetch_all(
    conn: AsyncConnection[Any], query: LiteralString, params: Params = None
) -> list[dict[str, Any]]:
    """Run a query and return every row as a dict keyed by column name."""
    async with conn.cursor(row_factory=dict_row) as cur:
        await cur.execute(query, params)
        return await cur.fetchall()


async def fetch_one(
    conn: AsyncConnection[Any], query: LiteralString, params: Params = None
) -> dict[str, Any] | None:
    """Run a query and return the first row as a dict, or None when there is none."""
    async with conn.cursor(row_factory=dict_row) as cur:
        await cur.execute(query, params)
        return await cur.fetchone()
