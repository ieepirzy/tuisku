import asyncio

from tests.conftest import make_settings
from tuisku import db


def test_fetch_helpers_return_dicts(database_url: str) -> None:
    async def run() -> None:
        pool = db.create_pool(make_settings(database_url))
        await pool.open(wait=True, timeout=10)
        try:
            async with pool.connection() as conn:
                rows = await db.fetch_all(
                    conn, "SELECT n, n * 2 AS twice FROM generate_series(1, %s) AS n", (2,)
                )
                assert rows == [{"n": 1, "twice": 2}, {"n": 2, "twice": 4}]
                assert await db.fetch_one(conn, "SELECT 1 AS x WHERE false") is None
        finally:
            await pool.close()

    asyncio.run(run())
