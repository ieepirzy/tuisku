"""Shared fixtures.

Database tests need TUISKU_TEST_DATABASE_URL: a Postgres URL whose role may
CREATE DATABASE. Each test session creates a fresh, uniquely named database,
migrates it, and drops it afterwards. Without a reachable database these tests
skip locally but fail when CI=true, and in CI any skip at all is a failure.
"""

from __future__ import annotations

import os
import uuid
from collections.abc import Iterator
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

import psycopg
import pytest
from psycopg import sql

from tuisku.config import Settings
from tuisku.migrate import run_migrations

REPO_ROOT = Path(__file__).resolve().parent.parent
ALEMBIC_INI = str(REPO_ROOT / "alembic.ini")
# Nothing listens on port 1: connections are refused immediately.
UNREACHABLE_DATABASE_URL = "postgresql://tuisku:unused@127.0.0.1:1/tuisku"


def _in_ci() -> bool:
    return os.environ.get("CI", "").strip().lower() == "true"


def _database_unavailable(reason: str) -> None:
    if _in_ci():
        pytest.fail(f"{reason} (CI=true: database tests must run)", pytrace=False)
    pytest.skip(reason)


@pytest.hookimpl(hookwrapper=True)
def pytest_runtest_makereport(item: pytest.Item, call: pytest.CallInfo[None]):
    outcome = yield
    report = outcome.get_result()
    if _in_ci() and report.skipped and not hasattr(report, "wasxfail"):
        report.outcome = "failed"
        report.longrepr = f"unexpected skip in CI: {report.longrepr}"


def _with_dbname(url: str, dbname: str) -> str:
    parts = urlsplit(url)
    return urlunsplit(parts._replace(path=f"/{dbname}"))


def make_settings(database_url: str, **overrides: object) -> Settings:
    values: dict[str, object] = {
        "database_url": database_url,
        "alembic_config": ALEMBIC_INI,
        "build_revision": "test-revision",
    }
    values.update(overrides)
    return Settings.model_validate(values)


@pytest.fixture(scope="session")
def admin_database_url() -> str:
    url = os.environ.get("TUISKU_TEST_DATABASE_URL", "").strip()
    if not url:
        _database_unavailable("TUISKU_TEST_DATABASE_URL is not set")
    try:
        with psycopg.connect(url, connect_timeout=5) as conn:
            conn.execute("SELECT 1")
    except psycopg.Error as exc:
        _database_unavailable(f"test database unreachable ({type(exc).__name__})")
    return url


@pytest.fixture(scope="session")
def database_url(admin_database_url: str) -> Iterator[str]:
    """A fresh, migrated database for this test session."""
    name = f"tuisku_test_{uuid.uuid4().hex[:12]}"
    with psycopg.connect(admin_database_url, autocommit=True) as admin:
        admin.execute(sql.SQL("CREATE DATABASE {}").format(sql.Identifier(name)))
    url = _with_dbname(admin_database_url, name)
    try:
        run_migrations(make_settings(url))
        yield url
    finally:
        with psycopg.connect(admin_database_url, autocommit=True) as admin:
            admin.execute(
                sql.SQL("DROP DATABASE IF EXISTS {} WITH (FORCE)").format(sql.Identifier(name))
            )
