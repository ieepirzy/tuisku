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
from contextlib import contextmanager
from dataclasses import dataclass
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


@pytest.hookimpl(hookwrapper=True)
def pytest_make_collect_report(collector: pytest.Collector):
    # Collection-time skips (e.g. `pytest.skip(allow_module_level=True)`) are
    # also failures in CI.
    outcome = yield
    report = outcome.get_result()
    if _in_ci() and report.skipped:
        report.outcome = "failed"
        report.longrepr = f"unexpected collection skip in CI: {report.longrepr}"


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


@contextmanager
def _temporary_database(admin_database_url: str) -> Iterator[str]:
    """Create a uniquely named empty database; drop it on exit."""
    name = f"tuisku_test_{uuid.uuid4().hex[:12]}"
    with psycopg.connect(admin_database_url, autocommit=True) as admin:
        admin.execute(sql.SQL("CREATE DATABASE {}").format(sql.Identifier(name)))
    try:
        yield _with_dbname(admin_database_url, name)
    finally:
        with psycopg.connect(admin_database_url, autocommit=True) as admin:
            admin.execute(
                sql.SQL("DROP DATABASE IF EXISTS {} WITH (FORCE)").format(sql.Identifier(name))
            )


@pytest.fixture(scope="session")
def database_url(admin_database_url: str) -> Iterator[str]:
    """A fresh database for this test session, migrated with the repository's migrations."""
    with _temporary_database(admin_database_url) as url:
        run_migrations(make_settings(url))
        yield url


@pytest.fixture
def empty_database_url(admin_database_url: str) -> Iterator[str]:
    """A fresh, unmigrated database for one test."""
    with _temporary_database(admin_database_url) as url:
        yield url


@dataclass(frozen=True)
class AppDatabase:
    """A database migrated by the owner role with TUISKU_APP_ROLE and TUISKU_WORKER_ROLE set
    (ADR 0004 roles, ADR 0011 worker role)."""

    owner_url: str  # the migrating role: owns the tables
    app_url: str  # the API role: ingest and triage only
    app_role: str
    worker_url: str  # the worker role: rule output, firing keys, findings and incidents
    worker_role: str


def _with_user(url: str, user: str, password: str) -> str:
    parts = urlsplit(url)
    host = parts.hostname or "localhost"
    netloc = f"{user}:{password}@{host}" + (f":{parts.port}" if parts.port else "")
    return urlunsplit(parts._replace(netloc=netloc))


@pytest.fixture(scope="session")
def app_db(admin_database_url: str) -> Iterator[AppDatabase]:
    """Test-only login roles (cluster-wide, so uniquely named and dropped afterwards)."""
    suffix = uuid.uuid4().hex[:8]
    role, worker = f"tuisku_app_test_{suffix}", f"tuisku_worker_test_{suffix}"
    password = uuid.uuid4().hex  # throwaway, for this test session only
    with psycopg.connect(admin_database_url, autocommit=True) as admin:
        for name in (role, worker):
            admin.execute(
                sql.SQL("CREATE ROLE {} LOGIN PASSWORD {}").format(
                    sql.Identifier(name), sql.Literal(password)
                )
            )
    try:
        with _temporary_database(admin_database_url) as url:
            run_migrations(make_settings(url, app_role=role, worker_role=worker))
            yield AppDatabase(
                owner_url=url,
                app_url=_with_user(url, role, password),
                app_role=role,
                worker_url=_with_user(url, worker, password),
                worker_role=worker,
            )
    finally:
        with psycopg.connect(admin_database_url, autocommit=True) as admin:
            for name in (role, worker):
                admin.execute(sql.SQL("DROP ROLE IF EXISTS {}").format(sql.Identifier(name)))


@pytest.fixture(scope="session")
def template_database_url(admin_database_url: str) -> Iterator[str]:
    """A migrated database used only as a template: never connected to after migrating."""
    with _temporary_database(admin_database_url) as url:
        run_migrations(make_settings(url))
        yield url


@pytest.fixture
def fresh_database_url(admin_database_url: str, template_database_url: str) -> Iterator[str]:
    """A fresh, migrated database for one test, cloned from the template (fast)."""
    template = urlsplit(template_database_url).path.lstrip("/")
    name = f"tuisku_test_{uuid.uuid4().hex[:12]}"
    with psycopg.connect(admin_database_url, autocommit=True) as admin:
        admin.execute(
            sql.SQL("CREATE DATABASE {} TEMPLATE {}").format(
                sql.Identifier(name), sql.Identifier(template)
            )
        )
    try:
        yield _with_dbname(admin_database_url, name)
    finally:
        with psycopg.connect(admin_database_url, autocommit=True) as admin:
            admin.execute(
                sql.SQL("DROP DATABASE IF EXISTS {} WITH (FORCE)").format(sql.Identifier(name))
            )
