"""Programmatic `alembic upgrade head` under a Postgres session advisory lock.

SQLAlchemy appears here only because Alembic needs a SQLAlchemy Core connection.
Application code uses psycopg directly; there are no ORM models.
"""

from __future__ import annotations

import logging
import time
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, text
from sqlalchemy.engine import Connection
from sqlalchemy.pool import NullPool

from tuisku.config import ConfigError, Settings

log = logging.getLogger(__name__)

# Fixed key shared by every migrator (`tuisku migrate` and plain `alembic
# upgrade` through migrations/env.py): ASCII "tuisku".
MIGRATION_LOCK_KEY = 0x747569736B75
_LOCK_POLL_SECONDS = 1.0


class MigrationLockTimeout(RuntimeError):
    """Another migrator held the migration lock for longer than the configured timeout."""


def to_sqlalchemy_url(url: str) -> str:
    """Select the psycopg 3 driver for SQLAlchemy (postgresql:// -> postgresql+psycopg://)."""
    for prefix in ("postgresql://", "postgres://"):
        if url.startswith(prefix):
            return "postgresql+psycopg://" + url[len(prefix) :]
    return url


def alembic_config(settings: Settings) -> Config:
    path = Path(settings.alembic_config)
    if not path.is_file():
        raise ConfigError(
            f"alembic config not found at {path} (set TUISKU_ALEMBIC_CONFIG or run from the "
            "directory that holds alembic.ini)"
        )
    return Config(str(path))


@contextmanager
def migration_lock(conn: Connection, settings: Settings) -> Iterator[None]:
    """Hold the session advisory lock on `conn` and set lock_timeout for its DDL.

    Leaves `conn` outside a transaction on entry so Alembic manages its own;
    the session-level lock and setting survive commits on this connection.
    """
    deadline = time.monotonic() + settings.migration_lock_timeout_seconds
    log.info("acquiring migration lock")
    while True:
        acquired = conn.execute(
            text("SELECT pg_try_advisory_lock(:key)"), {"key": MIGRATION_LOCK_KEY}
        ).scalar_one()
        conn.commit()
        if acquired:
            break
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise MigrationLockTimeout(
                "timed out after "
                f"{settings.migration_lock_timeout_seconds:g}s waiting for the migration lock; "
                "another migration is still running"
            )
        time.sleep(min(_LOCK_POLL_SECONDS, remaining))
    try:
        lock_timeout_ms = int(settings.migration_ddl_lock_timeout_seconds * 1000)
        conn.execute(
            text("SELECT set_config('lock_timeout', :value, false)"),
            {"value": f"{lock_timeout_ms}ms"},
        )
        conn.commit()
        yield
    finally:
        conn.rollback()  # leave any failed transaction before unlocking
        conn.execute(text("SELECT pg_advisory_unlock(:key)"), {"key": MIGRATION_LOCK_KEY})
        conn.commit()
        log.info("released migration lock")


def run_migrations(settings: Settings, revision: str = "head") -> None:
    """Upgrade the database to `revision`, serialised across processes by an advisory lock."""
    url = to_sqlalchemy_url(settings.require_database_url())
    cfg = alembic_config(settings)
    engine = create_engine(url, poolclass=NullPool)
    try:
        with engine.connect() as conn, migration_lock(conn, settings):
            # env.py runs on this same connection, so the upgrade happens under the lock.
            cfg.attributes["connection"] = conn
            # Logging is already configured by the caller (the CLI).
            cfg.attributes["skip_logging_config"] = True
            # Revisions read the app role from here to decide whether to GRANT (ADR 0004).
            cfg.attributes["app_role"] = settings.app_role
            cfg.attributes["worker_role"] = settings.worker_role
            command.upgrade(cfg, revision)
            conn.commit()
    finally:
        engine.dispose()
