"""Programmatic `alembic upgrade head` under a Postgres session advisory lock.

SQLAlchemy appears here only because Alembic needs a SQLAlchemy Core connection.
Application code uses psycopg directly; there are no ORM models.
"""

from __future__ import annotations

import logging
from pathlib import Path

from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, text
from sqlalchemy.pool import NullPool

from tuisku.config import ConfigError, Settings

log = logging.getLogger(__name__)

# Fixed key shared by every `tuisku migrate` process: ASCII "tuisku".
MIGRATION_LOCK_KEY = 0x747569736B75


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


def run_migrations(settings: Settings, revision: str = "head") -> None:
    """Upgrade the database to `revision`, serialised across processes by an advisory lock."""
    url = to_sqlalchemy_url(settings.require_database_url())
    cfg = alembic_config(settings)
    engine = create_engine(url, poolclass=NullPool)
    try:
        with engine.connect() as conn:
            log.info("acquiring migration lock")
            conn.execute(text("SELECT pg_advisory_lock(:key)"), {"key": MIGRATION_LOCK_KEY})
            # End the implicit transaction so Alembic manages its own; the
            # session-level lock stays held on this connection.
            conn.commit()
            try:
                cfg.attributes["connection"] = conn
                # Logging is already configured by the caller (the CLI).
                cfg.attributes["skip_logging_config"] = True
                command.upgrade(cfg, revision)
                conn.commit()
            finally:
                conn.execute(text("SELECT pg_advisory_unlock(:key)"), {"key": MIGRATION_LOCK_KEY})
                conn.commit()
                log.info("released migration lock")
    finally:
        engine.dispose()
