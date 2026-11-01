"""Alembic environment for Tuisku.

There is no ORM and no target_metadata: revisions are hand-written with
`op.execute()` and raw SQL, and autogenerate is not used.
"""

from __future__ import annotations

from logging.config import fileConfig

from alembic import context
from sqlalchemy import create_engine
from sqlalchemy.engine import Connection
from sqlalchemy.pool import NullPool

from tuisku.config import Settings
from tuisku.migrate import to_sqlalchemy_url

config = context.config

if config.config_file_name is not None and not config.attributes.get("skip_logging_config"):
    fileConfig(config.config_file_name, disable_existing_loggers=False)

target_metadata = None


def _database_url() -> str:
    return to_sqlalchemy_url(Settings().require_database_url())


def run_migrations_offline() -> None:
    context.configure(
        url=_database_url(),
        target_metadata=target_metadata,
        literal_binds=True,
        transaction_per_migration=True,
    )
    with context.begin_transaction():
        context.run_migrations()


def _run(connection: Connection) -> None:
    context.configure(
        connection=connection,
        target_metadata=target_metadata,
        transaction_per_migration=True,
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    # `tuisku migrate` passes a connection that already holds the migration
    # advisory lock; plain `alembic upgrade` falls back to its own connection.
    connection: Connection | None = config.attributes.get("connection")
    if connection is not None:
        _run(connection)
        return
    engine = create_engine(_database_url(), poolclass=NullPool)
    try:
        with engine.connect() as conn:
            _run(conn)
    finally:
        engine.dispose()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
