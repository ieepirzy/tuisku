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
from tuisku.migrate import migration_lock, to_sqlalchemy_url

config = context.config

if config.config_file_name is not None and not config.attributes.get("skip_logging_config"):
    fileConfig(config.config_file_name, disable_existing_loggers=False)

target_metadata = None

# Revisions read the app role (TUISKU_APP_ROLE) from config.attributes, so they stay
# importable without a database or settings. `tuisku migrate` sets it already.
if "app_role" not in config.attributes:
    config.attributes["app_role"] = Settings().app_role


def _database_url(settings: Settings) -> str:
    return to_sqlalchemy_url(settings.require_database_url())


def run_migrations_offline() -> None:
    context.configure(
        url=_database_url(Settings()),
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
    # advisory lock; plain `alembic upgrade` opens its own and takes the same lock.
    connection: Connection | None = config.attributes.get("connection")
    if connection is not None:
        _run(connection)
        return
    settings = Settings()
    engine = create_engine(_database_url(settings), poolclass=NullPool)
    try:
        with engine.connect() as conn, migration_lock(conn, settings):
            _run(conn)
    finally:
        engine.dispose()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
