import threading

import psycopg

from tests.conftest import make_settings
from tuisku.cli import main
from tuisku.migrate import MIGRATION_LOCK_KEY, run_migrations, to_sqlalchemy_url


def _version_rows(database_url: str) -> list[tuple[str, ...]]:
    with psycopg.connect(database_url) as conn:
        return conn.execute("SELECT version_num FROM alembic_version").fetchall()


def test_migrate_runs_on_fresh_database_and_is_idempotent(database_url: str) -> None:
    # The session fixture already migrated this database once (from empty).
    before = _version_rows(database_url)
    run_migrations(make_settings(database_url))
    run_migrations(make_settings(database_url))
    assert _version_rows(database_url) == before


def test_migrate_waits_for_the_advisory_lock(database_url: str) -> None:
    done = threading.Event()

    def migrate() -> None:
        run_migrations(make_settings(database_url))
        done.set()

    with psycopg.connect(database_url, autocommit=True) as holder:
        holder.execute("SELECT pg_advisory_lock(%s)", (MIGRATION_LOCK_KEY,))
        worker = threading.Thread(target=migrate, daemon=True)
        worker.start()
        assert not done.wait(timeout=1.5), "migrate ran while another process held the lock"
        holder.execute("SELECT pg_advisory_unlock(%s)", (MIGRATION_LOCK_KEY,))
        worker.join(timeout=30)
    assert done.is_set()


def test_cli_migrate(database_url: str, monkeypatch) -> None:
    monkeypatch.setenv("TUISKU_DATABASE_URL", database_url)
    monkeypatch.setenv("TUISKU_ALEMBIC_CONFIG", make_settings(database_url).alembic_config)
    assert main(["migrate"]) == 0


def test_cli_migrate_without_database_url_fails(monkeypatch, capsys) -> None:
    monkeypatch.delenv("TUISKU_DATABASE_URL", raising=False)
    assert main(["migrate"]) == 2
    assert "TUISKU_DATABASE_URL is required" in capsys.readouterr().err


def test_sqlalchemy_url_uses_psycopg_driver() -> None:
    assert to_sqlalchemy_url("postgresql://u:p@h/d") == "postgresql+psycopg://u:p@h/d"
    assert to_sqlalchemy_url("postgres://u:p@h/d") == "postgresql+psycopg://u:p@h/d"
