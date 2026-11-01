import shutil
import threading
from pathlib import Path

import psycopg
import pytest
from alembic import command
from alembic.config import Config

from tests.conftest import ALEMBIC_INI, REPO_ROOT, make_settings
from tuisku.cli import main
from tuisku.migrate import (
    MIGRATION_LOCK_KEY,
    MigrationLockTimeout,
    run_migrations,
    to_sqlalchemy_url,
)

# A bigint advisory lock key shows in pg_locks as classid (high 32 bits),
# objid (low 32 bits) and objsubid = 1.
LOCK_CLASSID = MIGRATION_LOCK_KEY >> 32
LOCK_OBJID = MIGRATION_LOCK_KEY & 0xFFFFFFFF

PROBE_REVISION = f'''
from alembic import op

revision = "0001"
down_revision = None
branch_labels = None
depends_on = None

expand_only = True


def upgrade() -> None:
    # Fails unless this very connection holds the migration advisory lock and
    # has the default 30s DDL lock_timeout.
    op.execute("""
        DO $$
        BEGIN
            IF NOT EXISTS (
                SELECT 1 FROM pg_locks
                WHERE locktype = 'advisory' AND pid = pg_backend_pid() AND granted
                  AND classid = {LOCK_CLASSID} AND objid = {LOCK_OBJID} AND objsubid = 1
            ) THEN
                RAISE EXCEPTION 'migration advisory lock not held during upgrade';
            END IF;
            IF current_setting('lock_timeout') <> '30s' THEN
                RAISE EXCEPTION 'lock_timeout is %, expected 30s', current_setting('lock_timeout');
            END IF;
        END
        $$;
    """)
    op.execute("CREATE TABLE probe_items (id bigint PRIMARY KEY)")


def downgrade() -> None:
    op.execute("DROP TABLE probe_items")
'''


@pytest.fixture
def probe_alembic_ini(tmp_path: Path) -> str:
    """alembic.ini + migrations/ copied to tmp, with one revision that checks the lock."""
    shutil.copy(ALEMBIC_INI, tmp_path / "alembic.ini")
    shutil.copytree(REPO_ROOT / "migrations", tmp_path / "migrations")
    (tmp_path / "migrations" / "versions" / "20260101_0001_probe.py").write_text(PROBE_REVISION)
    return str(tmp_path / "alembic.ini")


def _version_rows(database_url: str) -> list[tuple[str, ...]]:
    with psycopg.connect(database_url) as conn:
        return conn.execute("SELECT version_num FROM alembic_version").fetchall()


def _table_exists(database_url: str, table: str) -> bool:
    with psycopg.connect(database_url) as conn:
        row = conn.execute("SELECT to_regclass(%s) IS NOT NULL", (table,)).fetchone()
        assert row is not None
        return bool(row[0])


def test_repository_migrations_apply_and_are_idempotent(database_url: str) -> None:
    # The session fixture already migrated this database once, from empty.
    before = _version_rows(database_url)
    run_migrations(make_settings(database_url))
    assert _version_rows(database_url) == before


def test_migrate_applies_a_revision_under_the_lock_and_is_idempotent(
    empty_database_url: str, probe_alembic_ini: str
) -> None:
    settings = make_settings(empty_database_url, alembic_config=probe_alembic_ini)
    run_migrations(settings)
    assert _version_rows(empty_database_url) == [("0001",)]
    assert _table_exists(empty_database_url, "probe_items")

    run_migrations(settings)
    assert _version_rows(empty_database_url) == [("0001",)]


def test_plain_alembic_upgrade_also_takes_the_lock(
    empty_database_url: str, probe_alembic_ini: str, monkeypatch
) -> None:
    monkeypatch.setenv("TUISKU_DATABASE_URL", empty_database_url)
    cfg = Config(probe_alembic_ini)
    cfg.attributes["skip_logging_config"] = True
    command.upgrade(cfg, "head")  # env.py's own-connection path
    assert _version_rows(empty_database_url) == [("0001",)]


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


def test_migrate_gives_up_after_the_lock_timeout(database_url: str) -> None:
    settings = make_settings(database_url, migration_lock_timeout_seconds=0.5)
    with psycopg.connect(database_url, autocommit=True) as holder:
        holder.execute("SELECT pg_advisory_lock(%s)", (MIGRATION_LOCK_KEY,))
        with pytest.raises(MigrationLockTimeout, match="waiting for the migration lock"):
            run_migrations(settings)


def test_cli_migrate(database_url: str, monkeypatch) -> None:
    monkeypatch.setenv("TUISKU_DATABASE_URL", database_url)
    monkeypatch.setenv("TUISKU_ALEMBIC_CONFIG", ALEMBIC_INI)
    assert main(["migrate"]) == 0


def test_cli_migrate_without_database_url_fails(monkeypatch, capsys) -> None:
    monkeypatch.delenv("TUISKU_DATABASE_URL", raising=False)
    assert main(["migrate"]) == 2
    assert "TUISKU_DATABASE_URL is required" in capsys.readouterr().err


def test_sqlalchemy_url_uses_psycopg_driver() -> None:
    assert to_sqlalchemy_url("postgresql://u:p@h/d") == "postgresql+psycopg://u:p@h/d"
    assert to_sqlalchemy_url("postgres://u:p@h/d") == "postgresql+psycopg://u:p@h/d"
