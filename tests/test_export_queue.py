"""The export queue (ADR 0012, revision 0004): filled by an owner trigger, drained by the worker
role, invisible to the API role (ADR 0011)."""

from __future__ import annotations

import psycopg
import pytest
from psycopg import errors

from tests.conftest import AppDatabase, make_settings
from tests.support import query


def _refused(url: str, statement: str) -> Exception:
    with psycopg.connect(url) as conn:
        with pytest.raises(psycopg.Error) as info:
            conn.execute(statement)  # type: ignore[arg-type]
        conn.rollback()
    return info.value


@pytest.mark.parametrize(
    "statement",
    [
        "SELECT * FROM export_queue",
        "DELETE FROM export_queue",
        "TRUNCATE export_queue",
        "UPDATE export_queue SET enqueued_at = now()",
        "INSERT INTO export_queue (stream, finding_event_id, state) VALUES ('finding', 1, '{}')",
        "LOCK TABLE export_queue IN ACCESS SHARE MODE",
        "SELECT public.tuisku_enqueue_export()",
    ],
)
def test_the_api_role_cannot_touch_the_export_queue(app_db: AppDatabase, statement: str) -> None:
    exc = _refused(app_db.app_url, statement)
    assert isinstance(exc, errors.InsufficientPrivilege), exc


@pytest.mark.parametrize(
    "statement",
    [
        "TRUNCATE export_queue",
        "UPDATE export_queue SET enqueued_at = now()",
        "INSERT INTO export_queue (stream, finding_event_id, state) VALUES ('finding', 1, '{}')",
        "SELECT * FROM export_queue FOR UPDATE",
        "SELECT public.tuisku_enqueue_export()",
    ],
)
def test_the_worker_role_only_reads_and_deletes_the_queue(
    app_db: AppDatabase, statement: str
) -> None:
    exc = _refused(app_db.worker_url, statement)
    assert isinstance(exc, errors.InsufficientPrivilege), exc


def test_the_enqueue_trigger_refuses_to_run_on_any_other_table(app_db: AppDatabase) -> None:
    with psycopg.connect(app_db.owner_url) as conn:
        conn.execute("CREATE TEMP TABLE elsewhere (id bigint, finding_id bigint)")
        conn.execute(
            "CREATE TRIGGER t AFTER INSERT ON elsewhere FOR EACH ROW "
            "EXECUTE FUNCTION public.tuisku_enqueue_export()"
        )
        with pytest.raises(errors.InsufficientPrivilege, match="used out of place"):
            conn.execute("INSERT INTO elsewhere VALUES (1, 1)")
        conn.rollback()


def test_the_queue_grants_are_exactly_select_and_delete_for_the_worker(
    app_db: AppDatabase,
) -> None:
    grants = query(
        app_db.owner_url,
        "SELECT grantee, privilege_type FROM information_schema.role_table_grants "
        "WHERE table_name = 'export_queue' AND grantee IN (%s, %s, 'PUBLIC')",
        (app_db.app_role, app_db.worker_role),
    )
    assert sorted(grants) == sorted(
        [(app_db.worker_role, "SELECT"), (app_db.worker_role, "DELETE")]
    )
    [(definer, public_exec)] = query(
        app_db.owner_url,
        "SELECT prosecdef, has_function_privilege('public', oid, 'EXECUTE') FROM pg_proc "
        "WHERE proname = 'tuisku_enqueue_export'",
    )
    assert definer and not public_exec


# --- the migration ------------------------------------------------------------------------------


def test_revision_0004_declares_itself_not_expand_only() -> None:
    from tests.test_migration_conventions import VERSIONS, expand_only_declarations

    [path] = VERSIONS.glob("*_0004_*.py")
    # It adds a trigger function, triggers on existing tables and grants (AGENTS.md).
    assert expand_only_declarations(path.read_text()) == [False]


def test_revision_0004_installs_deferred_triggers_and_downgrades_cleanly(
    empty_database_url: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    from alembic import command

    from tuisku.migrate import alembic_config, run_migrations

    url = empty_database_url
    settings = make_settings(url)
    run_migrations(settings, "0003")
    assert query(url, "SELECT to_regclass('export_queue') IS NULL") == [(True,)]
    run_migrations(settings)
    triggers = query(
        url,
        "SELECT tgrelid::regclass::text, tgdeferrable, tginitdeferred, tgconstraint <> 0 "
        "FROM pg_trigger WHERE tgfoid = 'tuisku_enqueue_export'::regproc ORDER BY 1",
    )
    assert triggers == [
        ("finding_events", True, True, True),
        ("incident_events", True, True, True),
    ]
    monkeypatch.setenv("TUISKU_DATABASE_URL", url)
    cfg = alembic_config(settings)
    cfg.attributes["skip_logging_config"] = True
    command.downgrade(cfg, "0003")
    assert query(
        url,
        "SELECT to_regclass('export_queue') IS NULL, "
        "NOT EXISTS (SELECT 1 FROM pg_proc WHERE proname = 'tuisku_enqueue_export')",
    ) == [(True, True)]
    run_migrations(settings)  # and up again
    assert query(url, "SELECT version_num FROM alembic_version") == [("0004",)]
