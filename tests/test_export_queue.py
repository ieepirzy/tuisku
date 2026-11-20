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
        "SELECT public.tuisku_export_time(now())",
        "SELECT * FROM export_state",
        "UPDATE export_state SET enabled = false",
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
        "SELECT public.tuisku_export_time(now())",
        "UPDATE export_state SET enabled = true",
        "INSERT INTO export_state (singleton) VALUES (true)",
    ],
)
def test_the_worker_role_only_reads_and_deletes_the_queue(
    app_db: AppDatabase, statement: str
) -> None:
    exc = _refused(app_db.worker_url, statement)
    assert isinstance(exc, errors.InsufficientPrivilege), exc


@pytest.mark.parametrize(
    ("function", "event"),
    [("tuisku_enqueue_export", "AFTER INSERT"), ("tuisku_check_triage_expiry", "BEFORE INSERT")],
)
def test_the_new_trigger_functions_refuse_to_run_on_any_other_table(
    app_db: AppDatabase, function: str, event: str
) -> None:
    with psycopg.connect(app_db.owner_url) as conn:
        conn.execute("UPDATE export_state SET enabled = true")  # rolled back below
        conn.execute(
            "CREATE TEMP TABLE elsewhere (id bigint, finding_id bigint, suppressed_until "
            "timestamptz)"
        )
        conn.execute(  # type: ignore[arg-type]
            f"CREATE TRIGGER t {event} ON elsewhere FOR EACH ROW "
            f"EXECUTE FUNCTION public.{function}()"
        )
        with pytest.raises(errors.InsufficientPrivilege, match="used out of place"):
            conn.execute("INSERT INTO elsewhere VALUES (1, 1, '-infinity')")
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
    state_grants = query(
        app_db.owner_url,
        "SELECT grantee, privilege_type FROM information_schema.role_table_grants "
        "WHERE table_name = 'export_state' AND grantee IN (%s, %s, 'PUBLIC')",
        (app_db.app_role, app_db.worker_role),
    )
    assert state_grants == [(app_db.worker_role, "SELECT")]
    functions = query(
        app_db.owner_url,
        "SELECT proname, prosecdef, has_function_privilege('public', oid, 'EXECUTE'), "
        "has_function_privilege(%s, oid, 'EXECUTE'), has_function_privilege(%s, oid, 'EXECUTE') "
        "FROM pg_proc WHERE proname IN ('tuisku_enqueue_export', 'tuisku_export_time', "
        "'tuisku_check_triage_expiry') ORDER BY proname",
        (app_db.app_role, app_db.worker_role),
    )
    assert functions == [
        ("tuisku_check_triage_expiry", False, False, False, False),
        ("tuisku_enqueue_export", True, False, False, False),
        ("tuisku_export_time", False, False, False, False),
    ]


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
    assert query(
        url,
        "SELECT enabled FROM export_state UNION ALL SELECT count(*) > 0 FROM worker_locks "
        "WHERE name = 'export' AND holder IS NULL",
    ) == [(False,), (True,)]
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
        "SELECT to_regclass('export_queue') IS NULL, to_regclass('export_state') IS NULL, "
        "NOT EXISTS (SELECT 1 FROM pg_proc WHERE proname LIKE 'tuisku\\_%%export%%' "
        "OR proname = 'tuisku_check_triage_expiry'), "
        "NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'worker_locks' "
        "AND column_name IN ('holder', 'lease_until')), "
        "NOT EXISTS (SELECT 1 FROM worker_locks WHERE name = 'export')",
    ) == [(True, True, True, True, True)]
    run_migrations(settings)  # and up again
    assert query(url, "SELECT version_num FROM alembic_version") == [("0004",)]
