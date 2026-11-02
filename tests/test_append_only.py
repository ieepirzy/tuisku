"""Evidence tables are append-only (ADR 0004 sections 3-4).

First line: the app role has only SELECT and INSERT on evidence tables. Second line: row and
statement triggers reject UPDATE, DELETE and TRUNCATE even for the owning role.
"""

from __future__ import annotations

import uuid

import psycopg
import pytest
from psycopg import errors

from tests.conftest import AppDatabase
from tests.support import client, ndjson, new_source, post_records, query, run

EVIDENCE_TABLES = [
    "raw_records",
    "raw_duplicates",
    "parse_attempts",
    "observations",
    "detections",
    "detection_observations",
    "detection_evidence",
    "source_admin_requests",
    "token_revocations",
    "operator_token_revocations",
]


@pytest.fixture(scope="module")
def populated(app_db: AppDatabase) -> AppDatabase:
    """At least one row in every evidence table."""
    name = f"e{uuid.uuid4().hex[:10]}"
    token = new_source(app_db.app_url, name)
    with client(app_db.app_url) as c:
        post_records(c, name, token, ndjson({"detect": 1}))
        post_records(c, name, token, ndjson({"detect": 1}))  # duplicate receipt
    with psycopg.connect(app_db.worker_url) as conn:  # only the worker links (ADR 0011)
        conn.execute(
            "INSERT INTO detection_evidence (detection_id, observation_id, linked_at) "
            "SELECT d.id, l.observation_id, now() FROM detections d "
            "JOIN detection_observations l ON l.detection_id = d.id LIMIT 1"
        )
    # A throwaway source, disabled, with a revoked token: rows in the request tables.
    other = f"x{uuid.uuid4().hex[:10]}"
    new_source(app_db.app_url, other)

    async def requests(conn):  # type: ignore[no-untyped-def]
        from tuisku.store import admin

        [token] = await admin.list_source_tokens(conn, other)
        await admin.revoke_source_token(conn, other, token["uid"])
        from tuisku.store.tokens import Role

        await admin.disable_source(conn, other)
        issued = await admin.create_operator_token(conn, name="gone", roles=[Role.READ])
        await admin.revoke_operator_token(conn, issued.uid)

    run(app_db.app_url, requests)
    for table in EVIDENCE_TABLES:
        assert query(app_db.owner_url, f"SELECT count(*) FROM {table}")[0][0] > 0, table
    return app_db


def _attempt(url: str, statement: str) -> Exception | None:
    with psycopg.connect(url) as conn:
        try:
            conn.execute(statement)
        except psycopg.Error as exc:
            conn.rollback()
            return exc
        conn.rollback()  # never keep a change even if it unexpectedly succeeded
    return None


# A plain (non-identity) column per table, set to itself.
_UPDATE_COLUMN = {
    "raw_records": "received_at",
    "raw_duplicates": "received_at",
    "parse_attempts": "status",
    "observations": "kind",
    "detections": "kind",
    "detection_observations": "detection_id",
    "detection_evidence": "linked_at",
    "source_admin_requests": "action",
    "token_revocations": "revoked_at",
    "operator_token_revocations": "revoked_at",
}


def _update(table: str) -> str:
    column = _UPDATE_COLUMN[table]
    return f"UPDATE {table} SET {column} = {column}"


@pytest.mark.parametrize("table", ["raw_records", "observations", "detections", "parse_attempts"])
@pytest.mark.parametrize("op", ["update", "delete", "truncate"])
def test_app_role_has_no_update_delete_or_truncate(
    populated: AppDatabase, table: str, op: str
) -> None:
    statement = {
        "update": _update(table),
        "delete": f"DELETE FROM {table}",
        "truncate": f"TRUNCATE {table} CASCADE",
    }[op]
    exc = _attempt(populated.app_url, statement)
    assert isinstance(exc, errors.InsufficientPrivilege)
    assert "permission denied" in str(exc)  # the grant refused it, before any trigger


@pytest.mark.parametrize("table", EVIDENCE_TABLES)
@pytest.mark.parametrize("op", ["update", "delete", "truncate"])
def test_triggers_block_even_the_owner(populated: AppDatabase, table: str, op: str) -> None:
    statement = {
        "update": _update(table),
        "delete": f"DELETE FROM {table}",
        "truncate": f"TRUNCATE {table} CASCADE",
    }[op]
    exc = _attempt(populated.owner_url, statement)
    assert isinstance(exc, errors.InsufficientPrivilege)
    assert "is append-only" in str(exc)


def test_app_role_does_not_own_evidence_tables(populated: AppDatabase) -> None:
    owners = query(
        populated.owner_url,
        "SELECT DISTINCT tableowner FROM pg_tables WHERE tablename = ANY(%s)",
        (EVIDENCE_TABLES,),
    )
    assert owners and all(owner != populated.app_role for (owner,) in owners)


def test_app_role_can_change_working_tables(populated: AppDatabase) -> None:
    assert _attempt(populated.app_url, "UPDATE meta_counters SET count = count") is None


@pytest.mark.parametrize(
    "statement",
    [
        # Only the worker claims, updates or deletes queue rows (ADR 0011).
        "DELETE FROM evaluation_queue",
        "UPDATE evaluation_queue SET claimed_until = 'infinity'",
        "SELECT * FROM evaluation_queue",
        "SELECT * FROM evaluation_dead_letter",
        "INSERT INTO evaluation_dead_letter (id, observation_id, enqueued_at, attempts) "
        "SELECT 0, max(id), now(), 0 FROM observations",
        "DELETE FROM meta_counters",
        # Tokens are revoked, never deleted or otherwise changed.
        "DELETE FROM operator_tokens",
        "UPDATE operator_tokens SET name = name",
        "UPDATE operator_tokens SET roles = '{admin}'",
        "UPDATE operator_tokens SET expires_at = NULL",
        # Round ten: revoked only through operator_token_revocations, so never un-revoked.
        "UPDATE operator_tokens SET revoked_at = NULL",
        "UPDATE operator_tokens SET revoked_at = now()",
    ],
)
def test_app_role_cannot_touch_the_queue_or_delete_counters_and_tokens(
    populated: AppDatabase, statement: str
) -> None:
    exc = _attempt(populated.app_url, statement)
    assert isinstance(exc, errors.InsufficientPrivilege), exc
    assert "permission denied" in str(exc)


# --- ADR 0011: only the worker role writes rule output ----------------------------------------

_TUISKU_DETECTION = (
    "INSERT INTO detections (evaluator, authorship, kind, identity, title, severity_id, "
    "received_at, eval_time, ocsf_version, rule_ref, subject, bucket_start) VALUES "
    "('tuisku', 'tuisku', %s, %s, 't', 3, now(), now(), '1.9.0', '{}', 'probe', %s)"
)


@pytest.mark.parametrize(
    ("kind", "identity", "bucketed"),
    [
        ("pack.rule", "a74b77e6-92fb-4d32-a9c3-955719118fdb", False),  # rule output
        ("tuisku.meta.source_limit_exceeded", "a74b77e6-92fb-4d32-a9c3-955719118fdb", True),
        ("tuisku.meta.source_limit_exceeded", "tuisku.meta.source_limit_exceeded", False),
    ],
)
def test_app_role_cannot_write_tuisku_detections(
    populated: AppDatabase, kind: str, identity: str, bucketed: bool
) -> None:
    with psycopg.connect(populated.app_url) as conn:
        with pytest.raises(errors.InsufficientPrivilege, match="worker role"):
            conn.execute(_TUISKU_DETECTION, (kind, identity, "now()" if bucketed else None))
        conn.rollback()


_META = (
    "INSERT INTO detections (source_id, evaluator, authorship, kind, identity, title, "
    "severity_id, received_at, eval_time, ocsf_version, rule_ref, subject, bucket_start) "
    "SELECT {source}, 'tuisku', 'tuisku', %(kind)s, %(kind)s, 't', 3, now(), now(), '1.9.0', "
    "'{{}}', 'probe', tuisku_current_bucket() + %(offset)s::interval FROM sources LIMIT 1"
)


@pytest.mark.parametrize(
    "kind",
    [
        "tuisku.meta.source_limit_exceeded",
        "tuisku.meta.source_rate_limited",
        "tuisku.meta.invalid_envelope",
    ],
)
def test_app_role_still_writes_its_ingest_meta_detections(
    populated: AppDatabase, kind: str
) -> None:
    with psycopg.connect(populated.app_url) as conn:
        conn.execute(_META.format(source="id"), {"kind": kind, "offset": "0"})  # type: ignore[arg-type]
        conn.rollback()


@pytest.mark.parametrize(
    ("kind", "source", "offset"),
    [
        # A future bucket, pre-claimed so a later breach in it is silently absorbed.
        ("tuisku.meta.source_limit_exceeded", "id", "5 minutes"),
        ("tuisku.meta.source_limit_exceeded", "id", "1 day"),
        ("tuisku.meta.source_limit_exceeded", "id", "-5 minutes"),  # only the current one
        # The worker's own meta kinds, even for the current bucket.
        ("tuisku.meta.evaluation_failed", "id", "0"),
        ("tuisku.meta.notification_undeliverable", "id", "0"),
        ("tuisku.meta.evaluation_failed", "id", "1 day"),
        ("tuisku.meta.notification_undeliverable", "id", "1 day"),
        # A meta-detection without a source.
        ("tuisku.meta.source_limit_exceeded", "NULL::bigint", "0"),
    ],
)
def test_app_role_cannot_preclaim_meta_buckets(
    populated: AppDatabase, kind: str, source: str, offset: str
) -> None:
    with psycopg.connect(populated.app_url) as conn:
        with pytest.raises(errors.InsufficientPrivilege, match="worker role"):
            conn.execute(_META.format(source=source), {"kind": kind, "offset": offset})  # type: ignore[arg-type]
        conn.rollback()


def test_worker_role_writes_tuisku_detections_and_links(populated: AppDatabase) -> None:
    with psycopg.connect(populated.worker_url) as conn:
        [(det,)] = conn.execute(
            _TUISKU_DETECTION + " RETURNING id",
            ("pack.rule", "a74b77e6-92fb-4d32-a9c3-955719118fdb", None),
        ).fetchall()
        conn.execute(
            "INSERT INTO detection_observations (detection_id, observation_id) "
            "SELECT %s, max(id) FROM observations",
            (det,),
        )
        conn.rollback()


@pytest.mark.parametrize(
    "statement",
    [
        "INSERT INTO detection_evidence (detection_id, observation_id, linked_at) "
        "SELECT max(d.id), max(o.id), now() FROM detections d, observations o",
        # A link from rule output to evidence, through the table ingest shares.
        "INSERT INTO detection_observations (detection_id, observation_id) "
        "SELECT d.id, o.id FROM detections d, observations o WHERE d.evaluator = 'tuisku' "
        "AND NOT EXISTS (SELECT 1 FROM detection_observations l WHERE l.detection_id = d.id "
        "AND l.observation_id = o.id) LIMIT 1",
    ],
)
def test_app_role_cannot_link_rule_output(populated: AppDatabase, statement: str) -> None:
    with psycopg.connect(populated.worker_url) as conn:  # make sure a rule detection exists
        conn.execute(_TUISKU_DETECTION, ("pack.rule", "a74b77e6-92fb-4d32-a9c3-955719118fdb", None))
    exc = _attempt(populated.app_url, statement)
    assert isinstance(exc, errors.InsufficientPrivilege), exc


# --- derivations come with their raw record (ADR 0011) -------------------------------------------


@pytest.mark.parametrize(
    "statement",
    [
        # The round-five probe: an `ok` attempt that would make the victim's rows stale.
        "INSERT INTO parse_attempts (raw_record_id, adapter, adapter_version, status, "
        "created_at) SELECT max(id), 'dummy', 'x', 'ok', now() FROM raw_records",
        # Fake rows attached to an existing attempt.
        "INSERT INTO observations (raw_record_id, parse_attempt_id, source_id, kind, "
        "received_at, eval_time, ocsf_version, attributes) SELECT p.raw_record_id, p.id, "
        "r.source_id, 'dummy.fake', now(), now(), '1.9.0', '{}' FROM parse_attempts p "
        "JOIN raw_records r ON r.id = p.raw_record_id WHERE p.status = 'ok' LIMIT 1",
        "INSERT INTO detections (raw_record_id, parse_attempt_id, source_id, evaluator, "
        "authorship, kind, identity, title, severity_id, received_at, eval_time, "
        "ocsf_version, rule_ref) SELECT p.raw_record_id, p.id, r.source_id, 'sensor', "
        "'community', 'dummy.fake', 'x', 't', 1, now(), now(), '1.9.0', '{}' "
        "FROM parse_attempts p JOIN raw_records r ON r.id = p.raw_record_id "
        "WHERE p.status = 'ok' LIMIT 1",
        # Existing rows linked to each other.
        # (the trigger runs before the primary key, so even an existing pair is refused by it)
        "INSERT INTO detection_observations (detection_id, observation_id) SELECT d.id, o.id "
        "FROM detections d, observations o WHERE d.evaluator = 'sensor' LIMIT 1",
    ],
)
def test_app_role_cannot_add_to_existing_records(populated: AppDatabase, statement: str) -> None:
    exc = _attempt(populated.app_url, statement)
    assert isinstance(exc, errors.InsufficientPrivilege), exc
    assert "ADR 0011" in str(exc)


@pytest.mark.parametrize(
    "statement",
    [
        "UPDATE sources SET name = 'renamed'",
        "UPDATE sources SET adapter = 'zeek'",
        "UPDATE sources SET adapter_options = '{}'",
        "DELETE FROM sources WHERE false",
        "UPDATE source_tokens SET token_sha256 = token_sha256",
        "UPDATE source_tokens SET source_id = source_id",
        "DELETE FROM source_tokens WHERE false",
        # Queue rows are enqueued fresh, never pre-leased or pre-failed.
        "INSERT INTO evaluation_queue (observation_id, claimed_until) "
        "SELECT max(id), 'infinity' FROM observations",
        "INSERT INTO evaluation_queue (observation_id, attempts) "
        "SELECT max(id), 99 FROM observations",
    ],
)
def test_app_role_cannot_rename_delete_or_preload(populated: AppDatabase, statement: str) -> None:
    exc = _attempt(populated.app_url, statement)
    assert isinstance(exc, errors.InsufficientPrivilege), exc
    assert "permission denied" in str(exc)


def test_app_role_disables_and_revokes_by_request_only(populated: AppDatabase) -> None:
    """Round nine: no UPDATE on sources or source_tokens. A request row, applied at once by an
    owner trigger, disables a source or revokes a token, and authentication honours it."""
    for statement in [
        "UPDATE sources SET disabled_at = disabled_at",
        "UPDATE source_tokens SET revoked_at = revoked_at",
    ]:
        exc = _attempt(populated.app_url, statement)
        assert isinstance(exc, errors.InsufficientPrivilege), statement
    name = f"r{uuid.uuid4().hex[:10]}"
    token = new_source(populated.app_url, name)
    with client(populated.app_url) as c:
        assert post_records(c, name, token, ndjson("a")).status_code == 200
        with psycopg.connect(populated.app_url) as conn:
            conn.execute(
                "INSERT INTO token_revocations (token_id) SELECT t.id FROM source_tokens t "
                "JOIN sources s ON s.id = t.source_id WHERE s.name = %s",
                (name,),
            )
        assert post_records(c, name, token, ndjson("b")).status_code == 401
    other = f"r{uuid.uuid4().hex[:10]}"
    other_token = new_source(populated.app_url, other)
    with psycopg.connect(populated.app_url) as conn:
        conn.execute(
            "INSERT INTO source_admin_requests (source_id, action) "
            "SELECT id, 'disable' FROM sources WHERE name = %s",
            (other,),
        )
    with client(populated.app_url) as c:
        assert post_records(c, other, other_token, ndjson("c")).status_code == 401
    [(disabled,)] = query(
        populated.owner_url, "SELECT disabled_at IS NOT NULL FROM sources WHERE name = %s", (other,)
    )
    assert disabled


def test_app_role_takes_no_row_lock_on_what_the_worker_uses(populated: AppDatabase) -> None:
    """A row lock (FOR UPDATE, FOR SHARE and their KEY variants) needs UPDATE. The app role
    holds UPDATE only on tables the worker never references or updates."""
    updatable = query(
        populated.owner_url,
        "SELECT DISTINCT table_name FROM information_schema.column_privileges "
        "WHERE grantee = %s AND privilege_type = 'UPDATE' ORDER BY 1",
        (populated.app_role,),
    )
    assert [t for (t,) in updatable] == ["meta_counters", "source_token_usage"]
    readable = [
        t
        for (t,) in query(
            populated.owner_url,
            "SELECT c.relname FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace "
            "WHERE n.nspname = 'public' AND c.relkind = 'r' "
            "AND has_table_privilege(%s, c.oid, 'SELECT')",
            (populated.app_role,),
        )
        if t not in ("meta_counters", "source_token_usage")
    ]
    assert "sources" in readable and "source_tokens" in readable
    for table in readable:
        for mode in ("UPDATE", "NO KEY UPDATE", "SHARE", "KEY SHARE"):
            exc = _attempt(populated.app_url, f"SELECT 1 FROM {table} LIMIT 1 FOR {mode}")
            assert isinstance(exc, errors.InsufficientPrivilege), (table, mode, exc)


def test_app_role_limits(populated: AppDatabase) -> None:
    [(limit,)] = query(
        populated.owner_url,
        "SELECT rolconnlimit FROM pg_roles WHERE rolname = %s",
        (populated.app_role,),
    )
    [(config,)] = query(
        populated.owner_url,
        "SELECT setconfig FROM pg_db_role_setting s JOIN pg_roles r ON r.oid = s.setrole "
        "JOIN pg_database d ON d.oid = s.setdatabase WHERE r.rolname = %s "
        "AND d.datname = current_database()",
        (populated.app_role,),
    )
    assert limit == 20
    assert "statement_timeout=30000ms" in config
    assert "idle_in_transaction_session_timeout=60000ms" in config


def test_raw_records_keep_the_source_name_they_arrived_with(populated: AppDatabase) -> None:
    name = f"n{uuid.uuid4().hex[:10]}"
    token = new_source(populated.app_url, name)
    with client(populated.app_url) as c:
        post_records(c, name, token, ndjson({"msg": "named"}))
    with psycopg.connect(populated.owner_url) as conn:  # an owner rename, out of band
        conn.execute("UPDATE sources SET name = %s WHERE name = %s", (name + "x", name))
    [(stored, current)] = query(
        populated.owner_url,
        "SELECT r.source_name, s.name FROM raw_records r JOIN sources s ON s.id = r.source_id "
        "WHERE s.name = %s",
        (name + "x",),
    )
    assert (stored, current) == (name, name + "x")


def test_a_fresh_attempt_cannot_be_pinned_on_another_record(populated: AppDatabase) -> None:
    """Even with a raw record and attempt of its own in the transaction, the API role cannot
    hang rows of that attempt on a victim's raw record."""
    with psycopg.connect(populated.app_url) as conn:
        [(source_id, token_id, victim)] = conn.execute(
            "SELECT r.source_id, r.token_id, r.id FROM raw_records r ORDER BY r.id LIMIT 1"
        ).fetchall()
        [(raw_id,)] = conn.execute(
            "INSERT INTO raw_records (source_id, source_name, token_id, sha256, received_at, "
            "transport, body, body_size) SELECT %s, name, %s, sha256(gen_random_uuid()::text::"
            "bytea), now(), 'ndjson', 'x', 1 FROM sources WHERE id = %s RETURNING id",
            (source_id, token_id, source_id),
        ).fetchall()
        [(attempt,)] = conn.execute(
            "INSERT INTO parse_attempts (raw_record_id, adapter, adapter_version, status, "
            "created_at) VALUES (%s, 'dummy', '0.1.0', 'ok', now()) RETURNING id",
            (raw_id,),
        ).fetchall()
        with pytest.raises(errors.InsufficientPrivilege, match="ADR 0011"):
            conn.execute(
                "INSERT INTO observations (raw_record_id, parse_attempt_id, source_id, kind, "
                "received_at, eval_time, ocsf_version, attributes) VALUES (%s, %s, %s, "
                "'dummy.fake', now(), now(), '1.9.0', '{}')",
                (victim, attempt, source_id),
            )
        conn.rollback()


# --- round six: the queue takes fresh rows only; raw records name their source ----------------


@pytest.mark.parametrize("column", ["observation_id", "detection_id"])
def test_app_role_cannot_enqueue_existing_rows(populated: AppDatabase, column: str) -> None:
    table = "observations" if column == "observation_id" else "detections"
    exc = _attempt(
        populated.app_url,
        f"INSERT INTO evaluation_queue ({column}) SELECT id FROM {table} ORDER BY id LIMIT 1",
    )
    assert isinstance(exc, errors.InsufficientPrivilege), exc
    assert "written in this transaction" in str(exc)


def test_ingest_still_enqueues_what_it_writes(populated: AppDatabase) -> None:
    name = f"q{uuid.uuid4().hex[:10]}"
    token = new_source(populated.app_url, name)
    with client(populated.app_url) as c:
        response = post_records(c, name, token, ndjson({"detect": 1, "msg": "fresh"}))
    assert response.json()["results"][0]["status"] == "accepted"
    [(queued,)] = query(
        populated.owner_url,
        "SELECT count(*) FROM evaluation_queue q JOIN observations o ON o.id = q.observation_id "
        "JOIN sources s ON s.id = o.source_id WHERE s.name = %s",
        (name,),
    )
    assert queued == 1


def test_raw_source_name_is_set_by_the_database(populated: AppDatabase) -> None:
    with psycopg.connect(populated.app_url) as conn:
        [(stored, actual)] = conn.execute(
            "INSERT INTO raw_records (source_id, source_name, token_id, sha256, received_at, "
            "transport, body, body_size) SELECT s.id, 'forged-name', t.id, "
            "sha256(gen_random_uuid()::text::bytea), now(), 'ndjson', 'x', 1 FROM sources s "
            "JOIN source_tokens t ON t.source_id = s.id LIMIT 1 "
            "RETURNING source_name, (SELECT name FROM sources WHERE id = source_id)"
        ).fetchall()
        conn.rollback()
    assert stored == actual != "forged-name"


# --- round seven: no function for PUBLIC, no TEMP, triggers only where they belong -------------


def test_no_tuisku_function_is_executable_by_public(populated: AppDatabase) -> None:
    rows = query(
        populated.owner_url,
        "SELECT p.oid::regprocedure::text FROM pg_proc p JOIN pg_namespace n "
        "ON n.oid = p.pronamespace WHERE n.nspname = 'public' AND p.proname LIKE 'tuisku\\_%%' "
        "AND (p.proacl IS NULL OR EXISTS (SELECT 1 FROM aclexplode(p.proacl) a "
        "WHERE a.grantee = 0 AND a.privilege_type = 'EXECUTE'))",
    )
    assert rows == []
    [(n,)] = query(
        populated.owner_url,
        "SELECT count(*) FROM pg_proc WHERE proname LIKE 'tuisku\\_%%'",
    )
    assert n >= 10  # the enumeration found the functions it checks


def test_the_app_role_executes_only_the_helpers(populated: AppDatabase) -> None:
    rows = query(
        populated.owner_url,
        "SELECT p.proname FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace "
        "WHERE n.nspname = 'public' AND p.proname LIKE 'tuisku\\_%%' "
        "AND has_function_privilege(%s, p.oid, 'EXECUTE') ORDER BY 1",
        (populated.app_role,),
    )
    assert [r[0] for r in rows] == [
        "tuisku_current_bucket",
        "tuisku_is_worker",
        "tuisku_xmin_is_current",
    ]


@pytest.mark.parametrize("role", ["app", "worker"])
def test_runtime_roles_cannot_create_temp_tables(populated: AppDatabase, role: str) -> None:
    url = populated.app_url if role == "app" else populated.worker_url
    exc = _attempt(url, "CREATE TEMP TABLE t (i int)")
    assert isinstance(exc, errors.InsufficientPrivilege), exc


@pytest.mark.parametrize(
    "function",
    [
        "tuisku_person_tokens_owner_only",
        "tuisku_derivation_same_transaction",
        "tuisku_queue_same_transaction",
        "tuisku_raw_source_name",
        "tuisku_detections_worker_only",
        "tuisku_rule_links_worker_only",
        "tuisku_apply_source_request",
        "tuisku_apply_token_revocation",
        "tuisku_operator_revocation_guard",
        "tuisku_apply_operator_revocation",
        "tuisku_force_creation_time",
    ],
)
def test_trigger_functions_refuse_to_run_on_other_tables(
    populated: AppDatabase, function: str
) -> None:
    """Even for a role that may execute them (the owner), on a table of its own."""
    with psycopg.connect(populated.owner_url) as conn:
        conn.execute("CREATE TEMP TABLE elsewhere (i int)")
        conn.execute(  # type: ignore[arg-type]
            f"CREATE TRIGGER t BEFORE INSERT ON elsewhere FOR EACH ROW "
            f"EXECUTE FUNCTION public.{function}()"
        )
        with pytest.raises(errors.InsufficientPrivilege, match="used out of place"):
            conn.execute("INSERT INTO elsewhere VALUES (1)")
        conn.rollback()


# --- round eight: no table locks, counters only its own ------------------------------------------


def test_the_app_role_cannot_lock_any_table(populated: AppDatabase) -> None:
    """LOCK TABLE above ROW EXCLUSIVE needs table-level UPDATE, DELETE or TRUNCATE; the app role
    holds none of them anywhere, so it cannot stall the worker behind a table lock."""
    tables = [
        t
        for (t,) in query(
            populated.owner_url, "SELECT tablename FROM pg_tables WHERE schemaname = 'public'"
        )
        # source_token_usage is the API's own: the worker never reads or references it.
        if t not in ("alembic_version", "source_token_usage")
    ]
    assert "meta_counters" in tables and len(tables) >= 13
    for table in tables:
        for mode in ("SHARE", "EXCLUSIVE", "ACCESS EXCLUSIVE"):
            exc = _attempt(populated.app_url, f"LOCK TABLE {table} IN {mode} MODE")
            assert isinstance(exc, errors.InsufficientPrivilege), (table, mode, exc)
    rows = query(
        populated.owner_url,
        "SELECT table_name, privilege_type FROM information_schema.role_table_grants "
        "WHERE grantee = %s AND privilege_type IN ('UPDATE', 'DELETE', 'TRUNCATE')",
        (populated.app_role,),
    )
    # Only column-level UPDATE grants remain, but for the API's own usage table.
    assert {t for t, _ in rows} <= {"source_token_usage"}


@pytest.mark.parametrize(
    ("kind", "source"),
    [
        ("tuisku.meta.backlog", "id"),
        ("tuisku.meta.evaluation_failed", "id"),
        ("tuisku.meta.source_limit_exceeded", "NULL::bigint"),
    ],
)
def test_app_role_counts_only_its_own_breaches(
    populated: AppDatabase, kind: str, source: str
) -> None:
    exc = _attempt(
        populated.app_url,
        f"INSERT INTO meta_counters (source_id, kind, subject, bucket_start, count) "
        f"SELECT {source}, '{kind}', 'x', now(), 1 FROM sources LIMIT 1",
    )
    assert isinstance(exc, errors.InsufficientPrivilege), exc


def test_app_role_cannot_see_or_lock_worker_counters(populated: AppDatabase) -> None:
    with psycopg.connect(populated.owner_url) as conn:
        conn.execute(
            "INSERT INTO meta_counters (source_id, kind, subject, bucket_start, count) "
            "VALUES (NULL, 'tuisku.meta.backlog', %s, now(), 1)",
            (f"probe-{uuid.uuid4().hex[:6]}",),
        )
    with psycopg.connect(populated.app_url) as conn:
        [(seen,)] = conn.execute(
            "SELECT count(*) FROM meta_counters WHERE kind = 'tuisku.meta.backlog'"
        ).fetchall()
        locked = conn.execute(
            "SELECT 1 FROM meta_counters WHERE kind = 'tuisku.meta.backlog' FOR UPDATE"
        ).fetchall()
        conn.rollback()
    assert seen == 0 and locked == []


def test_the_counter_trigger_holds_without_row_level_security(populated: AppDatabase) -> None:
    """Behind the policy: with row-level security switched off (in a transaction that is rolled
    back), the trigger still refuses the app role a worker counter."""
    with psycopg.connect(populated.owner_url) as conn:
        conn.execute(f'GRANT "{populated.app_role}" TO CURRENT_USER')  # type: ignore[arg-type]
        conn.execute("ALTER TABLE meta_counters DISABLE ROW LEVEL SECURITY")
        conn.execute(f'SET LOCAL ROLE "{populated.app_role}"')  # type: ignore[arg-type]
        with pytest.raises(errors.InsufficientPrivilege, match="its own ingest breaches"):
            conn.execute(
                "INSERT INTO meta_counters (source_id, kind, subject, bucket_start, count) "
                "SELECT id, 'tuisku.meta.backlog', 'x', now(), 1 FROM sources LIMIT 1"
            )
        conn.rollback()


def test_an_operator_revocation_cannot_be_undone(populated: AppDatabase) -> None:
    """Round ten: the API role revokes an operator token by request only; nothing it can do
    brings the token back, and authentication refuses it."""
    import hashlib

    from tuisku.store import admin
    from tuisku.store.tokens import Role

    async def issue(conn):  # type: ignore[no-untyped-def]
        return await admin.create_operator_token(conn, name="t", roles=[Role.TRIAGE])

    issued = run(populated.app_url, issue)

    async def check(conn):  # type: ignore[no-untyped-def]
        return await admin.authenticate_operator_token(conn, issued.token)

    assert run(populated.app_url, check) is not None

    async def revoke(conn):  # type: ignore[no-untyped-def]
        await admin.revoke_operator_token(conn, issued.uid)

    run(populated.app_url, revoke)
    for statement in [
        "UPDATE operator_tokens SET revoked_at = NULL WHERE uid = %(uid)s",
        "DELETE FROM operator_token_revocations",
        "UPDATE operator_token_revocations SET token_id = 0",
    ]:
        with psycopg.connect(populated.app_url) as conn:
            with pytest.raises(errors.InsufficientPrivilege):
                conn.execute(statement, {"uid": issued.uid})  # type: ignore[arg-type]
    assert run(populated.app_url, check) is None
    [(revoked,)] = query(
        populated.owner_url, "SELECT revoked_at FROM operator_tokens WHERE uid = %s", (issued.uid,)
    )
    assert revoked is not None
    # Person-bound tokens are revoked only by the owner, as they are issued (ADR 0005).
    person = str(uuid.uuid4())
    with psycopg.connect(populated.owner_url) as conn:
        conn.execute(
            "INSERT INTO operator_tokens (uid, name, person, roles, token_sha256) "
            "VALUES (%s, 'p', 'A. Person', '{triage}', %s)",
            (person, hashlib.sha256(person.encode()).digest()),
        )
    with psycopg.connect(populated.app_url) as conn:
        with pytest.raises(errors.InsufficientPrivilege, match="only by the database owner"):
            conn.execute(
                "INSERT INTO operator_token_revocations (token_id) SELECT id FROM "
                "operator_tokens WHERE uid = %s",
                (person,),
            )


@pytest.mark.parametrize(
    ("statement", "check"),
    [
        (
            "INSERT INTO operator_tokens (name, roles, token_sha256, created_at, revoked_at) "
            "VALUES ('old', '{triage}', %s, '2020-01-01', '2020-02-01') "
            "RETURNING created_at = now() AND revoked_at = now()",
            True,
        ),
        (
            "INSERT INTO sources (name, adapter, created_at, disabled_at) "
            "VALUES ('b' || md5(%s::text), 'falco', '2019-01-01', '2019-01-02') "
            "RETURNING created_at = now() AND disabled_at = now()",
            True,
        ),
        (
            "INSERT INTO source_tokens (source_id, token_sha256, created_at) "
            "SELECT id, %s, '2019-01-01' FROM sources LIMIT 1 RETURNING created_at = now()",
            True,
        ),
    ],
)
def test_the_api_role_cannot_backdate_what_it_creates(
    populated: AppDatabase, statement: str, check: bool
) -> None:
    import os

    with psycopg.connect(populated.app_url) as conn:
        [(forced,)] = conn.execute(statement, (os.urandom(32),)).fetchall()  # type: ignore[arg-type]
        conn.rollback()
    assert forced is check
