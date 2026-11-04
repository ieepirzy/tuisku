"""Revision 0002's append-only tables (ADR 0004 sections 3-4), with the worker running as the
app role: grants refuse UPDATE/DELETE/TRUNCATE to it, triggers refuse them even to the owner,
and event timestamps are forced to the database clock."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

import psycopg
import pytest
from psycopg import errors

from tests.conftest import AppDatabase
from tests.support import query
from tests.worker_support import Clock, builtin_rules, ingest, run_worker
from tuisku.store.ingest import Transport


@pytest.fixture(autouse=True)
def _live_operator(app_db: AppDatabase) -> None:
    """Operator events need a live operator token (ADR 0011)."""
    from tests.worker_support import ensure_test_operator

    ensure_test_operator(app_db.owner_url)


NEW_EVIDENCE_TABLES = [
    "finding_events",
    "finding_detections",
    "finding_overflow_groups",
    "incident_events",
    "incident_findings",
    "rule_firings",
    "pack_loads",
    "notifications",
    "notification_deliveries",
    "triage_requests",
]
_COLUMN = {
    "finding_events": "kind",
    "finding_detections": "linked_at",
    "finding_overflow_groups": "linked_at",
    "incident_events": "kind",
    "incident_findings": "linked_at",
    "rule_firings": "kind",
    "pack_loads": "version",
    "notifications": "kind",
    "notification_deliveries": "status",
    "triage_requests": "status",
}
T = datetime(2026, 11, 1, 10, 0, tzinfo=UTC)
OPERATOR = "00000000-0000-4000-8000-000000000000"  # its token secret is its uid, in tests


def _line(at: datetime, caller: str) -> tuple[datetime, bytes, Transport]:
    stamp = at.strftime("%Y-%m-%d %H:%M:%S,000")
    body = (
        f"{stamp} WARNING harava.api outbound data refused: caller={caller} "
        "urls=1 findings=email/query/plain"
    )
    return at + timedelta(seconds=1), body.encode(), Transport.NDJSON


@pytest.fixture(scope="module")
def worked(app_db: AppDatabase) -> AppDatabase:
    """Rows in every new evidence table, written by the worker connected as the app role."""
    source = f"w{uuid.uuid4().hex[:10]}"
    callers = ["agents", f"s{uuid.uuid4().hex[:6]}", f"t{uuid.uuid4().hex[:6]}"]
    ingest(
        app_db.app_url,
        source,
        "harava",
        [_line(T + timedelta(minutes=i), c) for i, c in enumerate(callers)],
    )
    stats = run_worker(
        app_db.worker_url,
        builtin_rules(),
        Clock(T + timedelta(minutes=5)),
        record_packs=True,
        max_open_findings=1,
    )
    assert stats.failed_pairs == 0
    from tests.worker_support import ensure_test_operator

    ensure_test_operator(app_db.owner_url)  # module scope runs before the autouse fixture
    with psycopg.connect(app_db.app_url) as conn:  # a triage request, as the API makes it
        conn.execute("SELECT set_config('tuisku.operator_token', %s, true)", (OPERATOR,))
        conn.execute(
            "INSERT INTO triage_requests (target, target_uid, status, actor) SELECT 'finding', "
            "uid, 'resolved', %s FROM findings WHERE status = 'open' ORDER BY id DESC LIMIT 1",
            (f"operator:{OPERATOR}",),
        )
    for table in NEW_EVIDENCE_TABLES:
        assert query(app_db.owner_url, f"SELECT count(*) FROM {table}")[0][0] > 0, table
    return app_db


def _attempt(url: str, statement: str) -> Exception | None:
    with psycopg.connect(url) as conn:
        try:
            conn.execute(statement)  # type: ignore[arg-type]
        except psycopg.Error as exc:
            conn.rollback()
            return exc
        conn.rollback()
    return None


def _statement(table: str, op: str) -> str:
    column = _COLUMN[table]
    return {
        "update": f"UPDATE {table} SET {column} = {column}",
        "delete": f"DELETE FROM {table}",
        "truncate": f"TRUNCATE {table} CASCADE",
    }[op]


@pytest.mark.parametrize("table", NEW_EVIDENCE_TABLES)
@pytest.mark.parametrize("op", ["update", "delete", "truncate"])
def test_app_role_cannot_change_new_evidence(worked: AppDatabase, table: str, op: str) -> None:
    exc = _attempt(worked.app_url, _statement(table, op))
    assert isinstance(exc, errors.InsufficientPrivilege)
    assert "permission denied" in str(exc)


@pytest.mark.parametrize("table", NEW_EVIDENCE_TABLES)
@pytest.mark.parametrize("op", ["update", "delete", "truncate"])
def test_triggers_block_the_owner_on_new_evidence(worked: AppDatabase, table: str, op: str) -> None:
    exc = _attempt(worked.owner_url, _statement(table, op))
    assert isinstance(exc, errors.InsufficientPrivilege)
    assert "is append-only" in str(exc)


def test_event_timestamps_come_from_the_database(worked: AppDatabase) -> None:
    with psycopg.connect(worked.worker_url) as conn:
        [(at,)] = conn.execute(
            "INSERT INTO finding_events (finding_id, actor, kind, at) "
            "SELECT id, 'system', 'status_changed', '2000-01-01T00:00:00Z' FROM findings LIMIT 1 "
            "RETURNING at"
        ).fetchall()
        [(now,)] = conn.execute("SELECT now()").fetchall()
        conn.rollback()
    assert at == now
    with psycopg.connect(worked.worker_url) as conn:
        [(at,)] = conn.execute(
            "INSERT INTO incident_events (incident_id, actor, kind, at) "
            "SELECT id, 'system', 'note', '2000-01-01T00:00:00Z' FROM incidents LIMIT 1 "
            "RETURNING at"
        ).fetchall()
        conn.rollback()
    assert at.year != 2000


def test_api_role_triages_but_cannot_write_rule_output(worked: AppDatabase) -> None:
    """ADR 0011: the API role updates findings and incidents and writes operator events; it
    cannot create rule output, firing keys, links, findings or incidents."""
    for statement in [
        # The API's own ingest meta-detection: its kind, a source, the current bucket.
        "INSERT INTO detections (source_id, evaluator, authorship, kind, identity, title, "
        "severity_id, received_at, eval_time, ocsf_version, rule_ref, subject, bucket_start) "
        "SELECT id, 'tuisku', 'tuisku', 'tuisku.meta.source_limit_exceeded', "
        "'tuisku.meta.source_limit_exceeded', 't', 3, now(), now(), '1.9.0', '{}', 'probe', "
        "tuisku_current_bucket() FROM sources LIMIT 1",
    ]:
        assert _attempt(worked.app_url, statement) is None, statement
    for statement in [
        # Round nine: triage is a request (triage_requests); no UPDATE and no event of its own.
        "UPDATE findings SET updated_at = updated_at",
        "UPDATE incidents SET updated_at = updated_at",
        "INSERT INTO finding_events (finding_id, actor, kind) SELECT id, "
        "'operator:00000000-0000-4000-8000-000000000000', 'status_changed' FROM findings LIMIT 1",
        "INSERT INTO findings (fingerprint, rule_id, rule_rev, title, severity_id, first_seen, "
        "last_seen, group_values, rule_ref, window_seconds, max_lifetime_seconds, notify, "
        "created_at, updated_at) SELECT fingerprint, rule_id, 99, title, severity_id, now(), "
        "now(), '[]', '{}', 60, 60, 'each', now(), now() FROM findings LIMIT 1",
        "INSERT INTO incidents (fingerprint, title, severity_id, opened_at, updated_at) "
        "VALUES (sha256('i'), 't', 1, now(), now())",
        "INSERT INTO finding_detections (finding_id, detection_id, linked_at) "
        "SELECT f.id, d.id, now() FROM findings f, detections d LIMIT 1",
        "INSERT INTO incident_findings (incident_id, finding_id, linked_at) "
        "SELECT i.id, f.id, now() FROM incidents i, findings f LIMIT 1",
        "INSERT INTO rule_firings (rule_id, rule_rev, kind, observation_id, group_key, eval_time, "
        "firing_detection_id) SELECT gen_random_uuid(), 1, 'row', o.id, sha256('q'), now(), d.id "
        "FROM observations o, detections d LIMIT 1",
        "INSERT INTO detection_evidence (detection_id, detection_ref_id, linked_at) "
        "SELECT a.id, b.id, now() FROM detections a, detections b LIMIT 1",
        "INSERT INTO notification_deliveries (notification_id, status) "
        "SELECT id, 'delivered' FROM notifications LIMIT 1",
        "INSERT INTO pack_loads (pack, version, authorship, sha256, max_lookback_seconds, rules) "
        "VALUES ('x', '1.0.0', 'local', sha256('x'), 0, '[]')",
        # Triggers: rule-actor events and tuisku detections are the worker's alone.
        "INSERT INTO finding_events (finding_id, actor, kind) SELECT id, 'system', "
        "'status_changed' FROM findings LIMIT 1",
        "INSERT INTO incident_events (incident_id, actor, kind) SELECT id, "
        "'rule:f542db3a-6926-4df9-9183-449491345d3c@1', 'note' FROM incidents LIMIT 1",
        "INSERT INTO detections (evaluator, authorship, kind, identity, title, severity_id, "
        "received_at, eval_time, ocsf_version, rule_ref) VALUES ('tuisku', 'local', 'x.y', "
        "'a74b77e6-92fb-4d32-a9c3-955719118fdb', 't', 0, now(), now(), '1.9.0', '{}')",
        # Meta-shaped, but its identity is a rule id: it could pass for rule output.
        "INSERT INTO detections (evaluator, authorship, kind, identity, title, severity_id, "
        "received_at, eval_time, ocsf_version, rule_ref, subject, bucket_start) VALUES "
        "('tuisku', 'tuisku', 'tuisku.meta.source_limit_exceeded', "
        "'a74b77e6-92fb-4d32-a9c3-955719118fdb', 't', 3, now(), now(), '1.9.0', '{}', 'probe', "
        "now())",
        "INSERT INTO detection_observations (detection_id, observation_id) SELECT d.id, o.id "
        "FROM detections d, observations o WHERE d.evaluator = 'tuisku' AND NOT EXISTS (SELECT 1 "
        "FROM detection_observations l WHERE l.detection_id = d.id AND l.observation_id = o.id) "
        "LIMIT 1",
    ]:
        exc = _attempt(worked.app_url, statement)
        assert isinstance(exc, errors.InsufficientPrivilege), (statement, exc)


def test_worker_role_works_its_tables(worked: AppDatabase) -> None:
    for statement in [
        "DELETE FROM evaluation_dead_letter_rules WHERE false",
        "UPDATE evaluation_attempts SET attempts = attempts",
        "UPDATE findings SET updated_at = updated_at",
    ]:
        assert _attempt(worked.worker_url, statement) is None, statement


def test_live_incident_fingerprint_is_unique(worked: AppDatabase) -> None:
    exc = _attempt(
        worked.worker_url,
        "INSERT INTO incidents (fingerprint, title, severity_id, opened_at, updated_at) "
        "SELECT fingerprint, title, severity_id, now(), now() FROM incidents "
        "WHERE status <> 'closed' LIMIT 1",
    )
    assert isinstance(exc, errors.UniqueViolation)


_FORGED_TIME_INSERTS: dict[str, str | list[str]] = {
    "finding_detections.linked_at": (
        "INSERT INTO finding_detections (finding_id, detection_id, linked_at) "
        "SELECT f.id, d.id, '2000-01-01Z' FROM findings f, detections d "
        "WHERE NOT EXISTS (SELECT 1 FROM finding_detections x WHERE x.detection_id = d.id) "
        "LIMIT 1 RETURNING linked_at"
    ),
    "incident_findings.linked_at": (
        "INSERT INTO incident_findings (incident_id, finding_id, linked_at) "
        "SELECT i.id, f.id, '2000-01-01Z' FROM incidents i, findings f WHERE NOT EXISTS "
        "(SELECT 1 FROM incident_findings x WHERE x.incident_id = i.id AND x.finding_id = f.id) "
        "LIMIT 1 RETURNING linked_at"
    ),
    "finding_overflow_groups.linked_at": (
        "INSERT INTO finding_overflow_groups (finding_id, group_key, group_values, detection_id, "
        "linked_at) SELECT f.id, sha256(gen_random_uuid()::text::bytea), '[]', d.id, "
        "'2000-01-01Z' FROM findings f, detections d LIMIT 1 RETURNING linked_at"
    ),
    "rule_firings.created_at": [
        "INSERT INTO detections (evaluator, authorship, kind, identity, title, severity_id, "
        "received_at, eval_time, ocsf_version, rule_ref) VALUES ('tuisku', 'local', 'testpack.t', "
        "'88888888-8888-4888-8888-888888888888', 't', 1, now(), now(), '1.9.0', '{}')",
        "INSERT INTO detection_observations (detection_id, observation_id) SELECT "
        "(SELECT max(id) FROM detections WHERE identity = '88888888-8888-4888-8888-888888888888'), "
        "(SELECT max(id) FROM observations)",
        "INSERT INTO rule_firings (rule_id, rule_rev, kind, observation_id, group_key, eval_time, "
        "firing_detection_id, created_at) SELECT '88888888-8888-4888-8888-888888888888', 1, "
        "'row', l.observation_id, sha256('t'), now(), l.detection_id, '2000-01-01Z' "
        "FROM detection_observations l JOIN detections d ON d.id = l.detection_id "
        "WHERE d.identity = '88888888-8888-4888-8888-888888888888' RETURNING created_at",
    ],
    "pack_loads.loaded_at": (
        "INSERT INTO pack_loads (pack, version, authorship, sha256, max_lookback_seconds, rules, "
        "loaded_at) VALUES ('x', '1.0.0', 'local', sha256('x'), 0, '[]', '2000-01-01Z') "
        "RETURNING loaded_at"
    ),
    "notification_deliveries.at": (
        "INSERT INTO notification_deliveries (notification_id, status, at) "
        "SELECT id, 'failed', '2000-01-01Z' FROM notifications LIMIT 1 RETURNING at"
    ),
}


@pytest.mark.parametrize("column", sorted(_FORGED_TIME_INSERTS))
def test_link_firing_and_load_timestamps_come_from_the_database(
    worked: AppDatabase, column: str
) -> None:
    statements = _FORGED_TIME_INSERTS[column]
    if isinstance(statements, str):
        statements = [statements]
    with psycopg.connect(worked.worker_url) as conn:
        for statement in statements[:-1]:
            conn.execute(statement)  # type: ignore[arg-type]
        rows = conn.execute(statements[-1]).fetchall()  # type: ignore[arg-type]
        [(now,)] = conn.execute("SELECT now()").fetchall()
        conn.rollback()
    assert rows == [(now,)], column


# --- firing keys: the trigger behind the role split (defence in depth, ADR 0011) -------------

_FRESH_DETECTION = (
    "INSERT INTO detections (evaluator, authorship, kind, identity, title, severity_id, "
    "received_at, eval_time, ocsf_version, rule_ref) VALUES ('tuisku', 'local', 'testpack.x', "
    "'77777777-7777-4777-8777-777777777777', 't', 1, now(), now(), '1.9.0', '{}') RETURNING id"
)
_ROW_KEY = (
    "INSERT INTO rule_firings (rule_id, rule_rev, kind, observation_id, group_key, eval_time, "
    "firing_detection_id) VALUES ('77777777-7777-4777-8777-777777777777', 1, %s, %s, "
    "sha256('z'), now(), %s)"
)


def _an_observation(conn: psycopg.Connection) -> int:
    [(obs,)] = conn.execute("SELECT max(id) FROM observations").fetchall()
    return obs


@pytest.mark.parametrize("kind", ["row", "member", "link"])
def test_a_key_needs_a_link_written_in_this_transaction(worked: AppDatabase, kind: str) -> None:
    """Bypass (a), for the worker role: a throwaway detection in the same transaction is not
    enough; the key's row must be linked to it, in this transaction."""
    with psycopg.connect(worked.worker_url) as conn:
        [(det,)] = conn.execute(_FRESH_DETECTION).fetchall()
        with pytest.raises(errors.CheckViolation, match="not linked"):
            conn.execute(_ROW_KEY, (kind, _an_observation(conn), det))  # type: ignore[arg-type]
        conn.rollback()


def test_a_key_with_a_fresh_link_is_accepted(worked: AppDatabase) -> None:
    with psycopg.connect(worked.worker_url) as conn:  # what the worker itself does
        [(det,)] = conn.execute(_FRESH_DETECTION).fetchall()
        obs = _an_observation(conn)
        conn.execute(
            "INSERT INTO detection_observations (detection_id, observation_id) VALUES (%s, %s)",
            (det, obs),
        )
        with conn.transaction():  # a savepoint, as in the worker
            conn.execute(_ROW_KEY, ("row", obs, det))  # type: ignore[arg-type]
        conn.rollback()


def test_a_link_from_an_earlier_transaction_does_not_count(worked: AppDatabase) -> None:
    """Bypass (b), for the worker role: tie an old detection to the victim, commit, then add a
    member key."""
    with psycopg.connect(worked.worker_url) as conn:
        [(det,)] = conn.execute(_FRESH_DETECTION).fetchall()
        obs = _an_observation(conn)
        conn.execute(
            "INSERT INTO detection_evidence (detection_id, observation_id, linked_at) "
            "VALUES (%s, %s, now())",
            (det, obs),
        )
        conn.commit()  # evidence is append-only: this stays, harmlessly
        with pytest.raises(errors.CheckViolation, match="not linked"):
            conn.execute(_ROW_KEY, ("member", obs, det))  # type: ignore[arg-type]
        conn.rollback()


# --- the reviewer's bypasses, attempted by the API role (ADR 0011) ----------------------------

FALCO_CRITICAL = "a74b77e6-92fb-4d32-a9c3-955719118fdb"


def _falco_line(tag: str) -> bytes:
    import yaml

    from tests.conftest import REPO_ROOT

    doc = yaml.safe_load(
        (REPO_ROOT / "packs/sensors-default/fixtures/falco-critical.yaml").read_text()
    )
    raw: str = doc["cases"][0]["records"][0]["raw"]
    container = uuid.UUID(tag).hex[:12]
    raw = raw.replace("5d0b0f8e-1b7a-4c1e-9d2a-2f0e6c1a9b01", tag).replace("web-1", tag)
    # The main entity (first key) is the host: a fresh one means a fresh finding.
    return raw.replace("3ad7b26ded6d", container).replace("node-1", f"node-{container}").encode()


@pytest.mark.parametrize("bypass", ["a", "b"])
def test_api_role_cannot_hide_a_page(app_db: AppDatabase, bypass: str) -> None:
    from tests.worker_support import RecordingNotifier

    source = f"f{uuid.uuid4().hex[:10]}"
    tag = str(uuid.uuid4())
    at = datetime(2026, 10, 30, 12, 0, 1, tzinfo=UTC)
    ingest(app_db.app_url, source, "falco", [(at, _falco_line(tag), Transport.NDJSON)])
    [(victim, victim_uid)] = query(
        app_db.owner_url,
        "SELECT d.id, d.uid::text FROM detections d JOIN sources s ON s.id = d.source_id "
        "WHERE s.name = %s AND d.evaluator = 'sensor'",
        (source,),
    )
    with psycopg.connect(app_db.app_url) as conn:
        if bypass == "a":  # a throwaway rule detection, then a row key for the victim
            with pytest.raises(errors.InsufficientPrivilege, match="worker role"):
                conn.execute(
                    "INSERT INTO detections (evaluator, authorship, kind, identity, title, "
                    "severity_id, received_at, eval_time, ocsf_version, rule_ref) VALUES "
                    "('tuisku', 'local', 'x.y', %s, 't', 0, now(), now(), '1.9.0', '{}')",
                    (FALCO_CRITICAL,),
                )
            conn.rollback()
        else:  # tie an old rule detection to the victim
            with pytest.raises(errors.InsufficientPrivilege, match="permission denied"):
                conn.execute(
                    "INSERT INTO detection_evidence (detection_id, detection_ref_id, linked_at) "
                    "SELECT max(id), %s, now() FROM detections WHERE evaluator = 'tuisku'",
                    (victim,),
                )
            conn.rollback()
        with pytest.raises(errors.InsufficientPrivilege, match="permission denied"):
            conn.execute(
                "INSERT INTO rule_firings (rule_id, rule_rev, kind, detection_id, group_key, "
                "eval_time, firing_detection_id) SELECT %s, 1, %s, %s, sha256('q'), now(), "
                "max(id) FROM detections WHERE evaluator = 'tuisku'",
                (FALCO_CRITICAL, "row" if bypass == "a" else "member", victim),
            )
        conn.rollback()
    notifier = RecordingNotifier()
    run_worker(app_db.worker_url, builtin_rules(), Clock(at + timedelta(minutes=1)), notifier)
    fired_for_victim = query(
        app_db.owner_url,
        "SELECT count(*) FROM detections WHERE identity = %s "
        "AND explanation -> 'triggered_by' ->> 'uid' = %s",
        (FALCO_CRITICAL, victim_uid),
    )
    assert fired_for_victim == [(1,)]
    assert any(
        n["kind"] == "finding_opened" and n["rule"] == f"{FALCO_CRITICAL}@2" for n in notifier.sent
    )


def test_a_detection_observations_link_from_an_earlier_transaction_does_not_count(
    worked: AppDatabase,
) -> None:
    """Like the detection_evidence case, through the other link table."""
    with psycopg.connect(worked.worker_url) as conn:
        [(det,)] = conn.execute(_FRESH_DETECTION).fetchall()
        obs = _an_observation(conn)
        conn.execute(
            "INSERT INTO detection_observations (detection_id, observation_id) VALUES (%s, %s)",
            (det, obs),
        )
        conn.commit()  # an old link, left behind
        with pytest.raises(errors.CheckViolation, match="not linked"):
            conn.execute(_ROW_KEY, ("member", obs, det))  # type: ignore[arg-type]
        conn.rollback()


@pytest.mark.parametrize(
    ("url", "statements"),
    [
        (
            "app_url",
            [
                f"SELECT set_config('tuisku.operator_token', '{OPERATOR}', true)",
                "INSERT INTO triage_requests (target, target_uid, status, actor, requested_at) "
                f"SELECT 'finding', uid, 'acknowledged', 'operator:{OPERATOR}', '2000-01-01Z' "
                "FROM findings WHERE status = 'open' ORDER BY id LIMIT 1 RETURNING requested_at",
            ],
        ),
        (
            "worker_url",
            [
                "INSERT INTO notifications (dedupe_key, kind, severity_id, payload, created_at) "
                "VALUES ('forged:' || gen_random_uuid(), 'x', 0, '{}', '2000-01-01Z') "
                "RETURNING created_at"
            ],
        ),
    ],
    ids=["triage_requests.requested_at", "notifications.created_at"],
)
def test_request_and_outbox_timestamps_come_from_the_database(
    worked: AppDatabase, url: str, statements: list[str]
) -> None:
    with psycopg.connect(getattr(worked, url)) as conn:
        for statement in statements[:-1]:
            conn.execute(statement)  # type: ignore[arg-type]
        rows = conn.execute(statements[-1]).fetchall()  # type: ignore[arg-type]
        [(now,)] = conn.execute("SELECT now()").fetchall()
        conn.rollback()
    assert rows == [(now,)]


@pytest.mark.parametrize("table", ["finding_events", "incident_events"])
def test_operators_write_only_triage_event_kinds(worked: AppDatabase, table: str) -> None:
    """Behind the grants (the API role has no INSERT on events): given one, in a transaction that
    is rolled back, a live operator still cannot write a non-triage event such as `opened`."""
    parent = "finding_id" if table == "finding_events" else "incident_id"
    source = "findings" if table == "finding_events" else "incidents"
    with psycopg.connect(worked.owner_url) as conn:
        conn.execute(f'GRANT "{worked.app_role}" TO CURRENT_USER')  # type: ignore[arg-type]
        conn.execute(f'GRANT INSERT ON {table} TO "{worked.app_role}"')  # type: ignore[arg-type]
        conn.execute(f'SET LOCAL ROLE "{worked.app_role}"')  # type: ignore[arg-type]
        with pytest.raises(errors.InsufficientPrivilege, match="only triage events"):
            conn.execute(  # type: ignore[arg-type]
                f"INSERT INTO {table} ({parent}, actor, kind) SELECT id, "
                f"'operator:{OPERATOR}', 'opened' FROM {source} LIMIT 1"
            )
        conn.rollback()


def test_revision_0002_needs_the_worker_role_with_an_app_role(
    app_db: AppDatabase, empty_database_url: str
) -> None:
    from alembic import command
    from sqlalchemy import create_engine
    from sqlalchemy.pool import NullPool

    from tests.conftest import make_settings
    from tuisku.migrate import alembic_config, run_migrations, to_sqlalchemy_url

    settings = make_settings(
        empty_database_url, app_role=app_db.app_role, worker_role=app_db.worker_role
    )
    run_migrations(settings, "0001")
    cfg = alembic_config(settings)
    engine = create_engine(to_sqlalchemy_url(settings.require_database_url()), poolclass=NullPool)
    try:
        with engine.connect() as conn:
            cfg.attributes.update(
                connection=conn,
                skip_logging_config=True,
                app_role=app_db.app_role,
                worker_role=None,
            )
            with pytest.raises(ValueError, match="separate worker role is required"):
                command.upgrade(cfg, "0002")
    finally:
        engine.dispose()
