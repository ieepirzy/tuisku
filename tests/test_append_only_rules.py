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
}
T = datetime(2026, 11, 1, 10, 0, tzinfo=UTC)


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
        app_db.app_url,
        builtin_rules(),
        Clock(T + timedelta(minutes=5)),
        record_packs=True,
        max_open_findings=1,
    )
    assert stats.failed_pairs == 0
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
    with psycopg.connect(worked.app_url) as conn:
        [(at,)] = conn.execute(
            "INSERT INTO finding_events (finding_id, actor, kind, at) "
            "SELECT id, 'system', 'status_changed', '2000-01-01T00:00:00Z' FROM findings LIMIT 1 "
            "RETURNING at"
        ).fetchall()
        [(now,)] = conn.execute("SELECT now()").fetchall()
        conn.rollback()
    assert at == now
    with psycopg.connect(worked.app_url) as conn:
        [(at,)] = conn.execute(
            "INSERT INTO incident_events (incident_id, actor, kind, at) "
            "SELECT id, 'system', 'note', '2000-01-01T00:00:00Z' FROM incidents LIMIT 1 "
            "RETURNING at"
        ).fetchall()
        conn.rollback()
    assert at.year != 2000


def test_app_role_can_work_findings_and_incidents(worked: AppDatabase) -> None:
    for statement in [
        "UPDATE findings SET updated_at = updated_at",
        "UPDATE incidents SET updated_at = updated_at",
        "DELETE FROM evaluation_dead_letter_rules WHERE false",
        "UPDATE evaluation_attempts SET attempts = attempts",
    ]:
        assert _attempt(worked.app_url, statement) is None, statement


def test_live_incident_fingerprint_is_unique(worked: AppDatabase) -> None:
    exc = _attempt(
        worked.app_url,
        "INSERT INTO incidents (fingerprint, title, severity_id, opened_at, updated_at) "
        "SELECT fingerprint, title, severity_id, now(), now() FROM incidents "
        "WHERE status <> 'closed' LIMIT 1",
    )
    assert isinstance(exc, errors.UniqueViolation)


_FORGED_TIME_INSERTS = {
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
    "rule_firings.created_at": (
        "INSERT INTO rule_firings (rule_id, rule_rev, kind, observation_id, group_key, eval_time, "
        "firing_detection_id, created_at) SELECT d.identity::uuid, 999, 'link', o.id, "
        "sha256('x'), now(), d.id, '2000-01-01Z' FROM detections d, observations o "
        "WHERE d.evaluator = 'tuisku' AND d.kind NOT LIKE 'tuisku.meta.%%' LIMIT 1 "
        "RETURNING created_at"
    ),
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
    with psycopg.connect(worked.app_url) as conn:
        rows = conn.execute(_FORGED_TIME_INSERTS[column]).fetchall()  # type: ignore[arg-type]
        [(now,)] = conn.execute("SELECT now()").fetchall()
        conn.rollback()
    assert rows == [(now,)], column
