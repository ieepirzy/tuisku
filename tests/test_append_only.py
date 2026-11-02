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
from tests.support import client, ndjson, new_source, post_records, query

EVIDENCE_TABLES = [
    "raw_records",
    "raw_duplicates",
    "parse_attempts",
    "observations",
    "detections",
    "detection_observations",
    "detection_evidence",
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
    assert _attempt(populated.app_url, "UPDATE sources SET disabled_at = disabled_at") is None
    assert _attempt(populated.app_url, "DELETE FROM evaluation_queue WHERE false") is None


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


def test_app_role_still_writes_its_ingest_meta_detections(populated: AppDatabase) -> None:
    with psycopg.connect(populated.app_url) as conn:
        conn.execute(
            _TUISKU_DETECTION.replace("%s)", "now())"),
            ("tuisku.meta.source_limit_exceeded", "tuisku.meta.source_limit_exceeded"),
        )
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
