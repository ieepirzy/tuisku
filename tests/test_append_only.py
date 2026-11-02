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
