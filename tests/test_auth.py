"""Source token authentication: every failure is the same 401, unknown sources included."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

import pytest

from tests.conftest import AppDatabase
from tests.support import client, ndjson, new_source, post_records, query, run
from tuisku.store import admin
from tuisku.store.tokens import new_source_token


def _name() -> str:
    return f"a{uuid.uuid4().hex[:10]}"


def _assert_401(response) -> None:
    assert response.status_code == 401
    assert response.json() == {"detail": "invalid credentials"}
    assert response.headers["WWW-Authenticate"] == "Bearer"


def test_valid_token_is_accepted_and_marks_last_used(app_db: AppDatabase) -> None:
    name = _name()
    token = new_source(app_db.app_url, name)
    with client(app_db.app_url) as c:
        assert post_records(c, name, token, ndjson("a")).status_code == 200
    [(last_used,)] = query(
        app_db.owner_url,
        "SELECT t.last_used_at FROM source_tokens t JOIN sources s ON s.id = t.source_id "
        "WHERE s.name = %s",
        (name,),
    )
    assert last_used is not None


@pytest.mark.parametrize(
    "header",
    [
        None,
        "Bearer",
        "Basic dXNlcjpwYXNz",
        "Bearer garbage",
        f"Bearer {new_source_token()}",  # well-formed but unknown
        f"Bearer {new_source_token().replace('tsk_src_', 'tsk_op_')}",
    ],
)
def test_missing_or_garbage_tokens_are_401(app_db: AppDatabase, header: str | None) -> None:
    name = _name()
    new_source(app_db.app_url, name)
    headers = {"Content-Type": "application/x-ndjson"}
    if header is not None:
        headers["Authorization"] = header
    with client(app_db.app_url) as c:
        _assert_401(c.post(f"/v1/sources/{name}/records", content=ndjson("a"), headers=headers))


def test_expired_token_is_401(app_db: AppDatabase) -> None:
    name = _name()
    token = new_source(app_db.app_url, name, expires_at=datetime.now(UTC) - timedelta(seconds=1))
    with client(app_db.app_url) as c:
        _assert_401(post_records(c, name, token, ndjson("a")))


def test_unexpired_token_is_accepted(app_db: AppDatabase) -> None:
    name = _name()
    token = new_source(app_db.app_url, name, expires_at=datetime.now(UTC) + timedelta(hours=1))
    with client(app_db.app_url) as c:
        assert post_records(c, name, token, ndjson("a")).status_code == 200


def test_revoked_token_is_401_and_other_tokens_keep_working(app_db: AppDatabase) -> None:
    name = _name()
    old = new_source(app_db.app_url, name)
    new = run(app_db.app_url, lambda conn: admin.add_source_token(conn, name)).token
    [(old_uid,)] = query(
        app_db.owner_url,
        "SELECT t.uid FROM source_tokens t JOIN sources s ON s.id = t.source_id "
        "WHERE s.name = %s ORDER BY t.id LIMIT 1",
        (name,),
    )
    run(app_db.app_url, lambda conn: admin.revoke_source_token(conn, name, old_uid))
    with client(app_db.app_url) as c:
        _assert_401(post_records(c, name, old, ndjson("a")))
        assert post_records(c, name, new, ndjson("a")).status_code == 200


def test_token_of_another_source_is_401(app_db: AppDatabase) -> None:
    mine, theirs = _name(), _name()
    new_source(app_db.app_url, mine)
    their_token = new_source(app_db.app_url, theirs)
    with client(app_db.app_url) as c:
        _assert_401(post_records(c, mine, their_token, ndjson("a")))


def test_unknown_source_is_401_not_404(app_db: AppDatabase) -> None:
    name = _name()
    token = new_source(app_db.app_url, name)
    with client(app_db.app_url) as c:
        _assert_401(post_records(c, "no-such-source", token, ndjson("a")))
        _assert_401(
            c.post(
                "/v1/sources/no-such-source/otlp/v1/metrics",
                content=b"{}",
                headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
            )
        )


def test_disabled_source_is_401(app_db: AppDatabase) -> None:
    name = _name()
    token = new_source(app_db.app_url, name)
    run(app_db.app_url, lambda conn: admin.disable_source(conn, name))
    with client(app_db.app_url) as c:
        _assert_401(post_records(c, name, token, ndjson("a")))


def test_auth_is_checked_before_the_body_limit(app_db: AppDatabase) -> None:
    name = _name()
    new_source(app_db.app_url, name)
    with client(app_db.app_url, ingest_max_body_bytes=10) as c:
        _assert_401(post_records(c, name, new_source_token(), b"x" * 100))
