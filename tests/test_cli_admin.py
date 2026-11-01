"""`tuisku source ...` and `tuisku operator-token ...`: tokens printed once, only hashes stored."""

from __future__ import annotations

import hashlib
import uuid

import pytest

from tests.conftest import ALEMBIC_INI, AppDatabase
from tests.support import client, ndjson, post_records, query
from tuisku.cli import main
from tuisku.store.tokens import is_operator_token, is_source_token


@pytest.fixture
def env(app_db: AppDatabase, monkeypatch: pytest.MonkeyPatch) -> AppDatabase:
    monkeypatch.setenv("TUISKU_DATABASE_URL", app_db.app_url)
    monkeypatch.setenv("TUISKU_ALEMBIC_CONFIG", ALEMBIC_INI)
    return app_db


def _token(capsys: pytest.CaptureFixture[str]) -> str:
    out, err = capsys.readouterr()
    lines = out.strip().splitlines()
    assert len(lines) == 1, "stdout carries the token and nothing else"
    assert lines[0] not in err
    return lines[0]


def test_source_add_prints_a_token_once_and_stores_only_its_hash(
    env: AppDatabase, capsys: pytest.CaptureFixture[str], caplog: pytest.LogCaptureFixture
) -> None:
    name = f"c{uuid.uuid4().hex[:10]}"
    assert (
        main(
            [
                "source",
                "add",
                name,
                "--adapter",
                "dummy",
                "--option",
                "log=conn",
                "--option-json",
                'local_rules=["a"]',
            ]
        )
        == 0
    )
    token = _token(capsys)
    assert is_source_token(token) and len(token) == len("tsk_src_") + 43
    assert token not in caplog.text
    [(digest, options)] = query(
        env.owner_url,
        "SELECT t.token_sha256, s.adapter_options FROM source_tokens t "
        "JOIN sources s ON s.id = t.source_id WHERE s.name = %s",
        (name,),
    )
    assert bytes(digest) == hashlib.sha256(token.encode()).digest()
    assert options == {"log": "conn", "local_rules": ["a"]}
    stored = query(
        env.owner_url,
        "SELECT count(*) FROM source_tokens WHERE token_sha256::text LIKE %s",
        (f"%{token.encode().hex()}%",),
    )
    assert stored == [(0,)]  # the plaintext appears nowhere in the table
    with client(env.app_url) as c:
        assert post_records(c, name, token, ndjson("a")).status_code == 200


def test_source_token_add_list_revoke_and_disable(
    env: AppDatabase, capsys: pytest.CaptureFixture[str]
) -> None:
    name = f"c{uuid.uuid4().hex[:10]}"
    assert main(["source", "add", name, "--adapter", "dummy"]) == 0
    first = _token(capsys)
    assert main(["source", "token", "add", name, "--label", "rotation"]) == 0
    second = _token(capsys)
    assert first != second
    assert main(["source", "token", "list", name]) == 0
    listing = capsys.readouterr().out
    assert first not in listing and second not in listing and "rotation" in listing
    [(first_uid,)] = query(
        env.owner_url,
        "SELECT t.uid FROM source_tokens t JOIN sources s ON s.id = t.source_id "
        "WHERE s.name = %s ORDER BY t.id LIMIT 1",
        (name,),
    )
    assert main(["source", "token", "revoke", name, str(first_uid)]) == 0
    with client(env.app_url) as c:
        assert post_records(c, name, first, ndjson("a")).status_code == 401
        assert post_records(c, name, second, ndjson("b")).status_code == 200
    assert main(["source", "disable", name]) == 0
    with client(env.app_url) as c:
        assert post_records(c, name, second, ndjson("c")).status_code == 401
    assert main(["source", "token", "revoke", name, str(uuid.uuid4())]) == 1
    assert main(["source", "disable", "no-such-source"]) == 1


def test_source_add_rejects_unknown_adapter(
    env: AppDatabase, capsys: pytest.CaptureFixture[str]
) -> None:
    assert main(["source", "add", "x", "--adapter", "nope"]) == 2
    assert "unknown adapter" in capsys.readouterr().err


def test_operator_token_add(env: AppDatabase, capsys: pytest.CaptureFixture[str]) -> None:
    assert (
        main(["operator-token", "add", "--name", "ops", "--role", "read", "--role", "triage"]) == 0
    )
    token = _token(capsys)
    assert is_operator_token(token)
    [(roles, person)] = query(
        env.owner_url,
        "SELECT roles, person FROM operator_tokens WHERE token_sha256 = %s",
        (hashlib.sha256(token.encode()).digest(),),
    )
    assert sorted(roles) == ["read", "triage"] and person is None


def test_approve_requires_a_person(env: AppDatabase, capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["operator-token", "add", "--name", "x", "--role", "approve"]) == 2
    assert "requires --person" in capsys.readouterr().err
    assert (
        main(
            [
                "operator-token",
                "add",
                "--name",
                "x",
                "--role",
                "approve",
                "--person",
                "Alice Example",
            ]
        )
        == 0
    )
    assert is_operator_token(_token(capsys))


def test_database_rejects_approve_without_person(app_db: AppDatabase) -> None:
    import psycopg

    with psycopg.connect(app_db.app_url) as conn, pytest.raises(psycopg.errors.CheckViolation):
        conn.execute(
            "INSERT INTO operator_tokens (name, roles, token_sha256) "
            "VALUES ('x', ARRAY['approve'], %s)",
            (b"\x00" * 32,),
        )
