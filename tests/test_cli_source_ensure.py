"""`tuisku source ensure`: idempotent, declarative source and token registration."""

from __future__ import annotations

import hashlib
import uuid

import pytest

from tests.conftest import ALEMBIC_INI, AppDatabase
from tests.support import client, ndjson, post_records, query
from tuisku.cli import main
from tuisku.store.tokens import new_source_token

ENV = "TEST_SOURCE_TOKEN"


@pytest.fixture
def env(app_db: AppDatabase, monkeypatch: pytest.MonkeyPatch) -> AppDatabase:
    # Connected as the app role, as `source add` is: no owner rights needed.
    monkeypatch.setenv("TUISKU_DATABASE_URL", app_db.app_url)
    monkeypatch.setenv("TUISKU_ALEMBIC_CONFIG", ALEMBIC_INI)
    return app_db


def _name() -> str:
    return f"e{uuid.uuid4().hex[:10]}"


def _ensure(name: str, *extra: str, adapter: str = "dummy") -> int:
    return main(["source", "ensure", name, "--adapter", adapter, "--token-env", ENV, *extra])


def _state(url: str, name: str) -> list[tuple[object, ...]]:
    return query(
        url,
        "SELECT s.adapter, s.adapter_options, t.token_sha256, t.label FROM sources s "
        "LEFT JOIN source_tokens t ON t.source_id = s.id WHERE s.name = %s ORDER BY t.id",
        (name,),
    )


def test_ensure_creates_registers_and_is_then_a_no_op(
    env: AppDatabase,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    caplog: pytest.LogCaptureFixture,
) -> None:
    name = _name()
    token = new_source_token()
    monkeypatch.setenv(ENV, token)
    options = ["--option", "log=conn", "--option-json", 'local_rules=["a", "b"]']
    assert _ensure(name, *options, "--token-label", "deploy") == 0
    out, err = capsys.readouterr()
    assert out == "" and token not in err and token not in caplog.text
    assert f"created source {name}" in err and "registered token" in err
    state = _state(env.owner_url, name)
    assert [(a, o, bytes(d), lbl) for a, o, d, lbl in state] == [
        (
            "dummy",
            {"log": "conn", "local_rules": ["a", "b"]},
            hashlib.sha256(token.encode()).digest(),
            "deploy",
        )
    ]
    with client(env.app_url) as c:
        assert post_records(c, name, token, ndjson("a")).status_code == 200

    # Every later deploy: same arguments (options in any order), nothing to do.
    assert _ensure(name, *options[2:], *options[:2]) == 0
    out, err = capsys.readouterr()
    assert out == "" and token not in err and "nothing to do" in err
    assert len(_state(env.owner_url, name)) == 1


def test_ensure_adds_a_token_to_an_existing_source(
    env: AppDatabase, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    name = _name()
    assert main(["source", "add", name, "--adapter", "dummy"]) == 0
    first = capsys.readouterr().out.strip()
    rotated = new_source_token()
    monkeypatch.setenv(ENV, rotated)
    assert _ensure(name) == 0
    err = capsys.readouterr().err
    assert "created source" not in err and "registered token" in err
    with client(env.app_url) as c:
        assert post_records(c, name, first, ndjson("a")).status_code == 200
        assert post_records(c, name, rotated, ndjson("b")).status_code == 200


def test_ensure_never_changes_a_source_that_differs(
    env: AppDatabase, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    name = _name()
    monkeypatch.setenv(ENV, new_source_token())
    assert _ensure(name, "--option", "log=conn") == 0
    before = _state(env.owner_url, name)
    capsys.readouterr()
    other_token = new_source_token()
    monkeypatch.setenv(ENV, other_token)
    assert _ensure(name, "--option", "log=conn", adapter="falco") == 1
    assert "adapter 'dummy', not 'falco'" in capsys.readouterr().err
    assert _ensure(name, "--option", "log=dns") == 1
    assert "different adapter options (keys: log)" in capsys.readouterr().err
    assert _ensure(name) == 1
    assert _ensure(name, "--option", "log=conn", "--option", "extra=1") == 1
    assert _ensure(name, "--option-json", "log=1") == 1  # "1" and 1 differ
    numeric = _name()
    assert _ensure(numeric, "--option-json", "n=1") == 0
    assert _ensure(numeric, "--option-json", "n=true") == 1  # true == 1 in Python, not in JSON
    assert "different adapter options (keys: n)" in capsys.readouterr().err
    capsys.readouterr()
    assert _state(env.owner_url, name) == before  # neither the source nor a token added


def test_ensure_refuses_tokens_it_must_not_reuse(
    env: AppDatabase, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    name, other = _name(), _name()
    token = new_source_token()
    monkeypatch.setenv(ENV, token)
    assert _ensure(other) == 0
    capsys.readouterr()
    # The token belongs to another source.
    assert _ensure(name) == 1
    err = capsys.readouterr().err
    assert "registered to another source" in err and token not in err
    # A revoked token is not brought back.
    [(uid,)] = query(
        env.owner_url,
        "SELECT t.uid::text FROM source_tokens t JOIN sources s ON s.id = t.source_id "
        "WHERE s.name = %s",
        (other,),
    )
    assert main(["source", "token", "revoke", other, uid]) == 0
    capsys.readouterr()
    assert _ensure(other) == 1
    assert "was revoked" in capsys.readouterr().err
    # A disabled source is an error, not a silent success that cannot authenticate.
    monkeypatch.setenv(ENV, new_source_token())
    assert main(["source", "disable", other]) == 0
    assert _ensure(other) == 1
    assert "is disabled" in capsys.readouterr().err


@pytest.mark.parametrize(
    "value",
    [None, "", "tsk_src_short", "tsk_op_" + "a" * 43, "not-a-token-at-all-SECRETISH"],
)
def test_ensure_validates_the_token_without_echoing_it(
    env: AppDatabase,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    value: str | None,
) -> None:
    name = _name()
    if value is None:
        monkeypatch.delenv(ENV, raising=False)
    else:
        monkeypatch.setenv(ENV, value)
    assert _ensure(name) == 2
    out, err = capsys.readouterr()
    assert ENV in err
    assert not value or (value not in err and value not in out)
    assert query(env.owner_url, "SELECT count(*) FROM sources WHERE name = %s", (name,)) == [(0,)]


def test_ensure_rejects_an_unknown_adapter(
    env: AppDatabase, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv(ENV, new_source_token())
    assert _ensure(_name(), adapter="nope") == 2
    assert "unknown adapter" in capsys.readouterr().err
