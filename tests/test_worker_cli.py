"""`tuisku worker` and the built-in adapter wiring."""

from __future__ import annotations

from pathlib import Path

import pytest

from tests.conftest import REPO_ROOT
from tests.support import query
from tuisku import adapters, cli
from tuisku.adapters import builtin


def test_builtin_imports_all_four_adapters() -> None:
    assert {a.name for a in builtin.BUILTIN} == {"falco", "harava", "suricata", "zeek"}
    assert {"falco", "harava", "suricata", "zeek"} <= set(adapters.names())


def _env(monkeypatch: pytest.MonkeyPatch, url: str | None = None) -> None:
    monkeypatch.setenv("TUISKU_BUILTIN_PACKS_DIR", str(REPO_ROOT / "packs"))
    if url:
        monkeypatch.setenv("TUISKU_DATABASE_URL", url)


def test_check_packs(monkeypatch: pytest.MonkeyPatch) -> None:
    _env(monkeypatch)
    assert cli.main(["worker", "--check-packs"]) == 0


def test_rejected_pack_exits_2(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    _env(monkeypatch)
    bad = tmp_path / "bad"
    (bad / "rules").mkdir(parents=True)
    (bad / "pack.yaml").write_text("pack: bad\nversion: 1.0.0\nauthorship: local\nlicense: MIT\n")
    (bad / "rules" / "r.yaml").write_text("id: nope\n")
    monkeypatch.setenv("TUISKU_RULE_PACK_PATHS", str(bad))
    assert cli.main(["worker", "--check-packs"]) == 2
    assert "rule packs rejected" in capsys.readouterr().err


def test_worker_once_records_pack_loads(
    fresh_database_url: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    _env(monkeypatch, fresh_database_url)
    assert cli.main(["worker", "--once"]) == 0
    rows = query(
        fresh_database_url, "SELECT pack, max_lookback_seconds FROM pack_loads ORDER BY pack"
    )
    assert rows == [("harava", 25 * 3600), ("sensors-default", 0)]
