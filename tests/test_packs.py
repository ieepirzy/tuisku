"""Built-in pack fixtures (ADR 0006 "Testing packs"): every rule ships at least one positive and
one negative fixture, and every fixture names a loaded rule and well-formed records. Running
the fixtures through the real adapters and the worker needs the worker, which follows this
change (tests/test_packs.py there replaces this file's structural checks with full runs)."""

from __future__ import annotations

from datetime import datetime
from pathlib import Path

import pytest
import yaml

from tests.conftest import REPO_ROOT
from tuisku.adapters import builtin
from tuisku.rules.packs import load_rule_set

PACKS = REPO_ROOT / "packs"


def _fixture_files() -> list[Path]:
    return sorted(PACKS.glob("*/fixtures/*.yaml"))


def test_every_rule_has_positive_and_negative_fixtures() -> None:
    covered: dict[str, tuple[int, int]] = {}
    for path in _fixture_files():
        doc = yaml.safe_load(path.read_text())
        pos = sum(doc["rule"] in c["fires"] for c in doc["cases"])
        neg = sum(doc["rule"] not in c["fires"] for c in doc["cases"])
        covered[doc["rule"]] = (pos, neg)
    rules = load_rule_set([], builtin=[PACKS]).rules
    assert rules
    for rule in rules:
        pos, neg = covered.get(rule.name, (0, 0))
        assert pos >= 1 and neg >= 1, f"{rule.name}: needs positive and negative fixtures"


@pytest.mark.parametrize("path", _fixture_files(), ids=lambda p: p.stem)
def test_fixtures_are_well_formed(path: Path) -> None:
    names = {r.name for r in load_rule_set([], builtin=[PACKS]).rules}
    adapters = {a.name for a in builtin.BUILTIN}
    doc = yaml.safe_load(path.read_text())
    assert doc["rule"] in names
    for case in doc["cases"]:
        assert set(case["fires"]) <= names, case["name"]
        assert case["source"]["adapter"] in adapters, case["name"]
        for record in case["records"]:
            datetime.fromisoformat(record["at"])
            assert ("raw" in record) != ("otlp_sum" in record), case["name"]
