"""Built-in pack fixtures (ADR 0006 "Testing packs").

Every rule ships at least one positive and one negative fixture: L0 lines run through the real
adapter on an injected clock, then the worker. Each case asserts exactly which rules fired,
across every loaded pack. A rule without fixtures fails here.
"""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any

import pytest
import yaml

from tests.worker_support import (
    PACKS,
    Clock,
    builtin_rules,
    fired,
    ingest,
    otlp_sum,
    run_worker,
)
from tuisku.store.ingest import Transport


def _fixture_files() -> list[Path]:
    return sorted(PACKS.glob("*/fixtures/*.yaml"))


def _cases() -> list[Any]:
    out = []
    for path in _fixture_files():
        doc = yaml.safe_load(path.read_text())
        pack = path.parent.parent.name
        for i, case in enumerate(doc["cases"]):
            out.append(pytest.param(pack, doc["rule"], case, id=f"{path.stem}[{i}] {case['name']}"))
    return out


def test_every_rule_has_positive_and_negative_fixtures() -> None:
    covered: dict[str, tuple[int, int]] = {}
    for path in _fixture_files():
        doc = yaml.safe_load(path.read_text())
        pos = sum(doc["rule"] in c["fires"] for c in doc["cases"])
        neg = sum(doc["rule"] not in c["fires"] for c in doc["cases"])
        covered[doc["rule"]] = (pos, neg)
    for rule in builtin_rules().rules:
        pos, neg = covered.get(rule.name, (0, 0))
        assert pos >= 1 and neg >= 1, f"{rule.name}: needs positive and negative fixtures"


def _record(record: dict[str, Any]) -> tuple[datetime, bytes, Transport]:
    at = datetime.fromisoformat(record["at"])
    if "raw" in record:
        return at, record["raw"].encode(), Transport.NDJSON
    spec = dict(record["otlp_sum"])
    body = otlp_sum(
        spec.pop("metric"),
        spec.pop("value"),
        time=datetime.fromisoformat(spec.pop("time")),
        start=datetime.fromisoformat(spec.pop("start")) if spec.get("start") else None,
        labels=spec.pop("labels", None),
    )
    spec.pop("start", None)
    assert not spec, f"unknown otlp_sum keys {spec}"
    return at, body, Transport.OTLP_JSON


@pytest.mark.parametrize(("pack", "rule", "case"), _cases())
def test_pack_fixture(
    fresh_database_url: str, tmp_path: Path, pack: str, rule: str, case: dict[str, Any]
) -> None:
    params_file = None
    if case.get("params"):
        params_file = tmp_path / "params.yaml"
        params_file.write_text(json.dumps({pack: case["params"]}))
    rules = builtin_rules(params_file)
    records = [_record(r) for r in case["records"]]
    source = case["source"]
    outcomes = ingest(
        fresh_database_url, "fixture", source["adapter"], records, source.get("options")
    )
    assert all(o == "accepted/ok" for o in outcomes), outcomes
    clock = Clock(max(at for at, _, _ in records))
    failing = case.get("fail_rule")
    if failing is None:
        run_worker(fresh_database_url, rules, clock)
    else:

        def explode(rule: Any, env: Any) -> None:
            if rule.name == failing:
                raise RuntimeError("fixture: this rule fails")

        for _ in range(6):  # five counted attempts, then dead letter, then the meta rule
            run_worker(fresh_database_url, rules, clock, before_pair=explode)
            clock.advance(minutes=1)
    assert fired(fresh_database_url) == sorted(case["fires"])
