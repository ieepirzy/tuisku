"""Pure rule-engine pieces: predicates, field paths, the pack loader, fingerprints, the
incident transition table and the metric delta algorithm."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

from tests.worker_support import PACKS
from tuisku.rules.fingerprint import finding_fingerprint, group_value, overflow_fingerprint
from tuisku.rules.match import match
from tuisku.rules.packs import PackError, load_rule_set
from tuisku.rules.predicates import MISSING, FieldPath, PathError, evaluate, prepare_value
from tuisku.store.lifecycle import INCIDENT_STATES, attachable_at, incident_transition_allowed
from tuisku.worker.metrics import Sample, series_deltas

# --- predicates ---------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("op", "field", "value", "expected"),
    [
        ("eq", "outbound", "outbound", True),
        ("eq", 1, 1.0, True),
        ("eq", "1", 1, False),  # mistyped: positive is false
        ("eq", True, 1, False),  # booleans are not numbers
        ("neq", "a", "b", True),
        ("neq", "a", "a", False),
        ("neq", 1, "1", True),  # mistyped: negative is true
        ("in", "agents", ("agents", "x"), True),
        ("in", ["agents"], ("agents",), False),  # a list is not a member
        ("not_in", "svc", ("agents",), True),
        ("not_in", "agents", ("agents",), False),
        ("not_in", 7, ("agents",), True),
        ("gt", 5, 4, True),
        ("gte", 4, 4, True),
        ("lt", "3", 4, False),
        ("lte", 4.0, 4, True),
        ("contains", "abcdef", "cd", True),
        ("contains", ["ip:1.2.3.4", "x"], "x", True),
        ("contains", {"x": 1}, "x", False),
        ("startswith", "harava.api", "harava.", True),
        ("startswith", 12, "1", False),
        ("exists", 0, None, True),
        ("exists", "", None, True),
    ],
)
def test_predicate_semantics(op: str, field: Any, value: Any, expected: bool) -> None:
    assert evaluate(op, field, value) is expected


@pytest.mark.parametrize(
    "op", ["eq", "in", "gt", "gte", "lt", "lte", "contains", "startswith", "exists", "cidr"]
)
def test_missing_field_makes_positive_predicates_false(op: str) -> None:
    value = {"in": ("a",), "cidr": prepare_value("cidr", "10.0.0.0/8"), "exists": None}.get(op, "a")
    if op in ("gt", "gte", "lt", "lte"):
        value = 1
    assert evaluate(op, MISSING, value) is False


@pytest.mark.parametrize("op", ["neq", "not_in"])
def test_missing_field_makes_negative_predicates_true(op: str) -> None:
    assert evaluate(op, MISSING, ("a",) if op == "not_in" else "a") is True


def test_cidr() -> None:
    nets = prepare_value("cidr", ["10.0.0.0/8", "2001:db8::/32"])
    assert evaluate("cidr", "10.1.2.3", nets)
    assert evaluate("cidr", "::ffff:10.1.2.3", nets)  # IPv4-mapped
    assert evaluate("cidr", "2001:db8::1", nets)
    assert not evaluate("cidr", "192.0.2.1", nets)
    assert not evaluate("cidr", "not an ip", nets)
    assert evaluate("cidr", 167837955, nets) is False


def test_hostile_value_never_raises() -> None:
    class Evil:
        def __eq__(self, other: object) -> bool:
            raise RuntimeError("no")

    assert evaluate("contains", [Evil()], "x") is False
    assert evaluate("not_in", Evil(), ("x",)) is True


def test_field_paths() -> None:
    env = {
        "kind": "k",
        "entity_keys": ["ip:1.2.3.4", "caller:harava/agents"],
        "attributes": {
            "labels": {"stage": "hop"},
            "findings": [{"detector": "email"}],
            "nothing": None,
        },
    }
    assert FieldPath.parse("entity_keys.1").resolve(env) == "caller:harava/agents"
    assert FieldPath.parse("attributes.labels.stage").resolve(env) == "hop"
    assert FieldPath.parse("attributes.findings.0.detector").resolve(env) == "email"
    assert FieldPath.parse("attributes.findings.5.detector").resolve(env) is MISSING
    assert FieldPath.parse("attributes.nothing").resolve(env) is MISSING
    assert FieldPath.parse("attributes.labels.stage.x").resolve(env) is MISSING
    assert FieldPath.parse("identity").resolve(env) is MISSING
    for bad in ["", "attributes", "unmapped.x", "a..b", "source_id", 3]:
        with pytest.raises(PathError):
            FieldPath.parse(bad)


@pytest.mark.parametrize(
    ("op", "value"),
    [
        ("in", "agents"),
        ("in", []),
        ("gt", "5"),
        ("cidr", "10.0.0.0/33"),
        ("eq", [1]),
        ("exists", "yes"),
        ("regex", "x"),
        ("startswith", 1),
    ],
)
def test_predicate_values_are_validated_at_load(op: str, value: Any) -> None:
    with pytest.raises(ValueError):
        prepare_value(op, value)


# --- the loader ---------------------------------------------------------------------------------

RID = "33333333-3333-4333-8333-333333333333"


def _rule(**over: Any) -> dict[str, Any]:
    doc: dict[str, Any] = {
        "id": RID,
        "rev": 1,
        "name": "p.r",
        "title": "t",
        "severity": "low",
        "select": {
            "layer": "observation",
            "kind": "harava.refusal",
            "where": [{"field": "attributes.caller", "op": "in", "value": {"param": "callers"}}],
        },
        "finding": {"group_by": ["attributes.caller"], "window": "1h", "max_lifetime": "1d"},
    }
    doc.update(over)
    return doc


def _pack(tmp_path: Path, *rules: dict[str, Any], params: Any = None, name: str = "p") -> Path:
    root = tmp_path / f"root-{name}"
    pack = root / name
    (pack / "rules").mkdir(parents=True)
    manifest: dict[str, Any] = {
        "pack": name,
        "version": "1.0.0",
        "authorship": "local",
        "license": "MIT",
        "params": params or {"callers": ["agents"]},
    }
    (pack / "pack.yaml").write_text(json.dumps(manifest))
    for i, r in enumerate(rules):
        (pack / "rules" / f"{i}.yaml").write_text(json.dumps(r))
    return root


def test_builtin_packs_load_with_hashes_and_lookback() -> None:
    rs = load_rule_set([], builtin=[PACKS])
    by_id = {p.info.id: p for p in rs.packs}
    assert set(by_id) == {"harava", "sensors-default", "tuisku-meta"}
    assert len(by_id["harava"].info.sha256) == 64
    assert by_id["harava"].max_lookback == timedelta(hours=25)  # (24 + 1) baseline windows
    assert by_id["sensors-default"].max_lookback == timedelta(0)


def test_params_resolve_and_override(tmp_path: Path) -> None:
    root = _pack(tmp_path, _rule())
    [rule] = load_rule_set([root]).rules
    env = {"layer": "observation", "kind": "harava.refusal", "attributes": {"caller": "agents"}}
    assert match(rule, env) is not None
    params = tmp_path / "params.yaml"
    params.write_text("p:\n  callers: [crawler]\n")
    rs = load_rule_set([root], params)
    [rule] = rs.rules
    assert match(rule, env) is None
    assert rule.params_used == {"callers": ["crawler"]}
    assert rs.params_sha256 is not None and len(rs.params_sha256) == 64


@pytest.mark.parametrize(
    ("over", "message"),
    [
        ({"surprise": 1}, "unknown key"),
        ({"id": "not-a-uuid"}, "UUID"),
        ({"name": "other.r"}, "name must be"),
        ({"severity": "huge"}, "severity"),
        ({"attack": ["X1"]}, "ATT&CK"),
        ({"finding": {"window": "8d", "max_lifetime": "9d"}}, "7-day"),
        ({"finding": {"window": "1h", "max_lifetime": "31d"}}, "30-day"),
        (
            {
                "finding": {
                    "window": "1h",
                    "max_lifetime": "1d",
                    "group_by": ["kind", "kind", "kind", "kind", "kind"],
                }
            },
            "at most 4",
        ),
        (
            {
                "finding": {"window": "30m", "max_lifetime": "1d"},
                "correlation": {"type": "event_count", "timespan": "1h", "condition": {"gte": 2}},
            },
            "window must be >= correlation.timespan",
        ),
        (
            {
                "finding": {"window": "1h", "max_lifetime": "1d"},
                "correlation": {"type": "event_count", "timespan": "8d", "condition": {"gte": 2}},
            },
            "7-day",
        ),
        ({"correlation": {"type": "temporal", "timespan": "1h"}}, "correlation.type"),
        (
            {
                "correlation": {
                    "type": "baseline",
                    "timespan": "1h",
                    "baseline": {"windows": 31, "factor": 2},
                }
            },
            "windows must be",
        ),
        (
            {
                "correlation": {
                    "type": "value_sum",
                    "timespan": "1h",
                    "field": "delta",
                    "condition": {"gte": 1},
                }
            },
            "metric.sample only",
        ),
        (
            {
                "select": {
                    "layer": "observation",
                    "kind": "harava.refusal",
                    "where": [{"field": "attributes.x", "op": "eq", "value": {"param": "nope"}}],
                }
            },
            "unknown param",
        ),
        (
            {"select": {"layer": "detection", "kind": "p.r", "include_rule_output": True}},
            "its own output",
        ),
    ],
)
def test_loader_rejects(tmp_path: Path, over: dict[str, Any], message: str) -> None:
    with pytest.raises(PackError, match=message):
        load_rule_set([_pack(tmp_path, _rule(**over))])


def test_loader_rejects_duplicate_yaml_keys(tmp_path: Path) -> None:
    root = _pack(tmp_path, _rule())
    (root / "p" / "rules" / "0.yaml").write_text(
        (root / "p" / "rules" / "0.yaml").read_text().replace('"rev": 1', '"rev": 1, "rev": 2')
    )
    with pytest.raises(PackError, match="duplicate key"):
        load_rule_set([root])


def test_loader_rejects_selection_cycles(tmp_path: Path) -> None:
    a = _rule(name="p.a", select={"layer": "detection", "kind": "p.b", "include_rule_output": True})
    b = _rule(
        id="44444444-4444-4444-8444-444444444444",
        name="p.b",
        select={"layer": "detection", "kind": "p.a", "include_rule_output": True},
    )
    with pytest.raises(PackError, match="cycle"):
        load_rule_set([_pack(tmp_path, a, b)])
    # One direction only is fine.
    b["select"]["include_rule_output"] = False
    assert len(load_rule_set([_pack(tmp_path / "ok", a, b)]).rules) == 2


def test_loader_rejects_reused_ids_and_bad_overrides(tmp_path: Path) -> None:
    with pytest.raises(PackError, match="used twice"):
        load_rule_set([_pack(tmp_path, _rule()), _pack(tmp_path, _rule(name="q.r"), name="q")])
    params = tmp_path / "params.yaml"
    for i, (text, message) in enumerate(
        [
            ("p:\n  callers: agents\n", "must be a list"),
            ("p:\n  other: [x]\n", "unknown param"),
            ("zz:\n  callers: [x]\n", "unknown pack"),
        ]
    ):
        params.write_text(text)
        with pytest.raises(PackError, match=message):
            load_rule_set([_pack(tmp_path / str(i), _rule())], params)


def test_rule_output_is_opt_in_and_never_self_selected(tmp_path: Path) -> None:
    feed = _rule(name="p.feed", select={"layer": "detection", "kind": "p.other"})
    [rule] = load_rule_set([_pack(tmp_path, feed)]).rules
    env = {"layer": "detection", "kind": "p.other", "evaluator": "tuisku", "identity": "x"}
    assert match(rule, env) is None
    meta = _rule(
        name="p.meta", select={"layer": "detection", "kind": "tuisku.meta.evaluation_failed"}
    )
    [rule] = load_rule_set([_pack(tmp_path / "m", meta)]).rules
    env = {"layer": "detection", "kind": "tuisku.meta.evaluation_failed", "evaluator": "tuisku"}
    assert match(rule, env) is not None  # meta-detections are always selectable by kind
    assert match(rule, env | {"identity": rule.id}) is None


# --- fingerprints -------------------------------------------------------------------------------


def test_fingerprint_boundaries_cannot_move() -> None:
    rid = RID
    assert finding_fingerprint(rid, 1, ["a,b"]) != finding_fingerprint(rid, 1, ["a", "b"])
    assert finding_fingerprint(rid, 1, ['a","b']) != finding_fingerprint(rid, 1, ["a", "b"])
    assert finding_fingerprint(rid, 1, [None]) != finding_fingerprint(rid, 1, ["null"])
    missing, null = group_value(MISSING), group_value(None)
    assert finding_fingerprint(rid, 1, [missing]) != finding_fingerprint(rid, 1, [null])
    assert finding_fingerprint(rid, 1, ["x"]) != finding_fingerprint(rid, 2, ["x"])
    assert finding_fingerprint(rid, 1, []) != overflow_fingerprint(rid, 1)
    # Stable across processes: the SHA-256 of JCS ["finding","<id>",1,["agents"]].
    import hashlib

    expected = hashlib.sha256(
        b'["finding","33333333-3333-4333-8333-333333333333",1,["agents"]]'
    ).digest()
    assert finding_fingerprint(rid, 1, ["agents"]) == expected


def test_group_values_are_normalised_without_collisions() -> None:
    import hashlib

    long_a, long_b = "x" * 256 + "a", "x" * 256 + "b"
    assert group_value(long_a) == {
        "prefix": "x" * 256,
        "sha256": hashlib.sha256(long_a.encode()).hexdigest(),
    }
    assert group_value(long_a) != group_value(long_b)  # same prefix, different groups
    assert group_value("x" * 256) == "x" * 256
    assert group_value(MISSING) == {"missing": True}
    assert group_value(None) is None  # an explicit null is not a missing field
    assert group_value(2**60) == {"int": str(2**60)}  # never equal to the string of digits
    assert group_value(2**60) != group_value(str(2**60))
    assert group_value({"b": 1, "a": 2}) == '{"a":2,"b":1}'


# --- incident transitions -----------------------------------------------------------------------


def test_incident_transition_table() -> None:
    allowed = {
        (a, b)
        for a in INCIDENT_STATES
        for b in INCIDENT_STATES
        if incident_transition_allowed(a, b)
    }
    expected = {
        (a, b)
        for i, a in enumerate(INCIDENT_STATES)
        for j, b in enumerate(INCIDENT_STATES)
        if a != "closed" and j > i
    } | {("contained", "investigating"), ("resolved", "investigating")}
    assert allowed == expected


def test_attachable_window_and_lifetime() -> None:
    t0 = datetime(2026, 11, 1, tzinfo=UTC)
    f = {
        "status": "open",
        "first_seen": t0,
        "last_seen": t0 + timedelta(hours=20),
        "window_seconds": 3600,
        "max_lifetime_seconds": 86400,
    }
    assert attachable_at(f, t0 + timedelta(hours=21))
    assert not attachable_at(f, t0 + timedelta(hours=21, seconds=1))  # past the window
    f["last_seen"] = t0 + timedelta(hours=23, minutes=30)
    assert not attachable_at(f, t0 + timedelta(hours=24, seconds=1))  # past the lifetime
    assert not attachable_at(f | {"status": "resolved"}, t0 + timedelta(hours=23, minutes=31))


# --- metric deltas ------------------------------------------------------------------------------


def _s(i: int, minute: int, value: float, start: str | None = "s0", temporality="cumulative"):
    return Sample(
        id=i,
        time=datetime(2026, 11, 1, 10, minute, tzinfo=UTC),
        value=value,
        start_time=start,
        temporality=temporality,
    )


def test_deltas_are_never_negative() -> None:
    never = lambda _s: False  # noqa: E731
    seq = [_s(1, 0, 5, temporality="delta"), _s(2, 10, -1e15, temporality="delta")]
    assert series_deltas(seq, None, never) == {1: 5, 2: 0}
    reset = [_s(1, 0, 10), _s(2, 10, -3)]  # a negative value after a reset counts as zero
    assert series_deltas(reset, None, lambda _s: True) == {1: 10, 2: 0}


def test_series_deltas() -> None:
    never = lambda _s: False  # noqa: E731
    always = lambda _s: True  # noqa: E731
    seq = [_s(1, 0, 10), _s(2, 10, 15), _s(3, 20, 4), _s(4, 30, 7, start="s1")]
    assert series_deltas(seq, None, never) == {1: 0, 2: 5, 3: 4, 4: 7}  # baseline, +5, reset x2
    assert series_deltas(seq, None, always)[1] == 10
    assert series_deltas(seq[1:], seq[0], never) == {2: 5, 3: 4, 4: 7}
    deltas = [_s(1, 0, 3, temporality="delta"), _s(2, 10, 2, temporality="delta")]
    assert series_deltas(deltas, None, never) == {1: 3, 2: 2}


def test_authorship_tuisku_is_reserved_for_builtin_packs(tmp_path: Path) -> None:
    root = _pack(tmp_path, _rule())
    manifest = root / "p" / "pack.yaml"
    manifest.write_text(manifest.read_text().replace('"local"', '"tuisku"'))
    with pytest.raises(PackError, match="reserved"):
        load_rule_set([root])
    assert len(load_rule_set([], builtin=[root]).rules) == 1


def test_deep_yaml_is_a_pack_error(tmp_path: Path) -> None:
    root = _pack(tmp_path, _rule())
    (root / "p" / "rules" / "0.yaml").write_text("[" * 20000 + "]" * 20000)
    with pytest.raises(PackError):
        load_rule_set([root])


def test_merge_keys_order_and_truncation() -> None:
    from tuisku.worker.fold import merge_keys

    keys, cut = merge_keys(["z:1", "a:1"], ["m:1", "b:1", "a:1"], cap=3)
    assert keys == ["z:1", "a:1", "b:1"] and cut
    assert merge_keys(["z:1"], ["b:1"], cap=3) == (["z:1", "b:1"], False)


def test_advisory_locks_are_taken_in_sorted_order() -> None:
    import asyncio

    from tuisku.worker.engine import Worker

    calls: list[int] = []

    class FakeConn:
        async def execute(self, query: str, params: tuple[int]) -> None:
            calls.append(params[0])

    worker = Worker(rule_set=load_rule_set([], builtin=[PACKS]), clock=lambda: datetime.now(UTC))
    asyncio.run(worker._lock(FakeConn(), [9, -4, 3, 1]))  # type: ignore[arg-type]
    assert calls == [-4, 1, 3, 9]


def test_window_filters_push_static_predicates_and_group_values() -> None:
    from psycopg import sql

    from tuisku.worker.engine import window_filters

    rs = load_rule_set([], builtin=[PACKS])
    [trend] = [r for r in rs.rules if r.name == "harava.destination_refused_trend"]
    env = {
        "layer": "observation",
        "kind": "metric.sample",
        "source": "edge",
        "attributes": {"metric": "harava.destination.refused", "labels": {"stage": "hop"}},
    }
    rendered = [f.as_string(None) for f in window_filters(trend, env)]  # type: ignore[arg-type]
    assert rendered == [
        "(t.attributes ->> 'metric') = 'harava.destination.refused'",
        "s.name = 'edge'",
        "(t.attributes #>> '{labels,stage}') = 'hop'",
    ]
    assert isinstance(window_filters(trend, env)[0], sql.Composable)
