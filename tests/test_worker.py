"""Worker mechanisms (ADRs 0006 and 0007) against a real Postgres."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import psycopg
import pytest
from psycopg import AsyncConnection, errors

from tests.support import query
from tests.worker_support import (
    QUIET_BACKLOG,
    Clock,
    RecordingNotifier,
    builtin_rules,
    fired,
    ingest,
    otlp_sum,
    run_async,
    run_worker,
)
from tuisku.rules.packs import Rule, load_rule_set
from tuisku.store.ingest import Transport
from tuisku.worker import engine
from tuisku.worker.engine import Worker, WorkerConfig, _window_rows
from tuisku.worker.metrics import compute_deltas

T = datetime(2026, 11, 1, 10, 0, tzinfo=UTC)
SERVICE_RULE = "harava.service_caller_outbound_refused"


def outbound(at: datetime, caller: str) -> str:
    stamp = at.strftime("%Y-%m-%d %H:%M:%S,000")
    return (
        f"{stamp} WARNING harava.api outbound data refused: caller={caller} "
        "urls=1 findings=email/query/plain"
    )


def lines(*items: tuple[datetime, str]) -> list[tuple[datetime, bytes, Transport]]:
    return [
        (at + timedelta(seconds=1), outbound(at, c).encode(), Transport.NDJSON) for at, c in items
    ]


def write_pack(
    root: Path, rules: list[dict[str, Any]], params: dict[str, Any] | None = None
) -> Path:
    pack = root / "testpack"
    (pack / "rules").mkdir(parents=True)
    manifest = {"pack": "testpack", "version": "0.1.0", "authorship": "local", "license": "MIT"}
    if params:
        manifest["params"] = params
    (pack / "pack.yaml").write_text(json.dumps(manifest))
    for i, rule in enumerate(rules):
        (pack / "rules" / f"r{i}.yaml").write_text(json.dumps(rule))
    return root


def rule_doc(name: str, rid: str, **extra: Any) -> dict[str, Any]:
    doc: dict[str, Any] = {
        "id": rid,
        "rev": 1,
        "name": f"testpack.{name}",
        "title": f"Test {name}",
        "severity": "medium",
        "select": {
            "layer": "observation",
            "kind": "harava.refusal",
            "where": [{"field": "attributes.type", "op": "eq", "value": "outbound"}],
        },
        "finding": {"group_by": ["attributes.caller"], "window": "1h", "max_lifetime": "24h"},
    }
    doc.update(extra)
    return doc


R1 = "11111111-1111-4111-8111-111111111111"
R2 = "22222222-2222-4222-8222-222222222222"


# --- idempotency --------------------------------------------------------------------------------


def test_reevaluating_a_row_never_writes_a_second_detection_or_page(
    fresh_database_url: str,
) -> None:
    url = fresh_database_url
    ingest(url, "h", "harava", lines((T, "agents"), (T + timedelta(minutes=1), "agents")))
    clock = Clock(T + timedelta(minutes=5))
    notifier = RecordingNotifier()
    run_worker(url, builtin_rules(), clock, notifier)
    before = (fired(url), list(notifier.kinds()))
    assert before[0].count("harava.agent_outbound_refused") == 2
    # A second run finds nothing to do.
    assert run_worker(url, builtin_rules(), clock, notifier).claimed == 0
    # Re-enqueue every observation, as if a lease had expired after a worker committed.
    with psycopg.connect(url) as conn:
        conn.execute("INSERT INTO evaluation_queue (observation_id) SELECT id FROM observations")
    stats = run_worker(url, builtin_rules(), clock, notifier)
    assert stats.claimed > 0 and stats.fired == 0
    assert (fired(url), notifier.kinds()) == before
    [(count,)] = query(
        url, "SELECT count FROM findings WHERE rule_ref->>'name' = 'harava.agent_outbound_refused'"
    )
    assert count == 2


def test_firing_key_alone_prevents_duplicates(
    fresh_database_url: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Even when the pre-check is skipped (two workers racing), the unique firing key rolls the
    second evaluation back and nothing is paged twice."""
    url = fresh_database_url
    ingest(url, "h", "harava", lines((T, "agents")))
    clock = Clock(T + timedelta(minutes=5))
    notifier = RecordingNotifier()
    run_worker(url, builtin_rules(), clock, notifier)

    async def never_done(self: Worker, conn: Any, rule: Rule, env: Any) -> bool:
        return False

    monkeypatch.setattr(Worker, "_already_done", never_done)
    with psycopg.connect(url) as conn:
        conn.execute("INSERT INTO evaluation_queue (observation_id) SELECT id FROM observations")
    stats = run_worker(url, builtin_rules(), clock, notifier)
    assert stats.failed_pairs == 0
    assert fired(url) == ["harava.agent_outbound_refused"]
    assert notifier.kinds() == ["finding_opened", "incident_opened"]


def test_expired_lease_is_claimed_again(fresh_database_url: str) -> None:
    url = fresh_database_url
    ingest(url, "h", "harava", lines((T, "agents")))
    clock = Clock(T)
    worker = Worker(
        rule_set=builtin_rules(), clock=clock, notifier=RecordingNotifier(), config=QUIET_BACKLOG
    )
    claimed = run_async(url, worker.claim)  # a worker claims, then crashes
    assert len(claimed) == 2  # the observation and the sensor detection
    assert run_worker(url, builtin_rules(), clock).claimed == 0  # leased
    clock.advance(seconds=121)
    stats = run_worker(url, builtin_rules(), clock)
    # The two claimed rows, plus the rule's own detection, which is enqueued in turn.
    assert stats.claimed == 3 and fired(url) == ["harava.agent_outbound_refused"]
    assert query(url, "SELECT count(*) FROM evaluation_queue")[0][0] == 0


# --- failures -----------------------------------------------------------------------------------


def test_failing_rule_is_dead_lettered_without_hurting_other_rules(
    fresh_database_url: str, tmp_path: Path
) -> None:
    url = fresh_database_url
    rules = load_rule_set([write_pack(tmp_path, [rule_doc("good", R1), rule_doc("bad", R2)])])

    def explode(rule: Rule, env: Any) -> None:
        if rule.id == R2:
            raise RuntimeError("boom")

    ingest(url, "h", "harava", lines((T, "agents")))
    clock = Clock(T)
    for attempt in range(1, 6):
        worker = Worker(
            rule_set=rules,
            clock=clock,
            notifier=RecordingNotifier(),
            before_pair=explode,
            config=QUIET_BACKLOG,
        )
        stats = run_async(url, worker.run_until_idle)
        assert stats.failed_pairs == 1, attempt
        clock.advance(hours=1)  # past the retry backoff
    assert fired(url) == ["testpack.good"]  # written once, on the first attempt
    assert query(url, "SELECT count(*) FROM evaluation_queue")[0][0] == 0
    [(rule_id, attempts, error)] = query(
        url, "SELECT rule_id::text, attempts, last_error FROM evaluation_dead_letter_rules"
    )
    assert (rule_id, attempts, error) == (R2, 5, "RuntimeError")
    [(subject, kind, keys)] = query(
        url,
        "SELECT subject, kind, entity_keys FROM detections WHERE kind LIKE 'tuisku.meta.%'",
    )
    assert (subject, kind, keys) == (R2, "tuisku.meta.evaluation_failed", ["source:h"])


def test_deadlocks_are_retried_without_counting(fresh_database_url: str) -> None:
    url = fresh_database_url
    calls = {"n": 0}

    def deadlock_twice(rule: Rule, env: Any) -> None:
        calls["n"] += 1
        if calls["n"] <= 2:
            raise errors.DeadlockDetected("simulated")

    ingest(url, "h", "harava", lines((T, "agents")))
    worker = Worker(
        rule_set=builtin_rules(),
        clock=Clock(T),
        notifier=RecordingNotifier(),
        before_pair=deadlock_twice,
        config=QUIET_BACKLOG,
    )
    stats = run_async(url, worker.run_until_idle)
    assert stats.failed_pairs == 0 and calls["n"] == 3
    assert fired(url) == ["harava.agent_outbound_refused"]


def test_lock_conflicts_are_uncounted_until_the_cap(fresh_database_url: str) -> None:
    url = fresh_database_url

    def always(rule: Rule, env: Any) -> None:
        raise errors.LockNotAvailable("simulated")

    ingest(url, "h", "harava", lines((T, "agents")))
    clock = Clock(T)
    worker = Worker(
        rule_set=builtin_rules(),
        clock=clock,
        notifier=RecordingNotifier(),
        before_pair=always,
        config=QUIET_BACKLOG,
    )
    stats = run_async(url, worker.run_once)
    assert stats.failed_pairs == 1 and stats.dead_lettered == 0
    assert query(url, "SELECT attempts, transient FROM evaluation_attempts") == [(0, 1)]
    for _ in range(engine.MAX_UNCOUNTED_TRANSIENT - 1):
        clock.advance(minutes=1)
        run_async(url, worker.run_once)
    # The twentieth conflict counts as one attempt, so the pair cannot retry forever.
    assert query(url, "SELECT attempts, transient FROM evaluation_attempts") == [(1, 0)]


def test_lease_expiries_never_burn_attempts(fresh_database_url: str) -> None:
    url = fresh_database_url
    ingest(url, "h", "harava", lines((T, "agents")))
    clock = Clock(T)
    worker = Worker(
        rule_set=builtin_rules(), clock=clock, notifier=RecordingNotifier(), config=QUIET_BACKLOG
    )
    for _ in range(engine.MAX_ATTEMPTS + 2):  # claimed and lost (crash) again and again
        assert len(run_async(url, worker.claim)) == 2
        clock.advance(seconds=121)
    stats = run_worker(url, builtin_rules(), clock)
    assert stats.dead_lettered == 0 and fired(url) == ["harava.agent_outbound_refused"]
    assert query(url, "SELECT count(*) FROM evaluation_dead_letter_rules")[0][0] == 0


# --- caps ---------------------------------------------------------------------------------------


def test_overflow_incident_at_the_live_incident_cap(
    fresh_database_url: str, tmp_path: Path
) -> None:
    url = fresh_database_url
    params = tmp_path / "params.yaml"
    params.write_text(json.dumps({"harava": {"restricted_callers": ["a1", "a2", "a3"]}}))
    ingest(
        url,
        "h",
        "harava",
        lines((T, "a1"), (T + timedelta(minutes=1), "a2"), (T + timedelta(minutes=2), "a3")),
    )
    run_worker(url, builtin_rules(params), Clock(T + timedelta(minutes=5)), max_live_incidents=1)
    rows = query(url, "SELECT overflow, finding_count, title FROM incidents ORDER BY id")
    assert rows == [
        (False, 1, "Agent caller had outbound data refused"),
        (True, 2, "Overflow: Agent caller had outbound data refused"),
    ]
    assert query(url, "SELECT count(*) FROM findings WHERE incident_id IS NULL")[0][0] == 0


# --- correlations -------------------------------------------------------------------------------


def _count_rule(rid: str, *, gte: int = 3, timespan: str = "10m", notify: str = "thresholds"):
    doc = rule_doc(
        "burst",
        rid,
        correlation={"type": "event_count", "timespan": timespan, "condition": {"gte": gte}},
    )
    doc["finding"]["notify"] = notify
    return doc


def test_late_row_is_checked_against_every_window_containing_it(
    fresh_database_url: str, tmp_path: Path
) -> None:
    url = fresh_database_url
    rules = load_rule_set([write_pack(tmp_path, [_count_rule(R1)])])
    clock = Clock(T + timedelta(minutes=9))
    ingest(url, "h", "harava", lines((T, "x"), (T + timedelta(minutes=8), "x")))
    run_worker(url, rules, clock)
    assert fired(url) == []  # two in ten minutes
    # A row stamped 10:05 arrives after 10:08 was evaluated: the window ending 10:08 now holds 3.
    ingest(url, "h", "harava", lines((T + timedelta(minutes=5), "x")))
    clock.advance(minutes=5)
    run_worker(url, rules, clock)
    [(eval_time, corr)] = query(
        url,
        "SELECT eval_time, explanation -> 'correlation' FROM detections WHERE evaluator = 'tuisku'",
    )
    assert eval_time == T + timedelta(minutes=8)
    assert corr["value"] == 3 and corr["condition"] == {"gte": 3}
    assert corr["window_end"] == (T + timedelta(minutes=8)).isoformat()


def test_late_row_outside_every_window_does_not_fire(
    fresh_database_url: str, tmp_path: Path
) -> None:
    url = fresh_database_url
    rules = load_rule_set([write_pack(tmp_path, [_count_rule(R1)])])
    ingest(
        url,
        "h",
        "harava",
        lines((T, "x"), (T + timedelta(minutes=8), "x"), (T - timedelta(minutes=11), "x")),
    )
    run_worker(url, rules, Clock(T + timedelta(minutes=20)))
    assert fired(url) == []


def test_rows_between_firings_are_linked_counted_and_paged(
    fresh_database_url: str, tmp_path: Path
) -> None:
    url = fresh_database_url
    rules = load_rule_set(
        [write_pack(tmp_path, [_count_rule(R1, gte=2, timespan="1h", notify="each")])]
    )
    ingest(url, "h", "harava", lines(*[(T + timedelta(minutes=i), "x") for i in range(11)]))
    notifier = RecordingNotifier()
    run_worker(url, rules, Clock(T + timedelta(minutes=20)), notifier)
    assert fired(url) == ["testpack.burst"]  # fired once at the second row
    [(count,)] = query(url, "SELECT count FROM findings")
    assert count == 11  # the firing's two window rows plus nine linked rows
    assert query(url, "SELECT count(*) FROM detection_evidence")[0][0] == 9
    # Count reaches 10 on the eighth linked row: the threshold pages before that occurrence.
    assert notifier.kinds() == ["finding_opened"] + ["finding_occurrence"] * 7 + [
        "finding_threshold",
        "finding_occurrence",
        "finding_occurrence",
    ]
    # Members of the firing's window are never linked again.
    assert query(url, "SELECT kind, count(*) FROM rule_firings GROUP BY kind ORDER BY kind") == [
        ("correlation", 1),
        ("link", 9),
        ("member", 1),
    ]


# --- findings lifecycle -------------------------------------------------------------------------


def test_expiry_and_lifetime_open_new_findings(fresh_database_url: str) -> None:
    url = fresh_database_url
    clock = Clock(T)
    ingest(url, "h", "harava", lines((T, "svc")))
    run_worker(url, builtin_rules(), clock)
    # 61 minutes later the window (1h) has passed: the sweep expires it, the next opens anew.
    clock.advance(minutes=61)
    ingest(url, "h", "harava", lines((clock.now, "svc")))
    stats = run_worker(url, builtin_rules(), clock)
    assert stats.expired_findings == 1
    assert query(url, "SELECT status, count FROM findings ORDER BY id") == [
        ("expired", 1),
        ("open", 1),
    ]
    [(actor, kind)] = query(
        url,
        "SELECT actor, new_value->>'status' FROM finding_events WHERE kind = 'status_changed'",
    )
    assert (actor, kind) == ("system", "expired")


# --- metric deltas ------------------------------------------------------------------------------


def _metric(at: datetime, value: int, *, start: datetime, stage: str, cls: str = "tunnel"):
    return (
        at + timedelta(seconds=5),
        otlp_sum(
            "harava.destination.refused",
            value,
            time=at,
            start=start,
            labels={"class": cls, "stage": stage},
        ),
        Transport.OTLP_JSON,
    )


@pytest.mark.parametrize("same_start", [True, False])
def test_new_label_set_on_a_long_running_process_counts_in_full(
    fresh_database_url: str, same_start: bool
) -> None:
    url = fresh_database_url
    old = T - timedelta(days=30)
    ingest(url, "h", "harava", [_metric(T, 900, start=old, stage="hop")])
    second_start = old if same_start else old + timedelta(days=1)
    ingest(
        url,
        "h",
        "harava",
        [_metric(T + timedelta(minutes=10), 15, start=second_start, stage="render", cls="overlay")],
    )
    run_worker(url, builtin_rules(), Clock(T + timedelta(minutes=20)))
    expected = ["harava.destination_refused_trend"] if same_start else []
    assert fired(url) == expected


def test_out_of_order_samples_never_double_the_total(fresh_database_url: str) -> None:
    url = fresh_database_url
    start = T - timedelta(seconds=30)
    ingest(
        url,
        "h",
        "harava",
        [
            _metric(T, 0, start=start, stage="hop"),
            _metric(T + timedelta(minutes=40), 10, start=start, stage="hop"),
            _metric(T + timedelta(minutes=20), 6, start=start, stage="hop"),  # arrives late
        ],
    )

    async def deltas(conn: AsyncConnection[Any]) -> list[float]:
        rows = await _window_rows(
            conn,
            "observation",
            "metric.sample",
            T - timedelta(hours=1),
            T + timedelta(hours=1),
            100,
        )
        out = await compute_deltas(conn, rows, timedelta(seconds=60))
        return [out[r["id"]] for r in rows]

    assert run_async(url, deltas) == [0.0, 6.0, 4.0]  # by sample time; sums to 10, not 16


def test_counter_reset_counts_the_new_value(fresh_database_url: str) -> None:
    url = fresh_database_url
    start = T - timedelta(seconds=30)
    ingest(
        url,
        "h",
        "harava",
        [
            _metric(T, 5, start=start, stage="hop"),
            _metric(T + timedelta(minutes=10), 2, start=start, stage="hop"),  # lower: a reset
            _metric(T + timedelta(minutes=20), 3, start=T + timedelta(minutes=15), stage="hop"),
        ],
    )

    async def deltas(conn: AsyncConnection[Any]) -> list[float]:
        rows = await _window_rows(
            conn,
            "observation",
            "metric.sample",
            T - timedelta(hours=1),
            T + timedelta(hours=1),
            100,
        )
        out = await compute_deltas(conn, rows, timedelta(seconds=60))
        return [out[r["id"]] for r in rows]

    assert run_async(url, deltas) == [5.0, 2.0, 3.0]


def test_worker_config_matches_engine_defaults() -> None:
    assert engine.MAX_ATTEMPTS == 5
    assert WorkerConfig().max_open_findings == 1000 and WorkerConfig().max_live_incidents == 100
