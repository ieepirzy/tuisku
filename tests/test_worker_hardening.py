"""Hardening from review: bounded windows, dead letters that page, overlap-aware firing,
notifier isolation, a resilient worker loop, triage edge cases, the re-evaluation guard."""

from __future__ import annotations

import ast
import asyncio
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import psycopg
import pytest
from psycopg import errors

from tests.conftest import REPO_ROOT, make_settings
from tests.support import auth, client, operator_token, query
from tests.test_worker import R1, _count_rule, _metric, lines, rule_doc, write_pack
from tests.worker_support import (
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
from tuisku.store import lifecycle
from tuisku.store.ingest import Transport, enqueue
from tuisku.store.tokens import Role
from tuisku.worker import notify, run
from tuisku.worker.engine import Stats, Worker, WorkerConfig

T = datetime(2026, 11, 1, 10, 0, tzinfo=UTC)
TREND = "harava.destination_refused_trend"


# --- 1. windows are read narrowly and never truncated ---------------------------------------------


def _other_metric(at: datetime, value: int) -> tuple[datetime, bytes, Transport]:
    body = otlp_sum(
        "harava.outbound.refused",
        value,
        time=at,
        start=T - timedelta(seconds=30),
        labels={"detector": "email", "location": "query", "encoding": "plain"},
    )
    return at + timedelta(seconds=5), body, Transport.OTLP_JSON


def test_other_series_cannot_crowd_a_window_out(fresh_database_url: str) -> None:
    url = fresh_database_url
    start = T - timedelta(seconds=30)
    # Many samples of another metric, all in the same hour, older than the trend samples.
    ingest(url, "h", "harava", [_other_metric(T + timedelta(seconds=i), i) for i in range(20)])
    ingest(
        url,
        "h",
        "harava",
        [
            _metric(T + timedelta(minutes=10), 4, start=start, stage="hop"),
            _metric(T + timedelta(minutes=20), 12, start=start, stage="hop"),
        ],
    )
    stats = run_worker(url, builtin_rules(), Clock(T + timedelta(minutes=30)), max_window_rows=3)
    assert stats.failed_pairs == 0
    assert fired(url) == [TREND]


def test_a_window_over_the_cap_fails_instead_of_truncating(fresh_database_url: str) -> None:
    url = fresh_database_url
    start = T - timedelta(seconds=30)
    ingest(
        url,
        "h",
        "harava",
        [
            _metric(T + timedelta(minutes=i), 3 * (i + 1), start=start, stage="hop")
            for i in range(5)
        ],
    )
    stats = run_worker(url, builtin_rules(), Clock(T + timedelta(minutes=10)), max_window_rows=3)
    assert stats.failed_pairs == 5 and fired(url) == []  # counted failures, nothing partial
    errors_ = query(url, "SELECT DISTINCT last_error FROM evaluation_attempts")
    assert errors_ == [("WindowTooLarge",)]


# --- 3. dead letters page, and a built-in rule selects them ---------------------------------------


def test_dead_letter_pages_and_the_meta_rule_fires(fresh_database_url: str) -> None:
    url = fresh_database_url
    ingest(url, "h", "harava", lines((T, "agents")))
    clock = Clock(T)
    notifier = RecordingNotifier()

    def explode(rule: Rule, env: Any) -> None:
        if rule.name == "harava.agent_outbound_refused":
            raise RuntimeError("boom")

    for _ in range(6):
        run_worker(url, builtin_rules(), clock, notifier, before_pair=explode)
        clock.advance(minutes=1)
    kinds = notifier.kinds()
    assert kinds.count("evaluation_dead_lettered") == 1
    dead = next(n for n in notifier.sent if n["kind"] == "evaluation_dead_lettered")
    assert dead["rule_name"] == "harava.agent_outbound_refused" and dead["attempts"] == 5
    assert fired(url) == ["tuisku-meta.evaluation_failed"]
    assert "finding_opened" in kinds  # the meta rule's finding (notify: each)


# --- 5. a late row never fires twice over evidence an older firing covers -------------------------


def test_late_row_does_not_refire_over_an_older_firing(
    fresh_database_url: str, tmp_path: Path
) -> None:
    url = fresh_database_url
    rules = load_rule_set([write_pack(tmp_path, [_count_rule(R1, gte=2, timespan="10m")])])
    clock = Clock(T + timedelta(minutes=2))
    ingest(url, "h", "harava", lines((T, "x"), (T + timedelta(minutes=1), "x")))
    run_worker(url, rules, clock)  # firing A at 10:01
    later = T + timedelta(minutes=55)
    ingest(url, "h", "harava", lines((later, "x"), (later + timedelta(minutes=1), "x")))
    clock.now = later + timedelta(minutes=2)
    run_worker(url, rules, clock)  # firing B at 10:56, the newest by id
    assert fired(url) == ["testpack.burst"] * 2
    # A row stamped 10:05 arrives: its window holds three rows, but A (10:01) overlaps it and
    # A's finding is still attachable, so it links instead of firing a third time.
    ingest(url, "h", "harava", lines((T + timedelta(minutes=5), "x")))
    clock.advance(minutes=1)
    stats = run_worker(url, rules, clock)
    assert fired(url) == ["testpack.burst"] * 2
    assert stats.linked == 1


# --- 7. notifier failures are isolated; the worker loop survives a bad pass -----------------------


class FlakyNotifier(RecordingNotifier):
    def deliver(self, notification: dict[str, Any]) -> None:
        if notification["kind"] == "incident_opened":
            raise ConnectionError("pager down")
        super().deliver(notification)


def test_one_bad_notification_does_not_block_the_rest(fresh_database_url: str) -> None:
    url = fresh_database_url
    ingest(url, "h", "harava", lines((T, "agents"), (T + timedelta(minutes=1), "agents")))
    notifier = FlakyNotifier()
    run_worker(url, builtin_rules(), Clock(T + timedelta(minutes=5)), notifier)
    assert notifier.kinds() == ["finding_opened", "finding_occurrence"]
    # Each pass drains once: the failing one is recorded and retried, the others delivered.
    rows = dict(query(url, "SELECT status, count(*) FROM notification_deliveries GROUP BY status"))
    assert rows["delivered"] == 2 and rows["failed"] >= 1


def test_undeliverable_notification_alerts_and_keeps_retrying(fresh_database_url: str) -> None:
    url = fresh_database_url
    ingest(url, "h", "harava", lines((T, "agents")))
    notifier = FlakyNotifier()  # incident_opened never delivers
    backoff = notify.Backoff(base_seconds=0, cap_seconds=0)
    clock = Clock(T + timedelta(minutes=5))
    for _ in range(notify.ALERT_AFTER_FAILURES + 5):
        run_worker(url, builtin_rules(), clock, notifier, notify_backoff=backoff)
    [(failed,)] = query(url, "SELECT count(*) FROM notification_deliveries WHERE status = 'failed'")
    assert failed > notify.ALERT_AFTER_FAILURES  # never given up
    metas = query(
        url,
        "SELECT subject FROM detections WHERE kind = 'tuisku.meta.notification_undeliverable'",
    )
    assert metas == [("incident_opened",)]  # raised once
    assert "tuisku-meta.notification_undeliverable" in fired(url)


def test_failed_delivery_waits_for_its_backoff(fresh_database_url: str) -> None:
    url = fresh_database_url
    ingest(url, "h", "harava", lines((T, "agents")))
    notifier = FlakyNotifier()
    backoff = notify.Backoff(base_seconds=3600, cap_seconds=3600)
    clock = Clock(T + timedelta(minutes=5))
    for _ in range(5):  # many passes, one failure: the retry is an hour away
        run_worker(url, builtin_rules(), clock, notifier, notify_backoff=backoff)
    [(failed,)] = query(url, "SELECT count(*) FROM notification_deliveries WHERE status = 'failed'")
    assert failed == 1


def test_short_outage_on_a_busy_queue_loses_nothing(fresh_database_url: str) -> None:
    """Many notifications, a notifier that is down for a moment, and a worker draining in a
    tight loop: every notification arrives exactly once and nothing is escalated."""
    import time

    url = fresh_database_url
    callers = [f"svc-{i}" for i in range(30)]
    ingest(
        url, "h", "harava", lines(*[(T + timedelta(seconds=i), c) for i, c in enumerate(callers)])
    )
    down_until = time.monotonic() + 1.5

    class Outage(RecordingNotifier):
        def deliver(self, notification: dict[str, Any]) -> None:
            if time.monotonic() < down_until:
                raise ConnectionError("pager restarting")
            super().deliver(notification)

    notifier = Outage()
    backoff = notify.Backoff(base_seconds=0.05, cap_seconds=0.5)
    clock = Clock(T + timedelta(minutes=5))
    deadline = time.monotonic() + 15
    run_worker(url, builtin_rules(), clock, notifier, notify_backoff=backoff)
    while time.monotonic() < deadline:
        [(pending,)] = query(
            url,
            "SELECT count(*) FROM notifications n WHERE NOT EXISTS (SELECT 1 FROM "
            "notification_deliveries d WHERE d.notification_id = n.id AND d.status = 'delivered')",
        )
        if pending == 0 and time.monotonic() > down_until:
            break
        run_async(url, lambda conn: notify.drain(conn, notifier, T, backoff=backoff))
    [(total,)] = query(url, "SELECT count(*) FROM notifications")
    assert total == 30  # one finding_opened per caller (service-caller rule)
    uids = [n["uid"] for n in notifier.sent]
    assert len(uids) == total and len(set(uids)) == total
    [(max_failures,)] = query(
        url,
        "SELECT coalesce(max(c), 0) FROM (SELECT count(*) AS c FROM notification_deliveries "
        "WHERE status = 'failed' GROUP BY notification_id) x",
    )
    # Waits of 0.05, 0.1, 0.2, 0.4, 0.5 s... fit at most 6 failures into a 1.5 s outage, however
    # often the worker drains; without backoff a tight loop burns the whole retry budget.
    assert max_failures <= 7
    assert query(url, "SELECT count(*) FROM detections WHERE kind LIKE 'tuisku.meta.%'") == [(0,)]


def test_worker_loop_survives_a_failing_pass(
    fresh_database_url: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls = {"n": 0}

    class Stop(BaseException):
        pass

    async def flaky(self: Worker, conn: Any, max_passes: int = 100) -> Stats:
        calls["n"] += 1
        if calls["n"] == 1:
            raise RuntimeError("database hiccup")
        if calls["n"] == 3:
            raise Stop()
        return Stats()

    async def no_sleep(_seconds: float) -> None:
        return None

    monkeypatch.setattr(Worker, "run_until_idle", flaky)
    monkeypatch.setattr(run.asyncio, "sleep", no_sleep)
    settings = make_settings(fresh_database_url, builtin_packs_dir=str(REPO_ROOT / "packs"))
    with pytest.raises(Stop):
        run.run_worker(settings)
    assert calls["n"] == 3  # failed, recovered, carried on


# --- 6 and 11. triage -----------------------------------------------------------------------------


def _one_finding(url: str, clock: Clock) -> str:
    ingest(url, "h", "harava", lines((clock.now, "agents")))
    run_worker(url, builtin_rules(), clock)
    [(uid,)] = query(url, "SELECT uid::text FROM findings")
    return uid


def test_resuppression_cannot_extend_past_thirty_days(fresh_database_url: str) -> None:
    url = fresh_database_url
    clock = Clock(T)
    uid = _one_finding(url, clock)
    triager = operator_token(url, Role.TRIAGE)
    path = f"/v1/findings/{uid}/status"

    def suppress(c: Any, until: datetime) -> int:
        body = {"status": "suppressed", "reason": "noisy", "suppressed_until": until.isoformat()}
        return c.post(path, json=body, headers=auth(triager)).status_code

    with client(url, clock=lambda: clock.now) as c:
        assert suppress(c, T + timedelta(days=20)) == 200
        clock.advance(days=15)
        assert suppress(c, T + timedelta(days=31)) == 409  # 30 days from the first suppression
        assert suppress(c, T + timedelta(days=30)) == 200


def test_triage_input_validation(fresh_database_url: str) -> None:
    url = fresh_database_url
    clock = Clock(T)
    uid = _one_finding(url, clock)
    [(incident,)] = query(url, "SELECT uid::text FROM incidents")
    triager = operator_token(url, Role.TRIAGE)
    with client(url, clock=lambda: clock.now) as c:
        r = c.post(
            f"/v1/findings/{uid}/status",
            json={"status": "suppressed", "reason": "x", "suppressed_until": "2026-11-01T12:00:00"},
            headers=auth(triager),
        )
        assert r.status_code == 400  # naive timestamp
        for body in (
            {"status": "acknowledged", "reason": "   "},
            {"status": "resolved", "reason": ""},
        ):
            assert (
                c.post(f"/v1/findings/{uid}/status", json=body, headers=auth(triager)).status_code
                == 422
            )
        r = c.post(
            f"/v1/incidents/{incident}/status",
            json={"status": "triaged", "reason": "\n"},
            headers=auth(triager),
        )
        assert r.status_code == 422


def test_thresholds_crossed_while_suppressed_page_when_it_lifts(fresh_database_url: str) -> None:
    url = fresh_database_url
    clock = Clock(T)
    uid = _one_finding(url, clock)
    triager = operator_token(url, Role.TRIAGE)
    with client(url, clock=lambda: clock.now) as c:
        body = {
            "status": "suppressed",
            "reason": "maintenance",
            "suppressed_until": (T + timedelta(minutes=30)).isoformat(),
        }
        assert (
            c.post(f"/v1/findings/{uid}/status", json=body, headers=auth(triager)).status_code
            == 200
        )
    notifier = RecordingNotifier()
    ingest(
        url, "h", "harava", lines(*[(T + timedelta(minutes=1 + i), "agents") for i in range(10)])
    )
    clock.advance(minutes=15)
    run_worker(url, builtin_rules(), clock, notifier)
    assert notifier.sent == [] and query(url, "SELECT count FROM findings") == [(11,)]
    clock.advance(minutes=20)  # the suppression expires in the sweep; the window has not
    run_worker(url, builtin_rules(), clock, notifier)
    assert [(n["kind"], n["threshold"]) for n in notifier.sent] == [("finding_threshold", 10)]


def test_api_retries_a_deadlock(fresh_database_url: str, monkeypatch: pytest.MonkeyPatch) -> None:
    url = fresh_database_url
    clock = Clock(T)
    _one_finding(url, clock)
    [(incident,)] = query(url, "SELECT uid::text FROM incidents")
    real = lifecycle.operator_incident_status
    calls = {"n": 0}

    async def once_deadlocked(*args: Any, **kwargs: Any) -> Any:
        calls["n"] += 1
        if calls["n"] == 1:
            raise errors.DeadlockDetected("simulated")
        return await real(*args, **kwargs)

    monkeypatch.setattr(lifecycle, "operator_incident_status", once_deadlocked)
    triager = operator_token(url, Role.TRIAGE)
    with client(url, clock=lambda: clock.now) as c:
        r = c.post(
            f"/v1/incidents/{incident}/status", json={"status": "triaged"}, headers=auth(triager)
        )
    assert r.status_code == 200 and calls["n"] == 2


# --- 12. overflow notifications carry hashes, not raw group values --------------------------------


def test_overflow_notification_carries_the_group_hash(fresh_database_url: str) -> None:
    url = fresh_database_url
    ingest(url, "h", "harava", lines((T, "svc-a"), (T + timedelta(minutes=1), "svc-secret")))
    notifier = RecordingNotifier()
    run_worker(url, builtin_rules(), Clock(T + timedelta(minutes=5)), notifier, max_open_findings=1)
    [overflow] = [n for n in notifier.sent if n["kind"] == "finding_overflow_group"]
    assert len(overflow["group_key"]) == 64 and "group_values" not in overflow
    assert overflow["entity_keys"] == ["caller:harava/svc-secret"]


# --- 8. a forged firing key is refused ------------------------------------------------------------


def test_firing_key_must_name_its_own_rules_detection(fresh_database_url: str) -> None:
    url = fresh_database_url
    _one_finding(url, Clock(T))
    with pytest.raises(errors.CheckViolation, match="not output of rule"):
        query(
            url,
            "INSERT INTO rule_firings (rule_id, rule_rev, kind, observation_id, group_key, "
            "eval_time, firing_detection_id) SELECT gen_random_uuid(), 1, 'member', o.id, "
            "sha256('x'), now(), d.id FROM detections d, observations o "
            "WHERE d.evaluator = 'tuisku' LIMIT 1 RETURNING id",
        )


# --- 17. re-evaluation needs its suppression first ------------------------------------------------


def test_reevaluation_enqueue_is_refused() -> None:
    with pytest.raises(NotImplementedError, match="re-evaluation suppression"):
        asyncio.run(
            enqueue(None, observation_ids=[1], detection_ids=[], enqueued_at=T, reevaluation=True)  # type: ignore[arg-type]
        )


def test_only_new_rows_are_enqueued() -> None:
    """Every enqueue call site enqueues rows it has just inserted. A reprocessing path that
    re-enqueues existing rows must first build ADR 0006's re-evaluation suppression; adding a
    call site here without it fails this test on purpose."""
    allowed = {
        ("store/ingest.py", "_insert_derived"),
        ("store/meta.py", "_record"),
        ("worker/engine.py", "_fire"),
    }
    found = set()
    src = REPO_ROOT / "src" / "tuisku"
    for path in src.rglob("*.py"):
        tree = ast.parse(path.read_text())
        for func in ast.walk(tree):
            if not isinstance(func, ast.FunctionDef | ast.AsyncFunctionDef):
                continue
            for node in ast.walk(func):
                if isinstance(node, ast.Call) and getattr(node.func, "id", None) == "enqueue":
                    found.add((path.relative_to(src).as_posix(), func.name))
                if isinstance(node, ast.Constant) and isinstance(node.value, str):
                    if "INSERT INTO evaluation_queue" in node.value and func.name != "enqueue":
                        found.add((path.relative_to(src).as_posix(), func.name))
    assert found == allowed


# --- round 2: late rows never expire a live finding; value_count skips missing fields ---------


def test_late_row_attaches_without_expiring_or_unsuppressing(fresh_database_url: str) -> None:
    url = fresh_database_url
    clock = Clock(T)
    uid = _one_finding(url, clock)  # agents, first_seen 10:00, window 1h
    triager = operator_token(url, Role.TRIAGE)
    with client(url, clock=lambda: clock.now) as c:
        body = {
            "status": "suppressed",
            "reason": "maintenance",
            "suppressed_until": (T + timedelta(minutes=50)).isoformat(),
        }
        assert (
            c.post(f"/v1/findings/{uid}/status", json=body, headers=auth(triager)).status_code
            == 200
        )
    # A refusal stamped 08:30 arrives at 10:05: older than first_seen by more than the window.
    late = T - timedelta(minutes=90)
    ingest(
        url,
        "h",
        "harava",
        [(T + timedelta(minutes=5), lines((late, "agents"))[0][1], Transport.NDJSON)],
    )
    clock.advance(minutes=6)
    notifier = RecordingNotifier()
    run_worker(url, builtin_rules(), clock, notifier)
    rows = query(url, "SELECT status, count, first_seen, last_seen FROM findings")
    assert rows == [("suppressed", 2, T, T)]  # still live, still suppressed, first_seen kept
    assert notifier.sent == []
    assert query(
        url, "SELECT count(*) FROM finding_events WHERE new_value->>'status' = 'expired'"
    ) == [(0,)]
    [(payload,)] = query(
        url, "SELECT payload FROM finding_events WHERE kind = 'detection_attached'"
    )
    assert payload["late"] is True


def test_value_count_ignores_missing_values(fresh_database_url: str, tmp_path: Path) -> None:
    url = fresh_database_url
    doc = _count_rule(R1, gte=2, timespan="1h")
    doc["correlation"] = {
        "type": "value_count",
        "field": "attributes.caller",
        "timespan": "1h",
        "condition": {"gte": 2},
    }
    doc["finding"]["group_by"] = []
    rules = load_rule_set([write_pack(tmp_path, [doc])])
    # One plain caller, one Harava did not name plainly (no caller attribute): one value.
    ingest(url, "h", "harava", lines((T, "x"), (T + timedelta(minutes=1), "two words")))
    run_worker(url, rules, Clock(T + timedelta(minutes=5)))
    assert fired(url) == []
    ingest(url, "h", "harava", lines((T + timedelta(minutes=2), "y")))
    run_worker(url, rules, Clock(T + timedelta(minutes=6)))
    assert fired(url) == ["testpack.burst"]


def test_delivery_backoff_never_waits_longer_than_the_cap(fresh_database_url: str) -> None:
    import time

    url = fresh_database_url
    ingest(url, "h", "harava", lines((T, "svc")))  # one finding_opened notification

    class Down(RecordingNotifier):
        def deliver(self, notification: dict[str, Any]) -> None:
            raise ConnectionError("down")

    notifier = Down()
    backoff = notify.Backoff(base_seconds=0.05, cap_seconds=0.1, alert_after=1000)
    run_worker(
        url, builtin_rules(), Clock(T + timedelta(minutes=5)), notifier, notify_backoff=backoff
    )
    for _ in range(6):
        time.sleep(0.15)  # past the cap; uncapped waits would reach 0.2, 0.4, 0.8 s ...
        run_async(url, lambda conn: notify.drain(conn, notifier, T, backoff=backoff))
    [(failed,)] = query(url, "SELECT count(*) FROM notification_deliveries WHERE status = 'failed'")
    assert failed >= 7  # the first failure plus one retry after every capped wait


# --- round five: a superseded row is never dropped silently -----------------------------------


def test_a_superseded_row_pages_and_raises_a_meta_detection(fresh_database_url: str) -> None:
    url = fresh_database_url
    ingest(url, "h", "harava", lines((T, "agents")))
    # Only the owner (or a reprocessing run, which does not exist yet) can supersede a record.
    with psycopg.connect(url) as conn:
        conn.execute(
            "INSERT INTO parse_attempts (raw_record_id, adapter, adapter_version, status, "
            "created_at) SELECT id, 'harava', '9.9.9', 'ok', now() FROM raw_records"
        )
    notifier = RecordingNotifier()
    stats = run_worker(url, builtin_rules(), Clock(T + timedelta(minutes=5)), notifier)
    assert stats.superseded >= 1
    assert "harava.agent_outbound_refused" in fired(url)  # evaluated anyway: it paged
    assert "finding_opened" in notifier.kinds()
    metas = query(
        url,
        "SELECT subject FROM detections WHERE kind = 'tuisku.meta.evaluation_failed'",
    )
    assert ("superseded_derivation",) in metas
    assert "tuisku-meta.evaluation_failed" in fired(url)


# --- round five: rules match the name a record arrived with ------------------------------------


def test_rules_match_the_source_name_a_record_arrived_with(
    fresh_database_url: str, tmp_path: Path
) -> None:
    url = fresh_database_url
    doc = rule_doc("named", R1)
    doc["select"]["where"].append({"field": "source", "op": "eq", "value": "edge-a"})
    rules = load_rule_set([write_pack(tmp_path, [doc])])
    ingest(url, "edge-a", "harava", lines((T, "x")))
    with psycopg.connect(url) as conn:  # renamed out of band before the worker ran
        conn.execute("UPDATE sources SET name = 'edge-b' WHERE name = 'edge-a'")
    run_worker(url, rules, Clock(T + timedelta(minutes=5)))
    assert fired(url) == ["testpack.named"]


# --- round six: a backed-up pipeline pages ---------------------------------------------------


def test_an_old_queue_raises_a_backlog_that_pages_by_itself(fresh_database_url: str) -> None:
    url = fresh_database_url
    ingest(url, "h", "harava", lines((T, "svc")))
    notifier = RecordingNotifier()
    worker = Worker(
        rule_set=builtin_rules(),
        clock=Clock(T + timedelta(minutes=10)),  # the row has waited 10 minutes
        notifier=notifier,
        config=WorkerConfig(backlog_after=timedelta(minutes=5)),
    )
    stats = run_async(url, worker.run_once)
    assert stats.backlog == 1
    [(subject,)] = query(url, "SELECT subject FROM detections WHERE kind = 'tuisku.meta.backlog'")
    assert subject == "queue"
    # Paged directly, in the same pass, by the database's own notification.
    assert "tuisku_backlog" in notifier.kinds()
    run_async(url, worker.run_until_idle)
    assert "tuisku-meta.backlog" in fired(url)


def test_a_fresh_queue_raises_no_backlog(fresh_database_url: str) -> None:
    url = fresh_database_url
    ingest(url, "h", "harava", lines((T, "svc")))
    worker = Worker(
        rule_set=builtin_rules(),
        clock=Clock(T + timedelta(minutes=4)),
        notifier=RecordingNotifier(),
        config=WorkerConfig(backlog_after=timedelta(minutes=5)),
    )
    assert run_async(url, worker.run_once).backlog == 0


def test_undelivered_notifications_raise_a_backlog(fresh_database_url: str) -> None:
    url = fresh_database_url
    ingest(url, "h", "harava", lines((T, "svc")))
    run_worker(url, builtin_rules(), Clock(T + timedelta(minutes=1)), FlakyNotifier())
    with psycopg.connect(url) as conn:  # an outbox row left undelivered for an hour
        conn.execute(
            "INSERT INTO notifications (dedupe_key, kind, severity_id, payload, created_at) "
            "VALUES ('stuck', 'x', 1, '{}', now())"
        )
    worker = Worker(
        rule_set=builtin_rules(),
        clock=Clock(T + timedelta(minutes=2)),
        notifier=FlakyNotifier(),
        config=WorkerConfig(backlog_after=timedelta(milliseconds=1)),
    )
    import time

    time.sleep(0.05)
    run_async(url, worker.check_backlog)
    subjects = query(url, "SELECT subject FROM detections WHERE kind = 'tuisku.meta.backlog'")
    assert ("notifications",) in subjects


def test_notification_created_at_is_the_database_clock(fresh_database_url: str) -> None:
    with psycopg.connect(fresh_database_url) as conn:
        [(created, now)] = conn.execute(
            "INSERT INTO notifications (dedupe_key, kind, severity_id, payload, created_at) "
            "VALUES ('t', 'x', 1, '{}', '2000-01-01') RETURNING created_at, now()"
        ).fetchall()
        conn.rollback()
    assert created == now
