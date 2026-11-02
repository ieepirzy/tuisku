"""Every way the round-four review found for the API role to stop a page, attempted as the API
role against the split roles of ADR 0011. Each attempt is refused, and the victim still pages.
"""

from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import psycopg
import pytest
from psycopg import errors

from tests.conftest import AppDatabase
from tests.support import query
from tests.test_append_only_rules import FALCO_CRITICAL, _falco_line
from tests.worker_support import Clock, RecordingNotifier, builtin_rules, ingest, run_worker
from tuisku.rules.packs import RuleSet
from tuisku.store.ingest import Transport

AT = datetime(2026, 10, 30, 12, 0, 1, tzinfo=UTC)
AGENT_RULE = "f542db3a-6926-4df9-9183-449491345d3c"


def _run_all(conn: psycopg.Connection, statement: str, params: Any = None) -> None:
    """Run ``"; "``-separated statements in one transaction, each with the same params."""
    for part in statement.split("; "):
        conn.execute(part, params)  # type: ignore[arg-type]


def _refused(url: str, statement: str, params: Any = None) -> Exception:
    with psycopg.connect(url) as conn:
        try:
            _run_all(conn, statement, params)
        except psycopg.Error as exc:
            conn.rollback()
            assert isinstance(exc, errors.InsufficientPrivilege), exc
            return exc
        conn.rollback()
    raise AssertionError(f"not refused: {statement}")


def _falco_victim(db: AppDatabase) -> tuple[int, str]:
    source = f"f{uuid.uuid4().hex[:10]}"
    ingest(db.app_url, source, "falco", [(AT, _falco_line(str(uuid.uuid4())), Transport.NDJSON)])
    [(victim, victim_uid)] = query(
        db.owner_url,
        "SELECT d.id, d.uid::text FROM detections d JOIN sources s ON s.id = d.source_id "
        "WHERE s.name = %s AND d.evaluator = 'sensor'",
        (source,),
    )
    return victim, victim_uid


def _paged_for(db: AppDatabase, notifier: RecordingNotifier, victim_uid: str) -> bool:
    [(det_uid,)] = query(
        db.owner_url,
        "SELECT uid::text FROM detections WHERE identity = %s "
        "AND explanation -> 'triggered_by' ->> 'uid' = %s",
        (FALCO_CRITICAL, victim_uid),
    )
    return any(n.get("detection_uid") == det_uid for n in notifier.sent)


# --- the queue ----------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "statement",
    [
        "DELETE FROM evaluation_queue",
        "UPDATE evaluation_queue SET claimed_until = 'infinity'",
        "UPDATE evaluation_queue SET attempts = 99",
    ],
)
def test_queue_rows_cannot_be_dropped_or_parked(app_db: AppDatabase, statement: str) -> None:
    _, victim_uid = _falco_victim(app_db)
    exc = _refused(app_db.app_url, statement)
    assert "permission denied" in str(exc)
    notifier = RecordingNotifier()
    run_worker(app_db.worker_url, builtin_rules(), Clock(AT + timedelta(days=1)), notifier)
    assert _paged_for(app_db, notifier, victim_uid)


# --- silent triage ------------------------------------------------------------------------------


def _agent_rules(tmp_path: Path, caller: str) -> RuleSet:
    tmp_path.mkdir(parents=True, exist_ok=True)
    params = tmp_path / "params.yaml"
    params.write_text(json.dumps({"harava": {"restricted_callers": ["agents", caller]}}))
    return builtin_rules(params)


def _refusal(at: datetime, caller: str) -> tuple[datetime, bytes, Transport]:
    stamp = at.strftime("%Y-%m-%d %H:%M:%S,000")
    line = (
        f"{stamp} WARNING harava.api outbound data refused: caller={caller} "
        "urls=1 findings=email/query/plain"
    )
    return at + timedelta(seconds=1), line.encode(), Transport.NDJSON


def _agent_finding(db: AppDatabase, tmp_path: Path) -> tuple[str, str, RuleSet, str]:
    caller = f"a{uuid.uuid4().hex[:8]}"
    source = f"h{uuid.uuid4().hex[:10]}"
    rules = _agent_rules(tmp_path, caller)
    ingest(db.app_url, source, "harava", [_refusal(AT, caller)])
    run_worker(db.worker_url, rules, Clock(AT + timedelta(minutes=1)))
    [(uid,)] = query(
        db.owner_url,
        "SELECT uid::text FROM findings WHERE rule_id = %s AND group_values = %s::jsonb",
        (AGENT_RULE, json.dumps([caller])),
    )
    return uid, caller, rules, source


_OPERATOR_EVENT = (
    "INSERT INTO finding_events (finding_id, actor, kind, new_value) SELECT id, "
    "'operator:00000000-0000-4000-8000-000000000000', 'suppressed', "
    '\'{"status": "suppressed"}\' FROM findings WHERE uid = %(uid)s; '
)


@pytest.mark.parametrize(
    ("statement", "message"),
    [
        # Suppressed with no operator event: silent.
        (
            "UPDATE findings SET status = 'suppressed', suppressed_until = now() + interval "
            "'1 day', suppression_reason = 'x' WHERE uid = %(uid)s",
            "operator event",
        ),
        # With an event, but for longer than 30 days (the probe's 9999-01-01).
        (
            _OPERATOR_EVENT + "UPDATE findings SET status = 'suppressed', suppressed_until = "
            "'9999-01-01', suppression_reason = 'x' WHERE uid = %(uid)s",
            "30 days",
        ),
        # Back-dating the start of the suppression to stretch the 30 days.
        (
            _OPERATOR_EVENT + "UPDATE findings SET status = 'suppressed', suppressed_until = "
            "now() + interval '40 days', suppressed_at = now() + interval '20 days', "
            "suppression_reason = 'x' WHERE uid = %(uid)s",
            "30 days",
        ),
        # Rewriting what triage does not own.
        ("UPDATE findings SET window_seconds = 2000000000 WHERE uid = %(uid)s", "permission"),
        ("UPDATE findings SET max_lifetime_seconds = 2000000000 WHERE uid = %(uid)s", "permission"),
        ("UPDATE findings SET notify = 'thresholds' WHERE uid = %(uid)s", "permission"),
        ("UPDATE findings SET count = 1000 WHERE uid = %(uid)s", "permission"),
        ("UPDATE incidents SET severity_id = 0", "permission"),
        (
            "UPDATE incidents SET status = 'closed', disposition = 'false_positive'",
            "operator event",
        ),
    ],
)
def test_findings_cannot_be_silenced_or_rewritten(
    app_db: AppDatabase, tmp_path: Path, statement: str, message: str
) -> None:
    uid, caller, rules, source = _agent_finding(app_db, tmp_path)
    exc = _refused(app_db.app_url, statement, {"uid": uid})
    assert message in str(exc)
    # The next refusal still pages (notify: each).
    ingest(app_db.app_url, source, "harava", [_refusal(AT + timedelta(minutes=5), caller)])
    notifier = RecordingNotifier()
    run_worker(app_db.worker_url, rules, Clock(AT + timedelta(minutes=6)), notifier)
    assert [n["kind"] for n in notifier.sent if n.get("finding_uid") == uid] == [
        "finding_occurrence"
    ]


def test_triage_with_its_event_is_still_allowed(app_db: AppDatabase, tmp_path: Path) -> None:
    uid, *_ = _agent_finding(app_db, tmp_path)
    with psycopg.connect(app_db.app_url) as conn:
        _run_all(
            conn,
            _OPERATOR_EVENT + "UPDATE findings SET status = 'suppressed', suppressed_until = "
            "now() + interval '1 day', suppression_reason = 'maintenance' WHERE uid = %(uid)s",
            {"uid": uid},
        )
        [(began, count_then)] = conn.execute(
            "SELECT suppressed_at = now(), count_at_suppression FROM findings WHERE uid = %s",
            (uid,),
        ).fetchall()
        conn.rollback()
    assert began and count_then == 1  # set by the database, not the caller


# --- notification keys --------------------------------------------------------------------------


def test_worker_notification_keys_cannot_be_preclaimed(app_db: AppDatabase, tmp_path: Path) -> None:
    uid, caller, rules, source = _agent_finding(app_db, tmp_path)
    [(incident_uid,)] = query(
        app_db.owner_url,
        "SELECT i.uid::text FROM incidents i JOIN findings f "
        "ON f.incident_id = i.id WHERE f.uid = %s",
        (uid,),
    )
    insert = (
        "INSERT INTO notifications (dedupe_key, kind, severity_id, payload, created_at) "
        "VALUES (%s, 'x', 0, '{}', now())"
    )
    for key in [
        f"finding_threshold:{uid}:10",
        f"finding_opened:{uuid.uuid4()}",
        f"finding_detection:{uuid.uuid4()}",
        f"finding_link:{uuid.uuid4()}",
        f"escalation:{incident_uid}:severity:5",
        f"incident_opened:{uuid.uuid4()}",
        f"overflow_group:{uid}:{'0' * 64}",
        f"dead_letter:1:{AGENT_RULE}",
    ]:
        exc = _refused(app_db.app_url, insert, (key,))
        assert "belongs to the worker" in str(exc)
    with psycopg.connect(app_db.app_url) as conn:  # what triage itself emits
        conn.execute(insert, (f"operator_escalation:{incident_uid}:reopened:x",))
        conn.execute(insert, (f"triage_threshold:{uid}:10",))
        conn.rollback()
    # Nine more refusals: the count reaches 10 and the threshold pages.
    ingest(
        app_db.app_url,
        source,
        "harava",
        [_refusal(AT + timedelta(minutes=2 + i), caller) for i in range(9)],
    )
    notifier = RecordingNotifier()
    run_worker(app_db.worker_url, rules, Clock(AT + timedelta(minutes=20)), notifier)
    thresholds = [
        n for n in notifier.sent if n["kind"] == "finding_threshold" and n["finding_uid"] == uid
    ]
    assert [n["threshold"] for n in thresholds] == [10]


# --- meta-detection buckets ---------------------------------------------------------------------


@pytest.mark.parametrize(
    "kind", ["tuisku.meta.evaluation_failed", "tuisku.meta.notification_undeliverable"]
)
def test_worker_meta_buckets_cannot_be_preclaimed(app_db: AppDatabase, kind: str) -> None:
    victim, victim_uid = _falco_victim(app_db)
    for offset in ["0", "5 minutes", "1 hour", "1 day"]:
        exc = _refused(
            app_db.app_url,
            "INSERT INTO detections (source_id, evaluator, authorship, kind, identity, title, "
            "severity_id, received_at, eval_time, ocsf_version, rule_ref, subject, bucket_start) "
            "SELECT d.source_id, 'tuisku', 'tuisku', %s, %s, 'forged', 0, now(), now(), '1.9.0', "
            "'{}', %s, tuisku_current_bucket() + %s::interval FROM detections d WHERE d.id = %s",
            (kind, kind, FALCO_CRITICAL, offset, victim),
        )
        assert "worker role" in str(exc)
    if kind != "tuisku.meta.evaluation_failed":
        return
    # The victim's rule keeps failing: the dead letter is raised in its bucket and pages.

    def fail_on_victim(rule: Any, env: Any) -> None:
        if rule.id == FALCO_CRITICAL and env["id"] == victim:
            raise RuntimeError("boom")

    clock = Clock(AT + timedelta(minutes=1))
    notifier = RecordingNotifier()
    for _ in range(7):
        run_worker(app_db.worker_url, builtin_rules(), clock, notifier, before_pair=fail_on_victim)
        clock.advance(minutes=1)
    dead = [n for n in notifier.sent if n["kind"] == "evaluation_dead_lettered"]
    assert any(n["row"]["uid"] == victim_uid for n in dead)
    [(metas,)] = query(
        app_db.owner_url,
        "SELECT count(*) FROM detections WHERE kind = 'tuisku.meta.evaluation_failed' "
        "AND subject = %s AND explanation -> 'row' ->> 'uid' = %s",
        (FALCO_CRITICAL, victim_uid),
    )
    assert metas == 1


@pytest.mark.parametrize(
    ("table", "change", "event"),
    [
        (
            "findings",
            "SET status = 'acknowledged', window_seconds = 2000000000 WHERE uid = %(uid)s",
            "INSERT INTO finding_events (finding_id, actor, kind, new_value) SELECT id, "
            "'operator:00000000-0000-4000-8000-000000000000', 'status_changed', "
            '\'{"status": "acknowledged"}\' FROM findings WHERE uid = %(uid)s',
        ),
        (
            "incidents",
            "SET status = 'triaged', severity_id = 0 WHERE id = (SELECT incident_id FROM "
            "findings WHERE uid = %(uid)s)",
            "INSERT INTO incident_events (incident_id, actor, kind, payload) SELECT incident_id, "
            "'operator:00000000-0000-4000-8000-000000000000', 'status_changed', "
            '\'{"to": "triaged"}\' FROM findings WHERE uid = %(uid)s',
        ),
    ],
)
def test_the_trigger_refuses_non_triage_changes_even_with_a_wider_grant(
    app_db: AppDatabase, tmp_path: Path, table: str, change: str, event: str
) -> None:
    """Behind the column grants: should a grant ever widen, the trigger still holds. Run in a
    transaction that is rolled back, so the wider grant never persists."""
    uid, *_ = _agent_finding(app_db, tmp_path)
    role = app_db.app_role
    with psycopg.connect(app_db.owner_url) as conn:
        conn.execute(f'GRANT "{role}" TO CURRENT_USER')  # type: ignore[arg-type]
        conn.execute(f'GRANT UPDATE ON {table} TO "{role}"')  # type: ignore[arg-type]
        conn.execute(f'SET LOCAL ROLE "{role}"')  # type: ignore[arg-type]
        conn.execute(event, {"uid": uid})  # type: ignore[arg-type]
        with pytest.raises(errors.InsufficientPrivilege, match="triage may change only"):
            conn.execute(f"UPDATE {table} " + change, {"uid": uid})  # type: ignore[arg-type]
        conn.rollback()


# --- round five: superseding a record's derivation ------------------------------------------


def test_a_victims_derivation_cannot_be_superseded(app_db: AppDatabase) -> None:
    victim, victim_uid = _falco_victim(app_db)
    exc = _refused(
        app_db.app_url,
        "INSERT INTO parse_attempts (raw_record_id, adapter, adapter_version, status, "
        "created_at) SELECT raw_record_id, 'falco', 'x', 'ok', now() FROM detections "
        "WHERE id = %s",
        (victim,),
    )
    assert "with its raw record" in str(exc)
    notifier = RecordingNotifier()
    run_worker(app_db.worker_url, builtin_rules(), Clock(AT + timedelta(minutes=1)), notifier)
    assert _paged_for(app_db, notifier, victim_uid)


# --- round five: lifting and re-suppressing ------------------------------------------------------


def _suppress(conn: psycopg.Connection, uid: str, until: str) -> None:
    _run_all(
        conn,
        _OPERATOR_EVENT
        + "UPDATE findings SET status = 'suppressed', suppressed_until = "
        + until
        + ", suppression_reason = 'x' WHERE uid = %(uid)s",
        {"uid": uid},
    )


_LIFT = (
    "INSERT INTO finding_events (finding_id, actor, kind, new_value) SELECT id, "
    "'operator:00000000-0000-4000-8000-000000000000', 'status_changed', "
    '\'{"status": "open"}\' FROM findings WHERE uid = %(uid)s; '
    "UPDATE findings SET status = 'open', suppressed_until = NULL, suppression_reason = NULL, "
    "suppressed_at = NULL, count_at_suppression = NULL WHERE uid = %(uid)s"
)


def test_a_lift_must_page_the_thresholds_crossed_while_suppressed(
    app_db: AppDatabase, tmp_path: Path
) -> None:
    uid, caller, rules, source = _agent_finding(app_db, tmp_path)
    with psycopg.connect(app_db.app_url) as conn:
        _suppress(conn, uid, "now() + interval '1 day'")
        conn.commit()
    ingest(
        app_db.app_url,
        source,
        "harava",
        [_refusal(AT + timedelta(minutes=2 + i), caller) for i in range(10)],
    )
    run_worker(app_db.worker_url, rules, Clock(AT + timedelta(minutes=20)))
    [(count,)] = query(app_db.owner_url, "SELECT count FROM findings WHERE uid = %s", (uid,))
    assert count == 11  # crossed 10 while suppressed, silently
    exc = _refused(app_db.app_url, _LIFT, {"uid": uid})  # the probe's bounce: no page
    assert "threshold 10" in str(exc)
    # A page written in an earlier transaction does not count: it must come with the lift.
    with psycopg.connect(app_db.owner_url) as conn:
        conn.execute(
            "INSERT INTO notifications (dedupe_key, kind, severity_id, payload, created_at) "
            "VALUES (%s, 'finding_threshold', 4, '{}', now())",
            (f"triage_threshold:{uid}:10",),
        )
    exc = _refused(app_db.app_url, _LIFT, {"uid": uid})
    assert "threshold 10" in str(exc)
    # With its page in the same transaction, the lift is accepted (another finding, as this
    # one's key is now taken).
    uid2, caller2, rules2, source2 = _agent_finding(app_db, tmp_path / "second")
    with psycopg.connect(app_db.app_url) as conn:
        _suppress(conn, uid2, "now() + interval '1 day'")
        conn.commit()
    ingest(
        app_db.app_url,
        source2,
        "harava",
        [_refusal(AT + timedelta(minutes=2 + i), caller2) for i in range(10)],
    )
    run_worker(app_db.worker_url, rules2, Clock(AT + timedelta(minutes=20)))
    with psycopg.connect(app_db.app_url) as conn:
        conn.execute(
            "INSERT INTO notifications (dedupe_key, kind, severity_id, payload, created_at) "
            "VALUES (%s, 'finding_threshold', 4, '{}', now())",
            (f"triage_threshold:{uid2}:10",),
        )
        _run_all(conn, _LIFT, {"uid": uid2})
        conn.rollback()


def test_a_bounce_does_not_restart_the_thirty_days(app_db: AppDatabase, tmp_path: Path) -> None:
    uid, *_ = _agent_finding(app_db, tmp_path)
    with psycopg.connect(app_db.app_url) as conn:
        _suppress(conn, uid, "now() + interval '1 day'")
        conn.commit()
        _run_all(conn, _LIFT, {"uid": uid})  # nothing crossed: no page needed
        conn.commit()
    # Re-suppressed in a later transaction: 30 days from now would end after 30 days from the
    # first suppression, so it is refused; 29 days fits.
    exc = _refused(
        app_db.app_url,
        _OPERATOR_EVENT + "UPDATE findings SET status = 'suppressed', suppressed_until = now() + "
        "interval '30 days', suppression_reason = 'y' WHERE uid = %(uid)s",
        {"uid": uid},
    )
    assert "30 days" in str(exc)
    with psycopg.connect(app_db.app_url) as conn:
        _suppress(conn, uid, "now() + interval '29 days'")
        [(kept,)] = conn.execute(
            "SELECT suppressed_at < now() FROM findings WHERE uid = %s", (uid,)
        ).fetchall()
        conn.rollback()
    assert kept  # the original start, not this transaction's


def test_triage_cannot_expire_or_retouch_the_suppression_count(
    app_db: AppDatabase, tmp_path: Path
) -> None:
    uid, *_ = _agent_finding(app_db, tmp_path)
    exc = _refused(
        app_db.app_url,
        "INSERT INTO finding_events (finding_id, actor, kind, new_value) SELECT id, "
        "'operator:00000000-0000-4000-8000-000000000000', 'status_changed', "
        '\'{"status": "expired"}\' FROM findings WHERE uid = %(uid)s; '
        "UPDATE findings SET status = 'expired' WHERE uid = %(uid)s",
        {"uid": uid},
    )
    assert "cannot set a finding to expired" in str(exc)
    with psycopg.connect(app_db.app_url) as conn:  # the probe: zero the count after suppressing
        _suppress(conn, uid, "now() + interval '1 day'")
        _run_all(
            conn,
            _OPERATOR_EVENT + "UPDATE findings SET count_at_suppression = 0 WHERE uid = %(uid)s",
            {"uid": uid},
        )
        [(count_then, count)] = conn.execute(
            "SELECT count_at_suppression, count FROM findings WHERE uid = %s", (uid,)
        ).fetchall()
        conn.rollback()
    assert count_then == count  # the database keeps the count it recorded
