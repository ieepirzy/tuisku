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
from tests.worker_support import (
    Clock,
    RecordingNotifier,
    builtin_rules,
    ingest,
    run_async,
    run_worker,
)
from tuisku.rules.packs import RuleSet
from tuisku.store.ingest import Transport


@pytest.fixture(autouse=True)
def _live_operator(app_db: AppDatabase) -> None:
    """Operator events need a live operator token (ADR 0011)."""
    from tests.worker_support import ensure_test_operator

    ensure_test_operator(app_db.owner_url)


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
            assert isinstance(exc, (errors.InsufficientPrivilege, errors.CheckViolation)) or (
                exc.diag.sqlstate in ("TK404", "TK409")
            ), exc
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


OPERATOR = "operator:00000000-0000-4000-8000-000000000000"

_INCIDENT_OF = (
    "(SELECT i.uid FROM incidents i JOIN findings f ON f.incident_id = i.id WHERE f.uid = %(uid)s)"
)


def _request(
    target: str = "finding",
    status: str = "acknowledged",
    *,
    until: str = "NULL",
    reason: str = "NULL",
    disposition: str = "NULL",
    actor: str = f"'{OPERATOR}'",
    extra: str = "",
) -> str:
    """A triage request as SQL, for the finding ``%(uid)s`` (or its incident)."""
    target_uid = "%(uid)s" if target == "finding" else _INCIDENT_OF
    columns = "target, target_uid, status, suppressed_until, reason, disposition, actor"
    values = f"'{target}', {target_uid}, '{status}', {until}, {reason}, {disposition}, {actor}"
    if extra:
        name, value = extra.split("=", 1)
        columns += f", {name}"
        values += f", {value}"
    return f"INSERT INTO triage_requests ({columns}) VALUES ({values})"


@pytest.mark.parametrize(
    ("statement", "message"),
    [
        # Suppressed directly, with or without an event: the API role has no UPDATE at all.
        (
            "UPDATE findings SET status = 'suppressed', suppressed_until = now() + interval "
            "'1 day', suppression_reason = 'x' WHERE uid = %(uid)s",
            "permission denied for table findings",
        ),
        (
            "INSERT INTO finding_events (finding_id, actor, kind, new_value) SELECT id, "
            f"'{OPERATOR}', 'suppressed', '{{}}' FROM findings WHERE uid = %(uid)s",
            "permission denied for table finding_events",
        ),
        # Requested for longer than 30 days (the probe's 9999-01-01).
        (_request(status="suppressed", until="'9999-01-01'", reason="'x'"), "30 days"),
        # Back-dating the request to stretch the 30 days: the database stamps it now().
        (
            _request(
                status="suppressed",
                until="now() + interval '40 days'",
                reason="'x'",
                extra="requested_at=now() - interval '20 days'",
            ),
            "30 days",
        ),
        (_request(status="suppressed", reason="'x'"), "needs an expiry and a reason"),
        (_request(status="suppressed", until="now() + interval '1 day'", reason="' '"), "blank"),
        # Rewriting what triage does not own.
        ("UPDATE findings SET window_seconds = 2000000000 WHERE uid = %(uid)s", "permission"),
        ("UPDATE findings SET max_lifetime_seconds = 2000000000 WHERE uid = %(uid)s", "permission"),
        ("UPDATE findings SET notify = 'thresholds' WHERE uid = %(uid)s", "permission"),
        ("UPDATE findings SET count = 1000 WHERE uid = %(uid)s", "permission"),
        ("UPDATE incidents SET severity_id = 0", "permission"),
        (
            "UPDATE incidents SET status = 'closed', disposition = 'false_positive'",
            "permission denied for table incidents",
        ),
        (_request("incident", "closed"), "closing needs a disposition"),
        (_request("incident", "bogus"), "unknown incident state"),
        (_request("incident", "triaged", disposition="'duplicate'"), "only when closing"),
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


def test_a_triage_request_applies_with_its_event(app_db: AppDatabase, tmp_path: Path) -> None:
    uid, *_ = _agent_finding(app_db, tmp_path)
    with psycopg.connect(app_db.app_url) as conn:
        conn.execute(
            _request(status="suppressed", until="now() + interval '1 day'", reason="'maint'"),
            {"uid": uid},
        )
        [(began, count_then, status)] = conn.execute(
            "SELECT suppressed_at = now(), count_at_suppression, status FROM findings "
            "WHERE uid = %s",
            (uid,),
        ).fetchall()
        [(actor, kind)] = conn.execute(
            "SELECT e.actor, e.kind FROM finding_events e JOIN findings f ON f.id = e.finding_id "
            "WHERE f.uid = %s AND e.actor LIKE 'operator:%%'",
            (uid,),
        ).fetchall()
        conn.rollback()
    assert began and count_then == 1 and status == "suppressed"  # set by the database
    assert (actor, kind) == (OPERATOR, "suppressed")


# --- notification keys --------------------------------------------------------------------------


def test_the_api_role_writes_no_notifications(app_db: AppDatabase, tmp_path: Path) -> None:
    """Round six: no INSERT on notifications at all, so no key can be pre-claimed (the dummy
    `triage_threshold` probe) and the outbox cannot be flooded (the 200k-junk probe)."""
    uid, caller, rules, source = _agent_finding(app_db, tmp_path)
    insert = (
        "INSERT INTO notifications (dedupe_key, kind, severity_id, payload, created_at) "
        "VALUES (%s, 'noop', 0, '{}', '2000-01-01')"
    )
    for key in [
        f"finding_threshold:{uid}:10",
        f"triage_threshold:{uid}:10",
        f"operator_escalation:{uuid.uuid4()}",
        f"escalation:{uuid.uuid4()}:reopened:1",
        f"dead_letter:1:{AGENT_RULE}",
    ]:
        exc = _refused(app_db.app_url, insert, (key,))
        assert "permission denied for table notifications" in str(exc)
    exc = _refused(
        app_db.app_url,
        "INSERT INTO notifications (dedupe_key, kind, severity_id, payload, created_at) "
        "SELECT 'junk:' || g, 'noop', 0, '{}', now() FROM generate_series(1, 200000) g",
    )
    assert "permission denied" in str(exc)
    # Nine more refusals: the count reaches 10 and the threshold pages as usual.
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
    conn.execute(_request(status="suppressed", until=until, reason="'x'"), {"uid": uid})


_LIFT = _request(status="open")
_RESOLVE = _request(status="resolved")


@pytest.mark.parametrize("leave", ["open", "resolved"])
def test_leaving_a_suppression_pages_the_thresholds_crossed(
    app_db: AppDatabase, tmp_path: Path, leave: str
) -> None:
    """Round six: suppressed -> resolved (or open) paged nothing. The database now pages every
    threshold crossed while suppressed, whoever lifts it and however."""
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
    quiet = RecordingNotifier()
    run_worker(app_db.worker_url, rules, Clock(AT + timedelta(minutes=20)), quiet)
    assert not [n for n in quiet.sent if n.get("finding_uid") == uid]  # crossed 10 silently
    with psycopg.connect(app_db.app_url) as conn:  # the probe: no page of its own
        _run_all(conn, _LIFT if leave == "open" else _RESOLVE, {"uid": uid})
        conn.commit()
    notifier = RecordingNotifier()
    run_worker(app_db.worker_url, rules, Clock(AT + timedelta(minutes=21)), notifier)
    pages = [n for n in notifier.sent if n.get("finding_uid") == uid]
    assert [(n["kind"], n["threshold"], n["count"]) for n in pages] == [
        ("finding_threshold", 10, 11)
    ]


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
        _request(status="suppressed", until="now() + interval '30 days'", reason="'y'"),
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
    exc = _refused(app_db.app_url, _request(status="expired"), {"uid": uid})
    assert "cannot set a finding to expired" in str(exc)
    exc = _refused(
        app_db.app_url,
        "UPDATE findings SET count_at_suppression = 0 WHERE uid = %(uid)s",
        {"uid": uid},
    )
    assert "permission denied" in str(exc)
    with psycopg.connect(app_db.app_url) as conn:  # re-suppressing keeps the recorded count
        _suppress(conn, uid, "now() + interval '1 day'")
        _suppress(conn, uid, "now() + interval '2 days'")
        [(count_then, count)] = conn.execute(
            "SELECT count_at_suppression, count FROM findings WHERE uid = %s", (uid,)
        ).fetchall()
        conn.rollback()
    assert count_then == count


# --- round six: operator events --------------------------------------------------------------


@pytest.mark.parametrize(
    ("actor", "message"),
    [
        ("operator:11111111-1111-4111-8111-111111111111", "no live operator"),
        ("operator:not-a-uuid", "triage_requests_actor_check"),
        ("system", "triage_requests_actor_check"),
    ],
)
def test_triage_requests_need_a_live_operator(
    app_db: AppDatabase, tmp_path: Path, actor: str, message: str
) -> None:
    uid, *_ = _agent_finding(app_db, tmp_path)
    exc = _refused(app_db.app_url, _request(actor=f"'{actor}'"), {"uid": uid})
    assert message in str(exc)


@pytest.mark.parametrize("kind", ["status_changed", "opened", "detection_attached"])
def test_the_api_role_writes_no_events(app_db: AppDatabase, tmp_path: Path, kind: str) -> None:
    """Events are written only by the worker and the owner's triage trigger (ADR 0011)."""
    uid, *_ = _agent_finding(app_db, tmp_path)
    for statement in [
        "INSERT INTO finding_events (finding_id, actor, kind) SELECT id, %(actor)s, %(kind)s "
        "FROM findings WHERE uid = %(uid)s",
        "INSERT INTO incident_events (incident_id, actor, kind) SELECT incident_id, %(actor)s, "
        "%(kind)s FROM findings WHERE uid = %(uid)s",
    ]:
        exc = _refused(app_db.app_url, statement, {"actor": OPERATOR, "kind": kind, "uid": uid})
        assert "permission denied" in str(exc)


def test_a_revoked_operator_cannot_triage(app_db: AppDatabase, tmp_path: Path) -> None:
    uid, *_ = _agent_finding(app_db, tmp_path)
    token = str(uuid.uuid4())
    with psycopg.connect(app_db.owner_url) as conn:
        conn.execute(
            "INSERT INTO operator_tokens (uid, name, roles, token_sha256, revoked_at) "
            "VALUES (%s, 'gone', '{triage}', sha256(%s::bytea), now())",
            (token, token.encode()),
        )
    exc = _refused(app_db.app_url, _request(actor=f"'operator:{token}'"), {"uid": uid})
    assert "no live operator" in str(exc)


def test_closing_the_incident_of_a_suppressed_finding_pages_its_thresholds(
    app_db: AppDatabase, tmp_path: Path
) -> None:
    from tests.support import auth, client, operator_token
    from tuisku.store.tokens import Role

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
    [(incident,)] = query(
        app_db.owner_url,
        "SELECT i.uid::text FROM incidents i JOIN findings f ON f.incident_id = i.id "
        "WHERE f.uid = %s",
        (uid,),
    )
    triager = operator_token(app_db.app_url, Role.TRIAGE)
    with client(app_db.app_url) as c:
        r = c.post(
            f"/v1/incidents/{incident}/status",
            json={"status": "closed", "disposition": "benign_true_positive"},
            headers=auth(triager),
        )
    assert r.status_code == 200, r.text
    notifier = RecordingNotifier()
    run_worker(app_db.worker_url, rules, Clock(AT + timedelta(minutes=21)), notifier)
    pages = [n for n in notifier.sent if n.get("finding_uid") == uid]
    assert [(n["kind"], n["threshold"]) for n in pages] == [("finding_threshold", 10)]


# --- round seven: the temp-table attack on the definer pagers ---------------------------------

_PAGERS = [
    (
        "tuisku_page_lifted_thresholds",
        "CREATE TEMP TABLE f (uid uuid, status text, count bigint, count_at_suppression bigint, "
        "severity_id smallint, rule_id uuid, rule_rev int, title text, entity_keys text[]); "
        "CREATE TRIGGER t AFTER UPDATE OF status ON f FOR EACH ROW "
        "EXECUTE FUNCTION public.tuisku_page_lifted_thresholds()",
        "INSERT INTO f VALUES (gen_random_uuid(), 'suppressed', 1000, 0, 0, gen_random_uuid(), 1, "
        "'forged', '{}'); UPDATE f SET status = 'open'",
    ),
    (
        "tuisku_page_reopened_incident",
        "CREATE TEMP TABLE i (uid uuid, status text, severity_id smallint, title text, "
        "entity_keys text[]); CREATE TRIGGER t AFTER UPDATE OF status ON i FOR EACH ROW "
        "EXECUTE FUNCTION public.tuisku_page_reopened_incident()",
        "INSERT INTO i VALUES (gen_random_uuid(), 'contained', 0, 'forged', '{}'); "
        "UPDATE i SET status = 'investigating'",
    ),
    (
        "tuisku_page_backlog",
        "CREATE TEMP TABLE b (uid uuid, severity_id smallint, title text, subject text, "
        "entity_keys text[], kind text); CREATE TRIGGER t AFTER INSERT ON b FOR EACH ROW "
        "EXECUTE FUNCTION public.tuisku_page_backlog()",
        "INSERT INTO b SELECT gen_random_uuid(), 0, 'junk', 'x', '{}', 'tuisku.meta.backlog' "
        "FROM generate_series(1, 50)",
    ),
]


@pytest.mark.parametrize(("function", "setup", "fire"), _PAGERS)
def test_the_api_role_cannot_create_a_temp_table_to_run_a_pager(
    app_db: AppDatabase, function: str, setup: str, fire: str
) -> None:
    """The round-seven probe as the API role: no TEMP, so no table of its own to trigger on."""
    exc = _refused(app_db.app_url, setup)
    assert "permission denied" in str(exc)


@pytest.mark.parametrize(("function", "setup", "fire"), _PAGERS)
def test_even_with_temp_the_api_role_cannot_attach_a_pager(
    app_db: AppDatabase, function: str, setup: str, fire: str
) -> None:
    """Behind the missing TEMP: given TEMP (in a transaction that is rolled back), the API role
    still cannot attach the function, because PUBLIC has no EXECUTE on it."""
    with psycopg.connect(app_db.owner_url) as conn:
        dbname = conn.info.dbname
        conn.execute(f'GRANT "{app_db.app_role}" TO CURRENT_USER')  # type: ignore[arg-type]
        conn.execute(f'GRANT TEMP ON DATABASE "{dbname}" TO "{app_db.app_role}"')  # type: ignore[arg-type]
        conn.execute(f'SET LOCAL ROLE "{app_db.app_role}"')  # type: ignore[arg-type]
        with pytest.raises(
            errors.InsufficientPrivilege, match=f"permission denied for function public.{function}"
        ):
            _run_all(conn, setup)
        conn.rollback()


@pytest.mark.parametrize(("function", "setup", "fire"), _PAGERS)
def test_a_pager_refuses_to_run_on_any_other_table(
    app_db: AppDatabase, function: str, setup: str, fire: str
) -> None:
    """Behind EXECUTE: even the owner, who may attach it, cannot make it write a page from a
    table of its own."""
    with psycopg.connect(app_db.owner_url) as conn:
        [(before,)] = conn.execute("SELECT count(*) FROM notifications").fetchall()
        _run_all(conn, setup)
        with pytest.raises(errors.InsufficientPrivilege, match="used out of place"):
            _run_all(conn, fire)
        conn.rollback()
        [(after,)] = conn.execute("SELECT count(*) FROM notifications").fetchall()
    assert after == before


@pytest.mark.parametrize(
    ("expires", "roles", "message"),
    [
        ("now() - interval '1 minute'", "{triage}", "no live operator token"),
        ("NULL", "{read}", "no live operator token"),
    ],
)
def test_triage_requests_need_an_unexpired_triage_token(
    app_db: AppDatabase, tmp_path: Path, expires: str, roles: str, message: str
) -> None:
    uid, *_ = _agent_finding(app_db, tmp_path)
    token = str(uuid.uuid4())
    with psycopg.connect(app_db.owner_url) as conn:
        conn.execute(  # type: ignore[arg-type]
            "INSERT INTO operator_tokens (uid, name, roles, token_sha256, expires_at) "
            f"VALUES (%s, 'x', %s, sha256(%s::bytea), {expires})",
            (token, roles, token.encode()),
        )
    exc = _refused(app_db.app_url, _request(actor=f"'operator:{token}'"), {"uid": uid})
    assert message in str(exc)


@pytest.mark.parametrize(
    ("function", "event"),
    [
        ("tuisku_force_event_time", "BEFORE INSERT"),
        ("tuisku_check_firing_identity", "BEFORE INSERT"),
        ("tuisku_events_operator_only", "BEFORE INSERT"),
        ("tuisku_apply_triage", "AFTER INSERT"),
    ],
)
def test_revision_0002_trigger_functions_refuse_other_tables(
    app_db: AppDatabase, function: str, event: str
) -> None:
    with psycopg.connect(app_db.owner_url) as conn:
        conn.execute("CREATE TEMP TABLE elsewhere (i int)")
        conn.execute("INSERT INTO elsewhere VALUES (1)")
        args = "('at')" if function == "tuisku_force_event_time" else "()"
        conn.execute(  # type: ignore[arg-type]
            f"CREATE TRIGGER t {event} ON elsewhere FOR EACH ROW "
            f"EXECUTE FUNCTION public.{function}{args}"
        )
        fire = (
            "INSERT INTO elsewhere VALUES (2)"
            if "INSERT" in event
            else "UPDATE elsewhere SET i = 3"
        )
        with pytest.raises(errors.InsufficientPrivilege, match="used out of place"):
            conn.execute(fire)  # type: ignore[arg-type]
        conn.rollback()


# --- round eight: the worker's locks are not the API role's to hold --------------------------

_OLD_DRAIN_KEY = 0x7475_6973_6B75_6E6F  # the advisory key the drain used before round eight


@pytest.mark.parametrize("table", ["worker_locks", "group_locks"])
@pytest.mark.parametrize(
    "statement",
    [
        "SELECT * FROM {t}",
        "SELECT * FROM {t} FOR UPDATE",
        "SELECT * FROM {t} FOR KEY SHARE",
        "INSERT INTO {t} VALUES ('drain')",
        "LOCK TABLE {t} IN ACCESS SHARE MODE",
        "LOCK TABLE {t} IN ROW EXCLUSIVE MODE",
        "LOCK TABLE {t} IN ACCESS EXCLUSIVE MODE",
    ],
)
def test_the_api_role_cannot_touch_the_worker_locks(
    app_db: AppDatabase, table: str, statement: str
) -> None:
    exc = _refused(app_db.app_url, statement.format(t=table))
    assert "permission denied" in str(exc)


def test_the_worker_ignores_every_advisory_lock_the_api_role_holds(app_db: AppDatabase) -> None:
    """The round-eight probe: the API role holds the old drain key and the victim's old group
    and rule keys. Evaluation and the drain go on, because the worker no longer uses them."""
    from tuisku.rules.fingerprint import lock_key
    from tuisku.rules.match import match
    from tuisku.worker import fold
    from tuisku.worker.engine import load_row

    victim, victim_uid = _falco_victim(app_db)
    rules = builtin_rules()
    [falco] = [r for r in rules.rules if r.id == FALCO_CRITICAL]
    with psycopg.connect(app_db.worker_url) as conn:
        [(queue_id,)] = conn.execute(
            "SELECT id FROM evaluation_queue WHERE detection_id = %s", (victim,)
        ).fetchall()

    async def envelope(conn: Any) -> Any:
        return await load_row(conn, {"observation_id": None, "detection_id": victim})

    env = run_async(app_db.worker_url, envelope)
    m = match(falco, env)
    assert m is not None and queue_id
    keys = [
        _OLD_DRAIN_KEY,
        lock_key("rule", falco.id),
        lock_key("group", falco.id, falco.rev, fold.fingerprint_for(falco, m.group_values)),
    ]
    hold = psycopg.connect(app_db.app_url, autocommit=True)  # a compromised API process
    try:
        for key in keys:
            hold.execute("SELECT pg_advisory_lock(%s)", (key,))
        notifier = RecordingNotifier()
        run_worker(
            app_db.worker_url,
            rules,
            Clock(AT + timedelta(minutes=1)),
            notifier,
            lock_timeout_ms=500,
        )
        assert _paged_for(app_db, notifier, victim_uid)  # evaluated and delivered
    finally:
        hold.close()


def test_the_worker_progresses_while_the_api_role_holds_rows(
    app_db: AppDatabase, tmp_path: Path
) -> None:
    """Round nine: the API role can no longer lock a finding itself (no UPDATE), but an open,
    uncommitted triage request holds the finding's row through the owner's trigger. Rows for
    other groups still page; the held-up firing pages at once as `evaluation_delayed` (its own
    transaction, worker-only tables), the backlog check pages, and once released the finding's
    own page follows."""
    uid, caller, rules, source = _agent_finding(app_db, tmp_path)
    exc = _refused(
        app_db.app_url, "SELECT 1 FROM findings WHERE uid = %(uid)s FOR UPDATE", {"uid": uid}
    )
    assert "permission denied" in str(exc)
    victim, victim_uid = _falco_victim(app_db)
    ingest(app_db.app_url, source, "harava", [_refusal(AT + timedelta(minutes=2), caller)])
    hold = psycopg.connect(app_db.app_url)  # an open transaction
    try:
        hold.execute(_request(status="acknowledged"), {"uid": uid})
        from tuisku.worker.engine import Worker, WorkerConfig

        notifier = RecordingNotifier()
        w = Worker(
            rule_set=rules,
            clock=Clock(AT + timedelta(minutes=30)),
            notifier=notifier,
            config=WorkerConfig(lock_timeout_ms=200, backlog_after=timedelta(minutes=5)),
        )
        import time

        started = time.monotonic()
        for _ in range(3):
            run_async(app_db.worker_url, w.run_once)
        # Each wait on the held row is bounded by the 200 ms lock timeout, not by how long the
        # API role keeps its transaction open.
        assert time.monotonic() - started < 8
        assert _paged_for(app_db, notifier, victim_uid)  # progress elsewhere
        assert [n for n in notifier.sent if n.get("finding_uid") == uid] == []
        delayed = [n for n in notifier.sent if n["kind"] == "evaluation_delayed"]
        assert [n["rule_name"] for n in delayed] == [
            "harava.agent_outbound_refused"
        ]  # paged once, not per retry
        assert "tuisku_backlog" in notifier.kinds()  # and the queue's lag pages
    finally:
        hold.rollback()
        hold.close()
    notifier = RecordingNotifier()
    run_worker(app_db.worker_url, rules, Clock(AT + timedelta(minutes=31)), notifier)
    assert [n["kind"] for n in notifier.sent if n.get("finding_uid") == uid] == [
        "finding_occurrence"
    ]


def _readable_tables(url: str) -> list[tuple[str, bool, bool]]:
    """(table, may update, may insert) for every public table the API role may read."""
    return [
        (name, bool(upd), bool(ins))
        for name, upd, ins in query(
            url,
            "SELECT c.relname, has_table_privilege(c.oid, 'UPDATE') "
            "OR has_any_column_privilege(c.oid, 'UPDATE'), has_table_privilege(c.oid, 'INSERT') "
            "FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace "
            "WHERE n.nspname = 'public' AND c.relkind IN ('r', 'p') "
            "AND has_table_privilege(c.oid, 'SELECT') ORDER BY c.relname",
        )
    ]


def test_every_lock_the_api_role_can_take_leaves_pages_flowing(app_db: AppDatabase) -> None:
    """Round nine, per table: the API role takes FOR UPDATE and FOR SHARE on every row it may,
    and the strongest table lock its grants allow, on every table it can read, all in one open
    transaction. A critical row still pages, and a dead-lettered row's page still goes out."""
    tables = _readable_tables(app_db.app_url)
    assert {t for t, upd, _ in tables if upd} == {
        "meta_counters",
        "operator_tokens",
        "source_token_usage",
    }
    critical, critical_uid = _falco_victim(app_db)
    doomed, doomed_uid = _falco_victim(app_db)
    hold = psycopg.connect(app_db.app_url)
    try:
        for table, may_update, may_insert in tables:
            if may_update:
                hold.execute(f"SELECT 1 FROM {table} FOR UPDATE").fetchall()  # type: ignore[arg-type]
                hold.execute(f"SELECT 1 FROM {table} FOR SHARE").fetchall()  # type: ignore[arg-type]
            else:
                with pytest.raises(errors.InsufficientPrivilege):
                    with hold.transaction():
                        hold.execute(f"SELECT 1 FROM {table} FOR SHARE")  # type: ignore[arg-type]
            mode = "ROW EXCLUSIVE" if may_insert or may_update else "ACCESS SHARE"
            hold.execute(f"LOCK TABLE {table} IN {mode} MODE")  # type: ignore[arg-type]

        def fail_on_doomed(rule: Any, env: Any) -> None:
            if rule.id == FALCO_CRITICAL and env["id"] == doomed:
                raise RuntimeError("boom")

        clock = Clock(AT + timedelta(minutes=1))
        notifier = RecordingNotifier()
        for _ in range(7):
            run_worker(
                app_db.worker_url,
                builtin_rules(),
                clock,
                notifier,
                before_pair=fail_on_doomed,
                lock_timeout_ms=200,
            )
            clock.advance(minutes=1)
        assert _paged_for(app_db, notifier, critical_uid)
        dead = [n for n in notifier.sent if n["kind"] == "evaluation_dead_lettered"]
        assert any(n["row"]["uid"] == doomed_uid for n in dead)
    finally:
        hold.rollback()
        hold.close()


# --- round nine: the worker's heartbeat and the health endpoint -------------------------------


def test_the_health_endpoint_tells_an_outside_monitor_whether_the_worker_runs(
    app_db: AppDatabase,
) -> None:
    from tests.support import client

    with psycopg.connect(app_db.owner_url) as conn:
        conn.execute("DELETE FROM worker_heartbeats")
    with client(app_db.app_url, worker_backlog_seconds=1e9) as c:
        r = c.get("/v1/worker/health")  # unauthenticated
        assert (r.status_code, r.json()["status"]) == (503, "no_worker")
        run_worker(app_db.worker_url, builtin_rules(), Clock(AT))
        [(beats,)] = query(app_db.worker_url, "SELECT count(*) FROM worker_heartbeats")
        assert beats == 1
        r = c.get("/v1/worker/health")
        assert (r.status_code, r.json()["status"]) == (200, "ok"), r.text
        assert r.json()["heartbeat_age_seconds"] < 60
    # The API role reads the heartbeat; it cannot forge one.
    for statement in [
        "INSERT INTO worker_heartbeats (worker, beat_at) VALUES ('forged', now())",
        "UPDATE worker_heartbeats SET beat_at = now()",
    ]:
        assert "permission denied" in str(_refused(app_db.app_url, statement))
    with psycopg.connect(app_db.owner_url) as conn:  # a stale heartbeat
        conn.execute("UPDATE worker_heartbeats SET beat_at = now() - interval '1 hour'")
    with client(app_db.app_url, worker_backlog_seconds=1e9) as c:
        r = c.get("/v1/worker/health")
        assert (r.status_code, r.json()["status"]) == (503, "no_worker")


def test_the_health_endpoint_pages_an_undelivered_backlog(app_db: AppDatabase) -> None:
    from tests.support import client

    run_worker(app_db.worker_url, builtin_rules(), Clock(AT))
    with psycopg.connect(app_db.worker_url) as conn:  # one notification never delivered
        conn.execute(
            "INSERT INTO notifications (dedupe_key, kind, severity_id, payload) "
            "VALUES (%s, 'test', 0, '{}')",
            (f"health:{uuid.uuid4()}",),
        )
    with client(app_db.app_url, worker_backlog_seconds=0.001) as c:
        r = c.get("/v1/worker/health")
    assert (r.status_code, r.json()["status"]) == (503, "backlog"), r.text
    assert r.json()["oldest_undelivered_seconds"] > 0


@pytest.mark.parametrize("step", ["_finish", "_dead_letter"])
def test_one_stuck_row_never_cancels_the_drain(
    app_db: AppDatabase, monkeypatch: pytest.MonkeyPatch, step: str
) -> None:
    """Round nine: a lock or statement timeout while finishing or dead-lettering one row is
    retried later; the pass goes on to the other rows and to the drain."""
    from tuisku.worker.engine import Worker

    stuck, _ = _falco_victim(app_db)
    critical, critical_uid = _falco_victim(app_db)
    original = getattr(Worker, step)

    async def held_up(self: Any, conn: Any, queue_row: Any, *args: Any) -> Any:
        if queue_row["detection_id"] == stuck:
            raise errors.QueryCanceled("canceling statement due to statement timeout")
        return await original(self, conn, queue_row, *args)

    monkeypatch.setattr(Worker, step, held_up)

    def fail_on_stuck(rule: Any, env: Any) -> None:
        if step == "_dead_letter" and env["id"] == stuck:
            raise RuntimeError("boom")

    clock = Clock(AT + timedelta(minutes=1))
    notifier = RecordingNotifier()
    for _ in range(7):
        run_worker(app_db.worker_url, builtin_rules(), clock, notifier, before_pair=fail_on_stuck)
        clock.advance(minutes=1)
    assert _paged_for(app_db, notifier, critical_uid)
    [(left,)] = query(
        app_db.owner_url, "SELECT count(*) FROM evaluation_queue WHERE detection_id = %s", (stuck,)
    )
    assert left == 1  # still queued, retried later
