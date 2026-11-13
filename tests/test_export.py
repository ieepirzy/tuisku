"""Export of finding and incident events to an append-only sink over OTLP/HTTP JSON (ADR 0012).

A tiny local HTTP server stands in for the sink (an OpenTelemetry Collector's OTLP/HTTP logs
receiver) and records every POST.
"""

from __future__ import annotations

import hashlib
import json
import threading
import time
import uuid
from collections.abc import Iterator
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

import psycopg
import pytest
from psycopg import AsyncConnection
from pydantic import ValidationError

from tests.conftest import REPO_ROOT, AppDatabase, make_settings
from tests.support import auth, client, ndjson, new_source, operator_token, post_records, query
from tests.worker_support import (
    QUIET_BACKLOG,
    Clock,
    RecordingNotifier,
    builtin_rules,
    run_async,
    run_worker,
)
from tuisku.store.tokens import Role
from tuisku.worker import run as worker_run
from tuisku.worker.engine import Stats, Worker, WorkerConfig
from tuisku.worker.export import (
    SCHEMA,
    ExportConfig,
    Exporter,
    build_record,
    redact_entity_key,
)

FIXTURES = REPO_ROOT / "tests" / "fixtures" / "harava"
T0 = datetime(2026, 11, 1, 9, 30, tzinfo=UTC)
REASON = "Checked with A. Person: the agent run was expected"  # free text a person typed


# --- the sink -----------------------------------------------------------------------------------


@dataclass
class Sink:
    """Records each POST; answers with the next status in ``statuses`` (then 200)."""

    url: str = ""
    posts: list[dict[str, Any]] = field(default_factory=list)
    statuses: list[int] = field(default_factory=list)
    delay: float = 0.0
    lock: threading.Lock = field(default_factory=threading.Lock)

    def records(self) -> list[dict[str, Any]]:
        """Every exported record, from every POST, in order."""
        return [
            json.loads(lr["body"]["stringValue"])
            for post in self.posts
            for rl in post["resourceLogs"]
            for sl in rl["scopeLogs"]
            for lr in sl["logRecords"]
        ]


@pytest.fixture
def sink() -> Iterator[Sink]:
    state = Sink()

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self) -> None:  # noqa: N802 (http.server's name)
            body = self.rfile.read(int(self.headers["Content-Length"]))
            time.sleep(state.delay)
            with state.lock:
                status = state.statuses.pop(0) if state.statuses else 200
                if 200 <= status < 300:
                    assert self.path == "/v1/logs"
                    assert self.headers["Content-Type"] == "application/json"
                state.posts.append(json.loads(body) | {"_status": status})
            answer = b"{}" if status == 200 else b'{"error": "down"}'
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(answer)))
            self.end_headers()
            self.wfile.write(answer)

        def log_message(self, *args: Any) -> None:
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    state.url = f"http://127.0.0.1:{server.server_address[1]}/v1/logs"
    try:
        yield state
    finally:
        server.shutdown()
        server.server_close()


class Ticks:
    """A settable monotonic clock for the exporter's backoff."""

    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now


def exporter(url: str | None, ticks: Ticks | None = None, **config: Any) -> Exporter:
    return Exporter(
        ExportConfig(url=url, build_revision="test-revision", **config),
        monotonic=ticks or Ticks(),
    )


def run_with_export(url: str, clock: Clock, exp: Exporter, **config: Any) -> Stats:
    config.setdefault("backlog_after", QUIET_BACKLOG.backlog_after)
    worker = Worker(
        rule_set=builtin_rules(),
        clock=clock,
        notifier=RecordingNotifier(),
        config=WorkerConfig(**config),
        exporter=exp,
    )
    return run_async(url, worker.run_until_idle)


def export_once(url: str, exp: Exporter, backlog_after: timedelta = timedelta(days=1)) -> int:
    return run_async(url, lambda conn: exp.run(conn, backlog_after, datetime.now(UTC)))


def queued(url: str) -> int:
    return query(url, "SELECT count(*) FROM export_queue")[0][0]


def harava_finding(url: str, clock: Clock) -> None:
    """Ingest the Harava fixture through the API: the agent outbound rule opens a finding."""
    token = new_source(url, "harava-edge", adapter="harava")
    lines = (FIXTURES / "plain.log").read_text().splitlines()
    with client(url, clock=clock) as c:
        assert post_records(c, "harava-edge", token, ndjson(*lines)).status_code == 200


# --- end to end ---------------------------------------------------------------------------------


def test_findings_and_triage_are_exported_and_survive_a_failing_sink(
    fresh_database_url: str, sink: Sink
) -> None:
    url = fresh_database_url
    clock = Clock(T0)
    ticks = Ticks()
    exp = exporter(sink.url, ticks)
    harava_finding(url, clock)
    stats = run_with_export(url, clock, exp)
    assert stats.exported > 0
    assert queued(url) == 0

    # The envelope: one resource (service tuisku), one scope, one log record per event.
    post = sink.posts[0]
    [resource_logs] = post["resourceLogs"]
    attrs = {a["key"]: a["value"]["stringValue"] for a in resource_logs["resource"]["attributes"]}
    assert attrs == {"service.name": "tuisku", "service.version": "test-revision"}
    [scope_logs] = resource_logs["scopeLogs"]
    first = scope_logs["logRecords"][0]
    record = json.loads(first["body"]["stringValue"])
    log_attrs = {a["key"]: a["value"]["stringValue"] for a in first["attributes"]}
    assert log_attrs["tuisku.record_uid"] == record["record_uid"]
    assert log_attrs["tuisku.stream"] == record["stream"]

    # Every event of the database was exported exactly once, keyed by its uid.
    records = sink.records()
    events = {
        r[0]
        for r in query(
            url,
            "SELECT uid::text FROM finding_events UNION ALL SELECT uid::text FROM incident_events",
        )
    }
    assert sorted(r["record_uid"] for r in records) == sorted(events)

    # The opened agent finding: its event and its committed state.
    [(finding_uid,)] = query(
        url,
        "SELECT uid::text FROM findings WHERE rule_ref ->> 'name' = "
        "'harava.agent_outbound_refused'",
    )
    opened = next(
        r
        for r in records
        if r["stream"] == "finding"
        and r["finding"]["uid"] == finding_uid
        and r["event"]["kind"] == "opened"
    )
    assert opened["schema"] == SCHEMA
    assert opened["exporter"] == {"service": "tuisku", "build_revision": "test-revision"}
    assert opened["event"]["actor"].startswith("rule:f542db3a-6926-4df9-9183-449491345d3c@")
    assert opened["event"]["reason_sha256"] is None
    finding = opened["finding"]
    assert finding["rule_id"] == "f542db3a-6926-4df9-9183-449491345d3c"
    assert finding["pack_id"] == "harava" and len(finding["pack_sha256"]) == 64
    assert finding["status"] == "open" and finding["severity_id"] == 4
    assert "caller:harava/agents" in finding["entity_keys"]
    assert finding["first_seen_at"].endswith("Z") and finding["incident_uid"]
    # The state is what the event's transaction committed: linked to its incident already.
    [(incident_uid,)] = query(
        url,
        "SELECT i.uid::text FROM incidents i JOIN findings f ON f.incident_id = i.id "
        "WHERE f.uid = %s",
        (finding_uid,),
    )
    assert finding["incident_uid"] == incident_uid
    incident_opened = next(
        r
        for r in records
        if r["stream"] == "incident"
        and r["event"]["kind"] == "opened"
        and r["incident"]["uid"] == incident_uid
    )
    assert incident_opened["incident"]["status"] == "open"
    # Severity and time on the OTLP log record come from the event and the finding.
    log_record = next(
        lr
        for lr in scope_logs["logRecords"]
        if json.loads(lr["body"]["stringValue"])["record_uid"] == opened["record_uid"]
    )
    assert (log_record["severityNumber"], log_record["severityText"]) == (17, "High")
    [(at,)] = query(url, "SELECT at FROM finding_events WHERE uid = %s", (opened["record_uid"],))
    assert int(log_record["timeUnixNano"]) == int(at.timestamp()) * 10**9 + at.microsecond * 1000

    # A triage status change, through the API, is exported too: its reason only as a digest.
    triager = operator_token(url, Role.TRIAGE)
    with client(url, clock=clock) as c:
        r = c.post(
            f"/v1/findings/{finding_uid}/status",
            json={"status": "acknowledged", "reason": REASON},
            headers=auth(triager),
        )
        assert r.status_code == 200, r.text
    assert queued(url) == 1
    before = len(sink.posts)
    run_with_export(url, clock, exp)
    [triaged] = [json.loads(lr["body"]["stringValue"]) for lr in _log_records(sink.posts[before])]
    assert triaged["event"]["kind"] == "status_changed"
    assert triaged["event"]["actor"].startswith("operator:")
    assert triaged["event"]["new_value"] == {"status": "acknowledged"}
    assert triaged["finding"]["status"] == "acknowledged"
    assert triaged["event"]["reason_sha256"] == hashlib.sha256(REASON.encode()).hexdigest()
    assert triaged["event"]["reason_length"] == len(REASON)
    assert "A. Person" not in json.dumps(sink.posts)

    # The sink fails: the rows stay queued, and are sent again after the backoff.
    with client(url, clock=clock) as c:
        r = c.post(
            f"/v1/findings/{finding_uid}/status",
            json={"status": "resolved", "reason": REASON},
            headers=auth(triager),
        )
        assert r.status_code == 200, r.text
    sink.statuses[:] = [500]
    before = len(sink.posts)
    run_with_export(url, clock, exp)
    assert [p["_status"] for p in sink.posts[before:]] == [500]
    assert queued(url) == 1 and exp.failures == 1
    run_with_export(url, clock, exp)  # still backing off: nothing is sent
    assert len(sink.posts) == before + 1
    ticks.now += 5.0
    run_with_export(url, clock, exp)
    assert [p["_status"] for p in sink.posts[before:]] == [500, 200]
    assert queued(url) == 0 and exp.failures == 0
    failed, resent = (_log_records(p) for p in sink.posts[before:])
    assert failed == resent  # the same record, byte for byte: consumers deduplicate on its uid
    [resolved] = [json.loads(lr["body"]["stringValue"]) for lr in resent]
    assert resolved["finding"]["status"] == "resolved"


def _log_records(post: dict[str, Any]) -> list[dict[str, Any]]:
    return [lr for rl in post["resourceLogs"] for sl in rl["scopeLogs"] for lr in sl["logRecords"]]


def test_a_lower_id_that_commits_later_is_not_lost(fresh_database_url: str, sink: Sink) -> None:
    """Identity values are not commit-ordered: an id cursor would skip the earlier id that
    commits after a later one has been exported. The queue does not."""
    url = fresh_database_url
    clock = Clock(T0)
    harava_finding(url, clock)
    exp = exporter(sink.url)
    run_with_export(url, clock, exp)
    [(finding_id,)] = query(
        url, "SELECT id FROM findings WHERE rule_ref ->> 'name' = 'harava.agent_outbound_refused'"
    )
    insert = (
        "INSERT INTO finding_events (finding_id, actor, kind, new_value) "
        "VALUES (%s, 'system', 'status_changed', '{\"status\": \"open\"}') RETURNING id, uid::text"
    )
    with psycopg.connect(url) as slow:
        # The slow transaction takes the lower event id, and the lower queue id too (its
        # deferred trigger is made to run now instead of at commit).
        slow.execute("SET CONSTRAINTS ALL IMMEDIATE")
        early_id, early_uid = slow.execute(insert, (finding_id,)).fetchone()  # type: ignore[misc]
        with psycopg.connect(url) as fast:
            late_id, late_uid = fast.execute(insert, (finding_id,)).fetchone()  # type: ignore[misc]
        assert early_id < late_id
        before = len(sink.posts)
        assert export_once(url, exp) == 1
        assert [r["record_uid"] for r in _records(sink.posts[before:])] == [late_uid]
        slow.commit()
    [(early_queue_id,)] = query(url, "SELECT id FROM export_queue")
    assert export_once(url, exp) == 1
    assert [r["record_uid"] for r in _records(sink.posts[before + 1 :])] == [early_uid]
    assert queued(url) == 0 and early_queue_id > 0


def _records(posts: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [json.loads(lr["body"]["stringValue"]) for p in posts for lr in _log_records(p)]


def test_a_timeout_or_refused_connection_leaves_rows_queued(
    fresh_database_url: str, sink: Sink
) -> None:
    url = fresh_database_url
    clock = Clock(T0)
    harava_finding(url, clock)
    ticks = Ticks()
    # Nothing listens on port 1.
    down = exporter("http://127.0.0.1:1/v1/logs", ticks)
    stats = run_with_export(url, clock, down)
    assert stats.exported == 0 and stats.evaluated > 0  # evaluation went on
    n = queued(url)
    assert n > 0 and down.failures == 1

    sink.delay = 2.0  # the sink answers, but too late
    slow = exporter(sink.url, ticks, timeout_seconds=0.3)
    started = time.monotonic()
    assert export_once(url, slow) == 0
    assert time.monotonic() - started < 1.5
    assert queued(url) == n and slow.failures == 1


def test_a_backlog_of_exports_pages(fresh_database_url: str) -> None:
    url = fresh_database_url
    clock = Clock(T0)
    harava_finding(url, clock)
    exp = exporter("http://127.0.0.1:1/v1/logs")
    notifier = RecordingNotifier()
    worker = Worker(
        rule_set=builtin_rules(),
        clock=clock,
        notifier=notifier,
        config=WorkerConfig(backlog_after=timedelta(minutes=5)),
        exporter=exp,
    )
    run_async(url, worker.run_until_idle)
    assert queued(url) > 0
    # No export backlog yet: the rows are young (whatever the evaluation queue says).
    assert query(
        url,
        "SELECT count(*) FROM detections WHERE kind = 'tuisku.meta.backlog' AND subject = 'export'",
    ) == [(0,)]
    with psycopg.connect(url) as conn:  # the owner may backdate the working table
        conn.execute("UPDATE export_queue SET enqueued_at = now() - interval '10 minutes'")
    run_async(url, worker.run_once)
    [(details,)] = query(
        url,
        "SELECT explanation FROM detections WHERE kind = 'tuisku.meta.backlog' "
        "AND subject = 'export'",
    )
    assert details["queued"] == queued(url) and details["limit_seconds"] == 300
    run_async(url, worker.run_once)  # the page the database wrote goes out with the next drain
    assert "tuisku_backlog" in notifier.kinds()


def test_export_disabled_discards_old_rows_and_never_pages(fresh_database_url: str) -> None:
    url = fresh_database_url
    clock = Clock(T0)
    harava_finding(url, clock)
    off = exporter(None)
    assert not off.enabled
    notifier = RecordingNotifier()
    worker = Worker(
        rule_set=builtin_rules(),
        clock=clock,
        notifier=notifier,
        config=WorkerConfig(backlog_after=timedelta(minutes=5)),
        exporter=off,
    )
    run_async(url, worker.run_until_idle)
    n = queued(url)
    assert n > 0  # young rows wait: an enabled replica would still send them
    with psycopg.connect(url) as conn:
        conn.execute(
            "UPDATE export_queue SET enqueued_at = now() - interval '10 minutes' "
            "WHERE id IN (SELECT id FROM export_queue ORDER BY id LIMIT 2)"
        )
    run_async(url, worker.run_once)
    assert queued(url) == n - 2
    assert query(url, "SELECT count(*) FROM detections WHERE subject = 'export'") == [(0,)]
    assert "tuisku_backlog" not in notifier.kinds()


def test_the_worker_command_always_has_an_exporter() -> None:
    off = worker_run.exporter(make_settings("postgresql://u@h/d"))
    assert not off.enabled
    on = worker_run.exporter(
        make_settings(
            "postgresql://u@h/d",
            export_otlp_logs_url="http://collector.example:4318/v1/logs",
            export_batch_size=7,
            export_timeout_seconds=3,
            export_redact_entity_kinds=" user, k8s-ns ",
        )
    )
    assert on.config.url == "http://collector.example:4318/v1/logs"
    assert (on.config.batch_size, on.config.timeout_seconds) == (7, 3)
    assert on.config.redact_entity_kinds == frozenset({"user", "k8s-ns"})
    assert on.config.build_revision == "test-revision"


@pytest.mark.parametrize(
    ("setting", "value"),
    [
        ("export_otlp_logs_url", "ftp://collector.example/v1/logs"),
        ("export_otlp_logs_url", "collector:4318"),
        ("export_redact_entity_kinds", "user;email"),
        ("export_batch_size", 0),
    ],
)
def test_export_settings_are_validated(setting: str, value: Any) -> None:
    with pytest.raises(ValidationError) as info:
        make_settings("postgresql://u@h/d", **{setting: value})
    assert "collector.example" not in str(info.value)  # a URL may carry a secret


def test_default_settings_disable_export_and_redact_users_and_emails() -> None:
    settings = make_settings("postgresql://u@h/d")
    assert settings.export_otlp_logs_url is None
    assert settings.export_redacted_kinds == frozenset({"user", "email"})
    assert (settings.export_batch_size, settings.export_timeout_seconds) == (100, 10.0)


# --- the record: no personal data ---------------------------------------------------------------


def _row(**overrides: Any) -> dict[str, Any]:
    row: dict[str, Any] = {
        "stream": "incident",
        "event_uid": "11111111-1111-4111-8111-111111111111",
        "at": datetime(2026, 11, 1, 9, 0, tzinfo=UTC),
        "actor": "operator:00000000-0000-4000-8000-000000000000",
        "kind": "status_changed",
        "old_value": None,
        "new_value": None,
        "reason": None,
        "payload": {"from": "open", "to": "closed", "disposition": "false_positive"},
        "state": {
            "uid": "22222222-2222-4222-8222-222222222222",
            "title": "Agent caller had outbound data refused",
            "severity_id": 4,
            "status": "closed",
            "entity_keys": ["user:alice", "email:alice@example.org", "ip:192.0.2.1", "nokind"],
            "opened_at": "2026-11-01T11:00:00+02:00",
        },
    }
    row.update(overrides)
    return row


def test_entity_keys_of_the_configured_kinds_are_hashed() -> None:
    record = build_record(_row(), ExportConfig())
    alice = hashlib.sha256(b"alice").hexdigest()
    email = hashlib.sha256(b"alice@example.org").hexdigest()
    assert record["incident"]["entity_keys"] == [
        f"user:sha256:{alice}",
        f"email:sha256:{email}",
        "ip:192.0.2.1",
        "nokind",
    ]
    assert "alice" not in json.dumps(record)
    assert record["incident"]["opened_at"] == "2026-11-01T09:00:00Z"
    ips = build_record(_row(), ExportConfig(redact_entity_kinds=frozenset({"ip"})))
    assert ips["incident"]["entity_keys"][:3] == [
        "user:alice",
        "email:alice@example.org",
        f"ip:sha256:{hashlib.sha256(b'192.0.2.1').hexdigest()}",
    ]
    assert redact_entity_key("user:", frozenset({"user"})).startswith("user:sha256:")


def test_typed_text_is_exported_as_a_digest_only() -> None:
    note = "call A. Person at home"
    record = build_record(
        _row(
            kind="note",
            payload={
                "from": "open",
                "to": "closed",
                "reason": REASON,
                "note": note,
                "extra": {"text": note},
                "count": 3,
            },
        ),
        ExportConfig(),
    )
    event = record["event"]
    assert event["reason_sha256"] == hashlib.sha256(REASON.encode()).hexdigest()
    assert event["reason_length"] == len(REASON)
    assert event["payload"]["from"] == "open" and event["payload"]["count"] == 3
    assert event["payload"]["note"] == {
        "sha256": hashlib.sha256(note.encode()).hexdigest(),
        "length": len(note),
    }
    assert set(event["payload"]["extra"]) == {"sha256", "length"}
    assert "reason" not in event["payload"]
    assert "Person" not in json.dumps(record)
    # A finding event's reason column, the same way.
    finding = build_record(
        _row(
            stream="finding",
            reason=REASON,
            payload={},
            new_value={"status": "resolved"},
            state={"uid": "x", "rule_ref": {"pack": "p"}, "entity_keys": []},
        ),
        ExportConfig(),
    )
    assert finding["event"]["reason_length"] == len(REASON)
    assert finding["finding"]["pack_id"] == "p"
    assert REASON not in json.dumps(finding)


# --- roles (ADR 0011) ---------------------------------------------------------------------------


def test_api_triage_is_enqueued_and_the_worker_role_exports_it(
    app_db: AppDatabase, sink: Sink, tmp_path: Path
) -> None:
    """The API role cannot write the queue, yet its triage is enqueued (by the owner trigger),
    and the worker role, with SELECT and DELETE only, exports and removes it."""
    clock = Clock(T0)
    caller = f"c{uuid.uuid4().hex[:10]}"
    params = tmp_path / "params.yaml"
    params.write_text(f"harava: {{restricted_callers: [{caller}]}}\n")
    source = f"h{uuid.uuid4().hex[:10]}"
    token = new_source(app_db.app_url, source, adapter="harava")
    line = (
        f"2026-11-01 09:14:03,512 WARNING harava.api outbound data refused: caller={caller} "
        "urls=1 findings=email/query/percent"
    )
    with client(app_db.app_url, clock=clock) as c:
        assert post_records(c, source, token, ndjson(line)).status_code == 200
    run_worker(app_db.worker_url, builtin_rules(params), Clock(T0 + timedelta(minutes=1)))
    [(finding_uid,)] = query(
        app_db.owner_url,
        "SELECT uid::text FROM findings WHERE rule_ref ->> 'name' = "
        "'harava.agent_outbound_refused' AND group_values = %s::jsonb",
        (json.dumps([caller]),),
    )
    triager = operator_token(app_db.app_url, Role.TRIAGE)
    with client(app_db.app_url, clock=clock) as c:
        r = c.post(
            f"/v1/findings/{finding_uid}/status",
            json={"status": "acknowledged", "reason": REASON},
            headers=auth(triager),
        )
        assert r.status_code == 200, r.text
    [(event_uid,)] = query(
        app_db.owner_url,
        "SELECT e.uid::text FROM export_queue q JOIN finding_events e "
        "ON e.id = q.finding_event_id WHERE e.actor LIKE 'operator:%%' "
        "AND e.new_value ->> 'status' = 'acknowledged' AND q.state ->> 'uid' = %s",
        (finding_uid,),
    )
    exp = exporter(sink.url, batch_size=10_000)

    async def drain(conn: AsyncConnection[Any]) -> int:
        total = 0
        while n := await exp.run(conn, timedelta(days=1), datetime.now(UTC)):
            total += n
        return total

    assert run_async(app_db.worker_url, drain) > 0
    assert event_uid in {r["record_uid"] for r in sink.records()}
    assert query(
        app_db.owner_url,
        "SELECT count(*) FROM export_queue q JOIN finding_events e ON e.id = q.finding_event_id "
        "WHERE e.uid = %s",
        (event_uid,),
    ) == [(0,)]
