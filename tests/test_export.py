"""Export of finding and incident events to an append-only sink over OTLP/HTTP JSON (ADR 0012).

A tiny local HTTP server stands in for the sink (an OpenTelemetry Collector's OTLP/HTTP logs
receiver) and records every POST.
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import threading
import time
import uuid
from collections.abc import Callable, Iterator
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
from tests.worker_support import Clock, RecordingNotifier, builtin_rules, run_async, run_worker
from tuisku.config import ConfigError
from tuisku.store.tokens import Role
from tuisku.worker import run as worker_run
from tuisku.worker.engine import Worker
from tuisku.worker.export import SCHEMA, ExportConfig, Exporter, Pseudonyms, Round, build_record

FIXTURES = REPO_ROOT / "tests" / "fixtures" / "harava"
T0 = datetime(2026, 11, 1, 9, 30, tzinfo=UTC)
REASON = "Checked with A. Person: the agent run was expected"  # free text a person typed
KEY = "synthetic-test-pseudonym-key-7f3a9c1e5b"  # a test key, never a deployment's


def mac(text: str) -> str:
    return hmac.new(KEY.encode(), text.encode(), hashlib.sha256).hexdigest()


# --- the sink -----------------------------------------------------------------------------------


@dataclass
class Sink:
    """Records each POST. ``answer(records)`` picks the status and body (default 200, "{}")."""

    url: str = ""
    posts: list[dict[str, Any]] = field(default_factory=list)
    statuses: list[int] = field(default_factory=list)  # served first, one per POST
    answer: Callable[[list[dict[str, Any]]], tuple[int, bytes]] | None = None
    delay: float = 0.0
    lock: threading.Lock = field(default_factory=threading.Lock)

    def records(self, posts: list[dict[str, Any]] | None = None) -> list[dict[str, Any]]:
        """Every record of ``posts`` (default: every POST), in order."""
        return [
            json.loads(lr["body"]["stringValue"])
            for post in (self.posts if posts is None else posts)
            for rl in post["resourceLogs"]
            for sl in rl["scopeLogs"]
            for lr in sl["logRecords"]
        ]

    def log_records(self, post: dict[str, Any]) -> list[dict[str, Any]]:
        return [
            lr for rl in post["resourceLogs"] for sl in rl["scopeLogs"] for lr in sl["logRecords"]
        ]


@pytest.fixture
def sink() -> Iterator[Sink]:
    state = Sink()

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self) -> None:  # noqa: N802 (http.server's name)
            body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            time.sleep(state.delay)
            with state.lock:
                status, answer = 200, b"{}"
                if state.statuses:
                    status = state.statuses.pop(0)
                elif state.answer is not None:
                    status, answer = state.answer(state.records([body]))
                assert self.path == "/v1/logs"
                assert self.headers["Content-Type"] == "application/json"
                state.posts.append(body | {"_status": status, "_headers": dict(self.headers)})
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
    config.setdefault("pseudonym_key", KEY.encode())
    return Exporter(
        ExportConfig(url=url, build_revision="test-revision", **config),
        monotonic=ticks or Ticks(),
    )


def export_round(url: str, exp: Exporter, backlog_after: timedelta = timedelta(days=1)) -> Round:
    return run_async(url, lambda conn: exp.round(conn, backlog_after))


def enable_export(owner_url: str, on: bool = True) -> None:
    """What `tuisku migrate` does with an export URL set (ADR 0012)."""
    with psycopg.connect(owner_url) as conn:
        conn.execute("UPDATE export_state SET enabled = %s", (on,))


def queued(url: str) -> int:
    return query(url, "SELECT count(*) FROM export_queue")[0][0]


def export_failed(url: str) -> list[tuple[str, dict[str, Any]]]:
    return query(
        url,
        "SELECT subject, explanation FROM detections WHERE kind = 'tuisku.meta.export_failed' "
        "ORDER BY id",
    )


def harava_finding(url: str, clock: Clock) -> None:
    """Ingest the Harava fixture through the API, then evaluate: the agent outbound rule opens a
    finding and an incident."""
    token = new_source(url, "harava-edge", adapter="harava")
    lines = (FIXTURES / "plain.log").read_text().splitlines()
    with client(url, clock=clock) as c:
        assert post_records(c, "harava-edge", token, ndjson(*lines)).status_code == 200
    run_worker(url, builtin_rules(), clock)


def agent_finding_uid(url: str) -> str:
    [(uid,)] = query(
        url,
        "SELECT uid::text FROM findings WHERE rule_ref ->> 'name' = "
        "'harava.agent_outbound_refused'",
    )
    return uid


# --- end to end ---------------------------------------------------------------------------------


def test_findings_and_triage_are_exported_and_survive_a_failing_sink(
    fresh_database_url: str, sink: Sink
) -> None:
    url = fresh_database_url
    enable_export(url)
    clock = Clock(T0)
    ticks = Ticks()
    exp = exporter(sink.url, ticks)
    harava_finding(url, clock)
    assert export_round(url, exp).delivered > 0
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
    events = [
        r[0]
        for r in query(
            url,
            "SELECT uid::text FROM finding_events UNION ALL SELECT uid::text FROM incident_events",
        )
    ]
    assert sorted(r["record_uid"] for r in records) == sorted(events)

    # The opened agent finding: its event and its committed state.
    finding_uid = agent_finding_uid(url)
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
    assert opened["event"]["reason_hmac"] is None
    finding = opened["finding"]
    assert finding["rule_id"] == "f542db3a-6926-4df9-9183-449491345d3c"
    assert finding["pack_id"] == "harava" and len(finding["pack_sha256"]) == 64
    assert finding["status"] == "open" and finding["severity_id"] == 4
    # The caller is pseudonymised by default (ADR 0008): never raw in the sink.
    assert finding["entity_keys"] == [f"caller:hmac:{mac('harava/agents')}"]
    assert "caller:harava/agents" not in json.dumps(sink.posts)
    assert finding["first_seen_at"] == "2026-11-01T09:14:03.512000Z"
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
    assert opened["event"]["at"] == at.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ")

    # A triage status change, through the API, is exported too: its reason only as an HMAC.
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
    export_round(url, exp)
    [triaged] = sink.records(sink.posts[before:])
    assert triaged["event"]["kind"] == "status_changed"
    assert triaged["event"]["actor"].startswith("operator:")
    assert triaged["event"]["new_value"] == {"status": "acknowledged"}
    assert triaged["finding"]["status"] == "acknowledged"
    assert triaged["event"]["reason_hmac"] == mac(REASON)
    assert triaged["event"]["reason_length"] == len(REASON)
    assert hashlib.sha256(REASON.encode()).hexdigest() not in json.dumps(triaged)
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
    export_round(url, exp)
    assert [p["_status"] for p in sink.posts[before:]] == [500]
    assert queued(url) == 1 and exp.failures == 1
    export_round(url, exp)  # still backing off: nothing is sent
    assert len(sink.posts) == before + 1
    ticks.now += 5.0
    export_round(url, exp)
    assert [p["_status"] for p in sink.posts[before:]] == [500, 200]
    assert queued(url) == 0 and exp.failures == 0
    failed, resent = (sink.log_records(p) for p in sink.posts[before:])
    assert failed == resent  # the same record, byte for byte: consumers deduplicate on its uid
    [resolved] = sink.records(sink.posts[-1:])
    assert resolved["finding"]["status"] == "resolved"


def test_a_lower_id_that_commits_later_is_not_lost(fresh_database_url: str, sink: Sink) -> None:
    """Identity values are not commit-ordered: an id cursor would skip the earlier id that
    commits after a later one has been exported. The queue does not."""
    url = fresh_database_url
    enable_export(url)
    harava_finding(url, Clock(T0))
    exp = exporter(sink.url)
    export_round(url, exp)
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
        assert export_round(url, exp).delivered == 1
        assert [r["record_uid"] for r in sink.records(sink.posts[before:])] == [late_uid]
        slow.commit()
    assert export_round(url, exp).delivered == 1
    assert [r["record_uid"] for r in sink.records(sink.posts[before + 1 :])] == [early_uid]
    assert queued(url) == 0


def test_a_timeout_or_refused_connection_leaves_rows_queued(
    fresh_database_url: str, sink: Sink
) -> None:
    url = fresh_database_url
    enable_export(url)
    harava_finding(url, Clock(T0))
    ticks = Ticks()
    down = exporter("http://127.0.0.1:1/v1/logs", ticks)  # nothing listens on port 1
    assert export_round(url, down).delivered == 0
    n = queued(url)
    assert n > 0 and down.failures == 1

    sink.delay = 2.0  # the sink answers, but too late
    slow = exporter(sink.url, ticks, timeout_seconds=0.3)
    started = time.monotonic()
    assert export_round(url, slow).delivered == 0
    assert time.monotonic() - started < 1.5
    assert queued(url) == n and slow.failures == 1


def test_a_slow_sink_holds_no_transaction_and_never_delays_evaluation(
    fresh_database_url: str, sink: Sink
) -> None:
    """The export runs on its own connection, with no transaction open across the request, so
    evaluation and paging go on while the sink takes its time (ADR 0012)."""
    url = fresh_database_url
    enable_export(url)
    clock = Clock(T0)
    harava_finding(url, clock)
    sink.delay = 1.5
    exp = exporter(sink.url, timeout_seconds=5)
    worker = Worker(rule_set=builtin_rules(), clock=clock, notifier=RecordingNotifier())

    async def scenario() -> tuple[list[Any], float, Round]:
        export_conn = await AsyncConnection.connect(url, autocommit=True)
        worker_conn = await AsyncConnection.connect(url, autocommit=True)
        async with export_conn, worker_conn:
            exporting = asyncio.create_task(exp.round(export_conn, timedelta(days=1)))
            await asyncio.sleep(0.5)  # the POST is in flight
            pid = export_conn.info.backend_pid
            cur = await worker_conn.execute(
                "SELECT state FROM pg_stat_activity WHERE pid = %s", (pid,)
            )
            states = await cur.fetchall()
            started = time.monotonic()
            await worker.run_once(worker_conn)
            took = time.monotonic() - started
            return states, took, await exporting

    states, took, done = asyncio.run(scenario())
    assert states == [("idle",)]  # not "idle in transaction": nothing is held across the POST
    assert took < 1.0
    assert done.delivered > 0 and queued(url) == 0


def test_exporters_take_turns_by_a_lease(fresh_database_url: str, sink: Sink) -> None:
    url = fresh_database_url
    enable_export(url)
    harava_finding(url, Clock(T0))
    n = queued(url)
    with psycopg.connect(url) as conn:  # another exporter holds a live lease
        conn.execute(
            "UPDATE worker_locks SET holder = 'other', lease_until = now() + interval '1 minute' "
            "WHERE name = 'export'"
        )
    exp = exporter(sink.url)
    assert export_round(url, exp).delivered == 0 and queued(url) == n and not sink.posts
    with psycopg.connect(url) as conn:  # its lease runs out (it died)
        conn.execute("UPDATE worker_locks SET lease_until = now() - interval '1 second'")
    assert export_round(url, exp).delivered == n
    # Released after the round.
    assert query(url, "SELECT holder, lease_until FROM worker_locks WHERE name = 'export'") == [
        (None, None)
    ]


def test_a_round_sends_many_batches(fresh_database_url: str, sink: Sink) -> None:
    url = fresh_database_url
    enable_export(url)
    harava_finding(url, Clock(T0))
    n = queued(url)
    assert n > 4
    done = export_round(url, exporter(sink.url, batch_size=2))
    assert done.delivered == n and len(sink.posts) == (n + 1) // 2 and queued(url) == 0


def test_a_backlog_of_exports_pages(fresh_database_url: str) -> None:
    url = fresh_database_url
    enable_export(url)
    clock = Clock(T0)
    harava_finding(url, clock)
    exp = exporter("http://127.0.0.1:1/v1/logs")
    export_round(url, exp, timedelta(minutes=5))
    assert queued(url) > 0
    # No export backlog yet: the rows are young.
    backlog = (
        "SELECT explanation FROM detections WHERE kind = 'tuisku.meta.backlog' "
        "AND subject = 'export'"
    )
    assert query(url, backlog) == []
    with psycopg.connect(url) as conn:  # the owner may backdate the working table
        conn.execute("UPDATE export_queue SET enqueued_at = now() - interval '10 minutes'")
    export_round(url, exp, timedelta(minutes=5))
    [(details,)] = query(url, backlog)
    assert details["queued"] == queued(url) and details["limit_seconds"] == 300
    notifier = RecordingNotifier()
    run_worker(url, builtin_rules(), clock, notifier)
    assert "tuisku_backlog" in notifier.kinds()


# --- export off, and a worker that does not match the database ----------------------------------


def test_export_off_enqueues_nothing(fresh_database_url: str) -> None:
    url = fresh_database_url  # migrated without an export URL: the default
    assert query(url, "SELECT enabled FROM export_state") == [(False,)]
    harava_finding(url, Clock(T0))
    assert query(url, "SELECT count(*) FROM finding_events") != [(0,)]
    assert queued(url) == 0


def test_export_off_discards_what_was_left_and_never_pages(fresh_database_url: str) -> None:
    url = fresh_database_url
    enable_export(url)
    harava_finding(url, Clock(T0))
    assert queued(url) > 0
    enable_export(url, False)  # export turned off by the next `tuisku migrate`
    off = exporter(None)
    assert not off.enabled
    assert export_round(url, off, timedelta(minutes=5)).discarded > 0
    assert queued(url) == 0
    assert query(url, "SELECT count(*) FROM detections WHERE subject = 'export'") == [(0,)]


def test_a_worker_without_export_never_discards_what_is_meant_to_be_exported(
    fresh_database_url: str,
) -> None:
    """The database enqueues, but this worker has no URL (another replica's job, or a
    misconfiguration). It leaves the rows, and once they are old the backlog pages."""
    url = fresh_database_url
    enable_export(url)
    harava_finding(url, Clock(T0))
    n = queued(url)
    off = exporter(None)
    export_round(url, off, timedelta(minutes=5))
    assert queued(url) == n
    with psycopg.connect(url) as conn:
        conn.execute("UPDATE export_queue SET enqueued_at = now() - interval '10 minutes'")
    export_round(url, off, timedelta(minutes=5))
    assert queued(url) == n
    assert query(
        url,
        "SELECT count(*) FROM detections WHERE kind = 'tuisku.meta.backlog' AND subject = 'export'",
    ) == [(1,)]


def test_a_worker_that_exports_while_the_database_does_not_enqueue_pages(
    fresh_database_url: str, sink: Sink
) -> None:
    url = fresh_database_url  # export_state off: `tuisku migrate` ran without the URL
    clock = Clock(T0)
    harava_finding(url, clock)
    export_round(url, exporter(sink.url))
    [(subject, _)] = export_failed(url)
    assert subject == "not_enqueued"
    run_worker(url, builtin_rules(), clock)
    assert "tuisku-meta.export_failed" in {
        r[0] for r in query(url, "SELECT kind FROM detections WHERE evaluator = 'tuisku'")
    }


def test_tuisku_migrate_sets_the_flag_from_the_export_url(fresh_database_url: str) -> None:
    from tuisku.migrate import run_migrations

    url = fresh_database_url
    run_migrations(make_settings(url, export_otlp_logs_url="http://collector.example/v1/logs"))
    assert query(url, "SELECT enabled FROM export_state") == [(True,)]
    run_migrations(make_settings(url))
    assert query(url, "SELECT enabled FROM export_state") == [(False,)]


# --- what the sink refuses or cannot be encoded -------------------------------------------------


def test_a_partial_success_pages(fresh_database_url: str, sink: Sink) -> None:
    url = fresh_database_url
    enable_export(url)
    clock = Clock(T0)
    harava_finding(url, clock)
    n = queued(url)
    sink.answer = lambda records: (200, b'{"partialSuccess": {"rejectedLogRecords": 2}}')
    done = export_round(url, exporter(sink.url))
    assert done.delivered == n - 2 and queued(url) == 0  # OTLP: never retried
    [(subject, details)] = export_failed(url)
    assert subject == "partial_success" and details["rejected"] == 2
    notifier = RecordingNotifier()
    run_worker(url, builtin_rules(), clock, notifier)
    paged = [n for n in notifier.sent if n.get("title") == "Events were not exported as recorded"]
    assert paged, notifier.kinds()


@pytest.mark.parametrize("stub_refused", [False, True])
def test_a_record_the_sink_refuses_is_isolated(
    fresh_database_url: str, sink: Sink, stub_refused: bool
) -> None:
    """A 400 halves the batch down to the one record; that record is replaced by a stub (or,
    refused too, dropped), it pages, and every other record is delivered."""
    url = fresh_database_url
    enable_export(url)
    harava_finding(url, Clock(T0))
    n = queued(url)
    [(bad_uid,)] = query(
        url,
        "SELECT event ->> 'uid' FROM export_queue WHERE stream = 'incident' ORDER BY id LIMIT 1",
    )

    def answer(records: list[dict[str, Any]]) -> tuple[int, bytes]:
        poisoned = [r for r in records if r["record_uid"] == bad_uid]
        if poisoned and (stub_refused or "error" not in poisoned[0]):
            return 400, b"{}"
        return 200, b"{}"

    sink.answer = answer
    done = export_round(url, exporter(sink.url, batch_size=8))
    assert queued(url) == 0
    delivered = [r for p in sink.posts if p["_status"] == 200 for r in sink.records([p])]
    assert len({r["record_uid"] for r in delivered} - {bad_uid}) == n - 1
    stubs = [r for r in delivered if r["record_uid"] == bad_uid]
    if stub_refused:
        assert stubs == [] and done.stubs == 0
    else:
        [stub] = stubs
        assert stub["error"] == "refused: HTTP 400" and stub["event"]["uid"] == bad_uid
    [(subject, details)] = export_failed(url)
    assert subject == "refused" and details["stub_delivered"] is not stub_refused


def test_a_row_that_cannot_be_encoded_never_blocks_the_rest(
    fresh_database_url: str, sink: Sink
) -> None:
    url = fresh_database_url
    enable_export(url)
    harava_finding(url, Clock(T0))
    n = queued(url)
    with psycopg.connect(url) as conn:  # the oldest row's snapshot is malformed
        [(bad_id, bad_uid)] = conn.execute(
            "UPDATE export_queue SET state = jsonb_build_object('rule_ref', 'not an object') "
            "WHERE id = (SELECT min(id) FROM export_queue WHERE stream = 'finding') "
            "RETURNING id, event ->> 'uid'"
        ).fetchall()
    assert export_round(url, exporter(sink.url)).delivered == n
    assert queued(url) == 0
    [stub] = [r for r in sink.records() if r["record_uid"] == bad_uid]
    assert stub["error"] == "unencodable: AttributeError"
    [(subject, details)] = export_failed(url)
    assert subject == "unencodable" and details["queue_id"] == bad_id


def test_out_of_range_times_and_odd_time_zones_still_encode(
    fresh_database_url: str, sink: Sink
) -> None:
    """The review's case: a suppression ending at '-infinity' (written here by the owner, since
    triage now refuses it) once made every export attempt fail. Times are text from SQL now."""
    url = fresh_database_url
    enable_export(url)
    harava_finding(url, Clock(T0))
    exp = exporter(sink.url)
    export_round(url, exp)
    with psycopg.connect(url) as conn:
        conn.execute("SET TIME ZONE 'Asia/Kathmandu'")
        [(fid, count)] = conn.execute(
            "SELECT id, count FROM findings WHERE rule_ref ->> 'name' = "
            "'harava.agent_outbound_refused'"
        ).fetchall()
        conn.execute(
            "UPDATE findings SET status = 'suppressed', suppressed_until = '-infinity', "
            "suppression_reason = 'x', suppressed_at = now(), count_at_suppression = %s "
            "WHERE id = %s",
            (count, fid),
        )
        conn.execute(
            "INSERT INTO finding_events (finding_id, actor, kind, new_value) VALUES "
            "(%s, 'system', 'suppressed', jsonb_build_object('suppressed_until', "
            "'-infinity'::timestamptz))",
            (fid,),
        )
    before = len(sink.posts)
    assert export_round(url, exp).delivered == 1
    [record] = sink.records(sink.posts[before:])
    assert record["finding"]["suppressed_until"] == "-infinity"
    assert record["event"]["new_value"] == {"suppressed_until": "-infinity"}
    [(at, last_seen)] = query(
        url,
        "SELECT e.at, f.last_seen FROM finding_events e JOIN findings f ON f.id = e.finding_id "
        "WHERE e.uid = %s",
        (record["record_uid"],),
    )
    # Written in a session on +05:45, rendered in UTC.
    assert record["event"]["at"] == at.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    assert record["finding"]["last_seen_at"] == last_seen.astimezone(UTC).strftime(
        "%Y-%m-%dT%H:%M:%S.%fZ"
    )
    with psycopg.connect(url) as conn:
        conn.execute("SET TIME ZONE 'Asia/Kathmandu'")
        rendered = conn.execute(
            "SELECT tuisku_export_time('infinity'), tuisku_export_time('0044-03-15 12:00Z BC'), "
            "tuisku_export_time('2026-11-01 12:00+05:45')"
        ).fetchall()
    assert rendered == [
        ("infinity", "0044-03-15T12:00:00.000000Z BC", "2026-11-01T06:15:00.000000Z")
    ]


def test_a_bad_request_never_retries_the_same_batch_forever(
    fresh_database_url: str, sink: Sink
) -> None:
    url = fresh_database_url
    enable_export(url)
    harava_finding(url, Clock(T0))
    n = queued(url)
    sink.statuses[:] = [413]  # the first, full batch is too large; halves fit
    done = export_round(url, exporter(sink.url))
    assert done.delivered == n and queued(url) == 0
    assert [p["_status"] for p in sink.posts][:2] == [413, 200]
    assert len(sink.records(sink.posts[1:2])) == n // 2


# --- settings and transport ---------------------------------------------------------------------


def test_the_worker_command_builds_its_exporter() -> None:
    off = worker_run.exporter(make_settings("postgresql://u@h/d"))
    assert not off.enabled
    on = worker_run.exporter(
        make_settings(
            "postgresql://u@h/d",
            export_otlp_logs_url="https://collector.example:4318/v1/logs",
            export_otlp_headers_json='{"Authorization": "Bearer synthetic"}',
            export_pseudonym_key=KEY,
            export_batch_size=7,
            export_timeout_seconds=3,
            export_pseudonymize_entity_kinds=" ip, k8s-ns ",
        )
    )
    assert on.config.url == "https://collector.example:4318/v1/logs"
    assert on.config.headers == {"Authorization": "Bearer synthetic"}
    assert on.config.pseudonym_key == KEY.encode()
    assert (on.config.batch_size, on.config.timeout_seconds) == (7, 3)
    assert on.config.pseudonymize_kinds == frozenset({"ip", "k8s-ns"})
    assert on.config.build_revision == "test-revision"


def test_export_needs_the_pseudonym_key() -> None:
    settings = make_settings("postgresql://u@h/d", export_otlp_logs_url="http://c.example/v1/logs")
    with pytest.raises(ConfigError, match="TUISKU_EXPORT_PSEUDONYM_KEY"):
        worker_run.exporter(settings)
    with pytest.raises(ValueError, match="pseudonym key"):
        Exporter(ExportConfig(url="http://c.example/v1/logs"))


@pytest.mark.parametrize(
    ("values"),
    [
        {"export_otlp_logs_url": "ftp://collector.example/v1/logs"},
        {"export_otlp_logs_url": "collector.example:4318"},
        {"export_otlp_logs_url": "http://user:secret@collector.example/v1/logs"},
        {
            "export_otlp_logs_url": "http://collector.example/v1/logs",
            "export_otlp_headers_json": '{"Authorization": "Bearer secret"}',
        },
        {"export_otlp_headers_json": '["secret"]'},
        {"export_otlp_headers_json": '{"Bad Header": "secret"}'},
        {"export_otlp_headers_json": '{"X-Key": "secret\\r\\nInjected: 1"}'},
        {"export_pseudonym_key": "secret-too-short"},
        {"export_pseudonym_key": "a" * 64},
        {"export_pseudonymize_entity_kinds": "ip;caller"},
        {"export_batch_size": 0},
    ],
)
def test_export_settings_are_validated(values: dict[str, Any]) -> None:
    with pytest.raises(ValidationError) as info:
        make_settings("postgresql://u@h/d", **values)
    assert "secret" not in str(info.value)  # never echoed


def test_default_settings_pseudonymise_ip_caller_and_identity() -> None:
    settings = make_settings("postgresql://u@h/d")
    assert settings.export_otlp_logs_url is None
    assert settings.export_pseudonymized_kinds == frozenset({"ip", "caller", "identity"})
    assert (settings.export_batch_size, settings.export_timeout_seconds) == (100, 10.0)


def test_headers_are_sent_and_environment_proxies_ignored(
    fresh_database_url: str, sink: Sink, monkeypatch: pytest.MonkeyPatch
) -> None:
    for name in ("http_proxy", "HTTP_PROXY"):
        monkeypatch.setenv(name, "http://127.0.0.1:1")  # a proxy that refuses everything
    for name in ("no_proxy", "NO_PROXY"):
        monkeypatch.delenv(name, raising=False)
    url = fresh_database_url
    enable_export(url)
    harava_finding(url, Clock(T0))
    exp = exporter(sink.url, headers={"X-Tuisku-Test": "synthetic"})
    assert export_round(url, exp).delivered > 0
    assert sink.posts[0]["_headers"]["X-Tuisku-Test"] == "synthetic"


# --- the record: no personal data ---------------------------------------------------------------

# Entity keys as the real adapters build them (tuisku.adapters.entities), synthetic values.
ADAPTER_KEYS = [
    "ip:192.0.2.1",
    "caller:harava/agents",
    "identity:idp.example/subject-1",
    "host:node-a",
    "process:node-a/42/1793000000000000000",
    "k8s:default/web-1",
    "domain:example.org",
    "image:registry.example/app",
    "nokind",
]


def _event(**overrides: Any) -> dict[str, Any]:
    event: dict[str, Any] = {
        "uid": "11111111-1111-4111-8111-111111111111",
        "at": "2026-11-01T09:00:00.000000Z",
        "at_unix_nano": "1793523600000000000",
        "actor": "operator:00000000-0000-4000-8000-000000000000",
        "kind": "status_changed",
        "old_value": None,
        "new_value": None,
        "reason": None,
        "payload": {"from": "open", "to": "closed", "disposition": "false_positive"},
    }
    event.update(overrides)
    return event


STATE = {
    "uid": "22222222-2222-4222-8222-222222222222",
    "title": "Agent caller had outbound data refused",
    "severity_id": 4,
    "status": "closed",
    "entity_keys": ADAPTER_KEYS,
}
P = Pseudonyms(KEY.encode(), frozenset({"ip", "caller", "identity"}))


def test_ip_caller_and_identity_keys_are_hmac_pseudonyms() -> None:
    record = build_record("incident", _event(), STATE, P, "r")
    assert record["incident"]["entity_keys"] == [
        f"ip:hmac:{mac('192.0.2.1')}",
        f"caller:hmac:{mac('harava/agents')}",
        f"identity:hmac:{mac('idp.example/subject-1')}",
        "host:node-a",
        "process:node-a/42/1793000000000000000",
        "k8s:default/web-1",
        "domain:example.org",
        "image:registry.example/app",
        "nokind",
    ]
    text = json.dumps(record)
    assert "192.0.2.1" not in text and "harava/agents" not in text and "subject-1" not in text
    # Keyed: an unsalted hash of the address (enumerable) appears nowhere.
    assert hashlib.sha256(b"192.0.2.1").hexdigest() not in text
    other = Pseudonyms(b"another-synthetic-key-for-this-test!!", P.kinds)
    assert other.entity_key("ip:192.0.2.1") != P.entity_key("ip:192.0.2.1")
    hosts = Pseudonyms(KEY.encode(), frozenset({"host"}))
    assert hosts.entity_key("host:node-a") == f"host:hmac:{mac('node-a')}"
    assert hosts.entity_key("ip:192.0.2.1") == "ip:192.0.2.1"


def test_typed_text_is_exported_as_an_hmac_only() -> None:
    note = "call A. Person at home"
    record = build_record(
        "incident",
        _event(
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
        STATE,
        P,
        "r",
    )
    event = record["event"]
    assert event["reason_hmac"] == mac(REASON) and event["reason_length"] == len(REASON)
    assert event["payload"]["from"] == "open" and event["payload"]["count"] == 3
    assert event["payload"]["note"] == {"hmac": mac(note), "length": len(note)}
    assert set(event["payload"]["extra"]) == {"hmac", "length"}
    assert "reason" not in event["payload"]
    assert "Person" not in json.dumps(record)
    # A finding event's reason column, the same way.
    finding = build_record(
        "finding",
        _event(reason=REASON, payload={}, new_value={"status": "resolved"}),
        {"uid": "x", "rule_ref": {"pack": "p"}, "entity_keys": []},
        P,
        "r",
    )
    assert finding["event"]["reason_length"] == len(REASON)
    assert finding["finding"]["pack_id"] == "p"
    assert REASON not in json.dumps(finding)


# --- roles (ADR 0011) ---------------------------------------------------------------------------


def _app_db_finding(app_db: AppDatabase, tmp_path: Path) -> str:
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
    return finding_uid


def test_api_triage_is_enqueued_and_the_worker_role_exports_it(
    app_db: AppDatabase, sink: Sink, tmp_path: Path
) -> None:
    """The API role cannot write the queue, yet its triage is enqueued (by the owner trigger),
    and the worker role, with SELECT and DELETE only, exports and removes it."""
    enable_export(app_db.owner_url)
    finding_uid = _app_db_finding(app_db, tmp_path)
    triager = operator_token(app_db.app_url, Role.TRIAGE)
    with client(app_db.app_url, clock=Clock(T0)) as c:
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
    assert export_round(app_db.worker_url, exp).delivered > 0
    assert event_uid in {r["record_uid"] for r in sink.records()}
    assert query(
        app_db.owner_url,
        "SELECT count(*) FROM export_queue q JOIN finding_events e ON e.id = q.finding_event_id "
        "WHERE e.uid = %s",
        (event_uid,),
    ) == [(0,)]


@pytest.mark.parametrize("until", ["'-infinity'", "now() - interval '1 minute'"])
def test_triage_refuses_a_suppression_that_never_was(
    app_db: AppDatabase, tmp_path: Path, until: str
) -> None:
    """As the API role, with an operator secret it has seen: a suppression expiry must be a
    finite time in the future (revision 0004), not just within 30 days."""
    finding_uid = _app_db_finding(app_db, tmp_path)
    token = operator_token(app_db.app_url, Role.TRIAGE)
    [(token_uid,)] = query(
        app_db.owner_url,
        "SELECT uid::text FROM operator_tokens WHERE token_sha256 = sha256(%s::bytea)",
        (token.encode(),),
    )
    with psycopg.connect(app_db.app_url) as conn:
        conn.execute("SELECT set_config('tuisku.operator_token', %s, true)", (token,))
        with pytest.raises(psycopg.Error) as info:
            conn.execute(  # type: ignore[arg-type]
                "INSERT INTO triage_requests (target, target_uid, status, suppressed_until, "
                f"reason, actor) VALUES ('finding', %s, 'suppressed', {until}, 'x', %s)",
                (finding_uid, f"operator:{token_uid}"),
            )
        conn.rollback()
    assert info.value.diag.sqlstate == "TK409"
    assert "in the future" in str(info.value)


# --- the worker command -------------------------------------------------------------------------


def test_tuisku_worker_exports_and_refuses_to_start_without_a_key(
    fresh_database_url: str, sink: Sink, monkeypatch: pytest.MonkeyPatch
) -> None:
    from tuisku import cli

    url = fresh_database_url
    enable_export(url)
    token = new_source(url, "harava-edge", adapter="harava")
    lines = (FIXTURES / "plain.log").read_text().splitlines()
    with client(url, clock=Clock(T0)) as c:
        assert post_records(c, "harava-edge", token, ndjson(*lines)).status_code == 200
    monkeypatch.setenv("TUISKU_BUILTIN_PACKS_DIR", str(REPO_ROOT / "packs"))
    monkeypatch.setenv("TUISKU_DATABASE_URL", url)
    monkeypatch.setenv("TUISKU_EXPORT_OTLP_LOGS_URL", sink.url)
    assert cli.main(["worker", "--once"]) == 2  # no pseudonym key: refuses to start
    assert not sink.posts
    monkeypatch.setenv("TUISKU_EXPORT_PSEUDONYM_KEY", KEY)
    assert cli.main(["worker", "--once"]) == 0
    assert queued(url) == 0 and len(sink.records()) > 0


def test_the_export_task_runs_until_cancelled(fresh_database_url: str, sink: Sink) -> None:
    url = fresh_database_url
    enable_export(url)
    harava_finding(url, Clock(T0))
    exp = exporter(sink.url)

    async def scenario() -> None:
        async def connect() -> AsyncConnection[Any]:
            return await AsyncConnection.connect(url, autocommit=True)

        task = asyncio.create_task(exp.run_forever(connect, timedelta(days=1), 0.05))
        for _ in range(100):
            await asyncio.sleep(0.05)
            if sink.posts:
                break
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task

    asyncio.run(scenario())
    assert queued(url) == 0 and sink.records()
