"""Ingest API against a real Postgres, connected as the app role (SELECT/INSERT on evidence)."""

from __future__ import annotations

import base64
import gzip
import hashlib
import json
import uuid
from datetime import timedelta

import psycopg
import pytest

from tests.conftest import AppDatabase
from tests.support import (
    NDJSON_HEADERS,
    T0,
    auth,
    client,
    ndjson,
    new_source,
    operator_token,
    post_records,
    query,
    run,
)
from tuisku.store import admin
from tuisku.store.tokens import Role


def _name() -> str:
    return f"s{uuid.uuid4().hex[:10]}"


@pytest.fixture
def source(app_db: AppDatabase) -> tuple[str, str]:
    name = _name()
    return name, new_source(app_db.app_url, name)


def _count(url: str, statement: str, *params: object) -> int:
    return query(url, statement, params)[0][0]


def test_happy_path_stores_raw_parse_attempt_observation_and_detection(
    app_db: AppDatabase, source: tuple[str, str]
) -> None:
    name, token = source
    line = {"kind": "dummy.flow", "time": "2026-11-01T11:59:00Z", "ip": "192.0.2.7", "detect": 1}
    with client(app_db.app_url) as c:
        response = post_records(c, name, token, ndjson(line, collector={"host": "sensor-1"}))
    assert response.status_code == 200
    assert response.json() == {"results": [{"line": 1, "status": "accepted", "parse": "ok"}]}

    raw = json.dumps(line).encode()
    [(sha, body, size, collector, transport, received_at, token_id)] = query(
        app_db.owner_url,
        "SELECT r.sha256, r.body, r.body_size, r.collector, r.transport, r.received_at, "
        "r.token_id FROM raw_records r JOIN sources s ON s.id = r.source_id WHERE s.name = %s",
        (name,),
    )
    assert bytes(sha) == hashlib.sha256(raw).digest()  # digest of `raw`, not of the envelope
    assert bytes(body) == raw and size == len(raw)
    assert collector == {"host": "sensor-1"} and transport == "ndjson"
    assert received_at == T0  # the injected clock
    assert token_id is not None

    [(status, adapter, version)] = query(
        app_db.owner_url,
        "SELECT p.status, p.adapter, p.adapter_version FROM parse_attempts p "
        "JOIN raw_records r ON r.id = p.raw_record_id JOIN sources s ON s.id = r.source_id "
        "WHERE s.name = %s",
        (name,),
    )
    assert (status, adapter, version) == ("ok", "dummy", "0.1.0")

    [(kind, eval_time, flags, keys)] = query(
        app_db.owner_url,
        "SELECT o.kind, o.eval_time, o.flags, o.entity_keys FROM observations o "
        "JOIN sources s ON s.id = o.source_id WHERE s.name = %s",
        (name,),
    )
    assert kind == "dummy.flow" and flags == [] and keys == ["ip:192.0.2.7"]
    assert eval_time == T0 - timedelta(minutes=1)  # event_time

    [(evaluator, authorship, linked)] = query(
        app_db.owner_url,
        "SELECT d.evaluator, d.authorship, (SELECT count(*) FROM detection_observations l "
        "WHERE l.detection_id = d.id) FROM detections d JOIN sources s ON s.id = d.source_id "
        "WHERE s.name = %s",
        (name,),
    )
    assert (evaluator, authorship, linked) == ("sensor", "community", 1)


def test_new_observations_and_detections_are_enqueued(
    app_db: AppDatabase, source: tuple[str, str]
) -> None:
    name, token = source
    with client(app_db.app_url) as c:
        post_records(c, name, token, ndjson({"detect": 1}, {"msg": "second"}))
    queued = query(
        app_db.owner_url,
        "SELECT q.observation_id IS NOT NULL, q.detection_id IS NOT NULL, q.attempts "
        "FROM evaluation_queue q "
        "LEFT JOIN observations o ON o.id = q.observation_id "
        "LEFT JOIN detections d ON d.id = q.detection_id "
        "JOIN sources s ON s.id = coalesce(o.source_id, d.source_id) WHERE s.name = %s",
        (name,),
    )
    assert sorted(queued) == [(False, True, 0), (True, False, 0), (True, False, 0)]


def test_duplicate_is_reported_and_recorded(app_db: AppDatabase, source: tuple[str, str]) -> None:
    name, token = source
    second = run(app_db.app_url, lambda conn: admin.add_source_token(conn, name, label="b"))
    with client(app_db.app_url) as c:
        first = post_records(c, name, token, ndjson({"msg": "x"}, collector={"offset": 1}))
        # Same raw, different collector metadata (a re-read of a rotated file), sent with the
        # source's second token: a duplicate, recorded against the token that re-delivered it.
        again = post_records(
            c, name, second.token, ndjson({"msg": "x"}, {"msg": "x"}, collector={"o": 2})
        )
    assert first.json()["results"][0]["status"] == "accepted"
    assert again.json()["results"] == [
        {"line": 1, "status": "duplicate"},
        {"line": 2, "status": "duplicate"},
    ]
    sql = "SELECT count(*) FROM {} x JOIN sources s ON s.id = x.source_id WHERE s.name = %s"
    assert _count(app_db.owner_url, sql.format("raw_records"), name) == 1
    assert _count(app_db.owner_url, sql.format("observations"), name) == 1  # not parsed again
    assert (
        _count(
            app_db.owner_url,
            "SELECT count(*) FROM raw_duplicates d JOIN raw_records r ON r.id = d.raw_record_id "
            "JOIN sources s ON s.id = r.source_id JOIN source_tokens t ON t.id = d.token_id "
            "WHERE s.name = %s AND t.uid = %s AND d.token_id <> r.token_id",
            name,
            second.uid,
        )
        == 2
    )


def test_adapter_failure_is_a_failed_parse_attempt_and_the_record_is_kept(
    app_db: AppDatabase, source: tuple[str, str]
) -> None:
    name, token = source
    with client(app_db.app_url) as c:
        response = post_records(c, name, token, ndjson({"fail": 1}, "not json at all"))
    assert response.json()["results"] == [
        {"line": 1, "status": "accepted", "parse": "failed"},
        {"line": 2, "status": "accepted", "parse": "failed"},
    ]
    errors = query(
        app_db.owner_url,
        "SELECT p.status, p.error FROM parse_attempts p JOIN raw_records r "
        "ON r.id = p.raw_record_id JOIN sources s ON s.id = r.source_id WHERE s.name = %s "
        "ORDER BY p.id",
        (name,),
    )
    assert errors == [
        ("failed", "dummy refuses this record"),
        ("failed", "invalid JSON at position 0"),
    ]


def test_unexpected_adapter_exception_records_only_its_type(
    app_db: AppDatabase, source: tuple[str, str]
) -> None:
    name, token = source
    with client(app_db.app_url) as c:
        response = post_records(c, name, token, ndjson({"crash": "secret-value"}))
    assert response.json()["results"][0] == {"line": 1, "status": "accepted", "parse": "failed"}
    [(error,)] = query(
        app_db.owner_url,
        "SELECT p.error FROM parse_attempts p JOIN raw_records r ON r.id = p.raw_record_id "
        "JOIN sources s ON s.id = r.source_id WHERE s.name = %s",
        (name,),
    )
    assert error == "adapter error: KeyError"


def test_database_error_on_one_record_does_not_abort_the_batch(
    app_db: AppDatabase, source: tuple[str, str]
) -> None:
    name, token = source
    body = ndjson({"msg": "before"}, {"kind": "x" * 200}, {"msg": "after"})  # kind > 128: CHECK
    with client(app_db.app_url) as c:
        response = post_records(c, name, token, body)
    assert response.status_code == 200
    assert response.json()["results"] == [
        {"line": 1, "status": "accepted", "parse": "ok"},
        {"line": 2, "status": "accepted", "parse": "failed"},
        {"line": 3, "status": "accepted", "parse": "ok"},
    ]
    rows = query(
        app_db.owner_url,
        "SELECT p.status, p.error, (SELECT count(*) FROM observations o "
        "WHERE o.raw_record_id = r.id) FROM raw_records r "
        "JOIN parse_attempts p ON p.raw_record_id = r.id JOIN sources s ON s.id = r.source_id "
        "WHERE s.name = %s ORDER BY r.id",
        (name,),
    )
    assert rows == [
        ("ok", None, 1),
        ("failed", "store rejected adapter output: observations_kind_check", 0),
        ("ok", None, 1),
    ]


def test_clock_skew_is_flagged_and_evaluated_at_received_at(
    app_db: AppDatabase, source: tuple[str, str]
) -> None:
    name, token = source
    future = (T0 + timedelta(minutes=6)).isoformat()
    near = (T0 + timedelta(minutes=4)).isoformat()  # within the 5 minute tolerance
    with client(app_db.app_url) as c:
        post_records(
            c,
            name,
            token,
            ndjson(
                {"time": future, "detect": 1, "msg": "a"},
                {"time": near, "msg": "b"},
                {"msg": "no time"},
                {"msg": "adapter cannot set the flag", "flags": ["clock_skew", "other"]},
            ),
        )
    rows = query(
        app_db.owner_url,
        "SELECT o.flags, o.eval_time, o.event_time FROM observations o "
        "JOIN sources s ON s.id = o.source_id WHERE s.name = %s ORDER BY o.id",
        (name,),
    )
    assert rows == [
        (["clock_skew"], T0, T0 + timedelta(minutes=6)),
        ([], T0 + timedelta(minutes=4), T0 + timedelta(minutes=4)),
        ([], T0, None),
        (["other"], T0, None),
    ]
    [(det_flags, det_eval)] = query(
        app_db.owner_url,
        "SELECT d.flags, d.eval_time FROM detections d JOIN sources s ON s.id = d.source_id "
        "WHERE s.name = %s AND d.evaluator = 'sensor'",
        (name,),
    )
    assert (det_flags, det_eval) == (["clock_skew"], T0)


def test_clock_skew_tolerance_is_a_setting(app_db: AppDatabase, source: tuple[str, str]) -> None:
    name, token = source
    with client(app_db.app_url, clock_skew_tolerance_seconds=60) as c:
        post_records(c, name, token, ndjson({"time": (T0 + timedelta(minutes=2)).isoformat()}))
    [(flags,)] = query(
        app_db.owner_url,
        "SELECT o.flags FROM observations o JOIN sources s ON s.id = o.source_id WHERE s.name = %s",
        (name,),
    )
    assert flags == ["clock_skew"]


def test_correlation_keys_are_qualified_by_source(
    app_db: AppDatabase, source: tuple[str, str]
) -> None:
    name, token = source
    with client(app_db.app_url) as c:
        post_records(c, name, token, ndjson({"flow": 1}))
    [(correlation, source_id)] = query(
        app_db.owner_url,
        "SELECT o.correlation, o.source_id FROM observations o "
        "JOIN sources s ON s.id = o.source_id WHERE s.name = %s",
        (name,),
    )
    assert correlation == {
        "dummy.flow_id": f"{source_id}:42",
        "dummy.fuid": [f"{source_id}:Fa1", f"{source_id}:Fb2"],  # order kept
    }


# --- limits -----------------------------------------------------------------------------------


def _meta(url: str, name: str) -> list[tuple[str, str, int]]:
    """(kind, subject, meta_counters count) for the source's meta-detections."""
    return query(
        url,
        "SELECT d.kind, d.subject, m.count FROM detections d "
        "JOIN sources s ON s.id = d.source_id "
        "JOIN meta_counters m ON m.source_id = d.source_id AND m.kind = d.kind "
        "AND m.subject = d.subject AND m.bucket_start = d.bucket_start "
        "WHERE s.name = %s AND d.evaluator = 'tuisku' ORDER BY d.id",
        (name,),
    )


def test_body_over_limit_is_413_from_content_length(
    app_db: AppDatabase, source: tuple[str, str]
) -> None:
    name, token = source
    body = ndjson({"msg": "x" * 200})
    with client(app_db.app_url, ingest_max_body_bytes=100) as c:
        response = post_records(c, name, token, body)
    assert response.status_code == 413
    assert (
        _count(
            app_db.owner_url,
            "SELECT count(*) FROM raw_records r JOIN sources s ON s.id = r.source_id "
            "WHERE s.name = %s",
            name,
        )
        == 0
    )
    assert _meta(app_db.owner_url, name) == [("tuisku.meta.source_limit_exceeded", "body_bytes", 1)]


def test_body_over_limit_is_413_while_streaming_without_content_length(
    app_db: AppDatabase, source: tuple[str, str]
) -> None:
    name, token = source

    def chunks():
        for _ in range(10):
            yield b'{"raw": "' + b"y" * 50 + b'"}\n'

    with client(app_db.app_url, ingest_max_body_bytes=200) as c:
        response = c.post(
            f"/v1/sources/{name}/records", content=chunks(), headers=NDJSON_HEADERS | auth(token)
        )
    assert response.status_code == 413


def test_too_many_lines_is_413(app_db: AppDatabase, source: tuple[str, str]) -> None:
    name, token = source
    with client(app_db.app_url, ingest_max_lines=2) as c:
        response = post_records(c, name, token, ndjson({"a": 1}, {"a": 2}, {"a": 3}))
    assert response.status_code == 413
    assert _meta(app_db.owner_url, name) == [("tuisku.meta.source_limit_exceeded", "lines", 1)]


def test_only_malformed_envelopes_are_rejected(
    app_db: AppDatabase, source: tuple[str, str]
) -> None:
    name, token = source
    lines = [
        json.dumps({"raw": "ok"}),
        json.dumps({"raw": "c", "collector": {"k": "v" * 100}}),  # collector too large: kept
        "not json",
        json.dumps(["raw"]),
        json.dumps({"raw": 5}),
        json.dumps({"raw": ""}),
        json.dumps({"raw": "x", "extra": 1}),
        json.dumps({"raw": "x", "collector": "host"}),
        json.dumps({"raw": "\ud800"}),  # lone surrogate: not encodable as UTF-8
        '{"raw": "a", "raw": "b"}',  # duplicate key
        json.dumps({"raw": "nul", "collector": {"k": "\u0000"}}),  # sanitized, kept
        "",  # blank lines are skipped, but keep their line numbers
        json.dumps({"raw": "ok2", "collector": None}),
    ]
    body = "\n".join(lines).encode() + b"\n\xff\xfe\n"  # final line: invalid UTF-8
    with client(app_db.app_url, ingest_max_collector_bytes=50) as c:
        response = post_records(c, name, token, body)
    assert response.status_code == 200
    results = response.json()["results"]
    # Stored lines are not JSON, so the dummy adapter fails on them: still accepted.
    stored = ("failed", "accepted", None)
    rejected = (None, "rejected", "invalid_envelope")
    assert [(r.get("parse"), r["status"], r.get("reason")) for r in results] == [
        stored,
        stored,
        *[rejected] * 8,
        stored,
        stored,
        rejected,
    ]
    assert [r["line"] for r in results][-3:] == [11, 13, 14]
    collectors = query(
        app_db.owner_url,
        "SELECT convert_from(r.body, 'UTF8'), r.collector FROM raw_records r "
        "JOIN sources s ON s.id = r.source_id WHERE s.name = %s ORDER BY r.id",
        (name,),
    )
    assert collectors == [
        ("ok", {}),
        ("c", {"tuisku_collector_dropped_bytes": 108}),
        ("nul", {"k": "\ufffd"}),
        ("ok2", {}),
    ]
    assert sorted(_meta(app_db.owner_url, name)) == [
        ("tuisku.meta.invalid_envelope", "envelope", 9),
        ("tuisku.meta.source_limit_exceeded", "collector_bytes", 1),
    ]


def test_over_long_record_is_stored_truncated_and_unparsed(
    app_db: AppDatabase, source: tuple[str, str]
) -> None:
    name, token = source
    long_raw = json.dumps({"msg": "z" * 300})
    with client(app_db.app_url, ingest_max_line_bytes=100) as c:
        first = post_records(c, name, token, ndjson(long_raw, {"msg": "short"}))
        again = post_records(c, name, token, ndjson(long_raw))
    assert first.status_code == 200
    assert first.json()["results"] == [
        {"line": 1, "status": "accepted", "parse": "skipped"},
        {"line": 2, "status": "accepted", "parse": "ok"},
    ]
    assert again.json()["results"] == [{"line": 1, "status": "duplicate"}]
    [(body, size, truncated, sha, attempts)] = query(
        app_db.owner_url,
        "SELECT r.body, r.body_size, r.truncated, r.sha256, "
        "(SELECT count(*) FROM parse_attempts p WHERE p.raw_record_id = r.id) "
        "FROM raw_records r JOIN sources s ON s.id = r.source_id "
        "WHERE s.name = %s AND r.truncated",
        (name,),
    )
    full = long_raw.encode()
    assert bytes(body) == full[:100] and size == len(full) and truncated
    assert bytes(sha) == hashlib.sha256(full).digest()  # over the full record
    assert attempts == 0
    # Both deliveries breached the limit: one detection, counted twice.
    assert _meta(app_db.owner_url, name) == [("tuisku.meta.source_limit_exceeded", "line_bytes", 2)]


def test_adapter_limit_exceeded_is_a_failed_parse_and_a_meta_detection(
    app_db: AppDatabase, source: tuple[str, str]
) -> None:
    name, token = source
    with client(app_db.app_url) as c:
        response = post_records(c, name, token, ndjson({"limit": "json_depth"}))
    assert response.json()["results"] == [{"line": 1, "status": "accepted", "parse": "failed"}]
    [(error,)] = query(
        app_db.owner_url,
        "SELECT p.error FROM parse_attempts p JOIN raw_records r ON r.id = p.raw_record_id "
        "JOIN sources s ON s.id = r.source_id WHERE s.name = %s",
        (name,),
    )
    assert error == "limit exceeded: json_depth"
    assert _meta(app_db.owner_url, name) == [("tuisku.meta.source_limit_exceeded", "json_depth", 1)]


def test_meta_detections_are_one_per_subject_and_bucket(
    app_db: AppDatabase, source: tuple[str, str]
) -> None:
    name, token = source
    with client(app_db.app_url) as c:
        for i in range(3):
            post_records(c, name, token, ndjson({"limit": "json_depth", "n": i}))
    # Another replica (a fresh app) in the same bucket adds to the count, not a row.
    with client(app_db.app_url) as c:
        post_records(c, name, token, ndjson({"limit": "json_depth", "n": 9}))
        post_records(c, name, token, ndjson({"limit": "json_keys"}))  # another subject
    assert _meta(app_db.owner_url, name) == [
        ("tuisku.meta.source_limit_exceeded", "json_depth", 4),
        ("tuisku.meta.source_limit_exceeded", "json_keys", 1),
    ]
    [(sensor_free, queued)] = query(
        app_db.owner_url,
        "SELECT bool_and(d.raw_record_id IS NULL AND d.authorship = 'tuisku' AND "
        "d.entity_keys = ARRAY['source:' || s.name]), "
        "bool_and(EXISTS (SELECT 1 FROM evaluation_queue q WHERE q.detection_id = d.id)) "
        "FROM detections d JOIN sources s ON s.id = d.source_id "
        "WHERE s.name = %s AND d.evaluator = 'tuisku'",
        (name,),
    )
    assert sensor_free and queued
    # Buckets come from the database clock, never the API's (injectable) clock: the database
    # accepts the API's meta-detections only for its current bucket (ADR 0011).
    [(in_db_bucket,)] = query(
        app_db.owner_url,
        "SELECT bool_and(d.bucket_start BETWEEN tuisku_current_bucket() - interval '5 minutes' "
        "AND tuisku_current_bucket()) FROM detections d JOIN sources s ON s.id = d.source_id "
        "WHERE s.name = %s AND d.evaluator = 'tuisku'",
        (name,),
    )
    assert in_db_bucket


def test_wrong_content_type_or_encoding_is_415(
    app_db: AppDatabase, source: tuple[str, str]
) -> None:
    name, token = source
    with client(app_db.app_url) as c:
        response = post_records(c, name, token, ndjson("x"), **{"Content-Type": "text/plain"})
        brotli = post_records(c, name, token, b"x", **{"Content-Encoding": "br"})
    assert response.status_code == 415
    assert brotli.status_code == 415


def test_gzip_body_is_decompressed(app_db: AppDatabase, source: tuple[str, str]) -> None:
    name, token = source
    body = ndjson({"msg": "zipped"})
    with client(app_db.app_url) as c:
        response = post_records(c, name, token, gzip.compress(body), **{"Content-Encoding": "gzip"})
        broken = post_records(c, name, token, b"\x1f\x8bnot gzip", **{"Content-Encoding": "gzip"})
        cut = post_records(c, name, token, gzip.compress(body)[:-6], **{"Content-Encoding": "gzip"})
    assert response.status_code == 200
    assert response.json()["results"] == [{"line": 1, "status": "accepted", "parse": "ok"}]
    assert broken.status_code == 400 and cut.status_code == 400
    [(raw,)] = query(
        app_db.owner_url,
        "SELECT r.body FROM raw_records r JOIN sources s ON s.id = r.source_id WHERE s.name = %s",
        (name,),
    )
    assert bytes(raw) == json.dumps({"msg": "zipped"}).encode()


def test_gzip_bomb_is_413(app_db: AppDatabase, source: tuple[str, str]) -> None:
    name, token = source
    bomb = gzip.compress(b"\n" * 2_000_000)  # about 2 KB on the wire, 2 MB inflated
    assert len(bomb) < 10_000
    with client(app_db.app_url, ingest_max_body_bytes=100_000) as c:
        response = post_records(c, name, token, bomb, **{"Content-Encoding": "gzip"})
        otlp = c.post(
            f"/v1/sources/{name}/otlp/v1/metrics",
            content=bomb,
            headers=auth(token) | {"Content-Type": "application/json", "Content-Encoding": "gzip"},
        )
    assert response.status_code == 413 and otlp.status_code == 413
    assert _meta(app_db.owner_url, name) == [("tuisku.meta.source_limit_exceeded", "body_bytes", 2)]


def test_time_budget_stops_the_request_with_503(
    app_db: AppDatabase, source: tuple[str, str]
) -> None:
    import time

    name, token = source
    # Every record is slow (0.4 s, under the per-record deadline); the request budget is 0.3 s.
    body = ndjson(*({"sleep": 0.4, "msg": m} for m in "abc"))
    started = time.monotonic()
    with client(
        app_db.app_url, ingest_request_budget_seconds=0.3, ingest_parse_timeout_seconds=5
    ) as c:
        response = post_records(c, name, token, body)
    elapsed = time.monotonic() - started
    assert response.status_code == 503
    assert response.headers["Retry-After"] == "1"
    assert response.json()["results"] == [
        {"line": 1, "status": "accepted", "parse": "ok"},
        {"line": 2, "status": "not_processed", "reason": "time_budget_exceeded"},
        {"line": 3, "status": "not_processed", "reason": "time_budget_exceeded"},
    ]
    assert elapsed < 1.0  # one parse, not three: the budget stopped the request
    # What was processed is committed; retrying the whole batch is safe.
    with client(app_db.app_url, ingest_parse_timeout_seconds=5) as c:
        retry = post_records(c, name, token, body)
    assert retry.status_code == 200
    assert [r["status"] for r in retry.json()["results"]] == ["duplicate", "accepted", "accepted"]


def test_parsing_runs_off_the_event_loop(app_db: AppDatabase, source: tuple[str, str]) -> None:
    name, token = source
    with client(app_db.app_url) as c:
        post_records(c, name, token, ndjson({"thread": 1}))
    [(attrs,)] = query(
        app_db.owner_url,
        "SELECT o.attributes FROM observations o JOIN sources s ON s.id = o.source_id "
        "WHERE s.name = %s",
        (name,),
    )
    assert attrs["on_event_loop"] is False


def test_rate_limit_returns_429_with_retry_after(
    app_db: AppDatabase, source: tuple[str, str]
) -> None:
    name, token = source
    with client(app_db.app_url, ingest_rate_per_second=0.5, ingest_rate_burst=2) as c:
        first = post_records(c, name, token, ndjson("a", "b", "c"))  # admitted, into debt
        second = post_records(c, name, token, ndjson("d"))
    assert first.status_code == 200
    assert second.status_code == 429
    assert int(second.headers["Retry-After"]) >= 1
    assert _meta(app_db.owner_url, name) == [
        ("tuisku.meta.source_rate_limited", "records_per_second", 1)
    ]


def test_rate_limit_is_per_source(app_db: AppDatabase, source: tuple[str, str]) -> None:
    name, token = source
    other = _name()
    other_token = new_source(app_db.app_url, other)
    with client(app_db.app_url, ingest_rate_per_second=0.5, ingest_rate_burst=1) as c:
        assert post_records(c, name, token, ndjson("a")).status_code == 200
        assert post_records(c, name, token, ndjson("b")).status_code == 429
        assert post_records(c, other, other_token, ndjson("a")).status_code == 200


# --- OTLP ----------------------------------------------------------------------------------


def test_otlp_body_is_one_raw_record(app_db: AppDatabase, source: tuple[str, str]) -> None:
    name, token = source
    body = json.dumps({"kind": "metric.sample", "msg": "otlp"}).encode()
    headers = auth(token) | {"Content-Type": "application/json"}
    url = f"/v1/sources/{name}/otlp/v1/metrics"
    with client(app_db.app_url) as c:
        first = c.post(url, content=body, headers=headers)
        again = c.post(url, content=body, headers=headers)
        wrong_type = c.post(url, content=body, headers=auth(token) | NDJSON_HEADERS)
    assert first.status_code == 200 and first.json() == {"status": "accepted", "parse": "ok"}
    assert again.json() == {"status": "duplicate"}
    assert wrong_type.status_code == 415
    [(sha, transport, raw_body)] = query(
        app_db.owner_url,
        "SELECT r.sha256, r.transport, r.body FROM raw_records r "
        "JOIN sources s ON s.id = r.source_id WHERE s.name = %s",
        (name,),
    )
    assert bytes(sha) == hashlib.sha256(body).digest() and transport == "otlp_json"
    assert bytes(raw_body) == body


def test_otlp_body_over_limit_is_413(app_db: AppDatabase, source: tuple[str, str]) -> None:
    name, token = source
    with client(app_db.app_url, ingest_max_body_bytes=10) as c:
        response = c.post(
            f"/v1/sources/{name}/otlp/v1/metrics",
            content=b'{"resourceMetrics": []}',
            headers=auth(token) | {"Content-Type": "application/json"},
        )
    assert response.status_code == 413


# --- read endpoints ------------------------------------------------------------------------


def test_read_endpoints(app_db: AppDatabase, source: tuple[str, str]) -> None:
    name, token = source
    reader = operator_token(app_db.app_url, Role.READ)
    admin_token = operator_token(app_db.app_url, Role.ADMIN)
    approver = operator_token(app_db.owner_url, Role.APPROVE, person="Alice Example")
    with client(app_db.app_url) as c:
        post_records(
            c,
            name,
            token,
            ndjson({"ip": "192.0.2.1", "detect": 1}, {"ip": "192.0.2.2"}, {"kind": "dummy.other"}),
        )
        obs = c.get("/v1/observations", params={"source": name}, headers=auth(reader))
        by_key = c.get(
            "/v1/observations",
            params={"source": name, "entity_key": "ip:192.0.2.2"},
            headers=auth(admin_token),  # admin includes read
        )
        by_kind = c.get(
            "/v1/observations", params={"source": name, "kind": "dummy.other"}, headers=auth(reader)
        )
        page1 = c.get("/v1/observations", params={"source": name, "limit": 2}, headers=auth(reader))
        page2 = c.get(
            "/v1/observations",
            params={"source": name, "limit": 2, "before": page1.json()["next_before"]},
            headers=auth(reader),
        )
        window = c.get(
            "/v1/observations",
            params={"source": name, "since": (T0 + timedelta(seconds=1)).isoformat()},
            headers=auth(reader),
        )
        dets = c.get("/v1/detections", params={"source": name}, headers=auth(reader))
        raw_uid = dets.json()["items"][0]["raw_record_uid"]
        raw = c.get(f"/v1/raw/{raw_uid}", headers=auth(reader))
        missing = c.get(f"/v1/raw/{uuid.uuid4()}", headers=auth(reader))
        too_many = c.get("/v1/observations", params={"limit": 501}, headers=auth(reader))
        no_token = c.get("/v1/observations")
        source_token_used = c.get("/v1/observations", headers=auth(token))
        approve_only = c.get("/v1/raw/" + raw_uid, headers=auth(approver))

    assert obs.status_code == 200
    items = obs.json()["items"]
    assert len(items) == 3 and items[0]["id"] > items[-1]["id"]  # newest first
    assert items[0]["source"] == name and items[0]["adapter_version"] == "0.1.0"
    assert [i["entity_keys"] for i in by_key.json()["items"]] == [["ip:192.0.2.2"]]
    assert [i["kind"] for i in by_kind.json()["items"]] == ["dummy.other"]
    assert len(page1.json()["items"]) == 2 and page1.json()["next_before"] is not None
    assert len(page2.json()["items"]) == 1 and page2.json()["next_before"] is None
    assert window.json()["items"] == []
    [det] = dets.json()["items"]
    assert det["evaluator"] == "sensor" and det["identity"] == "dummy:1"
    assert det["observation_uids"] == [items[-1]["uid"]]
    assert raw.status_code == 200
    raw_json = raw.json()
    assert (
        base64.b64decode(raw_json["body_base64"])
        == json.dumps({"ip": "192.0.2.1", "detect": 1}).encode()
    )
    assert (
        raw_json["sha256"] == hashlib.sha256(base64.b64decode(raw_json["body_base64"])).hexdigest()
    )
    assert [p["status"] for p in raw_json["parse_attempts"]] == ["ok"]
    assert raw_json["truncated"] is False
    assert missing.status_code == 404
    assert too_many.status_code == 422
    assert no_token.status_code == 401 and source_token_used.status_code == 401
    assert approve_only.status_code == 403  # approve does not include read


def test_declared_oversize_body_is_refused_before_it_is_read(
    app_db: AppDatabase, source: tuple[str, str]
) -> None:
    name, token = source
    consumed: list[int] = []

    def chunks():
        for i in range(3):
            consumed.append(i)
            yield b"x" * 10

    with client(app_db.app_url, ingest_max_body_bytes=100) as c:
        response = c.post(
            f"/v1/sources/{name}/records",
            content=chunks(),
            headers=NDJSON_HEADERS | auth(token) | {"Content-Length": "1000"},
        )
    assert response.status_code == 413
    assert len(consumed) < 3  # the body was never read to the end


def test_readers_return_only_the_current_derivation_by_default(
    app_db: AppDatabase, source: tuple[str, str]
) -> None:
    name, token = source
    reader = operator_token(app_db.app_url, Role.READ)
    with client(app_db.app_url) as c:
        post_records(c, name, token, ndjson({"kind": "dummy.v1"}, {"limit": "json_keys"}))
    # Reprocess the first record with a "newer adapter": a second successful attempt, then a
    # failed third one, which must leave the second current (ADR 0002 rule 3). Reprocessing is
    # not the API's: only the owner (or worker) may add attempts to an existing record.
    with psycopg.connect(app_db.owner_url) as conn:
        [(raw_id, source_id)] = conn.execute(
            "SELECT r.id, r.source_id FROM raw_records r JOIN parse_attempts p "
            "ON p.raw_record_id = r.id JOIN sources s ON s.id = r.source_id "
            "WHERE s.name = %s AND p.status = 'ok'",
            (name,),
        ).fetchall()
        [(attempt,)] = conn.execute(
            "INSERT INTO parse_attempts (raw_record_id, adapter, adapter_version, status, "
            "created_at) VALUES (%s, 'dummy', '0.2.0', 'ok', now()) RETURNING id",
            (raw_id,),
        ).fetchall()
        conn.execute(
            "INSERT INTO observations (raw_record_id, parse_attempt_id, source_id, kind, "
            "received_at, eval_time, ocsf_version, attributes) "
            "VALUES (%s, %s, %s, 'dummy.v2', %s, %s, '1.9.0', '{}')",
            (raw_id, attempt, source_id, T0, T0),
        )
        conn.execute(
            "INSERT INTO parse_attempts (raw_record_id, adapter, adapter_version, status, error, "
            "created_at) VALUES (%s, 'dummy', '0.3.0', 'failed', 'broken', now())",
            (raw_id,),
        )
    with client(app_db.app_url) as c:
        current = c.get("/v1/observations", params={"source": name}, headers=auth(reader))
        every = c.get(
            "/v1/observations",
            params={"source": name, "all_attempts": "true"},
            headers=auth(reader),
        )
        dets = c.get("/v1/detections", params={"source": name}, headers=auth(reader))
    assert [i["kind"] for i in current.json()["items"]] == ["dummy.v2"]
    assert [i["kind"] for i in every.json()["items"]] == ["dummy.v2", "dummy.v1"]
    # Meta-detections have no parse attempt and are always current; they carry their count.
    [meta] = dets.json()["items"]
    assert (meta["kind"], meta["subject"], meta["meta_count"]) == (
        "tuisku.meta.source_limit_exceeded",
        "json_keys",
        1,
    )


# --- per-record parse deadline -------------------------------------------------------------------


def test_a_runaway_parse_is_abandoned_and_the_record_kept(
    app_db: AppDatabase, source: tuple[str, str]
) -> None:
    import time

    name, token = source
    body = ndjson({"sleep": 3, "msg": "runaway"}, {"msg": "next"})
    started = time.monotonic()
    with client(app_db.app_url, ingest_parse_timeout_seconds=0.2) as c:
        response = post_records(c, name, token, body)
    elapsed = time.monotonic() - started
    assert response.status_code == 200
    assert elapsed < 2.5  # the 3 s parse was not waited for
    assert response.json()["results"] == [
        {"line": 1, "status": "accepted", "parse": "failed"},
        {"line": 2, "status": "accepted", "parse": "ok"},
    ]
    rows = query(
        app_db.owner_url,
        "SELECT p.status, p.error FROM parse_attempts p JOIN raw_records r "
        "ON r.id = p.raw_record_id JOIN sources s ON s.id = r.source_id WHERE s.name = %s "
        "ORDER BY r.id",
        (name,),
    )
    assert rows == [("failed", "time_budget"), ("ok", None)]
    assert ("tuisku.meta.source_limit_exceeded", "parse_time", 1) in _meta(app_db.owner_url, name)


# --- rate-limit refusals are counted in process ----------------------------------------------


def test_refusals_are_batched_then_flushed(app_db: AppDatabase, source: tuple[str, str]) -> None:
    name, token = source
    settings = {"ingest_rate_per_second": 0.01, "ingest_rate_burst": 1}
    with client(app_db.app_url, ingest_rate_breach_flush_seconds=3600, **settings) as c:
        assert post_records(c, name, token, ndjson("a")).status_code == 200
        for _ in range(5):
            assert post_records(c, name, token, ndjson("b")).status_code == 429
        # The first refusal is written at once; the next four wait in process.
        assert _meta(app_db.owner_url, name) == [
            ("tuisku.meta.source_rate_limited", "records_per_second", 1)
        ]
    # Shutting the app down flushes them.
    assert _meta(app_db.owner_url, name) == [
        ("tuisku.meta.source_rate_limited", "records_per_second", 5)
    ]


def test_refusal_counter_flushes_on_its_interval() -> None:
    from tuisku.api.ratelimit import RefusalCounter

    now = [0.0]
    counter = RefusalCounter(10, monotonic=lambda: now[0])
    assert counter.add(1, "s") == ("s", 1)
    assert counter.add(1, "s") is None and counter.add(1, "s") is None
    now[0] = 10.0
    assert counter.add(1, "s") == ("s", 3)
    assert counter.add(2, "t") == ("t", 1)  # per source
    assert counter.add(1, "s") is None
    assert counter.drain() == [("s", 1)]


# --- gzip --------------------------------------------------------------------------------------


def test_inflater_never_produces_more_than_cap_plus_one_per_step() -> None:
    from tuisku.api.ingest import _Inflater, _TooLarge

    cap = 1000
    inflater = _Inflater(cap)
    real = inflater._d
    sizes: list[int] = []

    class Spy:
        def __getattr__(self, name: str) -> object:
            return getattr(real, name)

        def decompress(self, data: bytes, max_length: int = 0) -> bytes:
            out = real.decompress(data, max_length)
            sizes.append(len(out))
            return out

    inflater._d = Spy()  # type: ignore[assignment]
    with pytest.raises(_TooLarge):
        inflater.feed(gzip.compress(b"\0" * 50_000_000))  # a 50 MB bomb in ~50 KB
    assert sizes and max(sizes) <= cap + 1


# --- duplicate race --------------------------------------------------------------------------


def test_a_concurrent_duplicate_in_the_fallback_is_recorded_as_a_duplicate(
    app_db: AppDatabase, source: tuple[str, str], monkeypatch: pytest.MonkeyPatch
) -> None:
    """The database refuses the adapter's output; while the record is re-stored on its own,
    another request has stored the same bytes. That is a duplicate, not a store error."""
    from tuisku.store import ingest as store_ingest

    name, token = source
    real = store_ingest._insert_raw
    calls = {"n": 0}

    async def racing(conn, credential, **kw):  # type: ignore[no-untyped-def]
        calls["n"] += 1
        if calls["n"] == 2:  # the fallback: another request wins the race first
            other = await psycopg.AsyncConnection.connect(app_db.app_url, autocommit=True)
            async with other:
                await real(other, credential, **kw)
        return await real(conn, credential, **kw)

    monkeypatch.setattr(store_ingest, "_insert_raw", racing)
    with client(app_db.app_url) as c:
        response = post_records(c, name, token, ndjson({"kind": "x" * 200}))
    assert response.json()["results"] == [{"line": 1, "status": "duplicate"}]
