"""OTLP/HTTP JSON logs ingest: one logRecord is one raw record, parsed as an NDJSON line is."""

from __future__ import annotations

import gzip
import hashlib
import json
import uuid
from typing import Any

import pytest

from tests.conftest import AppDatabase
from tests.support import auth, client, ndjson, new_source, post_records, query, run
from tuisku.api import otlp_logs
from tuisku.store import admin

JSON_HEADERS = {"Content-Type": "application/json"}


def _name() -> str:
    return f"s{uuid.uuid4().hex[:10]}"


@pytest.fixture
def source(app_db: AppDatabase) -> tuple[str, str]:
    name = _name()
    return name, new_source(app_db.app_url, name)


def attrs(**values: Any) -> list[dict[str, Any]]:
    """OTLP KeyValues from keyword arguments; ``k8s_node_name`` becomes ``k8s.node.name``."""
    out = []
    for key, value in values.items():
        if isinstance(value, bool):
            any_value: dict[str, Any] = {"boolValue": value}
        elif isinstance(value, int):
            any_value = {"intValue": str(value)}  # OTLP/JSON: 64-bit integers as strings
        else:
            any_value = {"stringValue": value}
        out.append({"key": key.replace("_", "."), "value": any_value})
    return out


def log_record(line: str | None = None, *, body: Any = None, **extra: Any) -> dict[str, Any]:
    """A log record as the Collector's filelog receiver emits it (pdata JSON)."""
    record: dict[str, Any] = {
        "timeUnixNano": "0",
        "observedTimeUnixNano": "1793361600200000000",
        "body": {"stringValue": line} if body is None else body,
        "attributes": attrs(
            log_file_name="events.json", log_file_path="/var/run/sensor/events.json"
        ),
        "traceId": "",
        "spanId": "",
    }
    record.update(extra)
    return record


def payload(*records: dict[str, Any], resource: list[dict[str, Any]] | None = None) -> bytes:
    """An ExportLogsServiceRequest with one resource and one scope, Collector-shaped."""
    if resource is None:
        resource = attrs(
            k8s_node_name="node-1",
            k8s_pod_name="sensor-x1",
            k8s_namespace_name="security",
            service_name="sensor",
        )
    return json.dumps(
        {
            "resourceLogs": [
                {
                    "resource": {"attributes": resource},
                    "scopeLogs": [{"scope": {}, "logRecords": list(records)}],
                    "schemaUrl": "https://opentelemetry.io/schemas/1.6.1",
                }
            ]
        }
    ).encode()


def post_logs(c: Any, name: str, token: str, body: bytes, **headers: str) -> Any:
    return c.post(
        f"/v1/sources/{name}/otlp/v1/logs",
        content=body,
        headers=JSON_HEADERS | auth(token) | headers,
    )


def _meta(url: str, name: str) -> list[tuple[str, str, int]]:
    return query(
        url,
        "SELECT d.kind, d.subject, m.count FROM detections d "
        "JOIN sources s ON s.id = d.source_id "
        "JOIN meta_counters m ON m.source_id = d.source_id AND m.kind = d.kind "
        "AND m.subject = d.subject AND m.bucket_start = d.bucket_start "
        "WHERE s.name = %s AND d.evaluator = 'tuisku' ORDER BY d.subject",
        (name,),
    )


def _raw(url: str, name: str) -> list[tuple[Any, ...]]:
    return query(
        url,
        "SELECT convert_from(r.body, 'UTF8'), r.sha256, r.transport, r.collector, r.truncated "
        "FROM raw_records r JOIN sources s ON s.id = r.source_id WHERE s.name = %s ORDER BY r.id",
        (name,),
    )


def _summary(response: Any) -> dict[str, Any]:
    return response.json()["tuisku"]


RESOURCE = {
    "k8s.node.name": "node-1",
    "k8s.pod.name": "sensor-x1",
    "k8s.namespace.name": "security",
    "service.name": "sensor",
}
RECORD_ATTRIBUTES = {"log.file.name": "events.json", "log.file.path": "/var/run/sensor/events.json"}


def test_each_log_record_is_one_raw_record_with_collector_metadata(
    app_db: AppDatabase, source: tuple[str, str]
) -> None:
    name, token = source
    first = json.dumps({"kind": "dummy.flow", "ip": "192.0.2.7", "detect": 1})
    second = json.dumps({"msg": "second"})
    body = payload(log_record(first), log_record(second, timeUnixNano="1793361600100000000"))
    with client(app_db.app_url) as c:
        response = post_logs(c, name, token, body)
        again = post_logs(c, name, token, body)
    assert response.status_code == 200, response.text
    # Fully accepted: an ExportLogsServiceResponse without partialSuccess, plus our summary.
    assert response.json() == {"tuisku": {"counts": {"accepted": 2}, "parse": {"ok": 2}}}
    assert again.json() == {"tuisku": {"counts": {"duplicate": 2}, "parse": {}}}
    rows = _raw(app_db.owner_url, name)
    assert [r[0] for r in rows] == [first, second]  # the body string, byte for byte
    assert bytes(rows[0][1]) == hashlib.sha256(first.encode()).digest()
    assert {r[2] for r in rows} == {"otlp_logs_json"}
    collector = {
        "resource": RESOURCE,
        "attributes": RECORD_ATTRIBUTES,
        "observed_time_unix_nano": "1793361600200000000",
    }
    assert rows[0][3] == collector  # timeUnixNano "0" is unset, so it is left out
    assert rows[1][3] == collector | {"time_unix_nano": "1793361600100000000"}
    [(detections,)] = query(
        app_db.owner_url,
        "SELECT count(*) FROM detections d JOIN sources s ON s.id = d.source_id "
        "WHERE s.name = %s AND d.kind = 'dummy.alert'",
        (name,),
    )
    assert detections == 1
    assert _meta(app_db.owner_url, name) == []


def test_record_attributes_are_kept_apart_from_the_resource(
    app_db: AppDatabase, source: tuple[str, str]
) -> None:
    name, token = source
    # A record attribute (which a collector operator may have parsed out of the log line) names
    # another node: it must not replace the resource's node.
    record = log_record("x", attributes=attrs(k8s_node_name="spoofed", log_iostream="stdout"))
    record["attributes"].append(
        {
            "key": "nested",
            "value": {
                "kvlistValue": {
                    "values": [
                        {"key": "list", "value": {"arrayValue": {"values": [{"intValue": 7}]}}},
                        {"key": "d", "value": {"doubleValue": 1.5}},
                        {"key": "empty", "value": {}},
                        {"key": "nul", "value": {"stringValue": "a\u0000b"}},
                    ]
                }
            },
        }
    )
    resource = attrs(k8s_node_name="node-1", host_pinned=True, process_pid=42)
    with client(app_db.app_url) as c:
        assert post_logs(c, name, token, payload(record, resource=resource)).status_code == 200
    [row] = _raw(app_db.owner_url, name)
    assert row[3] == {
        "resource": {"k8s.node.name": "node-1", "host.pinned": True, "process.pid": 42},
        "attributes": {
            "k8s.node.name": "spoofed",
            "log.iostream": "stdout",
            "nested": {"list": [7], "d": 1.5, "empty": None, "nul": "a�b"},
        },
        "observed_time_unix_nano": "1793361600200000000",
    }


def test_malformed_log_records_are_rejected_one_by_one(
    app_db: AppDatabase, source: tuple[str, str]
) -> None:
    name, token = source
    records: list[Any] = [
        log_record("ok"),
        log_record(body={"kvlistValue": {"values": [{"key": "a", "value": {"intValue": 1}}]}}),
        log_record(body={"intValue": "5"}),
        log_record(body={"doubleValue": int("9" * 400)}),  # never converted: no OverflowError
        log_record(body={}),  # no body
        log_record(""),
        log_record("\ud800"),  # lone surrogate: not encodable as UTF-8
        log_record(body={"stringValue": "a", "boolValue": True}),  # not one AnyValue
        "not an object",
        log_record("ok2"),
    ]
    del records[4]["body"]
    with client(app_db.app_url) as c:
        response = post_logs(c, name, token, payload(*records))
    assert response.status_code == 200
    content = response.json()
    assert content["partialSuccess"] == {
        "rejectedLogRecords": "8",
        "errorMessage": "8 log records rejected: body_not_string, invalid_log_record",
    }
    summary = content["tuisku"]
    # The dummy adapter fails on non-JSON bodies, but they are stored: still accepted.
    assert summary["counts"] == {"accepted": 2, "rejected": 8}
    assert summary["parse"] == {"failed": 2}
    assert summary["rejected"] == [
        {"record": n, "reason": "body_not_string"} for n in (2, 3, 4)
    ] + [{"record": n, "reason": "invalid_log_record"} for n in range(5, 10)]
    assert [r[0] for r in _raw(app_db.owner_url, name)] == ["ok", "ok2"]
    assert _meta(app_db.owner_url, name) == [("tuisku.meta.invalid_envelope", "log_record", 8)]


def _deep(levels: int) -> dict[str, Any]:
    value: dict[str, Any] = {"stringValue": "leaf"}
    for _ in range(levels):
        value = {"arrayValue": {"values": [value]}}
    return value


def test_bad_attributes_drop_the_collector_never_the_record(
    app_db: AppDatabase, source: tuple[str, str]
) -> None:
    name, token = source
    huge_int = int("9" * 400)  # float() of it raises OverflowError

    def bad(attribute: Any) -> dict[str, Any]:
        return log_record(f"line {attribute!r:.40}", attributes=[attribute])

    good_resource = payload(
        bad({"key": "i", "value": {"intValue": "1e3"}}),
        bad({"key": "o", "value": {"stringValue": "a", "intValue": "1"}}),  # oneof
        bad({"key": "d", "value": {"doubleValue": huge_int}}),
        bad({"key": "n", "value": {"doubleValue": "OVERFLOW"}}),  # 1e999, see below
        log_record("repeated", attributes=attrs(a="1") + attrs(a="2")),
        bad({"value": {"stringValue": "no key"}}),
        bad({"key": "deep", "value": _deep(otlp_logs.MAX_ANY_VALUE_DEPTH + 1)}),
        log_record("many keys", attributes=attrs(**{f"k{i}": "v" for i in range(5000)})),
        log_record("fine"),
    )
    # A JSON number that overflows a double: 1e999 decodes to infinity.
    good_resource = good_resource.replace(b'"OVERFLOW"', b"1e999")
    bad_resources = [
        [{"key": 1}],
        [{"key": "d", "value": {"doubleValue": huge_int}}],
        [{"key": "r", "value": {"intValue": "99999999999999999999"}}],
    ]
    with client(app_db.app_url, ingest_max_collector_bytes=1_000_000) as c:
        response = post_logs(c, name, token, good_resource)
        bad_resource_responses = [
            post_logs(c, name, token, payload(log_record(f"r{i}"), resource=resource))
            for i, resource in enumerate(bad_resources)
        ]
    assert response.status_code == 200, response.text
    assert _summary(response)["counts"] == {"accepted": 9}
    assert [r.status_code for r in bad_resource_responses] == [200] * 3
    dropped = {"tuisku_collector_dropped": "collector_invalid"}
    rows = _raw(app_db.owner_url, name)
    assert [r[3] for r in rows] == [dropped] * 6 + [
        {"tuisku_collector_dropped": "collector_depth"},
        {"tuisku_collector_dropped": "collector_keys"},
        {
            "resource": RESOURCE,
            "attributes": RECORD_ATTRIBUTES,
            "observed_time_unix_nano": "1793361600200000000",
        },
    ] + [dropped] * 3
    assert _meta(app_db.owner_url, name) == [
        ("tuisku.meta.invalid_envelope", "collector", 9),
        ("tuisku.meta.source_limit_exceeded", "collector_depth", 1),
        ("tuisku.meta.source_limit_exceeded", "collector_keys", 1),
    ]


@pytest.mark.parametrize(
    "body",
    [
        b"",
        b"not json",
        b"[]",
        b'{"resourceLogs": {}}',
        b'{"resourceLogs": [{"resource": "node-1"}]}',
        b'{"resourceLogs": [{"scopeLogs": [{"logRecords": "x"}]}]}',
        b'{"resourceLogs": [], "resourceLogs": []}',  # duplicate key
        b'{"resourceLogs": [], "x": NaN}',
        b"\xff\xfe",
    ],
)
def test_a_request_that_is_not_otlp_logs_json_is_400(
    app_db: AppDatabase, source: tuple[str, str], body: bytes
) -> None:
    name, token = source
    with client(app_db.app_url) as c:
        response = post_logs(c, name, token, body)
    assert response.status_code == 400
    assert _raw(app_db.owner_url, name) == []
    assert _meta(app_db.owner_url, name) == [
        ("tuisku.meta.invalid_envelope", "otlp_logs_request", 1)
    ]


def test_refused_requests_are_counted_in_batches(
    app_db: AppDatabase, source: tuple[str, str]
) -> None:
    name, token = source
    with client(app_db.app_url, ingest_rate_breach_flush_seconds=3600, ingest_max_lines=1) as c:
        for _ in range(4):
            assert post_logs(c, name, token, b"[]").status_code == 400
        for _ in range(3):
            too_many = payload(log_record("a"), log_record("b"))
            assert post_logs(c, name, token, too_many).status_code == 413
        # The first refusal of each kind is written at once; the rest wait in process.
        assert _meta(app_db.owner_url, name) == [
            ("tuisku.meta.source_limit_exceeded", "lines", 1),
            ("tuisku.meta.invalid_envelope", "otlp_logs_request", 1),
        ]
    # Shutting the app down flushes them.
    assert _meta(app_db.owner_url, name) == [
        ("tuisku.meta.source_limit_exceeded", "lines", 3),
        ("tuisku.meta.invalid_envelope", "otlp_logs_request", 4),
    ]


@pytest.mark.parametrize("body", [b"{}", b'{"resourceLogs": []}', payload()])
def test_an_empty_request_is_accepted_and_stores_nothing(
    app_db: AppDatabase, source: tuple[str, str], body: bytes
) -> None:
    name, token = source
    with client(app_db.app_url, ingest_rate_per_second=0.001, ingest_rate_burst=1) as c:
        response = post_logs(c, name, token, body)
        # It took nothing from the bucket: one record still fits.
        assert post_logs(c, name, token, payload(log_record("one"))).status_code == 200
    assert response.status_code == 200
    assert response.json() == {"tuisku": {"counts": {}, "parse": {}}}
    assert len(_raw(app_db.owner_url, name)) == 1
    assert _meta(app_db.owner_url, name) == []


def test_over_long_record_is_stored_truncated_and_unparsed(
    app_db: AppDatabase, source: tuple[str, str]
) -> None:
    name, token = source
    long_line = json.dumps({"msg": "z" * 300})
    with client(app_db.app_url, ingest_max_line_bytes=100) as c:
        response = post_logs(c, name, token, payload(log_record(long_line), log_record("{}")))
    assert response.status_code == 200
    assert _summary(response) == {"counts": {"accepted": 2}, "parse": {"skipped": 1, "ok": 1}}
    [(body, size, truncated, transport, sha)] = query(
        app_db.owner_url,
        "SELECT r.body, r.body_size, r.truncated, r.transport, r.sha256 FROM raw_records r "
        "JOIN sources s ON s.id = r.source_id WHERE s.name = %s AND r.truncated",
        (name,),
    )
    assert bytes(body) == long_line.encode()[:100] and size == len(long_line) and truncated
    assert transport == "otlp_logs_json"
    assert bytes(sha) == hashlib.sha256(long_line.encode()).digest()
    assert _meta(app_db.owner_url, name) == [("tuisku.meta.source_limit_exceeded", "line_bytes", 1)]


def test_more_log_records_than_the_line_limit_is_413(
    app_db: AppDatabase, source: tuple[str, str]
) -> None:
    name, token = source
    body = payload(log_record("a"), log_record("b"), log_record("c"))
    with client(app_db.app_url, ingest_max_lines=2) as c:
        response = post_logs(c, name, token, body)
        fits = post_logs(c, name, token, payload(log_record("a"), log_record("b")))
    assert response.status_code == 413
    assert fits.status_code == 200
    assert len(_raw(app_db.owner_url, name)) == 2
    assert _meta(app_db.owner_url, name) == [("tuisku.meta.source_limit_exceeded", "lines", 1)]


def test_oversized_collector_is_replaced_by_a_marker_with_its_exact_size(
    app_db: AppDatabase, source: tuple[str, str]
) -> None:
    name, token = source
    record = log_record("{}", attributes=attrs(note="ä€\U0001f600"))  # multi-byte UTF-8
    full = {
        "resource": RESOURCE,
        "attributes": {"note": "ä€\U0001f600"},
        "observed_time_unix_nano": "1793361600200000000",
    }
    size = len(json.dumps(full, ensure_ascii=False, separators=(",", ":")).encode())
    with client(app_db.app_url, ingest_max_collector_bytes=size - 1) as c:
        dropped = post_logs(c, name, token, payload(record))
    with client(app_db.app_url, ingest_max_collector_bytes=size) as c:
        kept = post_logs(c, name, token, payload(log_record("[]", attributes=record["attributes"])))
    assert _summary(dropped)["counts"] == _summary(kept)["counts"] == {"accepted": 1}
    assert [r[3] for r in _raw(app_db.owner_url, name)] == [
        {"tuisku_collector_dropped_bytes": size},
        full,
    ]
    assert _meta(app_db.owner_url, name) == [
        ("tuisku.meta.source_limit_exceeded", "collector_bytes", 1)
    ]


def test_gzip_body_is_decompressed(app_db: AppDatabase, source: tuple[str, str]) -> None:
    name, token = source
    body = payload(log_record("zipped"))
    with client(app_db.app_url) as c:
        response = post_logs(c, name, token, gzip.compress(body), **{"Content-Encoding": "gzip"})
        broken = post_logs(c, name, token, b"\x1f\x8bnot gzip", **{"Content-Encoding": "gzip"})
        bomb = gzip.compress(b" " * 2_000_000)
    with client(app_db.app_url, ingest_max_body_bytes=100_000) as c:
        too_large = post_logs(c, name, token, bomb, **{"Content-Encoding": "gzip"})
    assert response.status_code == 200
    assert _summary(response) == {"counts": {"accepted": 1}, "parse": {"failed": 1}}
    assert broken.status_code == 400 and too_large.status_code == 413
    assert [r[0] for r in _raw(app_db.owner_url, name)] == ["zipped"]


def test_credentials_and_content_type(app_db: AppDatabase, source: tuple[str, str]) -> None:
    name, token = source
    other = _name()
    other_token = new_source(app_db.app_url, other)
    disabled = _name()
    disabled_token = new_source(app_db.app_url, disabled)
    run(app_db.app_url, lambda conn: admin.disable_source(conn, disabled))
    body = payload(log_record("{}"))
    with client(app_db.app_url) as c:
        bad = post_logs(c, name, "tsk_src_" + "x" * 43, body)
        wrong_source = post_logs(c, name, other_token, body)
        no_token = c.post(f"/v1/sources/{name}/otlp/v1/logs", content=body, headers=JSON_HEADERS)
        off = post_logs(c, disabled, disabled_token, body)
        protobuf = post_logs(c, name, token, body, **{"Content-Type": "application/x-protobuf"})
        ok = post_logs(c, name, token, body)
    assert [r.status_code for r in (bad, wrong_source, no_token, off)] == [401] * 4
    assert protobuf.status_code == 415
    assert ok.status_code == 200
    assert len(_raw(app_db.owner_url, name)) == 1
    assert _raw(app_db.owner_url, disabled) == []


def test_rate_limit_charges_each_record_and_refuses_before_decoding(
    app_db: AppDatabase, source: tuple[str, str]
) -> None:
    name, token = source
    with client(app_db.app_url, ingest_rate_per_second=0.001, ingest_rate_burst=3) as c:
        # Four records against a burst of three: admitted once, leaving the bucket in debt.
        first = post_logs(c, name, token, payload(*(log_record(f"r{i}") for i in range(4))))
        limited = post_logs(c, name, token, payload(log_record("next")))
        # An empty bucket refuses even a body that would be a 400, before decoding it.
        not_decoded = post_logs(c, name, token, b"not json")
    assert first.status_code == 200
    assert limited.status_code == 429 and int(limited.headers["Retry-After"]) >= 1
    assert not_decoded.status_code == 429
    assert len(_raw(app_db.owner_url, name)) == 4
    # Two refusals, no 400: the bad body was never decoded.
    assert _meta(app_db.owner_url, name) == [
        ("tuisku.meta.source_rate_limited", "records_per_second", 2)
    ]


def test_time_budget_stops_the_request_with_503(
    app_db: AppDatabase, source: tuple[str, str]
) -> None:
    name, token = source
    body = payload(*(log_record(json.dumps({"sleep": 0.4, "msg": m})) for m in "abc"))
    with client(
        app_db.app_url, ingest_request_budget_seconds=0.3, ingest_parse_timeout_seconds=5
    ) as c:
        response = post_logs(c, name, token, body)
    assert response.status_code == 503
    assert response.headers["Retry-After"] == "1"
    assert "from 2 on were not stored" in response.json()["detail"]
    assert _summary(response) == {
        "counts": {"accepted": 1},
        "parse": {"ok": 1},
        "not_processed": 2,
    }
    with client(app_db.app_url, ingest_parse_timeout_seconds=5) as c:
        retry = post_logs(c, name, token, body)
    assert retry.status_code == 200
    assert _summary(retry)["counts"] == {"duplicate": 1, "accepted": 2}


@pytest.mark.parametrize("bodies", ["accepted", "rejected"])
def test_the_response_stays_small_at_the_record_limit(
    app_db: AppDatabase, source: tuple[str, str], bodies: str
) -> None:
    # An OTLP exporter reads at most 64 KiB of the answer and fails the export when it cannot
    # decode it: the answer must not grow with the number of records.
    name, token = source
    limit = 1500 if bodies == "accepted" else 5000
    if bodies == "accepted":
        records = [log_record(f'{{"n": {i}}}') for i in range(limit)]
    else:
        records = [log_record(body={"intValue": str(i)}) for i in range(limit)]
    with client(app_db.app_url, ingest_max_lines=limit, ingest_rate_burst=limit) as c:
        response = post_logs(c, name, token, payload(*records))
    assert response.status_code == 200, response.text[:200]
    assert len(response.content) < 8 * 1024
    content = response.json()
    if bodies == "accepted":
        assert "partialSuccess" not in content
        assert content["tuisku"]["counts"] == {"accepted": limit}
    else:
        assert content["partialSuccess"]["rejectedLogRecords"] == str(limit)
        assert content["tuisku"]["counts"] == {"rejected": limit}
        assert len(content["tuisku"]["rejected"]) == otlp_logs.MAX_LISTED_REJECTIONS


def test_same_line_over_ndjson_and_otlp_logs_derives_the_same_rows(
    app_db: AppDatabase,
) -> None:
    line = json.dumps({"kind": "dummy.flow", "ip": "192.0.2.9", "detect": 1, "msg": "same"})
    via_ndjson, via_otlp = _name(), _name()
    ndjson_token = new_source(app_db.app_url, via_ndjson)
    otlp_token = new_source(app_db.app_url, via_otlp)
    with client(app_db.app_url) as c:
        assert post_records(c, via_ndjson, ndjson_token, ndjson(line)).status_code == 200
        assert post_logs(c, via_otlp, otlp_token, payload(log_record(line))).status_code == 200

    def derived(name: str) -> list[tuple[Any, ...]]:
        return query(
            app_db.owner_url,
            "SELECT o.kind, o.attributes, o.entity_keys, d.kind, d.identity, d.severity_id "
            "FROM observations o JOIN detection_observations x ON x.observation_id = o.id "
            "JOIN detections d ON d.id = x.detection_id JOIN sources s ON s.id = o.source_id "
            "WHERE s.name = %s",
            (name,),
        )

    assert derived(via_otlp) == derived(via_ndjson) != []


# --- decoding, without a database ---------------------------------------------------------------


def _decode(body: bytes, max_records: int = 5000, max_collector_bytes: int = 4096) -> Any:
    return otlp_logs.decode_request(
        body, max_records=max_records, max_collector_bytes=max_collector_bytes
    )


def test_plain_value_flattens_any_value() -> None:
    plain = otlp_logs.plain_value
    assert plain({"stringValue": "s"}) == "s"
    assert plain({"intValue": "-9223372036854775808"}) == -(2**63)
    assert plain({"intValue": 3}) == 3
    assert plain({"doubleValue": "2.5"}) == 2.5
    assert plain({"doubleValue": "-1E-3"}) == -0.001
    assert plain({"doubleValue": 7}) == 7.0
    assert plain({"doubleValue": "NaN"}) == "NaN"  # jsonb has no NaN
    assert plain({"doubleValue": "-Infinity"}) == "-Infinity"
    assert plain({"bytesValue": "AAE="}) == "AAE="
    assert plain({"arrayValue": {}}) == []
    assert plain({"kvlistValue": {"values": [{"key": "k"}]}}) == {"k": None}
    assert plain({}) is None
    for bad in (
        "s",
        {"intValue": "9223372036854775808"},
        {"intValue": True},
        {"intValue": "1e3"},
        {"boolValue": "true"},
        {"stringValue": 1},
        {"doubleValue": "x"},
        {"doubleValue": "1_0"},  # Python-only spellings
        {"doubleValue": "inf"},
        {"doubleValue": " 1"},
        {"doubleValue": int("9" * 400)},  # OverflowError in float()
        {"doubleValue": float("inf")},
        {"stringValue": "a", "intValue": "1"},
        {"arrayValue": {"values": [1]}},
        {"kvlistValue": {"values": [{"value": {}}]}},
        {"kvlistValue": {"values": [{"key": "k"}, {"key": "k"}]}},
        _deep(otlp_logs.MAX_ANY_VALUE_DEPTH + 1),
    ):
        with pytest.raises(ValueError):
            plain(bad)
    assert plain(_deep(otlp_logs.MAX_ANY_VALUE_DEPTH)) is not None


def test_timestamps_must_fit_uint64() -> None:
    def times(value: Any) -> dict[str, Any]:
        [record] = _decode(payload(log_record("x", timeUnixNano=value), resource=[]))
        return {k: v for k, v in record.collector.items() if k.endswith("unix_nano")}

    assert times(str(2**64 - 1))["time_unix_nano"] == str(2**64 - 1)
    assert "time_unix_nano" not in times(str(2**64))
    assert "time_unix_nano" not in times("-1")
    assert times(5)["time_unix_nano"] == "5"


def test_decode_request_ignores_unknown_fields_and_keeps_order() -> None:
    body = json.dumps(
        {
            "resourceLogs": [
                {"scopeLogs": [{"logRecords": [log_record("a"), log_record("b")]}], "x": 1},
                {"resource": {}, "scopeLogs": [{"logRecords": [log_record("c", unknown=1)]}]},
            ],
            "extension": {"anything": True},
        }
    ).encode()
    decoded = _decode(body)
    assert [(d.number, d.raw) for d in decoded] == [(1, b"a"), (2, b"b"), (3, b"c")]
    with pytest.raises(otlp_logs.InvalidRequest) as info:
        _decode(b'{"resourceLogs": "secret-value"}')
    assert "secret-value" not in str(info.value)


def test_decode_stops_as_soon_as_there_are_too_many_records(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[int] = []
    real = otlp_logs._raw_body

    def counting(record: Any) -> Any:
        calls.append(1)
        return real(record)

    monkeypatch.setattr(otlp_logs, "_raw_body", counting)
    with pytest.raises(otlp_logs.TooManyRecords):
        _decode(payload(*(log_record(str(i)) for i in range(50))), max_records=3)
    assert len(calls) == 3


def test_a_resource_is_converted_and_sized_once_for_all_its_records(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sized: list[int] = []
    real = otlp_logs._size

    def counting(value: Any) -> int:
        size = real(value)
        sized.append(size)
        return size

    monkeypatch.setattr(otlp_logs, "_size", counting)
    resource = attrs(**{f"attr_{i}": "v" * 40 for i in range(50)})
    records = _decode(
        payload(*(log_record(str(i)) for i in range(200)), resource=resource),
        max_collector_bytes=1_000_000,
    )
    resource_size = len(
        json.dumps(otlp_logs._Converter().key_values(resource), separators=(",", ":"))
    )
    # The resource once, then each record's own attributes: never the resource again.
    assert sized.count(resource_size) == 1
    assert len(sized) == 1 + 200
    assert all(r.collector["resource"]["attr.0"] == "v" * 40 for r in records)


def test_a_large_shared_resource_costs_once_not_per_record() -> None:
    import time

    # About 1.2 MB of resource attributes (over the 4 KiB collector cap) shared by 4000 records.
    resource = attrs(**{f"attr_{i}": "v" * 400 for i in range(3000)})
    big = payload(*(log_record(str(i)) for i in range(4000)), resource=resource)
    started = time.monotonic()
    records = _decode(big, max_collector_bytes=4096)
    elapsed = time.monotonic() - started
    assert {r.collector_dropped for r in records} == {"collector_bytes"}
    assert elapsed < 3.0, elapsed  # per-record reprocessing takes minutes
