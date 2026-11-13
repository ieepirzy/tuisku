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
    # Fully accepted: an ExportLogsServiceResponse without partialSuccess, plus our results.
    assert response.json() == {
        "results": [
            {"record": 1, "status": "accepted", "parse": "ok"},
            {"record": 2, "status": "accepted", "parse": "ok"},
        ]
    }
    assert again.json()["results"] == [
        {"record": 1, "status": "duplicate"},
        {"record": 2, "status": "duplicate"},
    ]
    rows = _raw(app_db.owner_url, name)
    assert [r[0] for r in rows] == [first, second]  # the body string, byte for byte
    assert bytes(rows[0][1]) == hashlib.sha256(first.encode()).digest()
    assert {r[2] for r in rows} == {"otlp_logs_json"}
    resource = {
        "k8s.node.name": "node-1",
        "k8s.pod.name": "sensor-x1",
        "k8s.namespace.name": "security",
        "service.name": "sensor",
        "log.file.name": "events.json",
        "log.file.path": "/var/run/sensor/events.json",
        "otlp.observed_time_unix_nano": "1793361600200000000",
    }
    assert rows[0][3] == resource  # timeUnixNano "0" is unset, so it is left out
    assert rows[1][3] == resource | {"otlp.time_unix_nano": "1793361600100000000"}
    [(detections,)] = query(
        app_db.owner_url,
        "SELECT count(*) FROM detections d JOIN sources s ON s.id = d.source_id "
        "WHERE s.name = %s AND d.kind = 'dummy.alert'",
        (name,),
    )
    assert detections == 1
    assert _meta(app_db.owner_url, name) == []


def test_record_attributes_win_over_resource_attributes_and_values_are_flattened(
    app_db: AppDatabase, source: tuple[str, str]
) -> None:
    name, token = source
    record = log_record("x", attributes=attrs(host_name="from-record", log_iostream="stdout"))
    record["attributes"].append(
        {
            "key": "nested",
            "value": {
                "kvlistValue": {
                    "values": [
                        {"key": "list", "value": {"arrayValue": {"values": [{"intValue": 7}]}}},
                        {"key": "d", "value": {"doubleValue": 1.5}},
                        {"key": "empty", "value": {}},
                    ]
                }
            },
        }
    )
    resource = attrs(host_name="from-resource", host_pinned=True, process_pid=42)
    with client(app_db.app_url) as c:
        assert post_logs(c, name, token, payload(record, resource=resource)).status_code == 200
    [row] = _raw(app_db.owner_url, name)
    assert row[3] == {
        "host.name": "from-record",
        "host.pinned": True,
        "process.pid": 42,
        "log.iostream": "stdout",
        "nested": {"list": [7], "d": 1.5, "empty": None},
        "otlp.observed_time_unix_nano": "1793361600200000000",
    }


def test_malformed_log_records_are_rejected_one_by_one(
    app_db: AppDatabase, source: tuple[str, str]
) -> None:
    name, token = source
    records: list[Any] = [
        log_record("ok"),
        log_record(body={"kvlistValue": {"values": [{"key": "a", "value": {"intValue": 1}}]}}),
        log_record(body={"intValue": "5"}),
        log_record(body={}),  # no body
        log_record(""),
        log_record("\ud800"),  # lone surrogate: not encodable as UTF-8
        log_record(body={"stringValue": "a", "boolValue": True}),  # not one AnyValue
        log_record("bad attributes", attributes=[{"value": {"stringValue": "no key"}}]),
        "not an object",
        log_record("ok2"),
    ]
    del records[3]["body"]
    with client(app_db.app_url) as c:
        response = post_logs(c, name, token, payload(*records))
    assert response.status_code == 200
    content = response.json()
    assert content["partialSuccess"] == {
        "rejectedLogRecords": "8",
        "errorMessage": "8 log records rejected: body_not_string, invalid_log_record",
    }
    statuses = [(r["status"], r.get("reason")) for r in content["results"]]
    rejected_body = ("rejected", "body_not_string")
    rejected = ("rejected", "invalid_log_record")
    # The dummy adapter fails on non-JSON bodies, but they are stored: still accepted.
    assert statuses == [
        ("accepted", None),
        rejected_body,
        rejected_body,
        *[rejected] * 6,
        ("accepted", None),
    ]
    assert [r[0] for r in _raw(app_db.owner_url, name)] == ["ok", "ok2"]
    assert _meta(app_db.owner_url, name) == [("tuisku.meta.invalid_envelope", "log_record", 8)]


@pytest.mark.parametrize(
    "body",
    [
        b"",
        b"not json",
        b"[]",
        b'{"resourceLogs": {}}',
        b'{"resourceLogs": [{"resource": {"attributes": [{"key": 1}]}}]}',
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
    assert body.decode("utf-8", "replace") not in response.text or body == b""
    assert _raw(app_db.owner_url, name) == []
    assert _meta(app_db.owner_url, name) == [
        ("tuisku.meta.invalid_envelope", "otlp_logs_request", 1)
    ]


@pytest.mark.parametrize("body", [b"{}", b'{"resourceLogs": []}', payload()])
def test_an_empty_request_is_accepted_and_stores_nothing(
    app_db: AppDatabase, source: tuple[str, str], body: bytes
) -> None:
    name, token = source
    # Even with an exhausted rate limit: no records, nothing to admit.
    with client(app_db.app_url, ingest_rate_per_second=0.001, ingest_rate_burst=1) as c:
        assert post_logs(c, name, token, payload(log_record("one"))).status_code == 200
        response = post_logs(c, name, token, body)
    assert response.status_code == 200
    assert response.json() == {"results": []}
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
    assert response.json() == {
        "results": [
            {"record": 1, "status": "accepted", "parse": "skipped"},
            {"record": 2, "status": "accepted", "parse": "ok"},
        ]
    }
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


def test_oversized_collector_is_replaced_by_a_marker(
    app_db: AppDatabase, source: tuple[str, str]
) -> None:
    name, token = source
    with client(app_db.app_url, ingest_max_collector_bytes=100) as c:
        response = post_logs(c, name, token, payload(log_record("{}")))
    assert response.json()["results"] == [{"record": 1, "status": "accepted", "parse": "ok"}]
    [row] = _raw(app_db.owner_url, name)
    assert set(row[3]) == {"tuisku_collector_dropped_bytes"}
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
    assert response.json()["results"] == [{"record": 1, "status": "accepted", "parse": "failed"}]
    assert broken.status_code == 400 and too_large.status_code == 413
    assert [r[0] for r in _raw(app_db.owner_url, name)] == ["zipped"]


def test_credentials_content_type_and_rate_limit(
    app_db: AppDatabase, source: tuple[str, str]
) -> None:
    name, token = source
    other = _name()
    other_token = new_source(app_db.app_url, other)
    disabled = _name()
    disabled_token = new_source(app_db.app_url, disabled)
    run(app_db.app_url, lambda conn: admin.disable_source(conn, disabled))
    body = payload(log_record("{}"))
    with client(app_db.app_url, ingest_rate_per_second=0.5, ingest_rate_burst=1) as c:
        bad = post_logs(c, name, "tsk_src_" + "x" * 43, body)
        wrong_source = post_logs(c, name, other_token, body)
        no_token = c.post(f"/v1/sources/{name}/otlp/v1/logs", content=body, headers=JSON_HEADERS)
        off = post_logs(c, disabled, disabled_token, body)
        protobuf = post_logs(c, name, token, body, **{"Content-Type": "application/x-protobuf"})
        ok = post_logs(c, name, token, body)
        limited = post_logs(c, name, token, payload(log_record("[]")))
    assert [r.status_code for r in (bad, wrong_source, no_token, off)] == [401] * 4
    assert protobuf.status_code == 415
    assert ok.status_code == 200
    assert limited.status_code == 429 and int(limited.headers["Retry-After"]) >= 1
    assert len(_raw(app_db.owner_url, name)) == 1
    assert _raw(app_db.owner_url, disabled) == []


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
    assert response.json()["results"] == [
        {"record": 1, "status": "accepted", "parse": "ok"},
        {"record": 2, "status": "not_processed", "reason": "time_budget_exceeded"},
        {"record": 3, "status": "not_processed", "reason": "time_budget_exceeded"},
    ]
    with client(app_db.app_url, ingest_parse_timeout_seconds=5) as c:
        retry = post_logs(c, name, token, body)
    assert retry.status_code == 200
    assert [r["status"] for r in retry.json()["results"]] == ["duplicate", "accepted", "accepted"]


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


def test_plain_value_flattens_any_value() -> None:
    plain = otlp_logs.plain_value
    assert plain({"stringValue": "s"}) == "s"
    assert plain({"intValue": "-9223372036854775808"}) == -(2**63)
    assert plain({"intValue": 3}) == 3
    assert plain({"doubleValue": "2.5"}) == 2.5
    assert plain({"doubleValue": "NaN"}) == "NaN"  # jsonb has no NaN
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
        {"stringValue": "a", "intValue": "1"},
        {"arrayValue": {"values": [1]}},
        {"kvlistValue": {"values": [{"value": {}}]}},
    ):
        with pytest.raises(ValueError):
            plain(bad)
    deep: dict[str, Any] = {"stringValue": "leaf"}
    for _ in range(otlp_logs.MAX_ANY_VALUE_DEPTH + 1):
        deep = {"arrayValue": {"values": [deep]}}
    with pytest.raises(ValueError):
        plain(deep)


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
    decoded = [p.decode() for p in otlp_logs.decode_request(body)]
    assert [d.raw for d in decoded if isinstance(d, otlp_logs.LogRecordEnvelope)] == [
        b"a",
        b"b",
        b"c",
    ]
    with pytest.raises(otlp_logs.InvalidRequest) as info:
        otlp_logs.decode_request(b'{"resourceLogs": "secret-value"}')
    assert "secret-value" not in str(info.value)
