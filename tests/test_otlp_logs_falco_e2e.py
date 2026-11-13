"""End to end: Falco JSON lines shipped by an OpenTelemetry Collector (filelog receiver ->
otlphttp exporter, JSON encoding, gzip) -> OTLP logs ingest -> falco adapter -> worker ->
the sensors-default Falco Critical finding and incident."""

from __future__ import annotations

import gzip
import json
from datetime import UTC, datetime
from typing import Any

from tests.conftest import REPO_ROOT
from tests.support import auth, client, new_source, query
from tests.worker_support import Clock, RecordingNotifier, builtin_rules, run_worker

FIXTURES = REPO_ROOT / "tests" / "fixtures" / "falco"
SOURCE = "falco"


def _string(key: str, value: str) -> dict[str, Any]:
    return {"key": key, "value": {"stringValue": value}}


def collector_request(*lines: str) -> bytes:
    """What the Collector's otlphttp exporter (encoding: json) posts for lines read by a filelog
    receiver from a Falco sidecar's events file, with k8s resource attributes added by a
    resource or k8sattributes processor. Synthetic values only."""
    records = [
        {
            "observedTimeUnixNano": str(1793361600500000000 + i),
            "body": {"stringValue": line},
            "attributes": [
                _string("log.file.name", "events.json"),
                _string("log.file.path", "/var/run/falco/events.json"),
            ],
            "traceId": "",
            "spanId": "",
        }
        for i, line in enumerate(lines)
    ]
    request = {
        "resourceLogs": [
            {
                "resource": {
                    "attributes": [
                        _string("k8s.node.name", "node-1"),
                        _string("k8s.namespace.name", "falco"),
                        _string("k8s.pod.name", "falco-7xq2p"),
                        _string("service.name", "falco"),
                    ]
                },
                "scopeLogs": [{"scope": {}, "logRecords": records}],
            }
        ]
    }
    return json.dumps(request, separators=(",", ":")).encode()


def test_falco_events_over_otlp_logs_page_on_critical(fresh_database_url: str) -> None:
    url = fresh_database_url
    token = new_source(url, SOURCE, adapter="falco")
    notice = (FIXTURES / "shell_in_container.ndjson").read_text().strip()
    event = json.loads(notice)
    event["priority"] = "Critical"
    event["output"] = event["output"].replace(": Notice ", ": Critical ")
    critical = json.dumps(event)
    clock = Clock(datetime(2026, 10, 30, 12, 0, 5, tzinfo=UTC))

    with client(url, clock=clock) as c:
        response = c.post(
            f"/v1/sources/{SOURCE}/otlp/v1/logs",
            content=gzip.compress(collector_request(notice, critical)),
            headers=auth(token) | {"Content-Type": "application/json", "Content-Encoding": "gzip"},
        )
    assert response.status_code == 200, response.text
    assert response.json() == {
        "results": [
            {"record": 1, "status": "accepted", "parse": "ok"},
            {"record": 2, "status": "accepted", "parse": "ok"},
        ]
    }

    # L0: each Falco line verbatim, with the shipper's k8s metadata as receipt metadata only.
    raws = query(
        url,
        "SELECT convert_from(body, 'UTF8'), transport, collector FROM raw_records ORDER BY id",
    )
    assert [r[0] for r in raws] == [notice, critical]
    assert {r[1] for r in raws} == {"otlp_logs_json"}
    assert raws[0][2]["k8s.node.name"] == "node-1"
    assert raws[0][2]["k8s.pod.name"] == "falco-7xq2p"
    assert raws[0][2]["log.file.path"] == "/var/run/falco/events.json"

    # L1/L2 come from the Falco event itself, never from the collector metadata: the pod in the
    # entity keys is the workload Falco saw (web-1), not the Falco pod that shipped the line.
    observations = query(url, "SELECT kind, attributes, entity_keys FROM observations ORDER BY id")
    assert [o[0] for o in observations] == ["process.exec", "process.exec"]
    assert observations[0][1]["device"] == {"hostname": "node-1"}
    assert observations[0][1]["k8s"] == {"namespace": "default", "pod": "web-1"}
    assert "k8s:default/web-1" in observations[0][2]
    assert not any("falco-7xq2p" in k for o in observations for k in o[2])
    detections = query(
        url,
        "SELECT identity, authorship, severity_id, kind FROM detections "
        "WHERE evaluator = 'sensor' ORDER BY id",
    )
    assert detections == [
        ("falco:Terminal shell in container", "community", 2, "falco.rule"),
        ("falco:Terminal shell in container", "community", 5, "falco.rule"),
    ]

    # The worker: only the Critical match opens the sensors-default finding and an incident.
    notifier = RecordingNotifier()
    run_worker(url, builtin_rules(), clock, notifier, record_packs=True)
    findings = query(url, "SELECT rule_ref ->> 'name', count, status, severity_id FROM findings")
    assert findings == [("sensors-default.falco_critical", 1, "open", 5)]
    [(incident_status,)] = query(url, "SELECT status FROM incidents")
    assert incident_status == "open"
    assert sorted(notifier.kinds()) == ["finding_opened", "incident_opened"]
    assert query(url, "SELECT count(*) FROM evaluation_queue") == [(0,)]
