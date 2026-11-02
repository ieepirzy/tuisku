"""End to end: Harava log lines and OTLP JSON -> ingest API -> worker -> finding, incident and
logged notifications (issue #2: "page on any occurrence"), then triage through the API and
re-arm after the incident closes."""

from __future__ import annotations

import json
import logging
from datetime import UTC, datetime
from typing import Any

import pytest

from tests.conftest import REPO_ROOT
from tests.support import auth, client, ndjson, new_source, operator_token, post_records, query
from tests.worker_support import Clock, builtin_rules, run_worker
from tuisku.store.tokens import Role
from tuisku.worker.notify import LogNotifier

FIXTURES = REPO_ROOT / "tests" / "fixtures" / "harava"
AGENT_OUTBOUND = "harava.agent_outbound_refused"


def _notifications(caplog: pytest.LogCaptureFixture) -> list[dict[str, Any]]:
    out = []
    for record in caplog.records:
        if record.name == "tuisku.notify":
            out.append(json.loads(record.getMessage().removeprefix("notification ")))
    return out


def test_three_refusals_within_the_hour_page_three_times(
    fresh_database_url: str, caplog: pytest.LogCaptureFixture
) -> None:
    url = fresh_database_url
    token = new_source(url, "harava-edge", adapter="harava")
    clock = Clock(datetime(2026, 11, 1, 9, 30, tzinfo=UTC))
    lines = (FIXTURES / "plain.log").read_text().splitlines()
    otlp = [ln for ln in (FIXTURES / "otlp.ndjson").read_text().splitlines() if ln.strip()]
    with client(url, clock=clock) as c:
        r = post_records(c, "harava-edge", token, ndjson(*lines))
        assert r.status_code == 200, r.text
        for body in otlp:
            r = c.post(
                "/v1/sources/harava-edge/otlp/v1/metrics",
                content=body.encode(),
                headers={"Content-Type": "application/json"} | auth(token),
            )
            assert r.status_code == 200, r.text

    with caplog.at_level(logging.WARNING, logger="tuisku.notify"):
        run_worker(url, builtin_rules(), clock, LogNotifier(), record_packs=True)
    sent = _notifications(caplog)

    # The finding: one per agent caller, count 3 (the three agent outbound refusal lines).
    [(finding_uid, count, status)] = query(
        url,
        "SELECT uid::text, count, status FROM findings WHERE rule_ref ->> 'name' = %s",
        (AGENT_OUTBOUND,),
    )
    assert (count, status) == (3, "open")
    paged = [n for n in sent if n.get("finding_uid") == finding_uid]
    assert [n["kind"] for n in paged] == [
        "finding_opened",
        "finding_occurrence",
        "finding_occurrence",
    ]
    assert all(n["severity_id"] == 4 and "caller:harava/agents" in n["entity_keys"] for n in paged)
    # Notifications carry ids and titles, never L0 bodies.
    assert not any("findings=" in json.dumps(n) for n in sent)
    # The destination rule paged twice; the service caller (sidos) once, on opening.
    kinds = sorted(n["kind"] for n in sent)
    assert kinds.count("incident_opened") == 2
    # Detections: evaluator tuisku, authorship of the pack, identity = rule id.
    rows = query(
        url,
        "SELECT kind, authorship, identity, explanation -> 'pack' ->> 'id' FROM detections "
        "WHERE evaluator = 'tuisku' AND kind = %s",
        (AGENT_OUTBOUND,),
    )
    assert len(rows) == 3
    assert {r[1:] for r in rows} == {("tuisku", "f542db3a-6926-4df9-9183-449491345d3c", "harava")}
    assert query(url, "SELECT count(*) FROM pack_loads")[0][0] == 2
    assert query(url, "SELECT count(*) FROM evaluation_queue")[0][0] == 0

    # Read it back through the API.
    reader = operator_token(url, Role.READ)
    triager = operator_token(url, Role.TRIAGE)
    with client(url, clock=clock) as c:
        r = c.get("/v1/incidents", headers=auth(reader))
        assert r.status_code == 200
        incidents = {i["title"]: i for i in r.json()["items"]}
        incident = incidents["Agent caller had outbound data refused"]
        detail = c.get(f"/v1/incidents/{incident['uid']}", headers=auth(reader)).json()
        assert [e["kind"] for e in detail["timeline"]] == ["opened", "finding_attached"]
        assert detail["timeline"][0]["actor"] == "rule:f542db3a-6926-4df9-9183-449491345d3c@1"
        assert detail["evidence"] == {
            "findings": 1,
            "detections": 3,
            "observations": 3,
            "raw_records": 3,
            "observation_kinds": ["harava.refusal:3"],
        }
        assert detail["findings"][0]["ocsf_status"] == "New"
        r = c.get("/v1/findings", params={"status": "open"}, headers=auth(reader))
        assert {f["uid"] for f in r.json()["items"]} >= {finding_uid}

        # Read tokens cannot triage; closing needs a disposition.
        status_url = f"/v1/incidents/{incident['uid']}/status"
        assert (
            c.post(status_url, json={"status": "closed"}, headers=auth(reader)).status_code == 403
        )
        r = c.post(status_url, json={"status": "closed"}, headers=auth(triager))
        assert r.status_code == 409
        r = c.post(
            status_url,
            json={"status": "closed", "disposition": "true_positive", "reason": "confirmed"},
            headers=auth(triager),
        )
        assert r.status_code == 200, r.text

    # Closing resolved the attachable finding, attributed to the operator.
    [(f_status,)] = query(url, "SELECT status FROM findings WHERE uid = %s", (finding_uid,))
    assert f_status == "resolved"
    [(actor,)] = query(
        url,
        "SELECT e.actor FROM finding_events e JOIN findings f ON f.id = e.finding_id "
        "WHERE f.uid = %s AND e.kind = 'status_changed' AND e.new_value ->> 'status' = 'resolved'",
        (finding_uid,),
    )
    [(token_uid,)] = query(url, "SELECT uid::text FROM operator_tokens WHERE roles = '{triage}'")
    assert actor == f"operator:{token_uid}"

    # Re-arm: the next refusal opens a new finding and a new incident linked to the closed one.
    clock.advance(minutes=10)
    with client(url, clock=clock) as c:
        post_records(
            c,
            "harava-edge",
            token,
            ndjson(
                "2026-11-01 09:39:00,000 WARNING harava.api outbound data refused: caller=agents "
                "urls=1 findings=email/query/plain"
            ),
        )
    caplog.clear()
    with caplog.at_level(logging.WARNING, logger="tuisku.notify"):
        run_worker(url, builtin_rules(), clock, LogNotifier())
    rows = query(
        url,
        "SELECT status, count FROM findings WHERE rule_ref ->> 'name' = %s ORDER BY id",
        (AGENT_OUTBOUND,),
    )
    assert rows == [("resolved", 3), ("open", 1)]
    [(new_incident, previous)] = query(
        url,
        "SELECT i.uid::text, p.uid::text FROM incidents i JOIN incidents p "
        "ON p.id = i.previous_incident_id",
    )
    assert previous == incident["uid"] and new_incident != previous
    assert [n["kind"] for n in _notifications(caplog)] == ["finding_opened", "incident_opened"]
