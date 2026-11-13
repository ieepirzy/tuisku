"""The Alertmanager notifier (ADR 0007 "Notifications"), against a small local HTTP server."""

from __future__ import annotations

import asyncio
import base64
import json
import logging
import threading
import time
import uuid
from collections.abc import Iterator
from dataclasses import dataclass, field
from datetime import UTC, datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

import psycopg
import pytest
from pydantic import SecretStr, ValidationError

from tests.conftest import REPO_ROOT, make_settings
from tests.support import query
from tests.worker_support import run_async
from tuisku.config import ALERTMANAGER_OWN_LABELS, Settings
from tuisku.worker import notify
from tuisku.worker.alertmanager import (
    AlertmanagerNotifier,
    AlertmanagerRejected,
    AlertmanagerTimeout,
    AlertmanagerUnavailable,
    build_alert,
    severity_label,
)
from tuisku.worker.run import build_notifier, run_worker

UID = "3f0e9a52-8c1d-4f6e-9a57-0d2b7c1e4a10"
FINDING_UID = "5b3c2a10-1d2e-4f3a-8b9c-0a1b2c3d4e5f"
RULE = "6e1f2a3b-4c5d-4e6f-8a7b-9c0d1e2f3a4b@3"
SECRET = "s3cret-pw"
NOW = datetime(2026, 11, 13, 12, 0, tzinfo=UTC)
NO_WAIT = notify.Backoff(base_seconds=0, cap_seconds=0)


def notification(**extra: Any) -> dict[str, Any]:
    """As notify.drain builds it: core fields, then a finding payload with synthetic keys."""
    return {
        "uid": UID,
        "kind": "finding_opened",
        "severity_id": 4,
        "created_at": "2026-11-13T12:00:00.123456+00:00",
        "meta": False,
        "finding_uid": FINDING_UID,
        "rule": RULE,
        "title": "Synthetic rule title",
        "entity_keys": ["user:alice.example", "ip:192.0.2.7"],
        "count": 987654,
        "detection_uid": "7a8b9c0d-1e2f-4a3b-8c4d-5e6f7a8b9c0d",
        **extra,
    }


# --- a local Alertmanager ------------------------------------------------------------------------


@dataclass
class FakeAlertmanager:
    url: str = ""
    status: int = 200
    delay: float = 0.0
    location: str | None = None
    requests: list[dict[str, Any]] = field(default_factory=list)

    @property
    def alerts(self) -> list[dict[str, Any]]:
        return [a for r in self.requests for a in r["body"]]


@pytest.fixture
def alertmanager() -> Iterator[FakeAlertmanager]:
    fake = FakeAlertmanager()

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self) -> None:  # noqa: N802
            length = int(self.headers.get("Content-Length", "0"))
            body = json.loads(self.rfile.read(length))
            fake.requests.append({"path": self.path, "headers": dict(self.headers), "body": body})
            if fake.delay:
                time.sleep(fake.delay)
            self.send_response(fake.status)
            if fake.location:
                self.send_header("Location", fake.location)
            self.send_header("Content-Length", "0")
            self.end_headers()

        def do_GET(self) -> None:  # noqa: N802  (a followed redirect would land here)
            fake.requests.append({"path": self.path, "headers": dict(self.headers), "body": []})
            self.send_response(200)
            self.send_header("Content-Length", "0")
            self.end_headers()

        def log_message(self, format: str, *args: Any) -> None:
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    server.daemon_threads = True
    fake.url = f"http://127.0.0.1:{server.server_address[1]}"
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield fake
    finally:
        server.shutdown()
        server.server_close()


def notifier(fake: FakeAlertmanager, **kw: Any) -> AlertmanagerNotifier:
    return AlertmanagerNotifier(SecretStr(fake.url), **kw)


# --- the alert -----------------------------------------------------------------------------------


def test_alert_labels_annotations_and_times() -> None:
    alert = build_alert(notification(), static_labels={"team": "security"})
    assert alert == {
        "labels": {
            "alertname": "TuiskuNotification",
            "source": "tuisku",
            "tuisku_kind": "finding_opened",
            "severity": "high",
            "notification_uid": UID,
            "meta": "false",
            "team": "security",
        },
        "annotations": {
            "summary": "Synthetic rule title",
            "description": f"kind=finding_opened notification_uid={UID} severity_id=4 "
            f"finding_uid={FINDING_UID} "
            f"detection_uid=7a8b9c0d-1e2f-4a3b-8c4d-5e6f7a8b9c0d rule={RULE}",
        },
        "startsAt": "2026-11-13T12:00:00.123456+00:00",
    }
    assert set(alert["labels"]) - {"team"} == ALERTMANAGER_OWN_LABELS


def test_meta_pages_are_marked_and_untitled_ones_get_a_summary() -> None:
    alert = build_alert(
        {"uid": UID, "kind": "tuisku_backlog", "severity_id": 5, "created_at": "x", "meta": True},
        static_labels={},
    )
    assert alert["labels"]["meta"] == "true"
    assert alert["labels"]["severity"] == "critical"
    assert alert["annotations"]["summary"] == "Tuisku notification: tuisku_backlog"


def test_severity_mapping_follows_ocsf_captions() -> None:
    assert [severity_label(i) for i in range(7)] == [
        "unknown",
        "informational",
        "low",
        "medium",
        "high",
        "critical",
        "fatal",
    ]
    assert severity_label(99) == "other"
    assert severity_label(42) == "unknown"
    assert severity_label(None) == "unknown"


def test_no_entity_keys_or_telemetry_by_default() -> None:
    message = notification(
        group_key="ab" * 32,
        reason="crossed while suppressed",
        error="ValueError: field user=alice.example",
        subject="notifications",
        row={"layer": "observation", "uid": "1c2d3e4f-5a6b-4c7d-8e9f-0a1b2c3d4e5f"},
    )
    text = json.dumps(build_alert(message, static_labels={}))
    for leaked in ("alice", "192.0.2.7", "entity", "ab" * 32, "suppressed", "ValueError", "987654"):
        assert leaked not in text
    assert "row_uid=1c2d3e4f-5a6b-4c7d-8e9f-0a1b2c3d4e5f" in text


def test_include_entities_adds_an_annotation_never_a_label() -> None:
    alert = build_alert(notification(), static_labels={}, include_entities=True)
    assert alert["annotations"]["entity_keys"] == "user:alice.example, ip:192.0.2.7"
    assert "alice" not in json.dumps(alert["labels"])


def test_description_drops_values_that_are_not_ids() -> None:
    alert = build_alert(
        notification(rule="see https://evil.example/x", incident_uid="a b"), static_labels={}
    )
    description = alert["annotations"]["description"]
    assert "evil" not in description and "rule=" not in description
    assert "incident_uid" not in description


# --- settings ------------------------------------------------------------------------------------


def test_labels_json_is_parsed_and_validated(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TUISKU_NOTIFY_ALERTMANAGER_LABELS_JSON", '{"team":"sec","source":"tuisku"}')
    assert Settings().notify_alertmanager_labels_json == {"team": "sec", "source": "tuisku"}
    for bad in (
        "not json",
        '["a"]',
        '{"team": 1}',
        '{"bad-name": "x"}',
        '{"team": ""}',
        '{"alertname": "Other"}',
        '{"severity": "low"}',
        '{"source": "elsewhere"}',
    ):
        monkeypatch.setenv("TUISKU_NOTIFY_ALERTMANAGER_LABELS_JSON", bad)
        with pytest.raises(ValidationError):
            Settings()


def test_alertmanager_url_is_validated_and_never_echoed() -> None:
    for bad in (
        f"ftp://u:{SECRET}@am:9093",
        f"http://u:{SECRET}@am:9093/?token=x",
        f"http://u:{SECRET}@:9093",
    ):
        with pytest.raises(ValidationError) as excinfo:
            Settings(notify_alertmanager_url=bad)  # type: ignore[arg-type]
        assert SECRET not in str(excinfo.value)
    settings = Settings(notify_alertmanager_url=f"https://u:{SECRET}@am:9093/")  # type: ignore[arg-type]
    assert SECRET not in repr(settings) and SECRET not in str(settings.model_dump())
    assert Settings(notify_alertmanager_url="").notify_alertmanager_url is None  # type: ignore[arg-type]


def test_log_notifier_alone_is_the_default() -> None:
    settings = Settings()
    assert settings.notify_alertmanager_url is None
    assert settings.notify_alertmanager_include_entities is False
    assert type(build_notifier(settings)) is notify.LogNotifier


def test_worker_settings_pick_alertmanager_alongside_the_log() -> None:
    settings = Settings(
        notify_alertmanager_url=f"http://u:{SECRET}@am:9093",  # type: ignore[arg-type]
        notify_alertmanager_labels_json={"team": "sec"},
        notify_alertmanager_timeout_seconds=2.5,
    )
    built = build_notifier(settings)
    assert isinstance(built, notify.FanOutNotifier)
    log, am = built.notifiers
    assert type(log) is notify.LogNotifier
    assert isinstance(am, AlertmanagerNotifier)
    assert am.static_labels == {"team": "sec"} and am.timeout_seconds == 2.5
    assert am.include_entities is False
    assert SECRET not in repr(am)


# --- HTTP ----------------------------------------------------------------------------------------


def test_posts_one_alert_with_basic_auth_from_the_url(alertmanager: FakeAlertmanager) -> None:
    url = alertmanager.url.replace("http://", f"http://tuisku:{SECRET}@") + "/prefix/"
    AlertmanagerNotifier(SecretStr(url)).deliver(notification())
    [request] = alertmanager.requests
    assert request["path"] == "/prefix/api/v2/alerts"
    assert request["headers"]["Content-Type"] == "application/json"
    expected = base64.b64encode(f"tuisku:{SECRET}".encode()).decode()
    assert request["headers"]["Authorization"] == f"Basic {expected}"
    assert request["body"] == [build_alert(notification(), static_labels={})]


@pytest.mark.parametrize(
    ("status", "error"),
    [
        (500, AlertmanagerUnavailable),
        (503, AlertmanagerUnavailable),
        (429, AlertmanagerUnavailable),
        (400, AlertmanagerRejected),
        (302, AlertmanagerUnavailable),
    ],
)
def test_non_2xx_raises(alertmanager: FakeAlertmanager, status: int, error: type) -> None:
    alertmanager.status = status
    alertmanager.location = alertmanager.url + "/elsewhere"
    url = alertmanager.url.replace("http://", f"http://u:{SECRET}@")
    with pytest.raises(error) as excinfo:
        AlertmanagerNotifier(SecretStr(url)).deliver(notification())
    assert SECRET not in str(excinfo.value) and "127.0.0.1" not in str(excinfo.value)
    # Nothing chained: urllib's own errors carry the URL.
    assert excinfo.value.__cause__ is None and excinfo.value.__context__ is None
    assert [r["path"] for r in alertmanager.requests] == ["/api/v2/alerts"]  # no redirect


def test_timeout_raises(alertmanager: FakeAlertmanager) -> None:
    alertmanager.delay = 1.0
    with pytest.raises(AlertmanagerTimeout):
        notifier(alertmanager, timeout_seconds=0.2).deliver(notification())


def test_refused_connection_is_unavailable(alertmanager: FakeAlertmanager) -> None:
    gone = AlertmanagerNotifier(SecretStr("http://127.0.0.1:1"))
    with pytest.raises(AlertmanagerUnavailable):
        gone.deliver(notification())


# --- through the outbox --------------------------------------------------------------------------


def queue_notification(url: str, kind: str = "finding_opened") -> str:
    with psycopg.connect(url) as conn:
        row = conn.execute(
            "INSERT INTO notifications (dedupe_key, kind, severity_id, payload, created_at) "
            "VALUES (%s, %s, 4, %s, now()) RETURNING uid",
            (
                f"test:{uuid.uuid4()}",
                kind,
                json.dumps({"title": "Synthetic", "entity_keys": ["user:alice.example"]}),
            ),
        ).fetchone()
    assert row is not None
    return str(row[0])


def drain(url: str, notifier: notify.Notifier) -> int:
    return run_async(url, lambda conn: notify.drain(conn, notifier, NOW, backoff=NO_WAIT))


def outcomes(url: str) -> list[tuple[str, str, str | None]]:
    return [
        (str(uid), status, error)
        for uid, status, error in query(
            url,
            "SELECT n.uid, d.status, d.error FROM notification_deliveries d "
            "JOIN notifications n ON n.id = d.notification_id ORDER BY d.id",
        )
    ]


def test_drain_delivers_through_alertmanager(
    fresh_database_url: str, alertmanager: FakeAlertmanager
) -> None:
    uids = [queue_notification(fresh_database_url) for _ in range(3)]
    assert drain(fresh_database_url, notifier(alertmanager)) == 3
    assert len(alertmanager.requests) == 3  # one alert per request: exact accounting
    assert sorted(a["labels"]["notification_uid"] for a in alertmanager.alerts) == sorted(uids)
    assert sorted(outcomes(fresh_database_url)) == sorted((u, "delivered", None) for u in uids)
    assert "alice" not in json.dumps(alertmanager.alerts)
    assert drain(fresh_database_url, notifier(alertmanager)) == 0  # never twice


def test_a_500_is_a_failed_delivery_retried_until_it_pages_undeliverable(
    fresh_database_url: str, alertmanager: FakeAlertmanager
) -> None:
    uid = queue_notification(fresh_database_url)
    alertmanager.status = 500
    for _ in range(notify.ALERT_AFTER_FAILURES):
        assert drain(fresh_database_url, notifier(alertmanager)) == 0
    assert (
        outcomes(fresh_database_url)
        == [(uid, "failed", "AlertmanagerUnavailable")] * notify.ALERT_AFTER_FAILURES
    )
    assert query(
        fresh_database_url,
        "SELECT count(*) FROM detections WHERE kind = 'tuisku.meta.notification_undeliverable'",
    ) == [(1,)]
    alertmanager.status = 200
    assert drain(fresh_database_url, notifier(alertmanager)) >= 1  # the page about it, too
    assert (uid, "delivered", None) in outcomes(fresh_database_url)


def test_a_timeout_is_a_failed_delivery_and_ends_the_pass(
    fresh_database_url: str, alertmanager: FakeAlertmanager
) -> None:
    first, second = queue_notification(fresh_database_url), queue_notification(fresh_database_url)
    alertmanager.delay = 1.0
    assert drain(fresh_database_url, notifier(alertmanager, timeout_seconds=0.2)) == 0
    # One timeout per pass, not one per due notification; the other waits, untouched.
    [(uid, status, error)] = outcomes(fresh_database_url)
    assert (status, error) == ("failed", "AlertmanagerTimeout") and uid in (first, second)
    alertmanager.delay = 0
    assert drain(fresh_database_url, notifier(alertmanager)) == 2


def test_a_rejected_alert_does_not_hold_back_the_others(
    fresh_database_url: str, alertmanager: FakeAlertmanager
) -> None:
    for _ in range(2):
        queue_notification(fresh_database_url)
    alertmanager.status = 400
    assert drain(fresh_database_url, notifier(alertmanager)) == 0
    assert [(s, e) for _, s, e in outcomes(fresh_database_url)] == [
        ("failed", "AlertmanagerRejected")
    ] * 2


def test_a_slow_alertmanager_does_not_block_the_event_loop(
    fresh_database_url: str, alertmanager: FakeAlertmanager
) -> None:
    queue_notification(fresh_database_url)
    alertmanager.delay = 0.5

    async def work(conn: psycopg.AsyncConnection[Any]) -> int:
        ticks = 0

        async def ticker() -> None:
            nonlocal ticks
            while True:
                await asyncio.sleep(0.02)
                ticks += 1

        task = asyncio.create_task(ticker())
        try:
            await notify.drain(conn, notifier(alertmanager), NOW, backoff=NO_WAIT)
        finally:
            task.cancel()
        return ticks

    assert run_async(fresh_database_url, work) >= 10


def test_worker_from_settings_pages_alertmanager_and_still_logs(
    fresh_database_url: str, alertmanager: FakeAlertmanager, caplog: pytest.LogCaptureFixture
) -> None:
    uid = queue_notification(fresh_database_url)
    settings = make_settings(
        fresh_database_url,
        builtin_packs_dir=str(REPO_ROOT / "packs"),
        notify_alertmanager_url=alertmanager.url,
        notify_alertmanager_labels_json='{"team": "sec"}',
    )
    with caplog.at_level(logging.WARNING, logger="tuisku.notify"):
        assert run_worker(settings, once=True) == 0
    [alert] = [a for a in alertmanager.alerts if a["labels"]["notification_uid"] == uid]
    assert alert["labels"]["team"] == "sec" and alert["labels"]["source"] == "tuisku"
    assert any(uid in r.getMessage() for r in caplog.records if r.name == "tuisku.notify")
    assert (uid, "delivered", None) in outcomes(fresh_database_url)


def test_pages_about_tuisku_itself_are_labelled_meta(
    fresh_database_url: str, alertmanager: FakeAlertmanager
) -> None:
    meta_uid = queue_notification(fresh_database_url, kind="tuisku_backlog")  # the db marks it
    rule_uid = queue_notification(fresh_database_url)
    assert drain(fresh_database_url, notifier(alertmanager)) == 2
    labels = {a["labels"]["notification_uid"]: a["labels"]["meta"] for a in alertmanager.alerts}
    assert labels == {meta_uid: "true", rule_uid: "false"}
