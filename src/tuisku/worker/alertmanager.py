"""Alertmanager notifier (ADR 0007 "Notifications").

Each notification is POSTed as one alert to ``<base URL>/api/v2/alerts`` (the Alertmanager v2
API takes a JSON array of alerts). One alert per request keeps the outbox accounting exact:
each notification gets its own ``delivered`` or ``failed`` row.

The alert:

- **labels**: ``alertname="TuiskuNotification"``, ``source="tuisku"``, ``tuisku_kind`` (the
  notification kind), ``severity`` (see :data:`SEVERITY`), ``notification_uid``, ``meta``
  (``"true"`` for pages about Tuisku itself) and the deployment's static labels. The
  notification uid makes every alert distinct, so Alertmanager never merges two pages.
- **annotations**: ``summary`` is the rule's or meta-detection's title (pack-authored or fixed
  text, never telemetry), and ``description`` lists ids only (``key=value``, each value checked
  against a strict id pattern), with no links.
- **startsAt** is the notification's ``created_at``. ``endsAt`` is not set: a page is an event,
  not a condition Tuisku could resolve, so Alertmanager resolves it after its own
  ``resolve_timeout``. No ``generatorURL``.

No entity keys or telemetry values are sent, because the receiver may be an external service.
``TUISKU_NOTIFY_ALERTMANAGER_INCLUDE_ENTITIES=true`` adds the entity keys as an
``entity_keys`` annotation (never as labels): a JSON array of at most 32 keys, each without
control characters and cut to 256 characters. They are still untrusted text.

Delivery runs in a thread (``notify.drain`` uses ``asyncio.to_thread``) through
``http.client``, under a total deadline: a watchdog shuts the socket down when the timeout is
spent, so a server that answers slowly, byte by byte, is cut off too. A 2xx is delivered. A 400
or 422 refuses this one alert (:class:`AlertmanagerRejected`). Anything else (a 3xx, since
redirects are not followed; 401, 403, 404, 405, 408, 413, 429; a 5xx), a timeout or a
connection error means the channel is down for every alert (:class:`AlertmanagerUnavailable`, a
``NotifierUnavailable``): the drain records the failure and leaves the rest of its batch for the
next pass. No environment proxy is used. The URL may carry credentials, only with https; it is
never logged or put in an error, and ``user:password`` in it is sent as HTTP basic auth.
"""

from __future__ import annotations

import base64
import http.client
import json
import re
import socket
import threading
import unicodedata
from collections.abc import Mapping
from typing import Any
from urllib.parse import unquote, urlsplit

from pydantic import SecretStr

from tuisku.config import ALERTMANAGER_SOURCE, check_alertmanager_url
from tuisku.worker.notify import NotifierUnavailable

ALERTNAME = "TuiskuNotification"
ALERTS_PATH = "/api/v2/alerts"
MAX_SUMMARY_CHARS = 1024
MAX_ENTITY_KEYS = 32
MAX_ENTITY_KEY_CHARS = 256
# Statuses that refuse one alert; every other non-2xx is the channel failing for all of them.
REJECTS = frozenset({400, 422})
# A test swaps the https class for a plain one to see the basic-auth header on the wire.
_CONNECTIONS: dict[str, type[http.client.HTTPConnection]] = {
    "http": http.client.HTTPConnection,
    "https": http.client.HTTPSConnection,
}

# OCSF severity_id -> the ``severity`` label: the OCSF caption, lowercased. Unmapped values
# (and 0) are "unknown".
SEVERITY: Mapping[int, str] = {
    0: "unknown",
    1: "informational",
    2: "low",
    3: "medium",
    4: "high",
    5: "critical",
    6: "fatal",
    99: "other",
}

# Payload fields that hold ids, in the order the description lists them. Anything else in a
# payload (titles, entity keys, counts, group hashes, reasons, errors) stays out.
ID_FIELDS = ("finding_uid", "incident_uid", "previous_incident_uid", "detection_uid", "rule")
_ID_VALUE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:@-]{0,199}$")


class AlertmanagerRejected(Exception):
    """Alertmanager refused this alert (400 or 422)."""


class AlertmanagerUnavailable(NotifierUnavailable):
    """Alertmanager could not be reached, or answered with a status that fails every alert."""


class AlertmanagerTimeout(AlertmanagerUnavailable):
    """The request timed out."""


def severity_label(severity_id: Any) -> str:
    return SEVERITY.get(severity_id, "unknown") if isinstance(severity_id, int) else "unknown"


def _ids(notification: Mapping[str, Any]) -> list[tuple[str, str]]:
    pairs: list[tuple[str, Any]] = [(k, notification.get(k)) for k in ID_FIELDS]
    row = notification.get("row")
    if isinstance(row, Mapping):
        pairs += [("row_layer", row.get("layer")), ("row_uid", row.get("uid"))]
    return [(k, v) for k, v in pairs if isinstance(v, str) and _ID_VALUE.fullmatch(v)]


def _entity_keys(keys: list[Any]) -> str:
    """A JSON array: at most MAX_ENTITY_KEYS keys, control and format characters removed, each
    cut to MAX_ENTITY_KEY_CHARS."""
    clean = [
        "".join(c for c in str(k) if unicodedata.category(c) not in ("Cc", "Cf"))
        for k in keys[:MAX_ENTITY_KEYS]
    ]
    return json.dumps([k[:MAX_ENTITY_KEY_CHARS] for k in clean], ensure_ascii=False)


def build_alert(
    notification: Mapping[str, Any],
    *,
    static_labels: Mapping[str, str],
    include_entities: bool = False,
) -> dict[str, Any]:
    """The Alertmanager v2 alert for one notification (a message as ``notify.drain`` builds
    it: uid, kind, severity_id, created_at, meta, then the payload)."""
    uid = str(notification["uid"])
    kind = str(notification["kind"])
    severity_id = notification.get("severity_id")
    labels = {
        **static_labels,
        "alertname": ALERTNAME,
        "source": ALERTMANAGER_SOURCE,
        "tuisku_kind": kind,
        "severity": severity_label(severity_id),
        "notification_uid": uid,
        "meta": "true" if notification.get("meta") else "false",
    }
    title = notification.get("title")
    summary = title if isinstance(title, str) and title else f"Tuisku notification: {kind}"
    ids = [("kind", kind), ("notification_uid", uid), ("severity_id", str(severity_id))]
    annotations = {
        "summary": summary[:MAX_SUMMARY_CHARS],
        "description": " ".join(f"{k}={v}" for k, v in [*ids, *_ids(notification)]),
    }
    if include_entities:
        keys = notification.get("entity_keys")
        if isinstance(keys, list) and keys:
            annotations["entity_keys"] = _entity_keys(keys)
    return {
        "labels": labels,
        "annotations": annotations,
        "startsAt": str(notification["created_at"]),
    }


def _endpoint(base_url: str) -> tuple[str, str, int | None, str, dict[str, str]]:
    """(scheme, host, port, alerts path, headers): the basic-auth header for credentials in the
    URL, which only https may carry."""
    check_alertmanager_url(base_url)
    parts = urlsplit(base_url)
    headers = {"Content-Type": "application/json"}
    if parts.username is not None:
        userpass = f"{unquote(parts.username)}:{unquote(parts.password or '')}"
        headers["Authorization"] = "Basic " + base64.b64encode(userpass.encode()).decode()
    path = parts.path.rstrip("/") + ALERTS_PATH
    return parts.scheme, parts.hostname or "", parts.port, path, headers


class AlertmanagerNotifier:
    """POSTs each notification to Alertmanager as one alert. Blocking: ``notify.drain`` calls
    it off the event loop."""

    def __init__(
        self,
        url: SecretStr,
        *,
        static_labels: Mapping[str, str] | None = None,
        include_entities: bool = False,
        timeout_seconds: float = 5.0,
    ) -> None:
        self._scheme, self._host, self._port, self._path, self._headers = _endpoint(
            url.get_secret_value()
        )
        self.static_labels = dict(static_labels or {})
        self.include_entities = include_entities
        self.timeout_seconds = timeout_seconds

    def __repr__(self) -> str:  # never the URL
        return f"AlertmanagerNotifier(static_labels={self.static_labels!r})"

    def deliver(self, notification: dict[str, Any]) -> None:
        alert = build_alert(
            notification, static_labels=self.static_labels, include_entities=self.include_entities
        )
        self.post([alert])

    def post(self, alerts: list[dict[str, Any]]) -> None:
        body = json.dumps(alerts, separators=(",", ":"), sort_keys=True).encode()
        # http.client, not urllib: no redirects, no environment proxies, and the socket is in
        # reach of the watchdog that enforces the total deadline.
        port = self._port or (443 if self._scheme == "https" else 80)
        conn = _CONNECTIONS[self._scheme](self._host, port, timeout=self.timeout_seconds)
        expired = threading.Event()

        def cut() -> None:
            expired.set()
            sock = conn.sock  # during a TLS handshake, the plain socket under it
            if sock is not None:
                try:
                    sock.shutdown(socket.SHUT_RDWR)  # wakes a blocked connect, send or recv
                except OSError:
                    pass

        watchdog = threading.Timer(self.timeout_seconds, cut)
        watchdog.daemon = True
        status: int | None = None
        failure: str | None = None
        watchdog.start()
        try:
            conn.connect()  # bounded by the socket timeout, which equals the total
            if expired.is_set():
                raise TimeoutError
            conn.request("POST", self._path, body=body, headers=self._headers)
            response = conn.getresponse()
            status = response.status
            response.close()  # the body is not needed, and could be slow
        except (OSError, http.client.HTTPException) as exc:
            # Raised below, outside this block, so nothing is chained: the originals can
            # carry the address.
            failure = "timeout" if isinstance(exc, TimeoutError) else type(exc).__name__
        finally:
            watchdog.cancel()
            conn.close()
        # Once the watchdog has fired, nothing read counts: a shut-down socket reads as end of
        # input, which can look like a complete response.
        if failure == "timeout" or expired.is_set():
            raise AlertmanagerTimeout("timed out")
        if failure is not None or status is None:
            raise AlertmanagerUnavailable(failure or "no response")
        if 200 <= status < 300:
            return
        if status in REJECTS:
            raise AlertmanagerRejected(f"HTTP {status}")
        raise AlertmanagerUnavailable(f"HTTP {status}")
