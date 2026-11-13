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
``entity_keys`` annotation (never as labels).

Delivery runs in a thread (``notify.drain`` uses ``asyncio.to_thread``) with a socket timeout.
A 2xx is delivered. A 4xx other than 408 and 429 refuses this one alert
(:class:`AlertmanagerRejected`). Anything else, a timeout or a connection error means the
channel is down (:class:`AlertmanagerUnavailable`, a ``NotifierUnavailable``): the drain records
the failure and leaves the rest of its batch for the next pass. Redirects are not followed.
The URL may carry credentials; it is never logged or put in an error, and ``user:password`` in
it is sent as HTTP basic auth.
"""

from __future__ import annotations

import base64
import http.client
import json
import re
import urllib.error
import urllib.request
from collections.abc import Mapping
from typing import Any
from urllib.parse import unquote, urlsplit, urlunsplit

from pydantic import SecretStr

from tuisku.config import ALERTMANAGER_SOURCE
from tuisku.worker.notify import NotifierUnavailable

ALERTNAME = "TuiskuNotification"
ALERTS_PATH = "/api/v2/alerts"
MAX_RESPONSE_BYTES = 64 * 1024
MAX_SUMMARY_CHARS = 1024
MAX_ENTITY_KEYS = 32

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
    """Alertmanager refused this alert (a 4xx other than 408 or 429)."""


class AlertmanagerUnavailable(NotifierUnavailable):
    """Alertmanager could not be reached, or answered with something other than 2xx or 4xx."""


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
            annotations["entity_keys"] = ", ".join(str(k) for k in keys[:MAX_ENTITY_KEYS])
    return {
        "labels": labels,
        "annotations": annotations,
        "startsAt": str(notification["created_at"]),
    }


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args: Any, **kwargs: Any) -> None:
        return None  # a 3xx surfaces as an HTTPError: never re-sent elsewhere, never as a GET


def _endpoint(base_url: str) -> tuple[str, dict[str, str]]:
    """The alerts URL without credentials, and the basic-auth header for any in the URL."""
    parts = urlsplit(base_url)
    headers: dict[str, str] = {}
    if parts.username is not None:
        userpass = f"{unquote(parts.username)}:{unquote(parts.password or '')}"
        headers["Authorization"] = "Basic " + base64.b64encode(userpass.encode()).decode()
    netloc = parts.hostname or ""
    if ":" in netloc:
        netloc = f"[{netloc}]"  # IPv6 literal
    if parts.port is not None:
        netloc += f":{parts.port}"
    path = parts.path.rstrip("/") + ALERTS_PATH
    return urlunsplit((parts.scheme, netloc, path, "", "")), headers


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
        self._url, self._headers = _endpoint(url.get_secret_value())
        self.static_labels = dict(static_labels or {})
        self.include_entities = include_entities
        self.timeout_seconds = timeout_seconds
        self._opener = urllib.request.build_opener(_NoRedirect)

    def __repr__(self) -> str:  # never the URL
        return f"AlertmanagerNotifier(static_labels={self.static_labels!r})"

    def deliver(self, notification: dict[str, Any]) -> None:
        alert = build_alert(
            notification, static_labels=self.static_labels, include_entities=self.include_entities
        )
        self.post([alert])

    def post(self, alerts: list[dict[str, Any]]) -> None:
        body = json.dumps(alerts, separators=(",", ":"), sort_keys=True).encode()
        request = urllib.request.Request(
            self._url,
            data=body,
            method="POST",
            headers={"Content-Type": "application/json", **self._headers},
        )
        # Errors are re-raised `from None` with a status only: the originals carry the URL.
        try:
            with self._opener.open(request, timeout=self.timeout_seconds) as response:
                response.read(MAX_RESPONSE_BYTES)
                status = response.status
        except urllib.error.HTTPError as exc:
            status = exc.code
            exc.close()
        except TimeoutError:
            raise AlertmanagerTimeout("timed out") from None
        except urllib.error.URLError as exc:
            if isinstance(exc.reason, TimeoutError):
                raise AlertmanagerTimeout("timed out") from None
            raise AlertmanagerUnavailable(type(exc.reason).__name__) from None
        except (OSError, http.client.HTTPException) as exc:
            raise AlertmanagerUnavailable(type(exc).__name__) from None
        if 200 <= status < 300:
            return
        if 400 <= status < 500 and status not in (408, 429):
            raise AlertmanagerRejected(f"HTTP {status}")
        raise AlertmanagerUnavailable(f"HTTP {status}")
