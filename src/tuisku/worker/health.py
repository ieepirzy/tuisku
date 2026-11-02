"""The worker's own health signals (ADR 0011 "Availability limits").

A compromised API process shares the database with the worker, so a health view served by the
API, or read from a table, could be faked. These come from the worker process itself:

- ``serve``: a minimal, unauthenticated HTTP listener (``tuisku worker --health-port``). Any
  ``GET`` answers ``200 {"status": "ok"}`` while the last healthy pass ended within
  ``stale_seconds``, and ``503 {"status": "unhealthy"}`` otherwise. Status only: no backlog
  figures, which stay behind the ``read`` role on the API.
- ``ping``: an optional dead-man's-switch URL (``TUISKU_WORKER_DEADMAN_URL``), called after each
  healthy pass, so an outside monitor notices when the calls stop.
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
import urllib.request
from collections.abc import Callable

log = logging.getLogger(__name__)
READ_TIMEOUT_SECONDS = 5.0
MAX_REQUEST_BYTES = 8192


def is_healthy(healthy_at: float | None, stale_seconds: float, now: float | None = None) -> bool:
    if healthy_at is None:
        return False
    return (time.monotonic() if now is None else now) - healthy_at <= stale_seconds


def response(healthy: bool) -> bytes:
    body = json.dumps({"status": "ok" if healthy else "unhealthy"}).encode()
    status = "200 OK" if healthy else "503 Service Unavailable"
    head = (
        f"HTTP/1.1 {status}\r\nContent-Type: application/json\r\n"
        f"Content-Length: {len(body)}\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n"
    )
    return head.encode() + body


async def serve(
    healthy_at: Callable[[], float | None], stale_seconds: float, host: str, port: int
) -> asyncio.Server:
    """Start the listener; it runs until the returned server is closed."""

    async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            # Read (and ignore) the request head, bounded in size and time.
            await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), READ_TIMEOUT_SECONDS)
            writer.write(response(is_healthy(healthy_at(), stale_seconds)))
            await writer.drain()
        except (TimeoutError, asyncio.IncompleteReadError, asyncio.LimitOverrunError):
            pass
        except OSError:
            pass
        finally:
            writer.close()

    return await asyncio.start_server(handle, host, port, limit=MAX_REQUEST_BYTES)


def _get(url: str) -> None:
    with urllib.request.urlopen(url, timeout=READ_TIMEOUT_SECONDS) as r:  # noqa: S310
        r.read(1024)


async def ping(url: str) -> None:
    """Call the dead-man's-switch URL; a failure is logged (never the URL, which may carry a
    secret) and never stops the worker."""
    try:
        await asyncio.to_thread(_get, url)
    except Exception as exc:  # the monitor notices the missing call
        log.warning("dead-man's-switch call failed: %s", type(exc).__name__)
