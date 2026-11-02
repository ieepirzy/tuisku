"""Helpers for worker tests: feed records through the real adapters, run the worker."""

from __future__ import annotations

import asyncio
import json
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

from psycopg import AsyncConnection

from tests.conftest import REPO_ROOT
from tuisku.adapters import builtin as _builtin  # noqa: F401  (registers adapters)
from tuisku.rules.packs import RuleSet, load_rule_set
from tuisku.store import admin
from tuisku.store.ingest import IngestContext, Transport, ingest_record
from tuisku.worker.engine import Stats, Worker, WorkerConfig

PACKS = REPO_ROOT / "packs"


def builtin_rules(params_file: Path | None = None) -> RuleSet:
    return load_rule_set([], params_file, builtin=[PACKS])


class Clock:
    """A settable clock for the worker and for ingest."""

    def __init__(self, now: datetime) -> None:
        self.now = now

    def __call__(self) -> datetime:
        return self.now

    def advance(self, **kw: float) -> datetime:
        self.now += timedelta(**kw)
        return self.now


@dataclass
class RecordingNotifier:
    sent: list[dict[str, Any]] = field(default_factory=list)

    def deliver(self, notification: dict[str, Any]) -> None:
        self.sent.append(notification)

    def kinds(self) -> list[str]:
        return [n["kind"] for n in self.sent]


def run_async[T](url: str, work: Callable[[AsyncConnection[Any]], Any]) -> T:
    async def go() -> T:
        conn = await AsyncConnection.connect(url, autocommit=True)
        async with conn:
            return await work(conn)

    return asyncio.run(go())


def ingest(
    url: str,
    source: str,
    adapter: str,
    records: Sequence[tuple[datetime, bytes, Transport]],
    options: Mapping[str, Any] | None = None,
) -> list[str]:
    """Create ``source`` if needed and ingest each record at its own received_at."""

    async def work(conn: AsyncConnection[Any]) -> list[str]:
        async with conn.transaction():
            existing = await conn.execute("SELECT 1 FROM sources WHERE name = %s", (source,))
            if await existing.fetchone() is None:
                await admin.create_source(conn, source, adapter, options or {})
            issued = await admin.add_source_token(conn, source)
            credential = await admin.authenticate_source_token(conn, issued.token)
        assert credential is not None
        out: list[str] = []
        for at, body, transport in records:
            async with conn.transaction():
                outcome = await ingest_record(
                    conn,
                    credential,
                    body=body,
                    collector={},
                    transport=transport,
                    ctx=IngestContext(received_at=at, clock_skew_tolerance=timedelta(minutes=5)),
                )
            out.append(f"{outcome.status}/{outcome.parse}")
        return out

    return run_async(url, work)


def log_lines(at: datetime, *lines: str) -> list[tuple[datetime, bytes, Transport]]:
    return [(at, line.encode(), Transport.NDJSON) for line in lines]


def _nanos(t: datetime) -> str:
    return str(int(t.timestamp()) * 1_000_000_000 + t.microsecond * 1000)


def otlp_sum(
    metric: str,
    value: int,
    *,
    time: datetime,
    start: datetime | None,
    labels: Mapping[str, str] | None = None,
    resource: Mapping[str, str] | None = None,
    temporality: int = 2,
) -> bytes:
    """One cumulative-sum datapoint as an OTLP/JSON ExportMetricsServiceRequest."""
    attrs = [{"key": k, "value": {"stringValue": v}} for k, v in (labels or {}).items()]
    res = [
        {"key": k, "value": {"stringValue": v}}
        for k, v in (resource or {"service.name": "harava"}).items()
    ]
    point: dict[str, Any] = {"attributes": attrs, "timeUnixNano": _nanos(time), "asInt": str(value)}
    if start is not None:
        point["startTimeUnixNano"] = _nanos(start)
    body = {
        "resourceMetrics": [
            {
                "resource": {"attributes": res},
                "scopeMetrics": [
                    {
                        "scope": {"name": "harava"},
                        "metrics": [
                            {
                                "name": metric,
                                "unit": "1",
                                "sum": {
                                    "aggregationTemporality": temporality,
                                    "isMonotonic": True,
                                    "dataPoints": [point],
                                },
                            }
                        ],
                    }
                ],
            }
        ]
    }
    return json.dumps(body).encode()


def run_worker(
    url: str,
    rule_set: RuleSet,
    clock: Callable[[], datetime],
    notifier: RecordingNotifier | None = None,
    *,
    record_packs: bool = False,
    before_pair: Callable[[Any, Any], None] | None = None,
    **config: Any,
) -> Stats:
    worker = Worker(
        rule_set=rule_set,
        clock=clock,
        notifier=notifier if notifier is not None else RecordingNotifier(),
        config=WorkerConfig(**config),
        before_pair=before_pair,
    )

    async def work(conn: AsyncConnection[Any]) -> Stats:
        if record_packs:
            await worker.record_pack_loads(conn)
        return await worker.run_until_idle(conn)

    return run_async(url, work)


def fired(url: str) -> list[str]:
    """Kinds of every rule detection written (evaluator tuisku, not meta), sorted."""
    from tests.support import query

    rows = query(
        url,
        "SELECT kind FROM detections WHERE evaluator = 'tuisku' "
        "AND kind NOT LIKE 'tuisku.meta.%' ORDER BY kind",
    )
    return [r[0] for r in rows]
