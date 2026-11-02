"""Test helpers: a dummy adapter, source/token setup, and NDJSON builders."""

from __future__ import annotations

import asyncio
import json
import time
from collections.abc import Awaitable, Callable, Mapping
from datetime import UTC, datetime
from typing import Any

import psycopg
from fastapi.testclient import TestClient
from psycopg import AsyncConnection

from tests.conftest import make_settings
from tuisku.adapters import (
    AdapterError,
    Authorship,
    DetectionDraft,
    LimitExceeded,
    ObservationDraft,
    ParseResult,
    RawRecord,
    Severity,
    registry,
)
from tuisku.adapters.jsonsafe import loads_object
from tuisku.adapters.timeparse import parse_timestamp_or_none
from tuisku.api.app import create_app
from tuisku.store import admin
from tuisku.store.tokens import Role

T0 = datetime(2026, 11, 1, 12, 0, 0, tzinfo=UTC)


class DummyAdapter:
    """Parses ``{"kind": ..., "time": ..., "ip": ..., "detect": bool, "fail": bool, ...}``."""

    name = "dummy"
    version = "0.1.0"

    def parse(self, raw: RawRecord, options: Mapping[str, Any]) -> ParseResult:
        obj = loads_object(raw.text())
        if obj.get("fail"):
            raise AdapterError("dummy refuses this record")
        if obj.get("crash"):
            raise KeyError(obj["crash"])  # message would echo input: must not be stored
        if "limit" in obj:
            raise LimitExceeded(obj["limit"])
        if "sleep" in obj:
            time.sleep(obj["sleep"])  # a slow parse, for the request time budget
        attributes: dict[str, Any] = {"message": obj.get("msg", "")}
        if "thread" in obj:
            try:
                asyncio.get_running_loop()
                attributes["on_event_loop"] = True
            except RuntimeError:
                attributes["on_event_loop"] = False
        entity_keys = (f"ip:{obj['ip']}",) if "ip" in obj else ()
        obs = ObservationDraft(
            kind=obj.get("kind", "dummy.event"),
            event_time=parse_timestamp_or_none(obj.get("time")),
            attributes=attributes,
            entity_keys=entity_keys,
            correlation=(
                {"dummy.flow_id": "42", "dummy.fuid": ("Fa1", "Fb2")} if obj.get("flow") else {}
            ),
            flags=tuple(obj.get("flags", ())),
        )
        detections: tuple[DetectionDraft, ...] = ()
        if obj.get("detect"):
            detections = (
                DetectionDraft(
                    kind="dummy.alert",
                    authorship=Authorship.COMMUNITY,
                    identity="dummy:1",
                    title="dummy alert",
                    severity=Severity.HIGH,
                    event_time=obs.event_time,
                    rule_ref={"engine": "dummy", "id": 1},
                    entity_keys=entity_keys,
                    observation_refs=(0,),
                ),
            )
        return ParseResult(observations=(obs,), detections=detections)


DUMMY = registry.register(DummyAdapter())


def run[T](url: str, work: Callable[[AsyncConnection[Any]], Awaitable[T]]) -> T:
    async def go() -> T:
        conn = await AsyncConnection.connect(url)
        async with conn:
            return await work(conn)

    return asyncio.run(go())


def new_source(url: str, name: str, adapter: str = "dummy", **token_kw: Any) -> str:
    """Create a source with one token; return the token."""

    async def work(conn: AsyncConnection[Any]) -> str:
        await admin.create_source(conn, name, adapter)
        return (await admin.add_source_token(conn, name, **token_kw)).token

    return run(url, work)


def operator_token(url: str, *roles: Role, person: str | None = None) -> str:
    return run(
        url,
        lambda conn: admin.create_operator_token(conn, name="test", roles=roles, person=person),
    ).token


def ndjson(*records: Any, collector: Any = None) -> bytes:
    """Each record: a dict (serialized into ``raw``) or a str used verbatim as ``raw``."""
    lines = []
    for record in records:
        raw = record if isinstance(record, str) else json.dumps(record)
        envelope: dict[str, Any] = {"raw": raw}
        if collector is not None:
            envelope["collector"] = collector
        lines.append(json.dumps(envelope))
    return ("\n".join(lines) + "\n").encode()


def auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


NDJSON_HEADERS = {"Content-Type": "application/x-ndjson"}


def client(url: str, clock: Callable[[], datetime] = lambda: T0, **settings: Any) -> TestClient:
    return TestClient(create_app(make_settings(url, **settings), clock=clock))


def post_records(c: TestClient, source: str, token: str, body: bytes, **headers: str) -> Any:
    return c.post(
        f"/v1/sources/{source}/records",
        content=body,
        headers=NDJSON_HEADERS | auth(token) | headers,
    )


def query(url: str, statement: str, params: Any = None) -> list[tuple[Any, ...]]:
    with psycopg.connect(url) as conn:
        return conn.execute(statement, params).fetchall()  # type: ignore[arg-type]
