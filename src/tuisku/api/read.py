"""Evidence read endpoints for operator tokens with the ``read`` role (ADR 0005)."""

from __future__ import annotations

import base64
from datetime import datetime
from typing import Annotated, Any
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, Request

from tuisku.api.deps import get_pool, require_role
from tuisku.store import read
from tuisku.store.admin import OperatorCredential
from tuisku.store.tokens import Role

router = APIRouter()
Reader = Annotated[OperatorCredential, Depends(require_role(Role.READ))]


def _filters(
    kind: str | None = None,
    source: str | None = None,
    entity_key: str | None = None,
    since: datetime | None = None,
    until: datetime | None = None,
    before: Annotated[int | None, Query(ge=1)] = None,
    limit: Annotated[int, Query(ge=1, le=read.MAX_LIMIT)] = 100,
    all_attempts: bool = False,
) -> read.Filters:
    return read.Filters(
        kind=kind,
        source=source,
        entity_key=entity_key,
        since=since,
        until=until,
        before=before,
        limit=limit,
        all_attempts=all_attempts,
    )


Filters = Annotated[read.Filters, Depends(_filters)]


@router.get("/v1/observations")
async def list_observations(request: Request, _: Reader, filters: Filters) -> dict[str, Any]:
    async with get_pool(request).connection() as conn:
        items, next_before = await read.list_observations(conn, filters)
    return {"items": items, "next_before": next_before}


@router.get("/v1/detections")
async def list_detections(request: Request, _: Reader, filters: Filters) -> dict[str, Any]:
    async with get_pool(request).connection() as conn:
        items, next_before = await read.list_detections(conn, filters)
    return {"items": items, "next_before": next_before}


@router.get("/v1/raw/{uid}")
async def get_raw(uid: UUID, request: Request, _: Reader) -> dict[str, Any]:
    async with get_pool(request).connection() as conn:
        row = await read.get_raw_record(conn, uid)
    if row is None:
        raise HTTPException(status_code=404, detail="no such raw record")
    body: bytes | None = row.pop("body")
    row["sha256"] = row["sha256"].hex()
    # NULL once retention has cleared it; the hash and size remain.
    row["body_base64"] = None if body is None else base64.b64encode(body).decode("ascii")
    return row
