"""Findings and incidents: read (role ``read``) and triage (role ``triage``) (ADR 0007).

Every change writes an event row whose actor is ``operator:<token uid>``, set by the server
from the authenticated token, never from the request body.
"""

from __future__ import annotations

from datetime import datetime
from typing import Annotated, Any, Literal
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, ConfigDict, Field

from tuisku.api.deps import get_clock, get_pool, require_role
from tuisku.store import lifecycle, triage
from tuisku.store.admin import OperatorCredential
from tuisku.store.tokens import Role

router = APIRouter()
Reader = Annotated[OperatorCredential, Depends(require_role(Role.READ))]
Triager = Annotated[OperatorCredential, Depends(require_role(Role.TRIAGE))]
Limit = Annotated[int, Query(ge=1, le=triage.MAX_LIMIT)]
Before = Annotated[int | None, Query(ge=1)]


class IncidentStatus(BaseModel):
    model_config = ConfigDict(extra="forbid")
    status: Literal["open", "triaged", "investigating", "contained", "resolved", "closed"]
    disposition: (
        Literal[
            "true_positive", "benign_true_positive", "false_positive", "duplicate", "inconclusive"
        ]
        | None
    ) = None
    reason: str | None = Field(default=None, max_length=1000)


class FindingStatus(BaseModel):
    model_config = ConfigDict(extra="forbid")
    status: Literal["open", "acknowledged", "resolved", "suppressed"]
    reason: str | None = Field(default=None, max_length=1000)
    suppressed_until: datetime | None = None


@router.get("/v1/findings")
async def list_findings(
    request: Request,
    _: Reader,
    status: str | None = None,
    rule_id: UUID | None = None,
    entity_key: str | None = None,
    before: Before = None,
    limit: Limit = 100,
) -> dict[str, Any]:
    async with get_pool(request).connection() as conn:
        items, nxt = await triage.list_findings(
            conn,
            status=status,
            rule_id=rule_id,
            entity_key=entity_key,
            before=before,
            limit=limit,
        )
    return {"items": items, "next_before": nxt}


@router.get("/v1/incidents")
async def list_incidents(
    request: Request,
    _: Reader,
    status: str | None = None,
    entity_key: str | None = None,
    before: Before = None,
    limit: Limit = 100,
) -> dict[str, Any]:
    async with get_pool(request).connection() as conn:
        items, nxt = await triage.list_incidents(
            conn, status=status, entity_key=entity_key, before=before, limit=limit
        )
    return {"items": items, "next_before": nxt}


@router.get("/v1/incidents/{uid}")
async def get_incident(uid: UUID, request: Request, _: Reader) -> dict[str, Any]:
    async with get_pool(request).connection() as conn:
        incident = await triage.get_incident(conn, uid)
    if incident is None:
        raise HTTPException(status_code=404, detail="no such incident")
    return incident


@router.post("/v1/incidents/{uid}/status")
async def set_incident_status(
    uid: UUID, body: IncidentStatus, request: Request, operator: Triager
) -> dict[str, Any]:
    now = get_clock(request)()
    try:
        async with get_pool(request).connection() as conn, conn.transaction():
            incident = await lifecycle.operator_incident_status(
                conn,
                uid,
                body.status,
                actor=lifecycle.operator_actor(operator.token_uid),
                disposition=body.disposition,
                reason=body.reason,
                now=now,
            )
    except lifecycle.TransitionError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from None
    if incident is None:
        raise HTTPException(status_code=404, detail="no such incident")
    return {"uid": str(incident["uid"]), "status": incident["status"]}


@router.post("/v1/findings/{uid}/status")
async def set_finding_status(
    uid: UUID, body: FindingStatus, request: Request, operator: Triager
) -> dict[str, Any]:
    now = get_clock(request)()
    try:
        async with get_pool(request).connection() as conn, conn.transaction():
            finding = await lifecycle.operator_finding_status(
                conn,
                uid,
                body.status,
                actor=lifecycle.operator_actor(operator.token_uid),
                reason=body.reason,
                suppressed_until=body.suppressed_until,
                now=now,
            )
    except lifecycle.TransitionError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from None
    if finding is None:
        raise HTTPException(status_code=404, detail="no such finding")
    return {"uid": str(finding["uid"]), "status": finding["status"]}
