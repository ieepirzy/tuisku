"""Request dependencies: the clock, and source / operator token authentication."""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from datetime import UTC, datetime

from fastapi import HTTPException, Request
from psycopg_pool import AsyncConnectionPool

from tuisku.store import admin
from tuisku.store.tokens import Role, has_role

Clock = Callable[[], datetime]


def system_clock() -> datetime:
    return datetime.now(UTC)


def get_clock(request: Request) -> Clock:
    """The clock that sets received_at. Tests and replay inject their own (ADR 0004 s6)."""
    return request.app.state.clock


def get_pool(request: Request) -> AsyncConnectionPool:
    return request.app.state.pool


def unauthorized() -> HTTPException:
    # One answer for every failure, so responses never reveal which sources or tokens exist.
    return HTTPException(
        status_code=401, detail="invalid credentials", headers={"WWW-Authenticate": "Bearer"}
    )


def bearer_token(request: Request) -> str:
    header = request.headers.get("authorization", "")
    scheme, _, token = header.partition(" ")
    if scheme.lower() != "bearer" or not token.strip():
        raise unauthorized()
    return token.strip()


async def authenticate_source(request: Request, source: str) -> admin.SourceCredential:
    """Authenticate a ``tsk_src_`` token for the source named in the path.

    An unknown source, a token of another source, and a bad token all get the same 401.
    """
    token = bearer_token(request)
    async with get_pool(request).connection() as conn:
        credential = await admin.authenticate_source_token(conn, token)
    if credential is None or credential.source.name != source:
        raise unauthorized()
    return credential


def require_role(role: Role) -> Callable[[Request], Awaitable[admin.OperatorCredential]]:
    async def dependency(request: Request) -> admin.OperatorCredential:
        token = bearer_token(request)
        async with get_pool(request).connection() as conn:
            credential = await admin.authenticate_operator_token(conn, token)
        if credential is None:
            raise unauthorized()
        if not has_role(credential.roles, role):
            raise HTTPException(status_code=403, detail=f"requires the {role.value} role")
        return credential

    return dependency
