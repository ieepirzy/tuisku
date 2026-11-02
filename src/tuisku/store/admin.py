"""Sources, source tokens and operator tokens: creation, revocation and authentication.

Authentication looks a token up by its SHA-256 through a unique index, so no secret is ever
compared byte by byte in Python. Expiry and revocation are checked against the database clock.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from datetime import datetime
from typing import Any
from uuid import UUID

from psycopg import AsyncConnection
from psycopg.types.json import Jsonb

from tuisku import db
from tuisku.store.tokens import (
    Role,
    is_operator_token,
    is_source_token,
    new_operator_token,
    new_source_token,
    token_sha256,
)


class NotFoundError(LookupError):
    """The named source or token does not exist."""


@dataclass(frozen=True, slots=True)
class Source:
    id: int
    uid: UUID
    name: str
    adapter: str
    adapter_options: Mapping[str, Any]


@dataclass(frozen=True, slots=True)
class SourceCredential:
    """A source token that authenticated: which token, for which (enabled) source."""

    token_id: int
    source: Source


@dataclass(frozen=True, slots=True)
class OperatorCredential:
    token_id: int
    token_uid: UUID
    name: str
    person: str | None
    roles: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class IssuedToken:
    """A newly created token. ``token`` is shown once and never stored."""

    uid: UUID
    token: str


async def create_source(
    conn: AsyncConnection[Any], name: str, adapter: str, options: Mapping[str, Any] | None = None
) -> Source:
    row = await db.fetch_one(
        conn,
        "INSERT INTO sources (name, adapter, adapter_options) VALUES (%s, %s, %s) "
        "RETURNING id, uid, name, adapter, adapter_options",
        (name, adapter, Jsonb(dict(options or {}))),
    )
    assert row is not None
    return Source(**row)


async def _source_id(conn: AsyncConnection[Any], name: str) -> int:
    row = await db.fetch_one(conn, "SELECT id FROM sources WHERE name = %s", (name,))
    if row is None:
        raise NotFoundError(f"no source named {name!r}")
    return row["id"]


async def add_source_token(
    conn: AsyncConnection[Any],
    source_name: str,
    *,
    label: str | None = None,
    expires_at: datetime | None = None,
) -> IssuedToken:
    source_id = await _source_id(conn, source_name)
    token = new_source_token()
    row = await db.fetch_one(
        conn,
        "INSERT INTO source_tokens (source_id, token_sha256, label, expires_at) "
        "VALUES (%s, %s, %s, %s) RETURNING uid",
        (source_id, token_sha256(token), label, expires_at),
    )
    assert row is not None
    return IssuedToken(uid=row["uid"], token=token)


async def list_source_tokens(conn: AsyncConnection[Any], source_name: str) -> list[dict[str, Any]]:
    source_id = await _source_id(conn, source_name)
    return await db.fetch_all(
        conn,
        "SELECT uid, label, created_at, expires_at, revoked_at, last_used_at "
        "FROM source_tokens WHERE source_id = %s ORDER BY id",
        (source_id,),
    )


async def revoke_source_token(
    conn: AsyncConnection[Any], source_name: str, token_uid: UUID
) -> None:
    source_id = await _source_id(conn, source_name)
    row = await db.fetch_one(
        conn,
        "UPDATE source_tokens SET revoked_at = coalesce(revoked_at, now()) "
        "WHERE source_id = %s AND uid = %s RETURNING id",
        (source_id, token_uid),
    )
    if row is None:
        raise NotFoundError(f"source {source_name!r} has no token {token_uid}")


async def disable_source(conn: AsyncConnection[Any], name: str) -> None:
    row = await db.fetch_one(
        conn,
        "UPDATE sources SET disabled_at = coalesce(disabled_at, now()) WHERE name = %s "
        "RETURNING id",
        (name,),
    )
    if row is None:
        raise NotFoundError(f"no source named {name!r}")


async def create_operator_token(
    conn: AsyncConnection[Any],
    *,
    name: str,
    roles: Iterable[Role],
    person: str | None = None,
    expires_at: datetime | None = None,
) -> IssuedToken:
    role_values = sorted({Role(r).value for r in roles})
    if not role_values:
        raise ValueError("an operator token needs at least one role")
    if Role.APPROVE.value in role_values and not person:
        raise ValueError("the approve role can only be granted to a token bound to a person")
    token = new_operator_token()
    row = await db.fetch_one(
        conn,
        "INSERT INTO operator_tokens (name, person, roles, token_sha256, expires_at) "
        "VALUES (%s, %s, %s, %s, %s) RETURNING uid",
        (name, person, role_values, token_sha256(token), expires_at),
    )
    assert row is not None
    return IssuedToken(uid=row["uid"], token=token)


async def list_operator_tokens(conn: AsyncConnection[Any]) -> list[dict[str, Any]]:
    """Every operator and approve token, newest last; never the secrets."""
    return await db.fetch_all(
        conn,
        "SELECT uid, name, person, roles, created_at, expires_at, revoked_at "
        "FROM operator_tokens ORDER BY id",
    )


async def revoke_operator_token(
    conn: AsyncConnection[Any], token_uid: UUID, *, approver: bool = False
) -> None:
    """Revoke an operator token (``approver=False``) or an approve token (``approver=True``).

    Tokens are revoked, never deleted, so the actor named in past events stays resolvable.
    Person-bound and approve tokens can be revoked only by the database owner: the same
    trigger that guards their creation refuses the update for any other role (ADR 0005).
    """
    row = await db.fetch_one(conn, "SELECT roles FROM operator_tokens WHERE uid = %s", (token_uid,))
    if row is None:
        raise NotFoundError(f"no operator token {token_uid}")
    is_approve = Role.APPROVE.value in row["roles"]
    if is_approve != approver:
        command = "tuisku approver revoke" if is_approve else "tuisku operator-token revoke"
        raise NotFoundError(f"token {token_uid} is revoked with `{command}`")
    await conn.execute(
        "UPDATE operator_tokens SET revoked_at = coalesce(revoked_at, now()) WHERE uid = %s",
        (token_uid,),
    )


async def authenticate_source_token(
    conn: AsyncConnection[Any], token: str
) -> SourceCredential | None:
    """Return the credential for a valid source token, else None.

    Rejects malformed, unknown, expired and revoked tokens and tokens of disabled sources.
    The caller checks that the credential's source is the one addressed.
    """
    if not is_source_token(token):
        return None
    row = await db.fetch_one(
        conn,
        "SELECT t.id AS token_id, s.id, s.uid, s.name, s.adapter, s.adapter_options "
        "FROM source_tokens t JOIN sources s ON s.id = t.source_id "
        "WHERE t.token_sha256 = %s AND t.revoked_at IS NULL "
        "AND (t.expires_at IS NULL OR t.expires_at > now()) AND s.disabled_at IS NULL",
        (token_sha256(token),),
    )
    if row is None:
        return None
    token_id = row.pop("token_id")
    # Working column; throttled so busy tokens do not write on every request.
    await conn.execute(
        "UPDATE source_tokens SET last_used_at = now() WHERE id = %s "
        "AND (last_used_at IS NULL OR last_used_at < now() - interval '1 minute')",
        (token_id,),
    )
    return SourceCredential(token_id=token_id, source=Source(**row))


async def authenticate_operator_token(
    conn: AsyncConnection[Any], token: str
) -> OperatorCredential | None:
    if not is_operator_token(token):
        return None
    row = await db.fetch_one(
        conn,
        "SELECT id, uid, name, person, roles FROM operator_tokens "
        "WHERE token_sha256 = %s AND revoked_at IS NULL "
        "AND (expires_at IS NULL OR expires_at > now())",
        (token_sha256(token),),
    )
    if row is None:
        return None
    return OperatorCredential(
        token_id=row["id"],
        token_uid=row["uid"],
        name=row["name"],
        person=row["person"],
        roles=tuple(row["roles"]),
    )
