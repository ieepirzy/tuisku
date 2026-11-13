"""Sources, source tokens and operator tokens: creation, revocation and authentication.

Authentication looks a token up by its SHA-256 through a unique index, so no secret is ever
compared byte by byte in Python. Expiry and revocation are checked against the database clock.
"""

from __future__ import annotations

import json
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


class EnsureConflict(Exception):
    """``ensure_source`` found state it must not change. The message never contains a token."""


@dataclass(frozen=True, slots=True)
class EnsureResult:
    source_created: bool
    token_uid: UUID  # the token's uid, whether registered now or before
    token_registered: bool


def _canonical(value: Any) -> str:
    # JSON equality, not Python's: true and 1, or 1 and 1.0, are different options.
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


async def ensure_source(
    conn: AsyncConnection[Any],
    name: str,
    adapter: str,
    options: Mapping[str, Any],
    token: str,
    *,
    label: str | None = None,
) -> EnsureResult:
    """Make sure source ``name`` exists with exactly this adapter and options and that
    ``token`` is one of its live tokens. Idempotent, and safe to run concurrently.

    Creates the source if absent and registers the token (its SHA-256 only) if absent. Never
    changes an existing source or token: a different adapter or options, a disabled source, or
    a token that is revoked, expired or registered to another source raise
    :class:`EnsureConflict`.
    """
    if not is_source_token(token):
        raise ValueError("not a tsk_src_ token")
    created = await db.fetch_one(
        conn,
        "INSERT INTO sources (name, adapter, adapter_options) VALUES (%s, %s, %s) "
        "ON CONFLICT (name) DO NOTHING RETURNING id",
        (name, adapter, Jsonb(dict(options))),
    )
    source = await db.fetch_one(
        conn,
        "SELECT id, adapter, adapter_options, disabled_at FROM sources WHERE name = %s",
        (name,),
    )
    assert source is not None
    if source["adapter"] != adapter:
        raise EnsureConflict(
            f"source {name!r} exists with adapter {source['adapter']!r}, not {adapter!r}; "
            "it was not changed"
        )
    stored, wanted = dict(source["adapter_options"]), dict(options)
    differ = sorted(
        k
        for k in stored.keys() | wanted.keys()
        if k not in stored or k not in wanted or _canonical(stored[k]) != _canonical(wanted[k])
    )
    if differ:
        raise EnsureConflict(
            f"source {name!r} exists with different adapter options (keys: {', '.join(differ)}); "
            "it was not changed"
        )
    if source["disabled_at"] is not None:
        raise EnsureConflict(f"source {name!r} is disabled; its tokens do not authenticate")
    digest = token_sha256(token)
    inserted = await db.fetch_one(
        conn,
        "INSERT INTO source_tokens (source_id, token_sha256, label) VALUES (%s, %s, %s) "
        "ON CONFLICT (token_sha256) DO NOTHING RETURNING uid",
        (source["id"], digest, label),
    )
    if inserted is not None:
        return EnsureResult(created is not None, inserted["uid"], token_registered=True)
    existing = await db.fetch_one(
        conn,
        "SELECT uid, source_id, revoked_at IS NOT NULL AS revoked, "
        "expires_at IS NOT NULL AND expires_at <= now() AS expired "
        "FROM source_tokens WHERE token_sha256 = %s",
        (digest,),
    )
    assert existing is not None
    if existing["source_id"] != source["id"]:
        raise EnsureConflict(f"the token is registered to another source, not {name!r}")
    if existing["revoked"]:
        raise EnsureConflict(f"the token {existing['uid']} was revoked; issue a new one")
    if existing["expired"]:
        raise EnsureConflict(f"the token {existing['uid']} has expired; issue a new one")
    return EnsureResult(created is not None, existing["uid"], token_registered=False)


async def list_source_tokens(conn: AsyncConnection[Any], source_name: str) -> list[dict[str, Any]]:
    source_id = await _source_id(conn, source_name)
    return await db.fetch_all(
        conn,
        "SELECT t.uid, t.label, t.created_at, t.expires_at, t.revoked_at, u.last_used_at "
        "FROM source_tokens t LEFT JOIN source_token_usage u ON u.token_id = t.id "
        "WHERE t.source_id = %s ORDER BY t.id",
        (source_id,),
    )


async def revoke_source_token(
    conn: AsyncConnection[Any], source_name: str, token_uid: UUID
) -> None:
    source_id = await _source_id(conn, source_name)
    row = await db.fetch_one(
        conn,
        # A revocation request, applied at once by an owner trigger (ADR 0011).
        "INSERT INTO token_revocations (token_id) SELECT id FROM source_tokens "
        "WHERE source_id = %s AND uid = %s RETURNING token_id",
        (source_id, token_uid),
    )
    if row is None:
        raise NotFoundError(f"source {source_name!r} has no token {token_uid}")


async def disable_source(conn: AsyncConnection[Any], name: str) -> None:
    row = await db.fetch_one(
        conn,
        # A request, applied at once by an owner trigger (ADR 0011).
        "INSERT INTO source_admin_requests (source_id, action) SELECT id, 'disable' "
        "FROM sources WHERE name = %s RETURNING source_id",
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
    A revocation is a row in the append-only operator_token_revocations, applied by an owner
    trigger, so it cannot be undone. Person-bound and approve tokens can be revoked only by
    the database owner: a trigger refuses the request for any other role (ADR 0005).
    """
    row = await db.fetch_one(conn, "SELECT roles FROM operator_tokens WHERE uid = %s", (token_uid,))
    if row is None:
        raise NotFoundError(f"no operator token {token_uid}")
    is_approve = Role.APPROVE.value in row["roles"]
    if is_approve != approver:
        command = "tuisku approver revoke" if is_approve else "tuisku operator-token revoke"
        raise NotFoundError(f"token {token_uid} is revoked with `{command}`")
    # A revocation, applied at once by an owner trigger and never undone (ADR 0011).
    await conn.execute(
        "INSERT INTO operator_token_revocations (token_id) SELECT id FROM operator_tokens "
        "WHERE uid = %s",
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
        "INSERT INTO source_token_usage (token_id, last_used_at) VALUES (%s, now()) "
        "ON CONFLICT (token_id) DO UPDATE SET last_used_at = now() "
        "WHERE source_token_usage.last_used_at < now() - interval '1 minute'",
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
        "AND (expires_at IS NULL OR expires_at > now()) AND NOT EXISTS (SELECT 1 FROM "
        "operator_token_revocations r WHERE r.token_id = operator_tokens.id)",
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
