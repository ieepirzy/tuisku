"""Token format (ADR 0005): a recognisable prefix plus 256 random bits; only the SHA-256 is stored.

Tokens are secrets: never log them, never put them in exceptions or error responses.
"""

from __future__ import annotations

import hashlib
import re
import secrets
from enum import StrEnum

SOURCE_PREFIX = "tsk_src_"
OPERATOR_PREFIX = "tsk_op_"
# secrets.token_urlsafe(32) is 43 characters of the URL-safe base64 alphabet.
_BODY = r"[A-Za-z0-9_-]{43}"
_SOURCE_TOKEN = re.compile(rf"^{SOURCE_PREFIX}{_BODY}$")
_OPERATOR_TOKEN = re.compile(rf"^{OPERATOR_PREFIX}{_BODY}$")


class Role(StrEnum):
    """Operator roles. read < triage < admin is a hierarchy; approve stands apart (ADR 0005)."""

    READ = "read"
    TRIAGE = "triage"
    ADMIN = "admin"
    APPROVE = "approve"


_HIERARCHY = (Role.READ, Role.TRIAGE, Role.ADMIN)


def has_role(granted: list[str] | tuple[str, ...], needed: Role) -> bool:
    """True when ``granted`` includes ``needed``. Admin does not imply approve."""
    if needed is Role.APPROVE:
        return Role.APPROVE.value in granted
    level = _HIERARCHY.index(needed)
    return any(r.value in granted for r in _HIERARCHY[level:])


def new_source_token() -> str:
    return SOURCE_PREFIX + secrets.token_urlsafe(32)


def new_operator_token() -> str:
    return OPERATOR_PREFIX + secrets.token_urlsafe(32)


def token_sha256(token: str) -> bytes:
    return hashlib.sha256(token.encode("utf-8")).digest()


def is_source_token(value: str) -> bool:
    return _SOURCE_TOKEN.fullmatch(value) is not None


def is_operator_token(value: str) -> bool:
    return _OPERATOR_TOKEN.fullmatch(value) is not None
