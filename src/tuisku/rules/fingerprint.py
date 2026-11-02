"""Finding fingerprints and advisory-lock keys (ADR 0007).

The fingerprint is the SHA-256 of the RFC 8785 (JCS) canonical JSON array
``["finding", <rule id>, <rule rev>, [<group_by values in order>]]``; the overflow finding's is
``["overflow", <rule id>, <rule rev>]``. Canonical encoding means an attacker-chosen value cannot
move field boundaries and collide with another group.
"""

from __future__ import annotations

import hashlib
from collections.abc import Sequence
from typing import Any

import rfc8785

from tuisku.rules.predicates import MISSING

MAX_GROUP_VALUE_CHARS = 256  # ADR 0006 hard limit: values truncated before grouping
_JS_SAFE = 2**53 - 1  # JCS numbers are IEEE doubles; larger integers are grouped as text


def group_value(value: Any) -> Any:
    """Normalise one ``group_by`` value: missing is null, strings are truncated to 256
    characters, containers become their (truncated) canonical JSON text."""
    if value is MISSING or value is None:
        return None
    if isinstance(value, bool):
        return value
    if isinstance(value, int):
        return value if -_JS_SAFE <= value <= _JS_SAFE else str(value)[:MAX_GROUP_VALUE_CHARS]
    if isinstance(value, float):
        return value
    if isinstance(value, str):
        return value[:MAX_GROUP_VALUE_CHARS]
    try:
        text = rfc8785.dumps(value).decode("utf-8")
    except Exception:
        text = repr(type(value).__name__)
    return text[:MAX_GROUP_VALUE_CHARS]


def canonical(value: Any) -> bytes:
    return rfc8785.dumps(value)


def finding_fingerprint(rule_id: str, rev: int, values: Sequence[Any]) -> bytes:
    return hashlib.sha256(canonical(["finding", rule_id, rev, list(values)])).digest()


def overflow_fingerprint(rule_id: str, rev: int) -> bytes:
    return hashlib.sha256(canonical(["overflow", rule_id, rev])).digest()


def lock_key(*parts: str | int | bytes) -> int:
    """A signed 64-bit key for ``pg_advisory_xact_lock`` from a canonical tuple of parts."""
    encoded = [p.hex() if isinstance(p, bytes) else p for p in parts]
    digest = hashlib.sha256(canonical(["lock", *encoded])).digest()
    return int.from_bytes(digest[:8], "big", signed=True)
