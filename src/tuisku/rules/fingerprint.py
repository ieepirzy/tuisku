"""Finding fingerprints and worker lock keys (ADR 0007).

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

from tuisku.rules.predicates import MISSING, NULL

MAX_GROUP_VALUE_CHARS = 256  # ADR 0006 hard limit: longer values group by prefix and hash
_JS_SAFE = 2**53 - 1  # JCS numbers are IEEE doubles; larger integers are grouped as text


def _long(text: str) -> dict[str, str]:
    """A value longer than the limit groups by its prefix plus the SHA-256 of the whole."""
    digest = hashlib.sha256(text.encode("utf-8", "surrogatepass")).hexdigest()
    return {"prefix": text[:MAX_GROUP_VALUE_CHARS], "sha256": digest}


def group_value(value: Any) -> Any:
    """Normalise one ``group_by`` value for the fingerprint.

    Real field values only ever become JSON strings, numbers, booleans or null here, so the
    object markers below cannot collide with them: a missing field is ``{"missing": true}``
    (distinct from an explicit null), an integer beyond IEEE double precision is
    ``{"int": "<digits>"}``, a container is its canonical JSON text, and any string longer than
    256 characters is ``{"prefix": <first 256>, "sha256": <digest of all of it>}``.
    """
    if value is MISSING:
        return {"missing": True}
    if value is NULL:
        return None
    if value is None or isinstance(value, bool | float):
        return value
    if isinstance(value, int):
        return value if -_JS_SAFE <= value <= _JS_SAFE else {"int": str(value)}
    if isinstance(value, str):
        text = value
    else:
        try:
            text = rfc8785.dumps(value).decode("utf-8")
        except Exception:
            text = repr(type(value).__name__)
    return text if len(text) <= MAX_GROUP_VALUE_CHARS else _long(text)


def canonical(value: Any) -> bytes:
    return rfc8785.dumps(value)


def finding_fingerprint(rule_id: str, rev: int, values: Sequence[Any]) -> bytes:
    return hashlib.sha256(canonical(["finding", rule_id, rev, list(values)])).digest()


def overflow_fingerprint(rule_id: str, rev: int) -> bytes:
    return hashlib.sha256(canonical(["overflow", rule_id, rev])).digest()


def lock_key(*parts: str | int | bytes) -> int:
    """A signed 64-bit key for a ``group_locks`` row from a canonical tuple of parts."""
    encoded = [p.hex() if isinstance(p, bytes) else p for p in parts]
    digest = hashlib.sha256(canonical(["lock", *encoded])).digest()
    return int.from_bytes(digest[:8], "big", signed=True)
