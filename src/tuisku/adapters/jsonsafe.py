"""Bounded JSON decoding for untrusted records (ADR 0005 limits).

Breaches of the structural limits (nesting depth, object keys per record) raise
:class:`~tuisku.adapters.base.LimitExceeded` with ``limit`` set to ``"json_depth"`` or
``"json_keys"``, so ingest can record them as meta-detections. Everything else that makes a body
unusable raises :class:`~tuisku.adapters.base.AdapterError`. Error messages never echo the input.

U+0000 and lone surrogates, which Postgres ``jsonb`` and ``text`` reject, are **replaced** with
U+FFFD in every key and string value rather than rejected: rejecting them would let anyone who
controls a logged field (a User-Agent, a URL) make a whole sensor record fail to parse, which is
evasion. :func:`loads_object_flagged` reports the replacement as ``invalid_unicode_replaced`` so
adapters can put that flag on their observations; :func:`sanitize_text` does the same for plain
text lines. Duplicate object keys are still rejected.
"""

from __future__ import annotations

import json
import math
import re
from typing import Any

from tuisku.adapters.base import AdapterError, LimitExceeded

MAX_DEPTH = 64
MAX_KEYS = 4096

INVALID_UNICODE_FLAG = "invalid_unicode_replaced"

# Postgres rejects U+0000 and unpaired surrogates (which json.loads produces from \\ud800).
_FORBIDDEN_CHARS = re.compile("[\x00\ud800-\udfff]")


def _reject_constant(name: str) -> Any:
    raise AdapterError("non-standard JSON constant")


def sanitize_text(value: str) -> tuple[str, bool]:
    """Replace U+0000 and lone surrogates with U+FFFD; return ``(text, replaced)``.

    For plain-text inputs such as Harava log lines; add ``invalid_unicode_replaced`` to the
    observation's flags when ``replaced`` is True. Valid text is returned unchanged.
    """
    cleaned, count = _FORBIDDEN_CHARS.subn("\ufffd", value)
    return cleaned, count > 0


class _PairsHook:
    """Builds objects while parsing: rejects duplicate keys, counts keys against the limit and
    sanitizes keys and string values."""

    def __init__(self, max_keys: int) -> None:
        self.max_keys = max_keys
        self.keys = 0
        self.replaced = False

    def text(self, value: str) -> str:
        cleaned, replaced = sanitize_text(value)
        self.replaced |= replaced
        return cleaned

    def __call__(self, pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        self.keys += len(pairs)
        if self.keys > self.max_keys:
            raise LimitExceeded("json_keys", f"more than {self.max_keys} JSON object keys")
        obj: dict[str, Any] = {}
        for raw_key, value in pairs:
            key = self.text(raw_key)
            if key in obj:
                raise AdapterError("duplicate JSON object key")
            obj[key] = self.text(value) if isinstance(value, str) else value
        return obj


def _check(value: Any, max_depth: int, hook: _PairsHook) -> None:
    # Iterative walk: no recursion on attacker-controlled nesting. Object values were sanitized
    # by the hook; strings inside arrays are sanitized here, in place.
    stack: list[tuple[Any, int]] = [(value, 1)]
    while stack:
        node, depth = stack.pop()
        if isinstance(node, dict | list):
            if depth > max_depth:
                raise LimitExceeded("json_depth", f"JSON nesting deeper than {max_depth}")
            if isinstance(node, list):
                for i, item in enumerate(node):
                    if isinstance(item, str):
                        node[i] = hook.text(item)
            children = node.values() if isinstance(node, dict) else node
            stack.extend((v, depth + 1) for v in children)
        elif isinstance(node, float) and not math.isfinite(node):
            raise AdapterError("non-finite number")


def loads_object_flagged(
    text: str, *, max_depth: int = MAX_DEPTH, max_keys: int = MAX_KEYS
) -> tuple[dict[str, Any], tuple[str, ...]]:
    """Like :func:`loads_object`, also returning flags: ``("invalid_unicode_replaced",)`` when
    U+0000 or a lone surrogate was replaced with U+FFFD, else ``()``."""
    if not isinstance(text, str):
        raise AdapterError("expected JSON text")
    hook = _PairsHook(max_keys)
    try:
        value = json.loads(text, parse_constant=_reject_constant, object_pairs_hook=hook)
    except AdapterError:
        raise
    except RecursionError:
        raise LimitExceeded("json_depth", f"JSON nesting deeper than {max_depth}") from None
    except json.JSONDecodeError as exc:
        raise AdapterError(f"invalid JSON at position {exc.pos}") from None
    except ValueError:  # int() digit limit on huge integer literals
        raise AdapterError("JSON number out of range") from None
    if not isinstance(value, dict):
        raise AdapterError("expected a JSON object")
    _check(value, max_depth, hook)
    return value, ((INVALID_UNICODE_FLAG,) if hook.replaced else ())


def loads_object(
    text: str, *, max_depth: int = MAX_DEPTH, max_keys: int = MAX_KEYS
) -> dict[str, Any]:
    """Decode a JSON object, rejecting deep nesting, key floods, duplicate keys, NaN/Infinity,
    oversized integers and non-objects; U+0000 and lone surrogates become U+FFFD."""
    return loads_object_flagged(text, max_depth=max_depth, max_keys=max_keys)[0]


def bounded_str(value: object, max_len: int = 4096) -> str | None:
    """Return ``value`` if it is a string no longer than ``max_len``; otherwise None."""
    if isinstance(value, str) and len(value) <= max_len:
        return value
    return None
