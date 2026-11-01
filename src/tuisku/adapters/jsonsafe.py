"""Bounded JSON decoding for untrusted records (ADR 0005 limits)."""

from __future__ import annotations

import json
import math
from typing import Any

from tuisku.adapters.base import AdapterError

MAX_DEPTH = 64
MAX_KEYS = 4096


def _reject_constant(name: str) -> Any:
    raise AdapterError(f"non-standard JSON constant {name}")


def _check(value: Any, max_depth: int, max_keys: int) -> None:
    # Iterative walk: no recursion on attacker-controlled nesting.
    stack: list[tuple[Any, int]] = [(value, 1)]
    keys = 0
    while stack:
        node, depth = stack.pop()
        if isinstance(node, dict | list):
            if depth > max_depth:
                raise AdapterError(f"JSON nesting deeper than {max_depth}")
            if isinstance(node, dict):
                keys += len(node)
                if keys > max_keys:
                    raise AdapterError(f"more than {max_keys} JSON object keys")
                stack.extend((v, depth + 1) for v in node.values())
            else:
                stack.extend((v, depth + 1) for v in node)
        elif isinstance(node, float) and not math.isfinite(node):
            raise AdapterError("non-finite number")


def loads_object(
    text: str, *, max_depth: int = MAX_DEPTH, max_keys: int = MAX_KEYS
) -> dict[str, Any]:
    """Decode a JSON object, rejecting deep nesting, key floods, NaN/Infinity and non-objects."""
    try:
        value = json.loads(text, parse_constant=_reject_constant)
    except RecursionError:
        raise AdapterError(f"JSON nesting deeper than {max_depth}") from None
    except json.JSONDecodeError as exc:
        raise AdapterError(f"invalid JSON at position {exc.pos}") from None
    if not isinstance(value, dict):
        raise AdapterError("expected a JSON object")
    _check(value, max_depth, max_keys)
    return value


def bounded_str(value: object, max_len: int = 4096) -> str | None:
    """Return ``value`` if it is a string no longer than ``max_len``; otherwise None."""
    if isinstance(value, str) and len(value) <= max_len:
        return value
    return None
