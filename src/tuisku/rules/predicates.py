"""Field paths and the closed predicate set (ADR 0006 "Rules are data").

Pure Python, no ``eval``, no templating. A predicate never raises: when the field is missing or
has the wrong type, positive predicates are false and the negative predicates ``neq`` and
``not_in`` are true, so a record cannot dodge an allowlist rule by omitting the field.
"""

from __future__ import annotations

import ipaddress
import math
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any, Final

POSITIVE_OPS: Final = frozenset(
    {"eq", "in", "gt", "gte", "lt", "lte", "exists", "contains", "startswith", "cidr"}
)
NEGATIVE_OPS: Final = frozenset({"neq", "not_in"})
OPS: Final = POSITIVE_OPS | NEGATIVE_OPS

# Envelope fields a path may address; everything else lives under ``attributes.``.
ENVELOPE_FIELDS: Final = frozenset(
    {"kind", "source", "evaluator", "authorship", "identity", "severity_id", "entity_keys"}
)
MAX_PATH_SEGMENTS: Final = 16


class _Missing:
    __slots__ = ()

    def __repr__(self) -> str:
        return "MISSING"


MISSING: Final = _Missing()


class PathError(ValueError):
    """A field path that is not well formed (raised at pack load, never at evaluation)."""


@dataclass(frozen=True, slots=True)
class FieldPath:
    """A parsed path: an envelope field or ``attributes``, then keys or list indexes."""

    text: str
    segments: tuple[str | int, ...]

    @classmethod
    def parse(cls, text: object) -> FieldPath:
        if not isinstance(text, str) or not text or len(text) > 256:
            raise PathError("a field path is a non-empty string of at most 256 characters")
        parts = text.split(".")
        if len(parts) > MAX_PATH_SEGMENTS or any(p == "" for p in parts):
            raise PathError(f"malformed field path {text!r}")
        head = parts[0]
        if head == "attributes":
            if len(parts) < 2:
                raise PathError("'attributes' needs a key, e.g. attributes.caller")
        elif head not in ENVELOPE_FIELDS:
            allowed = ", ".join(sorted(ENVELOPE_FIELDS))
            raise PathError(f"unknown field {head!r}: use attributes.* or one of {allowed}")
        segments: list[str | int] = [head]
        for p in parts[1:]:
            segments.append(int(p) if p.isdigit() and len(p) <= 6 else p)
        return cls(text, tuple(segments))

    def resolve(self, envelope: Mapping[str, Any]) -> Any:
        """The value at this path in ``envelope``, or :data:`MISSING`. Never raises."""
        current: Any = envelope.get(str(self.segments[0]), MISSING) if self.segments else MISSING
        for seg in self.segments[1:]:
            if current is MISSING or current is None:
                return MISSING
            if isinstance(seg, int):
                if isinstance(current, list | tuple) and seg < len(current):
                    current = current[seg]
                elif isinstance(current, Mapping):
                    current = current.get(str(seg), MISSING)
                else:
                    return MISSING
            elif isinstance(current, Mapping):
                current = current.get(seg, MISSING)
            else:
                return MISSING
        return MISSING if current is None else current


def _is_number(value: Any) -> bool:
    return (
        isinstance(value, int | float)
        and not isinstance(value, bool)
        and not (isinstance(value, float) and not math.isfinite(value))
    )


def _same_kind(a: Any, b: Any) -> bool:
    """Values comparable for equality: both numbers, both strings or both booleans."""
    if _is_number(a) and _is_number(b):
        return True
    if isinstance(a, bool) or isinstance(b, bool):
        return isinstance(a, bool) and isinstance(b, bool)
    return isinstance(a, str) and isinstance(b, str)


def _eq(field: Any, value: Any) -> bool:
    return _same_kind(field, value) and field == value


def _in(field: Any, values: Sequence[Any]) -> bool:
    return any(_eq(field, v) for v in values)


def _order(op: str, field: Any, value: Any) -> bool:
    if not (_is_number(field) and _is_number(value)):
        return False
    if op == "gt":
        return field > value
    if op == "gte":
        return field >= value
    if op == "lt":
        return field < value
    return field <= value


def _contains(field: Any, value: Any) -> bool:
    if isinstance(field, str):
        return isinstance(value, str) and value in field
    if isinstance(field, list | tuple):
        return any(_eq(item, value) for item in field)
    return False


def _cidr(field: Any, networks: Sequence[ipaddress.IPv4Network | ipaddress.IPv6Network]) -> bool:
    if not isinstance(field, str) or len(field) > 64:
        return False
    try:
        addr = ipaddress.ip_address(field)
    except ValueError:
        return False
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped is not None:
        addr = addr.ipv4_mapped
    return any(addr.version == net.version and addr in net for net in networks)


def _positive(op: str, field: Any, value: Any) -> bool:
    if op == "exists":
        return field is not MISSING
    if field is MISSING:
        return False
    if op == "eq":
        return _eq(field, value)
    if op == "in":
        return _in(field, value)
    if op in ("gt", "gte", "lt", "lte"):
        return _order(op, field, value)
    if op == "contains":
        return _contains(field, value)
    if op == "startswith":
        return isinstance(field, str) and isinstance(value, str) and field.startswith(value)
    if op == "cidr":
        return _cidr(field, value)
    raise ValueError(f"unknown predicate {op!r}")


def evaluate(op: str, field: Any, value: Any) -> bool:
    """Apply predicate ``op`` to a resolved ``field`` (possibly :data:`MISSING`). Never raises.

    ``value`` must already be validated for ``op`` (lists for ``in``/``not_in``, parsed networks
    for ``cidr``); see :func:`prepare_value`.
    """
    try:
        if op == "neq":
            return not _positive("eq", field, value)
        if op == "not_in":
            return not _positive("in", field, value)
        return _positive(op, field, value)
    except Exception:  # defensive: a hostile value must never fail evaluation
        return op in NEGATIVE_OPS


def prepare_value(op: str, value: Any) -> Any:
    """Validate a predicate's (resolved) value at load time; return its evaluation form."""
    if op not in OPS:
        raise ValueError(f"unknown predicate {op!r} (allowed: {', '.join(sorted(OPS))})")
    if op == "exists":
        if value not in (None, True):
            raise ValueError("'exists' takes no value")
        return None
    if op in ("in", "not_in"):
        if not isinstance(value, list) or not value or len(value) > 10_000:
            raise ValueError(f"'{op}' needs a non-empty list of at most 10000 values")
        if not all(_scalar(v) for v in value):
            raise ValueError(f"'{op}' values must be strings, numbers or booleans")
        return tuple(value)
    if op in ("gt", "gte", "lt", "lte"):
        if not _is_number(value):
            raise ValueError(f"'{op}' needs a number")
        return value
    if op == "cidr":
        items = value if isinstance(value, list) else [value]
        if not items or len(items) > 1000:
            raise ValueError("'cidr' needs a network or a non-empty list of networks")
        try:
            return tuple(ipaddress.ip_network(str(v), strict=False) for v in items)
        except ValueError as exc:
            raise ValueError(f"'cidr': {exc}") from None
    if op in ("startswith",):
        if not isinstance(value, str):
            raise ValueError("'startswith' needs a string")
        return value
    if not _scalar(value):
        raise ValueError(f"'{op}' needs a string, number or boolean")
    return value


def _scalar(value: Any) -> bool:
    return isinstance(value, str | bool) or _is_number(value)
