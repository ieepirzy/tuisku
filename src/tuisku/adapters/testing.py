"""Helpers for adapter golden tests: run fixtures through an adapter and compare with JSON."""

from __future__ import annotations

import dataclasses
import json
import os
from collections.abc import Mapping
from datetime import UTC, datetime
from enum import Enum
from pathlib import Path
from typing import Any

from tuisku.adapters.base import Adapter, AdapterError, ParseResult, RawRecord

FIXED_RECEIVED_AT = datetime(2026, 11, 1, 12, 0, 0, tzinfo=UTC)


def _jsonable(value: Any) -> Any:
    if dataclasses.is_dataclass(value) and not isinstance(value, type):
        return {f.name: _jsonable(getattr(value, f.name)) for f in dataclasses.fields(value)}
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, Mapping):
        return {str(k): _jsonable(v) for k, v in value.items()}
    if isinstance(value, list | tuple):
        return [_jsonable(v) for v in value]
    return value


def result_to_jsonable(result: ParseResult) -> dict[str, Any]:
    return _jsonable(result)


def run_line(
    adapter: Adapter,
    line: str,
    options: Mapping[str, Any] | None = None,
    collector: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Parse one fixture line; a parse failure becomes ``{"error": "..."}``."""
    raw = RawRecord(
        source="fixture",
        body=line.encode("utf-8"),
        received_at=FIXED_RECEIVED_AT,
        collector=dict(collector or {}),
    )
    try:
        return {"adapter": f"{adapter.name}@{adapter.version}"} | result_to_jsonable(
            adapter.parse(raw, dict(options or {}))
        )
    except AdapterError as exc:
        return {"adapter": f"{adapter.name}@{adapter.version}", "error": str(exc)}


def run_fixture_file(
    adapter: Adapter, path: Path, options: Mapping[str, Any] | None = None
) -> list[dict[str, Any]]:
    """Each non-empty line of an ``.ndjson`` / ``.log`` fixture is one raw record."""
    lines = [ln for ln in path.read_text(encoding="utf-8").splitlines() if ln.strip()]
    return [run_line(adapter, ln, options) for ln in lines]


def assert_golden(actual: Any, golden: Path, *, update: bool | None = None) -> None:
    """Compare with a golden JSON file. Set ``TUISKU_UPDATE_GOLDEN=1`` to (re)write it."""
    if update is None:
        update = os.environ.get("TUISKU_UPDATE_GOLDEN") == "1"
    rendered = json.dumps(actual, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
    if update:
        golden.write_text(rendered, encoding="utf-8")
        return
    if not golden.exists():
        raise AssertionError(f"golden file {golden} missing; rerun with TUISKU_UPDATE_GOLDEN=1")
    expected = golden.read_text(encoding="utf-8")
    assert rendered == expected, (
        f"output differs from {golden}; bump the adapter version if intended"
    )
