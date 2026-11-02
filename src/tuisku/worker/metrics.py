"""Metric samples to deltas, at evaluation time (ADR 0006 "Metric samples").

- **Series key:** source, metric name, label set and resource attributes.
- **Within a series** samples are ordered by their own timestamp, not by arrival. A sample's
  delta is ``value - value of the latest earlier sample`` while ``start_time`` is unchanged.
  Deltas are computed from the stored samples every time, never stored, so a sample delivered
  out of order is compared with its true predecessor and its successor's delta shrinks to match:
  totals never double, and a late sample is never mistaken for a reset.
- **Reset:** a changed ``start_time`` or a lower value; the new value itself is the delta.
- **First sample ever seen for a series** counts in full when its ``start_time`` is no earlier
  than the source's first ``received_at`` minus one export interval, or when an earlier export
  from the same resource with the same ``start_time`` did not contain the series (the label set
  appeared while Tuisku was listening). Otherwise it is a baseline with delta 0.
- **Delta temporality:** taken as-is.
- **Never negative:** every delta is clamped to zero or more, so a hostile sample (the adapter
  already refuses negative counter values) cannot cancel other samples out of a sum.
"""

from __future__ import annotations

import json
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any, LiteralString

from psycopg import AsyncConnection

from tuisku import db
from tuisku.rules.fingerprint import canonical

METRIC_KIND = "metric.sample"


@dataclass(frozen=True, slots=True)
class Sample:
    id: int
    time: datetime
    value: float
    start_time: str | None
    temporality: str
    raw_record_id: int = 0


def _number(value: Any) -> float:
    if isinstance(value, bool) or not isinstance(value, int | float):
        return 0.0
    return float(value)


def series_deltas(
    samples: Sequence[Sample],
    predecessor: Sample | None,
    first_counts: Callable[[Sample], bool],
) -> dict[int, float]:
    """Deltas for ``samples`` (one series, ordered by time then id). Pure.

    ``predecessor`` is the latest sample before the first one, or None when the first one is
    the first sample ever seen for the series; ``first_counts`` then decides whether its full
    value counts (it is called only in that case).
    """
    out: dict[int, float] = {}
    prev = predecessor
    for s in samples:
        if s.temporality == "delta":
            delta = s.value
        elif prev is None:
            delta = s.value if first_counts(s) else 0.0
        elif s.start_time != prev.start_time or s.value < prev.value:
            delta = s.value  # reset: the counter restarted from the new start_time
        else:
            delta = s.value - prev.value
        # Never negative: a hostile sample must not cancel other samples out of a sum.
        out[s.id] = max(0.0, delta)
        prev = s
    return out


def series_key(envelope: Mapping[str, Any]) -> tuple[Any, ...]:
    attrs = envelope.get("attributes") or {}
    return (
        envelope.get("source_id"),
        canonical(attrs.get("metric")),
        canonical(attrs.get("labels") or {}),
        canonical(attrs.get("resource") or {}),
    )


_CURRENT: LiteralString = (
    "o.parse_attempt_id = (SELECT c.id FROM parse_attempts c WHERE c.raw_record_id = "
    "o.raw_record_id AND c.status = 'ok' ORDER BY c.id DESC LIMIT 1)"
)
_SERIES: LiteralString = (
    "o.kind = 'metric.sample' AND o.source_id = %(source_id)s "
    "AND o.attributes -> 'metric' = %(metric)s::jsonb "
    "AND coalesce(o.attributes -> 'labels', '{}') = %(labels)s::jsonb "
    "AND coalesce(o.attributes -> 'resource', '{}') = %(resource)s::jsonb AND " + _CURRENT
)
_COLUMNS: LiteralString = (
    "o.id, o.event_time AS time, o.attributes -> 'value' AS value, "
    "o.attributes ->> 'start_time' AS start_time, "
    "coalesce(o.attributes ->> 'temporality', 'cumulative') AS temporality, o.raw_record_id "
    "FROM observations o WHERE "
)


def _sample(row: Mapping[str, Any]) -> Sample:
    return Sample(
        id=row["id"],
        time=row["time"],
        value=_number(row["value"]),
        start_time=row["start_time"],
        temporality=row["temporality"],
        raw_record_id=row["raw_record_id"],
    )


async def _first_counts(
    conn: AsyncConnection[Any],
    params: dict[str, Any],
    sample: Sample,
    export_interval: timedelta,
) -> bool:
    if sample.start_time is None:
        return False
    start = datetime.fromisoformat(sample.start_time)
    first = await db.fetch_one(
        conn,
        "SELECT min(received_at) AS first FROM raw_records WHERE source_id = %(source_id)s",
        params,
    )
    if first is not None and first["first"] is not None:
        if start >= first["first"] - export_interval:
            return True  # the process started while Tuisku was listening
    # An earlier export from the same resource and start_time without this series: the label
    # set appeared while Tuisku was listening.
    row = await db.fetch_one(
        conn,
        "SELECT 1 AS hit FROM observations o WHERE o.kind = 'metric.sample' "
        "AND o.source_id = %(source_id)s "
        "AND coalesce(o.attributes -> 'resource', '{}') = %(resource)s::jsonb "
        "AND o.attributes ->> 'start_time' = %(start_time)s "
        "AND o.raw_record_id < %(raw_record_id)s AND NOT EXISTS ("
        "  SELECT 1 FROM observations s WHERE s.raw_record_id = o.raw_record_id "
        "  AND s.kind = 'metric.sample' AND s.attributes -> 'metric' = %(metric)s::jsonb "
        "  AND coalesce(s.attributes -> 'labels', '{}') = %(labels)s::jsonb) LIMIT 1",
        params | {"start_time": sample.start_time, "raw_record_id": sample.raw_record_id},
    )
    return row is not None


async def compute_deltas(
    conn: AsyncConnection[Any],
    envelopes: Sequence[Mapping[str, Any]],
    export_interval: timedelta,
) -> dict[int, float]:
    """Delta for every metric sample in ``envelopes``, keyed by observation id."""
    by_series: dict[tuple[Any, ...], list[Mapping[str, Any]]] = {}
    for env in envelopes:
        if env.get("layer") == "observation" and env.get("kind") == METRIC_KIND:
            by_series.setdefault(series_key(env), []).append(env)
    out: dict[int, float] = {}
    for members in by_series.values():
        attrs = members[0].get("attributes") or {}
        params: dict[str, Any] = {
            "source_id": members[0].get("source_id"),
            "metric": json.dumps(attrs.get("metric")),
            "labels": json.dumps(attrs.get("labels") or {}),
            "resource": json.dumps(attrs.get("resource") or {}),
        }
        first = min(members, key=lambda e: (e["event_time"], e["id"]))
        last = max(members, key=lambda e: (e["event_time"], e["id"]))
        rows = await db.fetch_all(
            conn,
            "SELECT " + _COLUMNS + _SERIES + " AND (o.event_time, o.id) >= (%(lo)s, %(lo_id)s) "
            "AND (o.event_time, o.id) <= (%(hi)s, %(hi_id)s) ORDER BY o.event_time, o.id",
            params
            | {
                "lo": first["event_time"],
                "lo_id": first["id"],
                "hi": last["event_time"],
                "hi_id": last["id"],
            },
        )
        pred_row = await db.fetch_one(
            conn,
            "SELECT " + _COLUMNS + _SERIES + " AND (o.event_time, o.id) < (%(lo)s, %(lo_id)s) "
            "ORDER BY o.event_time DESC, o.id DESC LIMIT 1",
            params | {"lo": first["event_time"], "lo_id": first["id"]},
        )
        samples = [_sample(r) for r in rows]
        predecessor = _sample(pred_row) if pred_row is not None else None
        first_ok = False
        if predecessor is None and samples and samples[0].temporality != "delta":
            first_ok = await _first_counts(conn, params, samples[0], export_interval)
        out.update(series_deltas(samples, predecessor, lambda _s, ok=first_ok: ok))
    return out
