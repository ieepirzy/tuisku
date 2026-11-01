"""Timestamp parsing for sensor formats. Always returns timezone-aware UTC datetimes.

Accepted:
- ISO 8601 / RFC 3339 with ``Z``, ``±HH:MM`` or ``±HHMM`` offsets and up to 9 fractional digits
  (Suricata ``2023-09-18T06:13:41.532140+0000``, Falco ``...123456789Z``);
- ``YYYY-MM-DD HH:MM:SS,mmm`` (Python logging's default) — no zone, interpreted as UTC;
- epoch seconds as int/float (Zeek ``ts``), or epoch nanoseconds as an int above 10**17
  (Falco ``evt.time``).
"""

from __future__ import annotations

import math
import re
from datetime import UTC, datetime, timedelta

_ISO = re.compile(
    r"^(\d{4})-(\d{2})-(\d{2})[T ](\d{2}):(\d{2}):(\d{2})"
    r"(?:[.,](\d{1,9}))?"
    r"(Z|[+-]\d{2}:?\d{2})?$"
)
# Bounds that reject absurd values rather than overflow.
_MIN = datetime(1990, 1, 1, tzinfo=UTC)
_MAX = datetime(2200, 1, 1, tzinfo=UTC)


def _check(dt: datetime) -> datetime:
    if not _MIN <= dt < _MAX:
        raise ValueError("timestamp out of range")
    return dt


def parse_timestamp(value: object) -> datetime:
    if isinstance(value, bool):
        raise ValueError("not a timestamp")
    if isinstance(value, int):
        if abs(value) > 10**17:
            seconds, nanos = divmod(value, 10**9)
            return _check(
                datetime.fromtimestamp(seconds, tz=UTC) + timedelta(microseconds=nanos // 1000)
            )
        return _check(datetime.fromtimestamp(value, tz=UTC))
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ValueError("not a finite timestamp")
        return _check(datetime.fromtimestamp(value, tz=UTC))
    if not isinstance(value, str) or len(value) > 40:
        raise ValueError("not a timestamp")
    m = _ISO.match(value.strip())
    if m is None:
        raise ValueError("unrecognized timestamp format")
    year, month, day, hour, minute, second, frac, zone = m.groups()
    micro = int((frac or "0").ljust(6, "0")[:6])
    dt = datetime(
        int(year), int(month), int(day), int(hour), int(minute), int(second), micro, tzinfo=UTC
    )
    if zone and zone != "Z":
        sign = 1 if zone[0] == "+" else -1
        digits = zone[1:].replace(":", "")
        offset = timedelta(hours=int(digits[:2]), minutes=int(digits[2:]))
        dt = dt - sign * offset
    return _check(dt)


def parse_timestamp_or_none(value: object) -> datetime | None:
    try:
        return parse_timestamp(value)
    except (ValueError, OverflowError, OSError):
        return None
