"""Timestamp parsing for sensor formats. Always returns timezone-aware UTC datetimes.

Accepted:
- ISO 8601 / RFC 3339 with ``Z``, ``±HH:MM`` or ``±HHMM`` offsets and up to 9 fractional digits
  (Suricata ``2023-09-18T06:13:41.532140+0000``, Falco ``...123456789Z``); ``T`` and ``Z`` may be
  lowercase, the date/time separator may be a space;
- offsets up to ±14:00 (minutes below 60);
- a leap second (``:60``) is read as ``:59.999999``;
- ``YYYY-MM-DD HH:MM:SS,mmm`` (Python logging's default);
- epoch seconds as int/float (Zeek ``ts``), or epoch nanoseconds as an int above 10**17
  (Falco ``evt.time``).

**Zone-less strings are ambiguous.** An ISO string without ``Z`` or an offset is interpreted as
UTC, because that is how Harava's containers log. :func:`parse_timestamp` hides that
assumption; adapters that want to record it call :func:`parse_timestamp_with_zone_flag` and add
the ``timezone_assumed_utc`` flag to the observation when the returned ``zone_given`` is False.
Epoch values carry no zone ambiguity and report ``zone_given=True``.

Every failure, however hostile the input, is an :class:`~tuisku.adapters.base.AdapterError`
(a ``ValueError``) with a fixed message that never echoes the input. The accepted range is
1990-01-01 (inclusive) to 2200-01-01 (exclusive), UTC.
"""

from __future__ import annotations

import math
import re
from datetime import UTC, datetime, timedelta

from tuisku.adapters.base import AdapterError

_ISO = re.compile(
    r"([0-9]{4})-([0-9]{2})-([0-9]{2})[Tt ]([0-9]{2}):([0-9]{2}):([0-9]{2})"
    r"(?:[.,]([0-9]{1,9}))?"
    r"([Zz]|[+-][0-9]{2}:?[0-9]{2})?"
)
# Bounds that reject absurd values rather than overflow.
_MIN = datetime(1990, 1, 1, tzinfo=UTC)
_MAX = datetime(2200, 1, 1, tzinfo=UTC)
_NANOS_THRESHOLD = 10**17
# Real-world UTC offsets span -12:00 to +14:00; accept up to ±14:00.
_MAX_OFFSET_MINUTES = 14 * 60


def _check(dt: datetime) -> datetime:
    if not _MIN <= dt < _MAX:
        raise AdapterError("timestamp out of range")
    return dt


def _from_epoch(value: int | float) -> datetime:
    try:
        if isinstance(value, int) and abs(value) > _NANOS_THRESHOLD:
            seconds, nanos = divmod(value, 10**9)
            dt = datetime.fromtimestamp(seconds, tz=UTC) + timedelta(microseconds=nanos // 1000)
        else:
            dt = datetime.fromtimestamp(value, tz=UTC)
    except (ValueError, OSError, OverflowError):
        raise AdapterError("timestamp out of range") from None
    return _check(dt)


def _from_iso(value: str) -> tuple[datetime, bool]:
    m = _ISO.fullmatch(value)
    if m is None:
        raise AdapterError("unrecognized timestamp format")
    year, month, day, hour, minute, second, frac, zone = m.groups()
    micro = int((frac or "0").ljust(6, "0")[:6])
    sec = int(second)
    if sec == 60:  # leap second
        sec, micro = 59, 999_999
    try:
        dt = datetime(int(year), int(month), int(day), int(hour), int(minute), sec, micro, UTC)
    except ValueError:
        raise AdapterError("invalid date or time") from None
    if zone and zone not in ("Z", "z"):
        sign = 1 if zone[0] == "+" else -1
        digits = zone[1:].replace(":", "")
        off_h, off_m = int(digits[:2]), int(digits[2:])
        if off_m >= 60 or off_h * 60 + off_m > _MAX_OFFSET_MINUTES:
            raise AdapterError("invalid UTC offset")
        try:
            dt = dt - sign * timedelta(hours=off_h, minutes=off_m)
        except OverflowError:
            raise AdapterError("timestamp out of range") from None
    return _check(dt), zone is not None


def parse_timestamp_with_zone_flag(value: object) -> tuple[datetime, bool]:
    """Parse ``value``; return ``(utc_datetime, zone_given)``.

    ``zone_given`` is False only for ISO strings without a zone, which are assumed to be UTC.
    """
    if isinstance(value, bool):
        raise AdapterError("not a timestamp")
    if isinstance(value, int):
        return _from_epoch(value), True
    if isinstance(value, float):
        if not math.isfinite(value):
            raise AdapterError("not a finite timestamp")
        return _from_epoch(value), True
    if not isinstance(value, str) or len(value) > 40:
        raise AdapterError("not a timestamp")
    return _from_iso(value)


def parse_timestamp(value: object) -> datetime:
    """Parse ``value`` to an aware UTC datetime; zone-less strings are taken as UTC."""
    return parse_timestamp_with_zone_flag(value)[0]


def parse_timestamp_or_none(value: object) -> datetime | None:
    try:
        return parse_timestamp(value)
    except ValueError:  # AdapterError is a ValueError
        return None
