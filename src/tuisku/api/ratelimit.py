"""Per-source token buckets for ingest (ADR 0005 "Per-source rate").

In-process: each API replica keeps its own buckets, so a deployment with N replicas behind a
load balancer admits up to N x rate records per second per source.

A request is admitted while the bucket is not empty and then takes one token per record, so
the bucket may go into debt. That lets a batch larger than the burst through once, and makes
the following requests wait until the debt is repaid; a batch is never refused forever.
"""

from __future__ import annotations

import math
import time
from collections.abc import Callable
from dataclasses import dataclass


@dataclass(slots=True)
class _Bucket:
    tokens: float
    updated: float


class RateLimiter:
    def __init__(
        self, rate: float, burst: float, monotonic: Callable[[], float] = time.monotonic
    ) -> None:
        if rate <= 0 or burst < 1:
            raise ValueError("rate must be > 0 and burst >= 1")
        self.rate = rate
        self.burst = burst
        self._monotonic = monotonic
        self._buckets: dict[int, _Bucket] = {}

    def take(self, key: int, n: int) -> int | None:
        """Admit ``n`` records for ``key``: None when admitted, else Retry-After seconds."""
        now = self._monotonic()
        bucket = self._buckets.get(key)
        if bucket is None:
            bucket = self._buckets[key] = _Bucket(tokens=self.burst, updated=now)
        else:
            elapsed = max(0.0, now - bucket.updated)
            bucket.tokens = min(self.burst, bucket.tokens + elapsed * self.rate)
            bucket.updated = now
        if bucket.tokens < 1:
            return max(1, math.ceil((1 - bucket.tokens) / self.rate))
        bucket.tokens -= n
        return None
