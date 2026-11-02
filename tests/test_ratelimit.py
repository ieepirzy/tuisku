from tuisku.api.ratelimit import RateLimiter


class FakeTime:
    def __init__(self) -> None:
        self.now = 0.0

    def __call__(self) -> float:
        return self.now


def test_bucket_admits_until_empty_then_refills() -> None:
    t = FakeTime()
    limiter = RateLimiter(rate=2, burst=4, monotonic=t)
    assert limiter.take(1, 4) is None
    assert limiter.take(1, 1) == 1  # empty: retry after 1/rate rounded up
    t.now = 0.5  # one token back
    assert limiter.take(1, 1) is None
    assert limiter.take(1, 1) == 1


def test_a_batch_larger_than_the_burst_is_admitted_once_then_repaid() -> None:
    t = FakeTime()
    limiter = RateLimiter(rate=1, burst=2, monotonic=t)
    assert limiter.take(7, 5) is None  # tokens: 2 - 5 = -3
    assert limiter.take(7, 1) == 4
    t.now = 4
    assert limiter.take(7, 1) is None


def test_refill_is_capped_at_the_burst() -> None:
    t = FakeTime()
    limiter = RateLimiter(rate=10, burst=3, monotonic=t)
    assert limiter.take(1, 3) is None
    t.now = 100
    assert limiter.take(1, 3) is None
    assert limiter.take(1, 1) is not None
