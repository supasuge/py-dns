"""
Token bucket rate limiter.

Why token bucket over a simple counter?
  - Allows short bursts up to `capacity` without throttling
  - Smooths steady-state flow to `rate` tokens/second
  - O(1) per check — no queue, no history

Usage:
    limiter = TokenBucket(rate=50, capacity=100)
    if not limiter.consume():
        raise RateLimitError("too many DNS queries")

To make it per-client (e.g. per source IP), keep a dict of buckets:
    buckets: dict[str, TokenBucket] = defaultdict(lambda: TokenBucket(10, 50))
    if not buckets[client_ip].consume():
        ...
"""

from __future__ import annotations

import time


class RateLimitExceeded(Exception):
    pass


class TokenBucket:
    """
    Thread-unsafe (acceptable for single-threaded async or single-threaded sync).
    For multi-threaded use, wrap consume() in a threading.Lock.

    rate     : tokens added per second (refill rate)
    capacity : maximum tokens (burst ceiling)
    """

    def __init__(self, rate: float, capacity: float) -> None:
        if rate <= 0 or capacity <= 0:
            raise ValueError("rate and capacity must be positive")
        self._rate     = rate
        self._capacity = capacity
        self._tokens   = float(capacity)   # start full
        self._last     = time.monotonic()

    def consume(self, tokens: float = 1.0) -> bool:
        """
        Attempt to consume `tokens` tokens.

        Returns True if successful (request allowed),
                False if the bucket is dry (request should be dropped).
        """
        self._refill()
        if self._tokens >= tokens:
            self._tokens -= tokens
            return True
        return False

    def consume_or_raise(self, tokens: float = 1.0) -> None:
        if not self.consume(tokens):
            raise RateLimitExceeded(
                f"Rate limit exceeded: {self._rate} req/s (burst {self._capacity})"
            )

    def _refill(self) -> None:
        now     = time.monotonic()
        elapsed = now - self._last
        self._tokens = min(self._capacity, self._tokens + elapsed * self._rate)
        self._last   = now

    @property
    def available(self) -> float:
        self._refill()
        return self._tokens