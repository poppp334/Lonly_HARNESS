#!/usr/bin/env python3
"""core/ratelimit.py — Thread-safe token-bucket rate limiter for capability execution.

Enforces per-capability and per-target execution rate limits across sessions.
"""
from __future__ import annotations

import threading
import time
from typing import Callable, Dict, Optional, Tuple


class TokenBucket:
    """Thread-safe fractional token bucket."""

    def __init__(
        self,
        rate_per_min: float,
        capacity: Optional[float] = None,
        clock: Callable[[], float] = time.monotonic,
        sleep: Callable[[float], None] = time.sleep,
    ):
        self.rate_per_sec = float(rate_per_min) / 60.0
        self.capacity = float(capacity if capacity is not None else max(1.0, float(rate_per_min)))
        self.tokens = self.capacity
        self.clock = clock
        self.sleep = sleep
        self.last_update = self.clock()
        self._lock = threading.Lock()

    def acquire(self, tokens: float = 1.0, max_wait: float = 0.0) -> bool:
        """Attempt to consume tokens. Waits up to max_wait if insufficient tokens are present."""
        with self._lock:
            now = self.clock()
            elapsed = max(0.0, now - self.last_update)
            self.last_update = now
            self.tokens = min(self.capacity, self.tokens + elapsed * self.rate_per_sec)

            if self.tokens >= tokens:
                self.tokens -= tokens
                return True

            needed = tokens - self.tokens
            wait_time = needed / self.rate_per_sec if self.rate_per_sec > 0 else float("inf")

            if wait_time <= max_wait:
                self.sleep(wait_time)
                self.last_update = self.clock()
                self.tokens = 0.0
                return True

            return False


class RateLimiter:
    """Registry of token buckets partitioned by capability and target."""

    def __init__(
        self,
        default_rate_per_min: float = 60.0,
        clock: Callable[[], float] = time.monotonic,
        sleep: Callable[[float], None] = time.sleep,
    ):
        self.default_rate = float(default_rate_per_min)
        self.clock = clock
        self.sleep = sleep
        self._buckets: Dict[Tuple[str, str], TokenBucket] = {}
        self._lock = threading.Lock()

    def acquire(
        self,
        capability: str,
        target: str = "",
        rate_per_min: Optional[float] = None,
        max_wait: float = 0.0,
    ) -> bool:
        """Acquire an execution permit for a given capability and target."""
        key = (str(capability), str(target or ""))
        rate = float(rate_per_min if rate_per_min is not None else self.default_rate)

        with self._lock:
            if key not in self._buckets:
                self._buckets[key] = TokenBucket(
                    rate_per_min=rate,
                    clock=self.clock,
                    sleep=self.sleep,
                )
            bucket = self._buckets[key]

        return bucket.acquire(tokens=1.0, max_wait=max_wait)
