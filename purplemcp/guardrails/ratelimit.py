"""Rate limiting — the fix for **tool abuse and runaway loops**.

A compromised or confused model can hammer a tool (scraping, brute force, a
billing-costly API). A per-key sliding-window limiter caps that blast radius.
"""

from __future__ import annotations

import time
from collections import defaultdict, deque


class RateLimitExceeded(Exception):
    """Raised when a caller exceeds its allowed rate."""


class RateLimiter:
    """Sliding-window limiter: at most ``max_calls`` per ``per_seconds`` per key."""

    def __init__(self, max_calls: int, per_seconds: float) -> None:
        self.max_calls = max_calls
        self.per_seconds = per_seconds
        self._events: dict[str, deque[float]] = defaultdict(deque)

    def check(self, key: str = "default") -> None:
        """Record a call, or raise :class:`RateLimitExceeded` if over the limit."""
        now = time.monotonic()
        window = self._events[key]
        cutoff = now - self.per_seconds
        while window and window[0] < cutoff:
            window.popleft()
        if len(window) >= self.max_calls:
            raise RateLimitExceeded(
                f"rate limit exceeded: {self.max_calls} per {self.per_seconds}s "
                f"(key={key!r})"
            )
        window.append(now)

    def allowed(self, key: str = "default") -> bool:
        """Non-raising variant: True if the call is within the limit."""
        try:
            self.check(key)
            return True
        except RateLimitExceeded:
            return False
