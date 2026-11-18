"""In-process fixed-window rate limiter for the API (gap G22, blueprint 5.1 #2).

The limit comes from `SafetySettings.api_rate_limit_per_minute`. `None` means the limit
is not configured, and the API then refuses every non-public request: no number is
invented (G14, ADR-0019). Time comes from the injected `Clock`.

Keys are strings chosen by the caller: `actor:<id>` after authentication and
`addr:<host>` before it. State lives in this object only, so it resets on restart and is
not shared between processes; that is acceptable for the single-process build (ADR-0010).
"""

from __future__ import annotations

import math
import threading
from datetime import datetime, timedelta

from ciso.common.clock import Clock
from ciso.common.errors import FailClosed, ValidationFailed
from ciso.common.schemas import Model

WINDOW = timedelta(minutes=1)
#: Expired windows are swept when the table grows past this many keys.
_SWEEP_AT = 1024


class RateDecision(Model):
    allowed: bool
    retry_after_seconds: int = 0


class RateLimiter:
    """Allows `limit_per_minute` hits per key per fixed one-minute window."""

    def __init__(self, clock: Clock, limit_per_minute: int | None) -> None:
        if limit_per_minute is not None and limit_per_minute < 1:
            raise ValidationFailed("limit_per_minute must be positive")
        self._clock = clock
        self._limit = limit_per_minute
        self._lock = threading.Lock()
        self._windows: dict[str, tuple[datetime, int]] = {}

    @property
    def configured(self) -> bool:
        return self._limit is not None

    def hit(self, key: str) -> RateDecision:
        """Count one request for `key`. Raises `FailClosed` when no limit is configured."""
        limit = self._limit
        if limit is None:
            raise FailClosed("api rate limit is not configured")
        now = self._clock.now()
        with self._lock:
            if len(self._windows) > _SWEEP_AT:
                self._sweep(now)
            start, count = self._windows.get(key, (now, 0))
            if now >= start + WINDOW:
                start, count = now, 0
            if count >= limit:
                self._windows[key] = (start, count)
                remaining = (start + WINDOW - now).total_seconds()
                return RateDecision(allowed=False, retry_after_seconds=max(1, math.ceil(remaining)))
            self._windows[key] = (start, count + 1)
            return RateDecision(allowed=True)

    def refund(self, key: str) -> None:
        """Give back one hit counted for `key` in its current window (no-op otherwise).

        Used for the address budget: a request is charged to its address before
        authentication and refunded once it authenticates, so only failures accumulate.
        """
        now = self._clock.now()
        with self._lock:
            current = self._windows.get(key)
            if current is not None and now < current[0] + WINDOW and current[1] > 0:
                self._windows[key] = (current[0], current[1] - 1)

    def _sweep(self, now: datetime) -> None:
        self._windows = {k: v for k, v in self._windows.items() if now < v[0] + WINDOW}
