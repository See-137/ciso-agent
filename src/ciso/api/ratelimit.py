"""In-process fixed-window rate limiter for the API (gap G22, blueprint 5.1 #2).

The limit comes from `SafetySettings.api_rate_limit_per_minute`. `None` means the limit
is not configured, and the API then refuses every non-public request: no number is
invented (G14, ADR-0019). Time comes from the injected `Clock`.

Keys are strings chosen by the caller: `actor:<id>` after authentication and
`addr:<host>` before it. State lives in this object only, so it resets on restart and is
not shared between processes; that is acceptable for the single-process build (ADR-0010).
"""

from __future__ import annotations

import hashlib
import math
import threading
from collections import OrderedDict
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


#: Most token fingerprints `KnownTokens` remembers (least recently used is forgotten).
MAX_KNOWN_TOKENS = 4096


class KnownTokens:
    """Fingerprints (SHA-256) of bearer tokens that authenticated (review L5).

    Behind a reverse proxy every client shares one address, so a flood of bad tokens fills
    that address's pre-authentication budget and every hook would get 429. A token that
    authenticated before skips the address check (it still pays the authentication and
    its actor's own budget). A token that later fails is forgotten at once, so a revoked
    token cannot use the bypass to make the service hash for it.
    """

    def __init__(self, capacity: int = MAX_KNOWN_TOKENS) -> None:
        self._capacity = capacity
        self._seen: OrderedDict[str, None] = OrderedDict()
        self._lock = threading.Lock()

    @staticmethod
    def fingerprint(token: str) -> str:
        return hashlib.sha256(token.encode("utf-8")).hexdigest()

    def known(self, token: str) -> bool:
        key = self.fingerprint(token)
        with self._lock:
            if key in self._seen:
                self._seen.move_to_end(key)
                return True
            return False

    def remember(self, token: str) -> None:
        key = self.fingerprint(token)
        with self._lock:
            self._seen[key] = None
            self._seen.move_to_end(key)
            while len(self._seen) > self._capacity:
                self._seen.popitem(last=False)

    def forget(self, token: str) -> None:
        with self._lock:
            self._seen.pop(self.fingerprint(token), None)
