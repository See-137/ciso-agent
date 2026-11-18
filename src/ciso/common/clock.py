"""Injectable UTC clock. No module calls datetime.now() directly."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Protocol

from ciso.common.errors import ValidationFailed


class Clock(Protocol):
    def now(self) -> datetime:
        """Current time, timezone-aware, UTC."""
        ...


class SystemClock:
    def now(self) -> datetime:
        return datetime.now(UTC)


class FixedClock:
    """Test clock. Time moves only when told to."""

    def __init__(self, start: datetime | None = None) -> None:
        self._now = start or datetime(2026, 11, 17, 12, 0, 0, tzinfo=UTC)
        if self._now.tzinfo is None:
            raise ValueError("FixedClock needs a timezone-aware datetime")

    def now(self) -> datetime:
        return self._now

    def advance(self, delta: timedelta | None = None, **kwargs: float) -> datetime:
        self._now = self._now + (delta if delta is not None else timedelta(**kwargs))
        return self._now


def ensure_utc(value: datetime) -> datetime:
    """Reject naive datetimes; normalise aware ones to UTC."""
    if value.tzinfo is None:
        raise ValidationFailed("naive datetime is not allowed; attach a timezone")
    return value.astimezone(UTC)
