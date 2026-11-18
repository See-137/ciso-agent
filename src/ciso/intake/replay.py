"""Memory of central gate message ids already accepted, for replay protection.

An id is remembered until its timestamp leaves the tolerance window; after that the
signature check refuses the delivery anyway. The memory is bounded and the caller provides
it (one per process, or a shared one). When it is full of unexpired ids it refuses new
deliveries instead of forgetting an id early, because forgetting would reopen the replay
window.
"""

from __future__ import annotations

import threading
from datetime import datetime
from typing import Protocol, runtime_checkable

from ciso.common.errors import FailClosed


@runtime_checkable
class SeenMessages(Protocol):
    def remember(self, message_id: str, *, now: datetime, until: datetime) -> bool:
        """True the first time `message_id` is seen (it is then kept until `until`);
        False when it was already seen and has not expired. Raises `FailClosed` when the
        id cannot be remembered."""
        ...


class BoundedSeenMessages:
    """In-memory `SeenMessages`. `capacity` has no default: `None` refuses every id."""

    def __init__(self, capacity: int | None = None) -> None:
        if capacity is not None and capacity <= 0:
            raise ValueError("replay memory capacity must be positive")
        self._capacity = capacity
        self._until: dict[str, datetime] = {}
        self._lock = threading.Lock()

    def remember(self, message_id: str, *, now: datetime, until: datetime) -> bool:
        if self._capacity is None:
            raise FailClosed("replay memory capacity is not configured")
        with self._lock:
            expired = [key for key, end in self._until.items() if end < now]
            for key in expired:
                del self._until[key]
            if message_id in self._until:
                return False
            if len(self._until) >= self._capacity:
                raise FailClosed("replay memory is full")
            self._until[message_id] = until
            return True
