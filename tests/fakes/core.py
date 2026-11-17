"""In-memory stand-ins for the cross-module protocols. Import as `tests.fakes.core`."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from ciso.common.clock import Clock, FixedClock
from ciso.common.enums import ActorType, KillCapability, Role
from ciso.common.errors import FailClosed, NotFound
from ciso.common.ids import new_id
from ciso.common.principal import Principal
from ciso.common.protocols import AuditEvent, AuditReceipt
from ciso.common.schemas import content_hash


def make_principal(
    actor_id: str = "human_admin",
    actor_type: ActorType = ActorType.HUMAN,
    *roles: Role,
    scopes: dict[str, frozenset[str]] | None = None,
) -> Principal:
    return Principal(
        actor_id=actor_id, actor_type=actor_type, roles=frozenset(roles), scopes=scopes or {}
    )


class FakeAudit:
    """Records events in a list. Set `fail = True` to simulate an unavailable audit path."""

    def __init__(self, clock: Clock | None = None) -> None:
        self.events: list[AuditEvent] = []
        self.fail = False
        self._clock: Clock = clock or FixedClock()

    def append(self, event: AuditEvent) -> AuditReceipt:
        if self.fail:
            raise FailClosed("audit path unavailable")
        self.events.append(event)
        return AuditReceipt(
            record_id=new_id("aud"),
            seq=len(self.events),
            occurred_at=self._clock.now(),
            hash=content_hash(event),
        )

    def actions(self) -> list[str]:
        return [event.action for event in self.events]

    def find(self, action: str) -> list[AuditEvent]:
        return [event for event in self.events if event.action == action]


class FakeKillSwitch:
    """`blocked` holds engaged capabilities. `broken = True` simulates an unreadable state."""

    def __init__(self) -> None:
        self.blocked: set[KillCapability] = set()
        self.broken = False
        self.reads: list[KillCapability] = []

    def is_blocked(self, capability: KillCapability) -> bool:
        self.reads.append(capability)
        return True if self.broken else capability in self.blocked


class FakeSecret:
    def __init__(self, value: str) -> None:
        self._value = value

    def reveal(self) -> str:
        return self._value

    def __repr__(self) -> str:
        return "FakeSecret(***)"


class FakeSecrets:
    def __init__(self, values: dict[str, str] | None = None) -> None:
        self._values = dict(values or {})
        self.requested: list[str] = []

    def get(self, ref: str) -> FakeSecret:
        self.requested.append(ref)
        if ref not in self._values:
            raise NotFound(f"no such secret: {ref}")
        return FakeSecret(self._values[ref])


class FakeRedactor:
    """Replaces each registered value with `[REDACTED]`. Enough for callers' tests."""

    def __init__(self, *values: str) -> None:
        self._values = [value for value in values if value]
        self.calls = 0

    def redact(self, text: str) -> str:
        self.calls += 1
        for value in self._values:
            text = text.replace(value, "[REDACTED]")
        return text

    def redact_value(self, value: Any) -> Any:
        if isinstance(value, str):
            return self.redact(value)
        if isinstance(value, dict):
            return {key: self.redact_value(item) for key, item in value.items()}
        if isinstance(value, list | tuple):
            return [self.redact_value(item) for item in value]
        return value


def at(clock: FixedClock) -> datetime:
    return clock.now()
