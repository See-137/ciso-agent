"""Interfaces that cross module boundaries.

Modules depend on these, not on each other's implementations, so the audit log, the kill
switch, the secret store and the redactor can each be replaced or faked.
"""

from __future__ import annotations

from typing import Any, Protocol, runtime_checkable

from pydantic import Field

from ciso.common.enums import ActorType, AuditOutcome, KillCapability
from ciso.common.principal import Principal
from ciso.common.schemas import Model, UtcDatetime


class AuditEvent(Model):
    """What a caller hands to the audit log. The log adds id, sequence, time and hashes.

    `action` is a dotted verb such as `policy.evaluate` or `killswitch.engage`.
    `details` must hold references and metadata, never raw secrets or bulk content; the
    log redacts it again on the way in.
    """

    actor_id: str
    actor_type: ActorType
    action: str
    target: str = ""
    outcome: AuditOutcome
    correlation_id: str = ""
    details: dict[str, Any] = Field(default_factory=dict)


class AuditReceipt(Model):
    record_id: str
    seq: int
    occurred_at: UtcDatetime
    hash: str


@runtime_checkable
class AuditSink(Protocol):
    def append(self, event: AuditEvent) -> AuditReceipt:
        """Record the event or raise. A caller that cannot audit must not proceed."""
        ...


@runtime_checkable
class KillSwitchReader(Protocol):
    def is_blocked(self, capability: KillCapability) -> bool:
        """True when the capability is stopped, and also when the state cannot be read."""
        ...


@runtime_checkable
class RevealableSecret(Protocol):
    def reveal(self) -> str:
        """The secret itself. Call at the last possible moment; never log the result."""
        ...


@runtime_checkable
class SecretResolver(Protocol):
    def get(self, ref: str) -> RevealableSecret:
        """Resolve `secret://<name>`. Raises NotFound; never returns an empty value."""
        ...


@runtime_checkable
class Redactor(Protocol):
    def redact(self, text: str) -> str:
        """Remove known secret values and token-shaped strings."""
        ...

    def redact_value(self, value: Any) -> Any:
        """Same, applied through nested dicts, lists and strings. Returns a new value."""
        ...


@runtime_checkable
class PrincipalResolver(Protocol):
    def resolve(self, actor_id: str) -> Principal | None:
        """The actor as the identity store sees it NOW, or None if unknown or disabled.

        A `Principal` object is only a snapshot: it can be stale (the role was revoked
        since) or simply made up by the caller. Any component that makes a privilege
        decision must call this with the actor id and decide on the result, never on the
        object it was handed. A resolver that cannot answer raises; callers treat that as
        a refusal.
        """
        ...
