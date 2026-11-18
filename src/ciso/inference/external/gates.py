"""The refusals that need no stored state, shared by authorize and transmit
(blueprint 8.4; gaps G12, G26; ADR-0006, ADR-0021).

Order: feature flag, kill switch, approver role, transport, allowed classifications,
payload limit, response limit, actor. Every default refuses.
"""

from __future__ import annotations

import logging
from typing import NamedTuple

from ciso.common.enums import APPROVER_ROLES, ActorType, KillCapability, Role
from ciso.common.errors import ValidationFailed
from ciso.common.protocols import KillSwitchReader, PrincipalResolver
from ciso.inference.external.records import GateReason

_LOG = logging.getLogger(__name__)


def byte_limit(value: object, name: str) -> int | None:
    """A size limit as configured: None (refuse) or a positive whole number."""
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise ValidationFailed(f"{name} must be a positive number of bytes or None")
    return value


class Caller(NamedTuple):
    """The actor as the identity store sees it now. `resolved` False means the store
    could not be asked; `known` False means it has no such enabled actor."""

    actor_id: str
    actor_type: ActorType
    known: bool
    resolved: bool


class Gates:
    def __init__(
        self,
        *,
        principals: PrincipalResolver,
        killswitch: KillSwitchReader,
        enabled: bool,
        approver_role: Role | None,
        allowed_classifications: frozenset[str],
        has_transport: bool,
        max_payload_bytes: int | None,
        max_response_bytes: int | None,
    ) -> None:
        self._principals = principals
        self._killswitch = killswitch
        self._enabled = enabled
        self._approver_role = approver_role
        self._allowed = allowed_classifications
        self._has_transport = has_transport
        self._max_payload = max_payload_bytes
        self._max_response = max_response_bytes

    def who(self, actor_id: str) -> Caller:
        """Resolve the actor id now. A `Principal` object would only be a snapshot."""
        try:
            principal = self._principals.resolve(actor_id)
        except Exception as exc:
            _LOG.warning("external inference: identity unavailable (%s)", type(exc).__name__)
            return Caller(actor_id, ActorType.ANONYMOUS, known=False, resolved=False)
        if principal is None:
            return Caller(actor_id, ActorType.ANONYMOUS, known=False, resolved=True)
        return Caller(principal.actor_id, principal.actor_type, known=True, resolved=True)

    def refusal(self, caller: Caller) -> GateReason | None:
        """Why this call may not go on, or None."""
        if self._enabled is not True:
            return GateReason.FEATURE_DISABLED
        return self.kill_switch() or self._settings() or self._actor(caller)

    def kill_switch(self) -> GateReason | None:
        """Read the kill switch now. Blocked, unreadable or anything but a plain False
        is a refusal."""
        try:
            blocked = self._killswitch.is_blocked(KillCapability.EXTERNAL_INFERENCE)
        except Exception as exc:
            _LOG.warning("external inference: kill switch unreadable (%s)", type(exc).__name__)
            return GateReason.KILL_SWITCH_UNAVAILABLE
        return None if blocked is False else GateReason.KILL_SWITCH_ENGAGED

    def _settings(self) -> GateReason | None:
        if self._approver_role is None:
            return GateReason.APPROVER_ROLE_UNSET
        if self._approver_role not in APPROVER_ROLES:
            return GateReason.APPROVER_ROLE_NOT_ALLOWED
        if not self._has_transport:
            return GateReason.TRANSPORT_ABSENT
        if not self._allowed:
            return GateReason.NO_ALLOWED_CLASSIFICATIONS
        if self._max_payload is None:
            return GateReason.PAYLOAD_LIMIT_UNSET
        if self._max_response is None:
            return GateReason.RESPONSE_LIMIT_UNSET
        return None

    @staticmethod
    def _actor(caller: Caller) -> GateReason | None:
        if not caller.resolved:
            return GateReason.IDENTITY_UNAVAILABLE
        if not caller.known:
            return GateReason.ACTOR_UNKNOWN
        if caller.actor_type is not ActorType.HUMAN:
            return GateReason.ACTOR_NOT_HUMAN
        return None
