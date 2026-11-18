"""Who may change a channel, and how a refusal is recorded (plan gaps G12, G13; review
finding L3). Used only by `ciso.execution.channels.ChannelRegistry`.

Every method here runs outside any database transaction: it calls the identity resolver
and the audit sink, and neither may be called while the write lock is held.
"""

from __future__ import annotations

import logging

from ciso.common.enums import ActorType, AuditOutcome, Role
from ciso.common.errors import AuthorizationError, FailClosed
from ciso.common.principal import Principal
from ciso.common.protocols import AuditEvent, AuditSink, PrincipalResolver
from ciso.execution.channel_rules import (
    MAX_TEXT,
    ChannelInvalid,
    ChannelRefusal,
    clean_text,
    is_outbox_name,
    value_digest,
)

logger = logging.getLogger(__name__)

_INVALID_LABEL = "channel:(invalid)"
_MESSAGES = {
    ChannelRefusal.BAD_CHANNEL_NAME: "bad channel name",
    ChannelRefusal.BAD_TARGET: "a channel target must be a local outbox name",
    ChannelRefusal.BAD_TEXT: (
        f"purpose and reason must be non-blank, at most {MAX_TEXT} characters, and free of "
        "control and direction characters"
    ),
}


def label(channel: object) -> str:
    """The audit target. A name that is not a channel name is never written out."""
    return f"channel:{channel}" if is_outbox_name(channel) else _INVALID_LABEL


class ChannelAccess:
    def __init__(self, audit: AuditSink, principals: PrincipalResolver) -> None:
        self._audit = audit
        self._principals = principals

    def authorise(self, actor_id: str, action: str, channel: str, *, admin: bool) -> Principal:
        """Resolve the actor now and decide on that answer. Refusals are audited."""
        resolved: Principal | None = None
        unavailable: Exception | None = None
        try:
            resolved = self._principals.resolve(actor_id)
            why = self._refusal(actor_id, resolved, admin=admin)
        except Exception as exc:
            unavailable = exc
            why = f"identity could not be checked ({type(exc).__name__})"
        if why is None and resolved is not None:
            return resolved
        actor_type = ActorType.ANONYMOUS
        if resolved is not None and resolved.actor_id == actor_id:
            actor_type = resolved.actor_type
        event = AuditEvent(
            actor_id=str(actor_id)[:128],
            actor_type=actor_type,
            action=action,
            target=label(channel),
            outcome=AuditOutcome.DENIED,
            details={"reason": why},
        )
        self.audit_quietly(event)
        if unavailable is not None:
            raise FailClosed(why or "refused") from unavailable
        raise AuthorizationError(why or "refused")

    @staticmethod
    def _refusal(actor_id: str, resolved: Principal | None, *, admin: bool) -> str | None:
        if resolved is None:
            return "actor is unknown or disabled"
        if resolved.actor_id != actor_id:
            return "identity store answered for a different actor"
        if resolved.actor_type is ActorType.ANONYMOUS:
            return "an anonymous actor cannot change channels"
        if not admin:
            return None
        if resolved.actor_type is not ActorType.HUMAN:
            return "only a human may approve or revoke a channel"
        if not resolved.covers(Role.SECURITY_ADMIN, {}):
            return "approving or revoking a channel needs an unnarrowed security_admin role"
        return None

    def require_name(self, actor: Principal, action: str, channel: str) -> None:
        if not is_outbox_name(channel):
            raise self.refused(actor, action, channel, ChannelRefusal.BAD_CHANNEL_NAME, channel)

    def text(self, actor: Principal, action: str, channel: str, value: str) -> str:
        """The purpose or reason, cleaned, or a refusal that is audited first."""
        cleaned = clean_text(value)
        if cleaned is None:
            raise self.refused(actor, action, channel, ChannelRefusal.BAD_TEXT, value)
        return cleaned

    def refused(
        self, actor: Principal, action: str, channel: str, code: ChannelRefusal, value: object
    ) -> ChannelInvalid:
        """Audit a refused value as DENIED, by reason code and digest and never the value
        itself. Returns the error for the caller to raise."""
        event = AuditEvent(
            actor_id=actor.actor_id,
            actor_type=actor.actor_type,
            action=action,
            target=label(channel),
            outcome=AuditOutcome.DENIED,
            details={"reason": code.value, "value_sha256": value_digest(value)},
        )
        self.audit_quietly(event)
        return ChannelInvalid(code, _MESSAGES[code])

    def audit_quietly(self, event: AuditEvent) -> None:
        """Write a record about something already refused or already failed. The caller
        raises whether or not this record can be written."""
        try:
            self._audit.append(event)
        except Exception:
            logger.exception("channel registry: audit record %s could not be written", event.action)
