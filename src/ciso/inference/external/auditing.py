"""Audit records of the external path's gateway. Never called inside a database
transaction. Details carry ids, hashes, counts and reason codes: never item text, purpose
text, payload bytes or answer text.
"""

from __future__ import annotations

from typing import Any, NoReturn

from ciso.common.enums import AuditOutcome
from ciso.common.errors import FailClosed
from ciso.common.protocols import AuditEvent, AuditSink
from ciso.inference.external.gates import Caller
from ciso.inference.external.records import ExternalGateRefused, GateReason


class GateAudit:
    def __init__(self, audit: AuditSink) -> None:
        self._audit = audit

    def emit(
        self,
        action: str,
        caller: Caller,
        target: str,
        outcome: AuditOutcome,
        details: dict[str, Any],
        correlation_id: str,
    ) -> None:
        """Write one event or raise `FailClosed`: no audit record, no step."""
        event = AuditEvent(
            actor_id=caller.actor_id,
            actor_type=caller.actor_type,
            action=action,
            target=target,
            outcome=outcome,
            correlation_id=correlation_id,
            details=details,
        )
        try:
            self._audit.append(event)
        except FailClosed:
            raise
        except Exception as exc:
            raise FailClosed("audit path unavailable; external inference step refused") from exc

    def refuse(
        self,
        action: str,
        caller: Caller,
        target: str,
        reason: GateReason,
        correlation_id: str,
        *,
        approval_reason: str | None = None,
        cause: BaseException | None = None,
        extra: dict[str, Any] | None = None,
    ) -> NoReturn:
        """Audit the refusal as DENIED, then raise it. If it cannot be audited,
        `FailClosed` is raised instead; nothing is sent either way."""
        details: dict[str, Any] = {"reason": reason.value, **(extra or {})}
        if approval_reason is not None:
            details["approval_reason"] = approval_reason
        if cause is not None:
            details["cause_type"] = type(cause).__name__
        self.emit(action, caller, target, AuditOutcome.DENIED, details, correlation_id)
        raise ExternalGateRefused(reason, approval_reason) from cause
