"""Audit records of the approval service. Never called inside a database transaction.

Details carry ids, hashes, roles and reason codes. They never carry a decision note.
"""

from __future__ import annotations

import logging
from collections.abc import Mapping
from typing import Any, NoReturn

from ciso.approvals.models import (
    Approval,
    ApprovalFault,
    ApprovalReason,
    ApprovalUnavailable,
)
from ciso.common.enums import ActorType, AuditOutcome
from ciso.common.protocols import AuditEvent, AuditReceipt, AuditSink
from ciso.common.schemas import content_hash

logger = logging.getLogger(__name__)


class Journal:
    def __init__(self, audit: AuditSink) -> None:
        self._audit = audit

    def emit(
        self,
        action: str,
        record: Approval,
        actor_id: str,
        actor_type: ActorType,
        outcome: AuditOutcome,
        extra: Mapping[str, Any],
    ) -> AuditReceipt:
        details: dict[str, Any] = {
            "subject_kind": record.subject_kind,
            "subject_hash": record.subject_hash,
            "binding_hash": content_hash(dict(record.binding)),
            "requested_by": record.requested_by,
            "parties": list(record.parties),
            "required_roles": [r.value for r in record.required_roles],
            "expires_at": record.expires_at.isoformat(),
            **extra,
        }
        return self._audit.append(
            AuditEvent(
                actor_id=actor_id, actor_type=actor_type, action=action, target=record.ref,
                outcome=outcome, correlation_id=record.correlation_id, details=details,
            )
        )  # fmt: skip

    def attempt(
        self,
        action: str,
        record: Approval,
        actor_id: str,
        actor_type: ActorType,
        extra: Mapping[str, Any],
    ) -> None:
        """Record the attempt, or raise: without it nothing may change."""
        try:
            self.emit(action, record, actor_id, actor_type, AuditOutcome.ATTEMPT, extra)
        except Exception as exc:
            raise ApprovalUnavailable(
                ApprovalReason.AUDIT_UNAVAILABLE, "attempt could not be audited; nothing changed"
            ) from exc

    def deny(
        self,
        action: str,
        record: Approval,
        actor_id: str,
        actor_type: ActorType,
        fault: ApprovalFault,
    ) -> NoReturn:
        """Audit a refusal against an existing approval, then raise it either way."""
        try:
            self.emit(action, record, actor_id, actor_type, AuditOutcome.DENIED,
                      {"reason": fault.reason.value})  # fmt: skip
        except Exception as exc:
            # The type name only: a sink's own message could quote the event.
            logger.error(
                "approvals: refusal of %s could not be audited (%s)", action, type(exc).__name__
            )
        raise fault
