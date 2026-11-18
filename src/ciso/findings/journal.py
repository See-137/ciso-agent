"""Audit records of the findings service. Never called inside a database transaction.

Details carry ids, references, statuses and reason codes; never a false-positive reason,
command text or content.
"""

from __future__ import annotations

import logging
from collections.abc import Mapping
from typing import Any

from ciso.common.enums import ActorType, AuditOutcome
from ciso.common.errors import FailClosed
from ciso.common.protocols import AuditEvent, AuditReceipt, AuditSink

logger = logging.getLogger(__name__)


class Journal:
    def __init__(self, audit: AuditSink) -> None:
        self._audit = audit

    def emit(
        self,
        action: str,
        actor_id: str,
        actor_type: ActorType,
        outcome: AuditOutcome,
        target: str,
        details: Mapping[str, Any],
    ) -> AuditReceipt:
        return self._audit.append(
            AuditEvent(
                actor_id=actor_id,
                actor_type=actor_type,
                action=action,
                target=target,
                outcome=outcome,
                details=dict(details),
            )
        )

    def attempt(
        self,
        action: str,
        actor_id: str,
        actor_type: ActorType,
        target: str,
        details: Mapping[str, Any],
    ) -> None:
        """Record the attempt, or raise: without it nothing may change."""
        try:
            self.emit(action, actor_id, actor_type, AuditOutcome.ATTEMPT, target, details)
        except Exception as exc:
            raise FailClosed("attempt could not be audited; nothing changed") from exc

    def best_effort(
        self,
        action: str,
        actor_id: str,
        actor_type: ActorType,
        outcome: AuditOutcome,
        target: str,
        details: Mapping[str, Any],
    ) -> None:
        """Audit a refusal or a failure whose own exception the caller raises next."""
        try:
            self.emit(action, actor_id, actor_type, outcome, target, details)
        except Exception as exc:
            # The type name only: a sink's own message could quote the event.
            logger.error(
                "findings: %s %s could not be audited (%s)",
                action,
                outcome.value,
                type(exc).__name__,
            )
