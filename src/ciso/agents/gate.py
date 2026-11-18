"""The one path every registry change takes (brief cross-cutting rules 1 and 2).

Order, for every change:
1. Resolve the caller NOW through the injected `PrincipalResolver`, by actor id only. A
   resolver that raises is a refusal (`FailClosed`). Refused: audit DENIED, raise.
2. Audit an ATTEMPT. If that fails nothing has changed.
3. Make the change in one short `BEGIN IMMEDIATE` transaction. Neither the audit sink nor
   the resolver is called while it is open.
4. Audit the RESULT (SUCCESS, or DENIED / FAILED with the error). A failed RESULT audit
   raises `FailClosed`; the change stands and the ATTEMPT record shows it was tried.
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from datetime import datetime
from typing import Any, NamedTuple

from sqlalchemy import Connection, Engine

from ciso.agents.models import AgentsRefused, RefusalCode
from ciso.common.clock import Clock
from ciso.common.enums import ActorType, AuditOutcome, Role
from ciso.common.errors import AuthorizationError, FailClosed
from ciso.common.principal import Principal
from ciso.common.protocols import AuditEvent, AuditSink, PrincipalResolver

logger = logging.getLogger(__name__)

Caller = Principal | str


class Acting(NamedTuple):
    """The caller as resolved now. `is_admin`: active human, unnarrowed security_admin."""

    actor_id: str
    is_admin: bool


#: Makes the change; returns the result and the details for the RESULT audit record.
Change = Callable[[Connection, datetime, Acting], tuple[Any, dict[str, Any]]]


def caller_id(by: Caller) -> str:
    """Only the actor id of a caller is used; roles on a Principal object are ignored."""
    return by if isinstance(by, str) else by.actor_id


def write_audit(audit: AuditSink, event: AuditEvent) -> None:
    try:
        audit.append(event)
    except FailClosed:
        raise
    except Exception as exc:
        raise FailClosed("audit path unavailable") from exc


class AdminGate:
    def __init__(
        self, engine: Engine, clock: Clock, audit: AuditSink, principals: PrincipalResolver
    ) -> None:
        self._engine = engine
        self._clock = clock
        self._audit = audit
        self._principals = principals

    def run(
        self,
        by: Caller,
        action: str,
        target: str,
        details: dict[str, Any],
        change: Change,
        *,
        admin_only: bool = True,
    ) -> Any:
        """Run `change` in the order of the module docstring and return its result.

        `admin_only=False` lets any active human through to `change`, which must then check
        `Acting.is_admin` or the person's own responsibility itself.
        """
        actor_id = caller_id(by)
        try:
            principal = self._principals.resolve(actor_id)
        except Exception as exc:
            self._deny(
                actor_id, ActorType.ANONYMOUS, action, target, RefusalCode.RESOLVER_UNAVAILABLE
            )
            raise FailClosed(f"{action} refused: identity could not be consulted") from exc
        actor_type = principal.actor_type if principal is not None else ActorType.ANONYMOUS
        refusal = _refusal(principal, admin_only)
        if refusal is not None:
            self._deny(actor_id, actor_type, action, target, refusal)
            raise AgentsRefused(refusal, action)
        assert principal is not None
        acting = Acting(actor_id, principal.covers(Role.SECURITY_ADMIN, {}))

        self._record(actor_id, actor_type, action, target, AuditOutcome.ATTEMPT, details)
        try:
            with self._engine.begin() as conn:
                result, result_details = change(conn, self._clock.now(), acting)
        except Exception as exc:
            self._record_failure(actor_id, actor_type, action, target, exc)
            raise
        self._record(actor_id, actor_type, action, target, AuditOutcome.SUCCESS, result_details)
        logger.info("agents: %s on %s done", action, target)
        return result

    def _deny(
        self, actor_id: str, actor_type: ActorType, action: str, target: str, code: RefusalCode
    ) -> None:
        logger.info("agents: %s on %s refused (%s)", action, target, code.value)
        details = {"reason": code.value}
        self._record(actor_id, actor_type, action, target, AuditOutcome.DENIED, details)

    def _record(
        self,
        actor_id: str,
        actor_type: ActorType,
        action: str,
        target: str,
        outcome: AuditOutcome,
        details: dict[str, Any],
    ) -> None:
        event = AuditEvent(
            actor_id=actor_id,
            actor_type=actor_type,
            action=action,
            target=target,
            outcome=outcome,
            details=details,
        )
        write_audit(self._audit, event)

    def _record_failure(
        self, actor_id: str, actor_type: ActorType, action: str, target: str, exc: Exception
    ) -> None:
        """Audit why the change did not happen. The original error is what the caller sees."""
        denied = isinstance(exc, AuthorizationError)
        outcome = AuditOutcome.DENIED if denied else AuditOutcome.FAILED
        code = getattr(exc, "code", None)
        details: dict[str, Any] = {"error": type(exc).__name__}
        if isinstance(code, RefusalCode):
            details["reason"] = code.value
        try:
            self._record(actor_id, actor_type, action, target, outcome, details)
        except FailClosed:
            logger.error("agents: could not audit the failed %s on %s", action, target)


def _refusal(principal: Principal | None, admin_only: bool) -> RefusalCode | None:
    if principal is None:
        return RefusalCode.UNKNOWN_CALLER
    if not principal.is_human:
        return RefusalCode.CALLER_NOT_HUMAN
    if admin_only and not principal.covers(Role.SECURITY_ADMIN, {}):
        return RefusalCode.CALLER_NOT_SECURITY_ADMIN
    return None
