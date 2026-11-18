"""The one path every privileged identity change takes (reviews H2 and F7).

Order, for every state change:
1. Re-resolve the caller from the database by actor id (a `Principal` object handed in is
   never trusted: it may be forged or stale). Refused: audit DENIED, raise.
2. Audit an ATTEMPT record. If that fails, stop: nothing has changed.
3. Make the change in a short `BEGIN IMMEDIATE` transaction, re-checking the caller inside
   it. No audit write happens while the write lock is held.
4. Audit the RESULT. If that fails, raise `FailClosed`; the change stands and the ATTEMPT
   record shows it was made.
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from datetime import datetime
from typing import Any

from sqlalchemy import Connection, Engine

from ciso.common.clock import Clock
from ciso.common.db import read_connection
from ciso.common.enums import ActorType, AuditOutcome
from ciso.common.errors import AuthorizationError, FailClosed
from ciso.common.principal import Principal
from ciso.common.protocols import AuditSink
from ciso.identity.store import admin_refusal, find_actor, write_audit

logger = logging.getLogger(__name__)

#: Returns why `actor_id` may not act, or None. Runs before and inside the transaction.
Authorizer = Callable[[Connection, str, datetime], str | None]
#: Makes the change; returns the result and the details for the RESULT audit record.
Change = Callable[[Connection, datetime], tuple[Any, dict[str, Any]]]

Caller = Principal | str


def caller_id(by: Caller) -> str:
    """Only the actor id of a caller is used; roles on a Principal object are ignored."""
    return by if isinstance(by, str) else by.actor_id


class AdminGate:
    def __init__(self, engine: Engine, clock: Clock, audit: AuditSink) -> None:
        self._engine = engine
        self._clock = clock
        self._audit = audit

    def run(
        self,
        by: Caller,
        action: str,
        target: str,
        details: dict[str, Any],
        change: Change,
        authorize: Authorizer = admin_refusal,
    ) -> Any:
        """Run `change` under the ordering in the module docstring and return its result."""
        actor_id = caller_id(by)
        now = self._clock.now()
        with read_connection(self._engine) as conn:
            refusal = authorize(conn, actor_id, now)
            actor = find_actor(conn, actor_id)
        actor_type = actor.actor_type if actor is not None else ActorType.ANONYMOUS
        if refusal is not None:
            self._record(
                actor_id, actor_type, action, target, AuditOutcome.DENIED, {"reason": refusal}
            )
            logger.info("identity: %s on %s denied (%s)", action, target, refusal)
            raise AuthorizationError(f"{action} refused: {refusal}")

        self._record(actor_id, actor_type, action, target, AuditOutcome.ATTEMPT, details)
        try:
            with self._engine.begin() as conn:
                refusal = authorize(conn, actor_id, now)
                if refusal is not None:
                    raise AuthorizationError(f"{action} refused: {refusal}")
                result, result_details = change(conn, now)
        except Exception as exc:
            self._record_failure(actor_id, actor_type, action, target, exc)
            raise
        try:
            self._record(actor_id, actor_type, action, target, AuditOutcome.SUCCESS, result_details)
        except FailClosed:
            logger.error(
                "identity: %s on %s was made but its result was not audited", action, target
            )
            raise
        logger.info("identity: %s on %s done", action, target)
        return result

    def _record(
        self,
        actor_id: str,
        actor_type: ActorType,
        action: str,
        target: str,
        outcome: AuditOutcome,
        details: dict[str, Any],
    ) -> None:
        write_audit(
            self._audit,
            actor_id=actor_id,
            actor_type=actor_type,
            action=action,
            target=target,
            outcome=outcome,
            details=details,
        )

    def _record_failure(
        self, actor_id: str, actor_type: ActorType, action: str, target: str, exc: Exception
    ) -> None:
        """Audit why the change did not happen. The original error is what the caller sees."""
        outcome = (
            AuditOutcome.DENIED if isinstance(exc, AuthorizationError) else AuditOutcome.FAILED
        )
        details = {"error": type(exc).__name__, "message": str(exc)}
        try:
            self._record(actor_id, actor_type, action, target, outcome, details)
        except FailClosed:
            logger.error("identity: could not audit the failed %s on %s", action, target)
