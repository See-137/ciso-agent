"""Host-local identity operations: never reachable from the API.

These two operations take no authenticated caller, so the composition root exposes them
only through a command-line entry point run on the host. Both follow the same order as
every other change: audit ATTEMPT, short transaction, audit RESULT.

- `bootstrap_first_admin` works once per database, ever (reviews H3, L5): it is refused
  if any `security_admin` assignment row has ever existed (revoked and lapsed included),
  and a single-row marker with a constant primary key makes two concurrent bootstraps
  impossible on any database.
- `recover_admin_token` is the way out of a lockout (ADR writer finding 2): it issues a
  fresh token to an existing, active, human `security_admin`, recording the operator.
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from datetime import datetime
from typing import Any

from sqlalchemy import Connection, Engine, select
from sqlalchemy.exc import IntegrityError

from ciso.common.clock import Clock
from ciso.common.enums import ActorType, AuditOutcome, Role
from ciso.common.errors import AuthorizationError, Conflict, FailClosed
from ciso.common.ids import new_id
from ciso.common.protocols import AuditSink
from ciso.common.schemas import Model
from ciso.identity import tables as t
from ciso.identity.roles import RoleScope
from ciso.identity.store import (
    HOST_LOCAL,
    Actor,
    ActorStatus,
    RoleAssignment,
    admin_refusal,
    check_text,
    insert_actor,
    insert_assignment,
    security_admin_ever_assigned,
    write_audit,
)
from ciso.identity.tokens import IssuedToken, TokenMinter

logger = logging.getLogger(__name__)

_RECOVERY_CHANNEL = "host_local_recovery"


class BootstrapResult(Model):
    actor: Actor
    token: IssuedToken


class HostLocalAdmin:
    """Bootstrap and lockout recovery. Host-local: never reachable from the API."""

    def __init__(self, engine: Engine, clock: Clock, audit: AuditSink, minter: TokenMinter) -> None:
        self._engine = engine
        self._clock = clock
        self._audit = audit
        self._minter = minter

    def _record(
        self, action: str, target: str, outcome: AuditOutcome, details: dict[str, Any]
    ) -> None:
        write_audit(
            self._audit,
            actor_id=HOST_LOCAL,
            actor_type=ActorType.HUMAN,
            action=action,
            target=target,
            outcome=outcome,
            details=details,
        )

    def _run(
        self,
        action: str,
        target: str,
        details: dict[str, Any],
        change: Callable[[Connection, datetime], tuple[Any, dict[str, Any]]],
    ) -> Any:
        self._record(action, target, AuditOutcome.ATTEMPT, details)
        now = self._clock.now()
        try:
            with self._engine.begin() as conn:
                result, result_details = change(conn, now)
        except Exception as exc:
            denied = isinstance(exc, Conflict | AuthorizationError)
            outcome = AuditOutcome.DENIED if denied else AuditOutcome.FAILED
            try:
                self._record(action, target, outcome, {**details, "error": str(exc)})
            except FailClosed:
                logger.error("identity: could not audit the failed %s", action)
            raise
        try:
            self._record(action, target, AuditOutcome.SUCCESS, {**details, **result_details})
        except FailClosed:
            logger.error(
                "identity: %s on %s was made but its result was not audited", action, target
            )
            raise
        return result

    def bootstrap_first_admin(self, display_name: str) -> BootstrapResult:
        """Create the first human security_admin and its one-time token.

        Host-local: never reachable from the API. Works once per database: `Conflict` if a
        security_admin assignment has ever existed or the bootstrap marker is present.
        Needs `max_token_ttl` (`FailClosed` without it).
        """
        lifetime = self._minter.lifetime(None)
        name = check_text(display_name, "display name")
        actor_id = new_id("act")

        def change(conn: Connection, now: datetime) -> tuple[BootstrapResult, dict[str, Any]]:
            marker = conn.execute(select(t.bootstrap_marker.c.id)).first()
            if marker is not None or security_admin_ever_assigned(conn):
                raise Conflict("bootstrap is closed: an administrator has existed before")
            try:
                conn.execute(
                    t.bootstrap_marker.insert().values(
                        id=t.BOOTSTRAP_MARKER_ID, actor_id=actor_id, created_at=now
                    )
                )
            except IntegrityError as exc:
                raise Conflict("bootstrap is closed: another bootstrap won") from exc
            actor = Actor(
                id=actor_id,
                actor_type=ActorType.HUMAN,
                display_name=name,
                status=ActorStatus.ACTIVE,
                created_at=now,
            )
            insert_actor(conn, actor, HOST_LOCAL)
            assignment = RoleAssignment(
                id=new_id("ras"),
                actor_id=actor_id,
                role=Role.SECURITY_ADMIN,
                scope=RoleScope(),
                valid_from=now,
                assigned_by=HOST_LOCAL,
                assigned_at=now,
            )
            insert_assignment(conn, assignment)
            issued = self._minter.mint(conn, actor_id, HOST_LOCAL, now, now + lifetime)
            result = BootstrapResult(actor=actor, token=issued)
            return result, {"assignment_id": assignment.id, "token_id": issued.token_id}

        result: BootstrapResult = self._run("identity.bootstrap", actor_id, {}, change)
        logger.warning("identity: bootstrap created first security_admin %s", actor_id)
        return result

    def recover_admin_token(self, actor_id: str, operator: str, reason: str) -> IssuedToken:
        """Issue a fresh token to an existing, active, human security_admin.

        Host-local: never reachable from the API. For the locked-out case (for example the
        only admin's token expired). `operator` names the person at the host and `reason`
        says why; both go into the audit record, marked as a host-local recovery. An agent
        or service, a disabled actor or a non-admin is refused (`AuthorizationError`).
        """
        details = {
            "operator": check_text(operator, "operator"),
            "reason": check_text(reason, "reason"),
            "channel": _RECOVERY_CHANNEL,
        }
        lifetime = self._minter.lifetime(None)

        def change(conn: Connection, now: datetime) -> tuple[IssuedToken, dict[str, Any]]:
            refusal = admin_refusal(conn, actor_id, now)
            if refusal is not None:
                raise AuthorizationError(f"recovery refused: {refusal.replace('caller', 'actor')}")
            issued = self._minter.mint(conn, actor_id, HOST_LOCAL, now, now + lifetime)
            return issued, {"token_id": issued.token_id}

        result: IssuedToken = self._run("identity.recover_admin_token", actor_id, details, change)
        logger.warning("identity: admin token recovered for %s at the host", actor_id)
        return result
