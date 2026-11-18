"""Actors and role assignments (blueprint 9.3; FR-002, FR-024; gap G30).

Bootstrap model only: the identity provider is undecided (OD-03), so actors are local rows.

Rules a caller must know:
- Every change goes through `AdminGate`: the caller is named by actor id and re-resolved
  from the database; a `Principal` passed in is used only for its `actor_id` (review H2).
  Only an active human holding a current, unscoped, open-ended `security_admin` grant may
  change actors or assignments.
- `security_admin` cannot be scoped or given an end date (review M3).
- The last active admin cannot be disabled or lose the role (`Conflict`).
- Disabling an actor revokes all of its tokens; enabling restores none (review M2).
- `IdentityService` is the `PrincipalResolver`: decide on `resolve(actor_id)`, not on a
  `Principal` object you were handed.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import Connection, Engine, select

from ciso.common.classification import ClassificationScheme
from ciso.common.clock import Clock
from ciso.common.db import read_connection
from ciso.common.enums import HUMAN_ONLY_ROLES, ActorType, Role
from ciso.common.errors import AuthorizationError, Conflict, NotFound, ValidationFailed
from ciso.common.ids import EntityRef, new_id
from ciso.common.principal import Principal
from ciso.common.protocols import AuditSink
from ciso.identity import tables as t
from ciso.identity.gate import AdminGate, Caller, caller_id
from ciso.identity.roles import RoleScope
from ciso.identity.store import (
    Actor,
    ActorStatus,
    RoleAssignment,
    admin_holders,
    assignment_from_row,
    build_principal,
    check_text,
    check_window,
    current_assignments,
    find_actor,
    insert_actor,
    insert_assignment,
    load_actor,
)

__all__ = ["Actor", "ActorStatus", "IdentityService", "RoleAssignment"]


class IdentityService:
    """Actors, role assignments and principals. Blueprint 9.3.

    `classification` may be None (no scheme configured, review F17): assignments that
    narrow by classification are then refused; everything else works.
    """

    def __init__(
        self,
        engine: Engine,
        clock: Clock,
        audit: AuditSink,
        classification: ClassificationScheme | None = None,
    ) -> None:
        self._engine = engine
        self._clock = clock
        self._classification = classification
        self._gate = AdminGate(engine, clock, audit)

    # -- actors -----------------------------------------------------------------------

    def create_actor(
        self,
        by: Caller,
        actor_type: ActorType,
        display_name: str,
        person_ref: str | None = None,
    ) -> Actor:
        """Create an active actor. `person_ref` is an `EntityRef` to a registry Person."""
        if actor_type is ActorType.ANONYMOUS:
            raise ValidationFailed("an anonymous actor cannot be created")
        name = check_text(display_name, "display name")
        ref = str(EntityRef.parse(person_ref)) if person_ref is not None else None
        actor_id = new_id("act")

        def change(conn: Connection, now: datetime) -> tuple[Actor, dict[str, Any]]:
            actor = Actor(
                id=actor_id,
                actor_type=actor_type,
                display_name=name,
                status=ActorStatus.ACTIVE,
                person_ref=ref,
                created_at=now,
            )
            insert_actor(conn, actor, caller_id(by))
            return actor, {"actor_type": actor_type.value}

        details = {"actor_type": actor_type.value}
        result: Actor = self._gate.run(by, "identity.actor.create", actor_id, details, change)
        return result

    def get_actor(self, actor_id: str) -> Actor:
        with read_connection(self._engine) as conn:
            return load_actor(conn, actor_id)

    def disable_actor(self, by: Caller, actor_id: str) -> Actor:
        """Disable and revoke every token of the actor. The last admin is refused."""
        return self._set_status(by, actor_id, ActorStatus.DISABLED)

    def enable_actor(self, by: Caller, actor_id: str) -> Actor:
        """Re-enable. No old token comes back; issue a new one."""
        return self._set_status(by, actor_id, ActorStatus.ACTIVE)

    def _set_status(self, by: Caller, actor_id: str, status: ActorStatus) -> Actor:
        disabling = status is ActorStatus.DISABLED
        action = f"identity.actor.{'disable' if disabling else 'enable'}"

        def change(conn: Connection, now: datetime) -> tuple[Actor, dict[str, Any]]:
            actor = load_actor(conn, actor_id)
            if actor.status is status:
                raise Conflict(f"actor {actor_id} is already {status.value}")
            if disabling and not admin_holders(conn, now, without_actor=actor_id):
                raise Conflict("refusing to disable the last active security_admin")
            conn.execute(
                t.actors.update().where(t.actors.c.id == actor_id).values(status=status.value)
            )
            revoked = 0
            if disabling:
                revoked = conn.execute(
                    t.credentials.update()
                    .where(t.credentials.c.actor_id == actor_id)
                    .where(t.credentials.c.revoked_at.is_(None))
                    .values(revoked_at=now, revoked_by=caller_id(by))
                ).rowcount
            return actor.model_copy(update={"status": status}), {"tokens_revoked": revoked}

        result: Actor = self._gate.run(by, action, actor_id, {}, change)
        return result

    # -- assignments ------------------------------------------------------------------

    def assign_role(
        self,
        by: Caller,
        actor_id: str,
        role: Role,
        scope: RoleScope | None = None,
        valid_from: datetime | None = None,
        valid_until: datetime | None = None,
    ) -> RoleAssignment:
        """Grant `role`. Agents and services are refused every human-only role.

        `security_admin` must be unscoped with no `valid_until`.
        """
        checked = self._check_scope(scope or RoleScope())
        start, end = check_window(self._clock.now(), valid_from, valid_until)
        if role is Role.SECURITY_ADMIN and (not checked.is_unrestricted or end is not None):
            raise ValidationFailed("security_admin cannot be scoped or given an end date")
        assignment_id = new_id("ras")
        scope_details = {k: sorted(v) for k, v in checked.as_attributes().items()}

        def change(conn: Connection, now: datetime) -> tuple[RoleAssignment, dict[str, Any]]:
            actor = load_actor(conn, actor_id)
            if actor.actor_type is not ActorType.HUMAN and role in HUMAN_ONLY_ROLES:
                raise AuthorizationError(f"{actor_id} refused: human_only_role {role.value}")
            if actor.status is not ActorStatus.ACTIVE:
                raise Conflict(f"actor {actor_id} is disabled")
            assignment = RoleAssignment(
                id=assignment_id,
                actor_id=actor_id,
                role=role,
                scope=checked,
                valid_from=start,
                valid_until=end,
                assigned_by=caller_id(by),
                assigned_at=now,
            )
            insert_assignment(conn, assignment)
            return assignment, {"assignment_id": assignment_id, "role": role.value}

        details = {"assignment_id": assignment_id, "role": role.value, "scope": scope_details}
        result: RoleAssignment = self._gate.run(
            by, "identity.role.assign", actor_id, details, change
        )
        return result

    def _check_scope(self, scope: RoleScope) -> RoleScope:
        for system in scope.systems:
            EntityRef.parse(system)
        if scope.classifications and self._classification is None:
            raise ValidationFailed(
                "no classification scheme is configured, so a role cannot be narrowed "
                "by classification"
            )
        scheme = self._classification
        for label in scope.classifications:
            if scheme is None or scheme.normalise(label) != label:
                raise ValidationFailed("a scope cannot be narrowed to the 'unknown' label")
        return scope

    def revoke_role(self, by: Caller, assignment_id: str) -> RoleAssignment:
        """Revoke one assignment. The last admin's admin grant is refused (`Conflict`)."""

        def change(conn: Connection, now: datetime) -> tuple[RoleAssignment, dict[str, Any]]:
            row = conn.execute(
                select(t.role_assignments).where(t.role_assignments.c.id == assignment_id)
            ).first()
            if row is None:
                raise NotFound(f"no such assignment: {assignment_id}")
            assignment = assignment_from_row(row)
            if assignment.revoked_at is not None:
                raise Conflict(f"assignment {assignment_id} is already revoked")
            if assignment.role is Role.SECURITY_ADMIN and not admin_holders(
                conn, now, without_assignment=assignment_id
            ):
                raise Conflict("refusing to revoke the last active security_admin")
            conn.execute(
                t.role_assignments.update()
                .where(t.role_assignments.c.id == assignment_id)
                .values(revoked_at=now, revoked_by=caller_id(by))
            )
            revoked = assignment.model_copy(update={"revoked_at": now, "revoked_by": caller_id(by)})
            return revoked, {"actor": assignment.actor_id, "role": assignment.role.value}

        result: RoleAssignment = self._gate.run(
            by, "identity.role.revoke", assignment_id, {}, change
        )
        return result

    def list_assignments(
        self,
        actor_id: str | None = None,
        role: Role | None = None,
        include_revoked: bool = False,
    ) -> tuple[RoleAssignment, ...]:
        query = select(t.role_assignments).order_by(t.role_assignments.c.id)
        if actor_id is not None:
            query = query.where(t.role_assignments.c.actor_id == actor_id)
        if role is not None:
            query = query.where(t.role_assignments.c.role == role.value)
        if not include_revoked:
            query = query.where(t.role_assignments.c.revoked_at.is_(None))
        with read_connection(self._engine) as conn:
            return tuple(assignment_from_row(row) for row in conn.execute(query))

    # -- principals -------------------------------------------------------------------

    def resolve(self, actor_id: str) -> Principal | None:
        """`PrincipalResolver`: the actor's authority now, or None if unknown or disabled.

        Only unrevoked assignments whose window contains the clock's now count. Raises
        `IntegrityFailure` if stored data is malformed or gives a non-human a human role.
        """
        now = self._clock.now()
        with read_connection(self._engine) as conn:
            actor = find_actor(conn, actor_id)
            if actor is None or actor.status is not ActorStatus.ACTIVE:
                return None
            grants = current_assignments(conn, actor_id, now)
        return build_principal(actor, grants)

    def principal_for(self, actor_id: str) -> Principal | None:
        """Like `resolve`, but an unknown actor raises `NotFound`. Kept for older callers."""
        self.get_actor(actor_id)
        return self.resolve(actor_id)
