"""Identity rows, row validation and the checks every privileged path shares.

Internal to `ciso.identity`. Stored data is not trusted on the way out (review M7): a
scope that does not match the closed `StoredScope` model raises `IntegrityFailure`
instead of quietly becoming an unscoped grant.
"""

from __future__ import annotations

import logging
from datetime import datetime
from enum import StrEnum
from typing import Annotated, Any

from pydantic import ConfigDict, Field
from sqlalchemy import Connection, func, select

from ciso.common.clock import ensure_utc
from ciso.common.enums import HUMAN_ONLY_ROLES, ActorType, AuditOutcome, Environment, Role
from ciso.common.errors import FailClosed, IntegrityFailure, NotFound, ValidationFailed
from ciso.common.principal import Principal, RoleGrant
from ciso.common.protocols import AuditEvent, AuditSink
from ciso.common.schemas import Model, UtcDatetime
from ciso.identity import tables as t
from ciso.identity.roles import RoleScope

logger = logging.getLogger(__name__)

_MAX_TEXT = 200
#: `actor_id` used in audit records when no actor is established (review F8).
UNAUTHENTICATED = "unauthenticated"
#: Issuer recorded for credentials minted by host-local operations.
HOST_LOCAL = "host_local"


class ActorStatus(StrEnum):
    ACTIVE = "active"
    DISABLED = "disabled"


class Actor(Model):
    """A user of this platform (human, service or agent). Not a company person record."""

    id: str
    actor_type: ActorType
    display_name: str
    status: ActorStatus
    person_ref: str | None = None
    created_at: UtcDatetime


class RoleAssignment(Model):
    """One role held by one actor, optionally narrowed by scope and a time window.

    The window is `valid_from <= now < valid_until`; `valid_until=None` has no end.
    """

    id: str
    actor_id: str
    role: Role
    scope: RoleScope = RoleScope()
    valid_from: UtcDatetime
    valid_until: UtcDatetime | None = None
    assigned_by: str
    assigned_at: UtcDatetime
    revoked_at: UtcDatetime | None = None
    revoked_by: str | None = None

    def is_current(self, now: datetime) -> bool:
        if self.revoked_at is not None or now < self.valid_from:
            return False
        return self.valid_until is None or now < self.valid_until


_Values = Annotated[list[str], Field(min_length=1)]


class StoredScope(Model):
    """The only shape `scope_json` may have. Strict: no unknown keys, no empty lists."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    system: _Values | None = None
    environment: Annotated[list[Environment], Field(min_length=1)] | None = None
    classification: _Values | None = None

    def to_role_scope(self) -> RoleScope:
        return RoleScope(
            systems=frozenset(self.system or ()),
            environments=frozenset(self.environment or ()),
            classifications=frozenset(self.classification or ()),
        )


def scope_to_json(scope: RoleScope) -> str:
    stored = StoredScope.model_validate(
        {name: sorted(values) for name, values in scope.as_attributes().items()}, strict=False
    )
    return stored.model_dump_json(exclude_none=True)


def write_audit(
    audit: AuditSink,
    *,
    actor_id: str,
    actor_type: ActorType,
    action: str,
    target: str,
    outcome: AuditOutcome,
    details: dict[str, Any] | None = None,
) -> None:
    """Append one event. Any failure becomes `FailClosed`."""
    event = AuditEvent(
        actor_id=actor_id,
        actor_type=actor_type,
        action=action,
        target=target,
        outcome=outcome,
        details=details or {},
    )
    try:
        audit.append(event)
    except FailClosed:
        raise
    except Exception as exc:
        raise FailClosed("audit path unavailable") from exc


def actor_from_row(row: Any) -> Actor:
    return Actor(
        id=row.id,
        actor_type=ActorType(row.actor_type),
        display_name=row.display_name,
        status=ActorStatus(row.status),
        person_ref=row.person_ref,
        created_at=row.created_at,
    )


def assignment_from_row(row: Any) -> RoleAssignment:
    try:
        scope = StoredScope.model_validate_json(row.scope_json).to_role_scope()
    except ValueError as exc:
        raise IntegrityFailure(f"assignment {row.id} has an invalid stored scope") from exc
    return RoleAssignment(
        id=row.id,
        actor_id=row.actor_id,
        role=Role(row.role),
        scope=scope,
        valid_from=row.valid_from,
        valid_until=row.valid_until,
        assigned_by=row.assigned_by,
        assigned_at=row.assigned_at,
        revoked_at=row.revoked_at,
        revoked_by=row.revoked_by,
    )


def find_actor(conn: Connection, actor_id: str) -> Actor | None:
    row = conn.execute(select(t.actors).where(t.actors.c.id == actor_id)).first()
    return None if row is None else actor_from_row(row)


def load_actor(conn: Connection, actor_id: str) -> Actor:
    actor = find_actor(conn, actor_id)
    if actor is None:
        raise NotFound(f"no such actor: {actor_id}")
    return actor


def insert_actor(conn: Connection, actor: Actor, created_by: str) -> None:
    conn.execute(
        t.actors.insert().values(
            id=actor.id,
            actor_type=actor.actor_type.value,
            display_name=actor.display_name,
            status=actor.status.value,
            person_ref=actor.person_ref,
            created_at=actor.created_at,
            created_by=created_by,
        )
    )


def insert_assignment(conn: Connection, assignment: RoleAssignment) -> None:
    conn.execute(
        t.role_assignments.insert().values(
            id=assignment.id,
            actor_id=assignment.actor_id,
            role=assignment.role.value,
            scope_json=scope_to_json(assignment.scope),
            valid_from=assignment.valid_from,
            valid_until=assignment.valid_until,
            assigned_by=assignment.assigned_by,
            assigned_at=assignment.assigned_at,
        )
    )


def current_assignments(conn: Connection, actor_id: str, now: datetime) -> list[RoleAssignment]:
    query = (
        select(t.role_assignments)
        .where(t.role_assignments.c.actor_id == actor_id)
        .order_by(t.role_assignments.c.id)
    )
    every = (assignment_from_row(row) for row in conn.execute(query))
    return [a for a in every if a.is_current(now)]


def is_admin_grant(assignment: RoleAssignment, now: datetime) -> bool:
    """A grant that may administer identity: current, unscoped, open-ended (review M3)."""
    return (
        assignment.role is Role.SECURITY_ADMIN
        and assignment.is_current(now)
        and assignment.scope.is_unrestricted
        and assignment.valid_until is None
    )


def admin_refusal(conn: Connection, actor_id: str, now: datetime) -> str | None:
    """Why `actor_id` may not administer identity now, or None if it may."""
    actor = find_actor(conn, actor_id)
    if actor is None:
        return "unknown_caller"
    if actor.status is not ActorStatus.ACTIVE:
        return "caller_disabled"
    if actor.actor_type is not ActorType.HUMAN:
        return "caller_not_human"
    if not any(is_admin_grant(a, now) for a in current_assignments(conn, actor_id, now)):
        return "caller_not_security_admin"
    return None


def admin_holders(
    conn: Connection,
    now: datetime,
    *,
    without_actor: str | None = None,
    without_assignment: str | None = None,
) -> set[str]:
    """Active humans who can administer now, ignoring one actor or one assignment."""
    query = (
        select(t.role_assignments)
        .join(t.actors, t.actors.c.id == t.role_assignments.c.actor_id)
        .where(t.role_assignments.c.role == Role.SECURITY_ADMIN.value)
        .where(t.actors.c.status == ActorStatus.ACTIVE.value)
        .where(t.actors.c.actor_type == ActorType.HUMAN.value)
    )
    holders: set[str] = set()
    for row in conn.execute(query):
        if row.actor_id == without_actor or row.id == without_assignment:
            continue
        if is_admin_grant(assignment_from_row(row), now):
            holders.add(row.actor_id)
    return holders


def security_admin_ever_assigned(conn: Connection) -> bool:
    """True if any security_admin assignment row exists, revoked and lapsed ones included."""
    query = (
        select(func.count())
        .select_from(t.role_assignments)
        .where(t.role_assignments.c.role == Role.SECURITY_ADMIN.value)
    )
    return int(conn.execute(query).scalar_one()) > 0


def build_principal(
    actor: Actor, grants: list[RoleAssignment], credential_issued_by: str = ""
) -> Principal:
    """One `RoleGrant` per current assignment, carrying that assignment's scope."""
    roles = frozenset(g.role for g in grants)
    if actor.actor_type is not ActorType.HUMAN and roles & HUMAN_ONLY_ROLES:
        raise IntegrityFailure(f"stored assignments give {actor.id} a human-only role")
    return Principal(
        actor_id=actor.id,
        actor_type=actor.actor_type,
        roles=roles,
        grants=tuple(RoleGrant(role=g.role, scope=g.scope.as_attributes()) for g in grants),
        display_name=actor.display_name,
        credential_issued_by=credential_issued_by,
    )


def check_text(value: str, what: str) -> str:
    cleaned = value.strip()
    if not cleaned or len(cleaned) > _MAX_TEXT:
        raise ValidationFailed(f"{what} must be 1 to {_MAX_TEXT} characters")
    return cleaned


def check_window(
    now: datetime, valid_from: datetime | None, valid_until: datetime | None
) -> tuple[datetime, datetime | None]:
    start = ensure_utc(valid_from) if valid_from is not None else now
    end = ensure_utc(valid_until) if valid_until is not None else None
    if end is not None and end <= start:
        raise ValidationFailed("valid_until must be after valid_from")
    return start, end
