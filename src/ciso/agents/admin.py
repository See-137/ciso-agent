"""Admin operations on the agent registry (docs/skill/spec-draft.md, S1; brief item 5).

Who may act:
- every operation: an active human holding `security_admin` through an unnarrowed grant,
  resolved NOW through the injected `PrincipalResolver` (see `ciso.agents.gate`);
- `suspend` only: also the agent's own `owner_ref` or `operator_ref` human. Stopping your
  own agent is always allowed; un-suspending is admin only.

Device assignments (review H3, H4, M5): `assign_device` says which people use a device
actor (the service actor a device token authenticates). Admin only, like every other
change; the device actor and every person are resolved NOW (an active service actor, active
humans) before the write, and a refusal is audited. A verified device vouches only for its
assigned people (`ciso.agents.attribution`).

Class rules, checked on the resulting record of every change: an `organizational` agent
needs an owner, an `employee_operated` agent needs an operator. `approve` also refuses an
agent of class `unknown`. Each refusal carries a `RefusalCode`.
"""

from __future__ import annotations

import re
from collections.abc import Sequence
from datetime import datetime
from typing import Any, Final

from sqlalchemy import Connection, Engine, select

from ciso.agents import store
from ciso.agents import tables as t
from ciso.agents.gate import Acting, AdminGate, Caller
from ciso.agents.models import (
    AgentRecord,
    AgentsConflict,
    AgentsNotFound,
    AgentsRefused,
    AgentStatus,
    DeviceAssignment,
    IdentityBinding,
    RefusalCode,
    Registration,
    check_person_ref,
)
from ciso.common.activity import PERSON_REF_KIND, AgentClass, IdentityClaim
from ciso.common.clock import Clock
from ciso.common.enums import ActorType
from ciso.common.errors import FailClosed, ValidationFailed
from ciso.common.ids import EntityRef, new_id
from ciso.common.protocols import AuditSink, PrincipalResolver

_SUSPENDABLE = frozenset({AgentStatus.DECLARED, AgentStatus.OBSERVED, AgentStatus.APPROVED})
_APPROVABLE = frozenset({AgentStatus.DECLARED, AgentStatus.OBSERVED})
#: Most people one `assign_device` call names.
MAX_ASSIGN_PEOPLE: Final = 16
_ACTOR_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}")


def class_problem(agent: AgentRecord | Registration) -> RefusalCode | None:
    """Why the agent's class and people do not fit together, or None."""
    if agent.agent_class is AgentClass.ORGANIZATIONAL and agent.owner_ref is None:
        return RefusalCode.OWNER_REQUIRED
    if agent.agent_class is AgentClass.EMPLOYEE_OPERATED and agent.operator_ref is None:
        return RefusalCode.OPERATOR_REQUIRED
    return None


def _checked(agent: AgentRecord) -> AgentRecord:
    problem = class_problem(agent)
    if problem is not None:
        raise AgentsConflict(problem, agent.id)
    return agent


def _person_or_none(value: str | None) -> str | None:
    return None if value is None else check_person_ref(value)


class AgentAdmin:
    def __init__(
        self, engine: Engine, clock: Clock, audit: AuditSink, principals: PrincipalResolver
    ) -> None:
        self._gate = AdminGate(engine, clock, audit, principals)
        self._principals = principals

    # -- agents ----------------------------------------------------------------------

    def register_agent(self, by: Caller, registration: Registration) -> AgentRecord:
        """Create a `declared` agent. Class `unknown` cannot be registered."""
        agent_id = new_id("agt")

        def change(conn: Connection, now: datetime, _: Acting) -> tuple[Any, dict[str, Any]]:
            if registration.agent_class is AgentClass.UNKNOWN:
                raise AgentsConflict(RefusalCode.CLASS_UNKNOWN, agent_id)
            agent = _checked(
                AgentRecord(
                    id=agent_id,
                    status=AgentStatus.DECLARED,
                    created_at=now,
                    updated_at=now,
                    **registration.model_dump(),
                )
            )
            store.insert_agent(conn, agent)
            return agent, {"agent_class": agent.agent_class.value}

        details = {"agent_class": registration.agent_class.value, "surface": registration.surface}
        result: AgentRecord = self._gate.run(by, "agents.agent.register", agent_id, details, change)
        return result

    def approve(self, by: Caller, agent_id: str) -> AgentRecord:
        def edit(agent: AgentRecord, _: Acting) -> dict[str, Any]:
            if agent.status not in _APPROVABLE:
                raise AgentsConflict(RefusalCode.WRONG_STATUS, agent.status.value)
            if agent.agent_class is AgentClass.UNKNOWN:
                raise AgentsConflict(RefusalCode.CLASS_UNKNOWN, agent_id)
            return {"status": AgentStatus.APPROVED}

        return self._edit(by, "agents.agent.approve", agent_id, edit)

    def suspend(self, by: Caller, agent_id: str) -> AgentRecord:
        """Admin, or the agent's own owner or operator."""

        def edit(agent: AgentRecord, acting: Acting) -> dict[str, Any]:
            own = f"{PERSON_REF_KIND}:{acting.actor_id}"
            if not acting.is_admin and own not in {agent.owner_ref, agent.operator_ref}:
                raise AgentsRefused(RefusalCode.NOT_RESPONSIBLE_FOR_AGENT, agent_id)
            if agent.status not in _SUSPENDABLE:
                raise AgentsConflict(RefusalCode.WRONG_STATUS, agent.status.value)
            return {"status": AgentStatus.SUSPENDED, "status_before_suspension": agent.status}

        return self._edit(by, "agents.agent.suspend", agent_id, edit, admin_only=False)

    def unsuspend(self, by: Caller, agent_id: str) -> AgentRecord:
        """Admin only. Returns the agent to the status it had before suspension."""

        def edit(agent: AgentRecord, _: Acting) -> dict[str, Any]:
            if agent.status is not AgentStatus.SUSPENDED:
                raise AgentsConflict(RefusalCode.WRONG_STATUS, agent.status.value)
            back = agent.status_before_suspension or AgentStatus.DECLARED
            return {"status": back, "status_before_suspension": None}

        return self._edit(by, "agents.agent.unsuspend", agent_id, edit)

    def retire(self, by: Caller, agent_id: str) -> AgentRecord:
        def edit(agent: AgentRecord, _: Acting) -> dict[str, Any]:
            if agent.status is AgentStatus.RETIRED:
                raise AgentsConflict(RefusalCode.WRONG_STATUS, agent.status.value)
            return {"status": AgentStatus.RETIRED, "status_before_suspension": None}

        return self._edit(by, "agents.agent.retire", agent_id, edit)

    def classify(
        self,
        by: Caller,
        agent_id: str,
        agent_class: AgentClass,
        *,
        owner_ref: str | None = None,
        operator_ref: str | None = None,
    ) -> AgentRecord:
        """Set class, owner and operator together (an observed agent gets all three at once)."""
        owner, operator = _person_or_none(owner_ref), _person_or_none(operator_ref)

        def edit(agent: AgentRecord, _: Acting) -> dict[str, Any]:
            if agent_class is AgentClass.UNKNOWN:
                raise AgentsConflict(RefusalCode.CLASS_UNKNOWN, agent_id)
            if agent.status is AgentStatus.RETIRED:
                raise AgentsConflict(RefusalCode.WRONG_STATUS, agent.status.value)
            return {"agent_class": agent_class, "owner_ref": owner, "operator_ref": operator}

        return self._edit(by, "agents.agent.classify", agent_id, edit)

    def set_owner(self, by: Caller, agent_id: str, owner_ref: str | None) -> AgentRecord:
        owner = _person_or_none(owner_ref)
        return self._edit(by, "agents.agent.set_owner", agent_id, _set_field("owner_ref", owner))

    def set_operator(self, by: Caller, agent_id: str, operator_ref: str | None) -> AgentRecord:
        operator = _person_or_none(operator_ref)
        edit = _set_field("operator_ref", operator)
        return self._edit(by, "agents.agent.set_operator", agent_id, edit)

    def _edit(
        self,
        by: Caller,
        action: str,
        agent_id: str,
        edit: Any,
        *,
        admin_only: bool = True,
    ) -> AgentRecord:
        def change(conn: Connection, now: datetime, acting: Acting) -> tuple[Any, dict[str, Any]]:
            agent = store.load_agent(conn, agent_id)
            updates = edit(agent, acting)
            changed = _checked(
                AgentRecord.model_validate({**agent.model_dump(), **updates, "updated_at": now})
            )
            store.update_agent(conn, changed)
            details = {"from": agent.status.value, "to": changed.status.value}
            return changed, details

        result: AgentRecord = self._gate.run(
            by, action, agent_id, {}, change, admin_only=admin_only
        )
        return result

    # -- identity bindings -----------------------------------------------------------

    def bind_claim(self, by: Caller, kind: str, subject: str, person_ref: str) -> IdentityBinding:
        """Bind a claim to a person. A claim has at most one active binding."""
        claim = IdentityClaim(kind=kind, subject=subject)
        person = check_person_ref(person_ref)
        binding_id = new_id("abn")

        def change(conn: Connection, now: datetime, acting: Acting) -> tuple[Any, dict[str, Any]]:
            if store.active_bindings(conn, [(claim.kind, claim.subject)]):
                raise AgentsConflict(RefusalCode.BINDING_EXISTS, claim.kind)
            binding = IdentityBinding(
                id=binding_id,
                kind=claim.kind,
                subject=claim.subject,
                person_ref=person,
                bound_at=now,
                bound_by=acting.actor_id,
            )
            conn.execute(t.bindings.insert().values(**binding.model_dump()))
            return binding, {"kind": claim.kind, "person_ref": person}

        details = {"kind": claim.kind, "subject": claim.subject, "person_ref": person}
        result: IdentityBinding = self._gate.run(
            by, "agents.binding.bind", binding_id, details, change
        )
        return result

    def unbind_claim(self, by: Caller, binding_id: str) -> IdentityBinding:
        def change(conn: Connection, now: datetime, acting: Acting) -> tuple[Any, dict[str, Any]]:
            row = conn.execute(select(t.bindings).where(t.bindings.c.id == binding_id)).first()
            if row is None or row.unbound_at is not None:
                raise AgentsNotFound(RefusalCode.BINDING_NOT_FOUND, binding_id)
            conn.execute(
                t.bindings.update()
                .where(t.bindings.c.id == binding_id)
                .values(unbound_at=now, unbound_by=acting.actor_id)
            )
            binding = store.binding_from_row(row)
            done = binding.model_copy(update={"unbound_at": now, "unbound_by": acting.actor_id})
            return done, {"kind": binding.kind, "person_ref": binding.person_ref}

        result: IdentityBinding = self._gate.run(
            by, "agents.binding.unbind", binding_id, {}, change
        )
        return result

    # -- device assignments -----------------------------------------------------------

    def assign_device(
        self, by: Caller, device_actor: str, person_refs: Sequence[str]
    ) -> tuple[DeviceAssignment, ...]:
        """Assign the device actor to each person (`actor:<id>`), all or none.

        Refused: a device actor that is not an active service actor
        (`device_not_a_service_actor`), a person that is not an active human
        (`person_not_an_active_human`), an active assignment of any pair
        (`assignment_exists`). The API layer should also check the actor is a registered
        device (`DeviceDirectory.is_device`); this package cannot read that table.
        """
        device, people = _assignment_targets(device_actor, person_refs)
        ids = [new_id("dva") for _ in people]

        def precheck() -> None:
            self._check_targets(device, people)

        def change(conn: Connection, now: datetime, acting: Acting) -> tuple[Any, dict[str, Any]]:
            made = []
            for assignment_id, person in zip(ids, people, strict=True):
                if store.active_assignment_exists(conn, device, person):
                    raise AgentsConflict(RefusalCode.ASSIGNMENT_EXISTS, device)
                item = DeviceAssignment(
                    id=assignment_id,
                    device_actor=device,
                    person_ref=person,
                    assigned_at=now,
                    assigned_by=acting.actor_id,
                )
                conn.execute(t.device_assignments.insert().values(**item.model_dump()))
                made.append(item)
            return tuple(made), {"assignments": ids}

        details = {"device_actor": device, "people": list(people)}
        result: tuple[DeviceAssignment, ...] = self._gate.run(
            by, "agents.device.assign", device, details, change, precheck=precheck
        )
        return result

    def unassign_device(self, by: Caller, assignment_id: str) -> DeviceAssignment:
        """End one active assignment. Admin only."""

        def change(conn: Connection, now: datetime, acting: Acting) -> tuple[Any, dict[str, Any]]:
            a = t.device_assignments
            row = conn.execute(select(a).where(a.c.id == assignment_id)).first()
            if row is None or row.unassigned_at is not None:
                raise AgentsNotFound(RefusalCode.ASSIGNMENT_NOT_FOUND, assignment_id)
            conn.execute(
                a.update()
                .where(a.c.id == assignment_id)
                .values(unassigned_at=now, unassigned_by=acting.actor_id)
            )
            item = store.assignment_from_row(row)
            done = item.model_copy(update={"unassigned_at": now, "unassigned_by": acting.actor_id})
            return done, {"device_actor": item.device_actor, "person_ref": item.person_ref}

        result: DeviceAssignment = self._gate.run(
            by, "agents.device.unassign", assignment_id, {}, change
        )
        return result

    def _check_targets(self, device: str, people: Sequence[str]) -> None:
        """Resolve the targets now. Runs after the ATTEMPT audit, outside any transaction."""
        if _resolved_type(self._principals, device) is not ActorType.SERVICE:
            raise AgentsRefused(RefusalCode.DEVICE_NOT_A_SERVICE, device)
        for person in people:
            actor_id = EntityRef.parse(person).id
            if _resolved_type(self._principals, actor_id) is not ActorType.HUMAN:
                raise AgentsRefused(RefusalCode.PERSON_NOT_HUMAN, person)


def _assignment_targets(
    device_actor: str, person_refs: Sequence[str]
) -> tuple[str, tuple[str, ...]]:
    if isinstance(person_refs, str) or not isinstance(device_actor, str):
        raise ValidationFailed("assign_device takes a device actor id and a list of people")
    if not _ACTOR_ID.fullmatch(device_actor):
        raise ValidationFailed("a device actor id is 1-64 characters of [A-Za-z0-9_.-]")
    people = tuple(check_person_ref(ref) for ref in person_refs)
    if not people or len(people) > MAX_ASSIGN_PEOPLE or len(set(people)) != len(people):
        raise ValidationFailed(f"name 1-{MAX_ASSIGN_PEOPLE} distinct people")
    return device_actor, people


def _resolved_type(principals: PrincipalResolver, actor_id: str) -> ActorType | None:
    """The actor's type as the identity store sees it now; None when unknown."""
    try:
        principal = principals.resolve(actor_id)
    except Exception as exc:
        raise FailClosed("identity could not be consulted") from exc
    return None if principal is None else principal.actor_type


def _set_field(name: str, value: str | None) -> Any:
    def edit(agent: AgentRecord, _: Acting) -> dict[str, Any]:
        if agent.status is AgentStatus.RETIRED:
            raise AgentsConflict(RefusalCode.WRONG_STATUS, agent.status.value)
        return {name: value}

    return edit
