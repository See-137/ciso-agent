"""Admin operations on the agent registry (docs/skill/spec-draft.md, S1; brief item 5).

Who may act:
- every operation: an active human holding `security_admin` through an unnarrowed grant,
  resolved NOW through the injected `PrincipalResolver` (see `ciso.agents.gate`);
- `suspend` only: also the agent's own `owner_ref` or `operator_ref` human. Stopping your
  own agent is always allowed; un-suspending is admin only.

Class rules, checked on the resulting record of every change: an `organizational` agent
needs an owner, an `employee_operated` agent needs an operator. `approve` also refuses an
agent of class `unknown`. Each refusal carries a `RefusalCode`.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

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
    IdentityBinding,
    RefusalCode,
    Registration,
    check_person_ref,
)
from ciso.common.activity import PERSON_REF_KIND, AgentClass, IdentityClaim
from ciso.common.clock import Clock
from ciso.common.ids import new_id
from ciso.common.protocols import AuditSink, PrincipalResolver

_SUSPENDABLE = frozenset({AgentStatus.DECLARED, AgentStatus.OBSERVED, AgentStatus.APPROVED})
_APPROVABLE = frozenset({AgentStatus.DECLARED, AgentStatus.OBSERVED})


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


def _set_field(name: str, value: str | None) -> Any:
    def edit(agent: AgentRecord, _: Acting) -> dict[str, Any]:
        if agent.status is AgentStatus.RETIRED:
            raise AgentsConflict(RefusalCode.WRONG_STATUS, agent.status.value)
        return {name: value}

    return edit
