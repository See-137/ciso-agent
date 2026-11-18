"""Admin operations (brief item 5): who may act, class rules, audit order, refusal codes."""

from __future__ import annotations

import pytest
from sqlalchemy import Engine, func, select
from tests.agents.conftest import (
    ADMIN,
    ALICE,
    ALICE_REF,
    BOB,
    BOB_REF,
    SCOPED_ADMIN,
    ActionFactory,
    registration,
)
from tests.fakes.core import FakeAudit, FakePrincipals, make_principal

from ciso.agents import (
    AgentAdmin,
    AgentRecord,
    AgentRegistry,
    AgentsConflict,
    AgentsNotFound,
    AgentsRefused,
    AgentStatus,
    RefusalCode,
)
from ciso.agents import tables as t
from ciso.common.activity import AgentClass
from ciso.common.clock import FixedClock
from ciso.common.enums import ActorType, AuditOutcome, Role
from ciso.common.errors import FailClosed
from ciso.common.protocols import AuditEvent, AuditReceipt

pytestmark = pytest.mark.unit


def _count(engine: Engine) -> int:
    with engine.connect() as conn:
        return conn.execute(select(func.count()).select_from(t.agents)).scalar_one()


def _outcomes(audit: FakeAudit, action: str) -> list[AuditOutcome]:
    return [e.outcome for e in audit.find(action)]


# -- who may act ---------------------------------------------------------------------


def test_admin_registers_with_attempt_then_success(
    admin_ops: AgentAdmin, audit: FakeAudit, engine: Engine
) -> None:
    agent = admin_ops.register_agent(ADMIN, registration())
    assert agent.status is AgentStatus.DECLARED
    assert agent.id.startswith("agt_")
    assert _outcomes(audit, "agents.agent.register") == [
        AuditOutcome.ATTEMPT,
        AuditOutcome.SUCCESS,
    ]
    assert _count(engine) == 1


@pytest.mark.parametrize(
    ("caller", "code"),
    [
        (ALICE, RefusalCode.CALLER_NOT_SECURITY_ADMIN),
        (SCOPED_ADMIN, RefusalCode.CALLER_NOT_SECURITY_ADMIN),
        ("svc_connector", RefusalCode.CALLER_NOT_HUMAN),
        ("nobody", RefusalCode.UNKNOWN_CALLER),
    ],
)
def test_non_admins_are_refused_and_audited(
    admin_ops: AgentAdmin, audit: FakeAudit, engine: Engine, caller: str, code: RefusalCode
) -> None:
    with pytest.raises(AgentsRefused) as err:
        admin_ops.register_agent(caller, registration())
    assert err.value.code is code
    events = audit.find("agents.agent.register")
    assert [e.outcome for e in events] == [AuditOutcome.DENIED]
    assert events[0].details == {"reason": code.value}
    assert _count(engine) == 0


def test_a_principal_object_is_not_trusted(
    admin_ops: AgentAdmin, people: FakePrincipals, engine: Engine
) -> None:
    forged = make_principal(ALICE, ActorType.HUMAN, Role.SECURITY_ADMIN)
    with pytest.raises(AgentsRefused) as err:
        admin_ops.register_agent(forged, registration())
    assert err.value.code is RefusalCode.CALLER_NOT_SECURITY_ADMIN
    assert people.lookups[-1] == ALICE


def test_revoked_admin_is_refused_now(
    admin_ops: AgentAdmin, people: FakePrincipals, approved_agent: AgentRecord
) -> None:
    people.register(make_principal(ADMIN, ActorType.HUMAN))
    with pytest.raises(AgentsRefused):
        admin_ops.retire(ADMIN, approved_agent.id)


def test_broken_resolver_fails_closed(
    admin_ops: AgentAdmin, people: FakePrincipals, audit: FakeAudit, engine: Engine
) -> None:
    people.broken = True
    with pytest.raises(FailClosed):
        admin_ops.register_agent(ADMIN, registration())
    assert audit.find("agents.agent.register")[0].details == {"reason": "resolver_unavailable"}
    assert _count(engine) == 0


def test_attempt_audit_failure_changes_nothing(
    admin_ops: AgentAdmin, audit: FakeAudit, engine: Engine
) -> None:
    audit.fail = True
    with pytest.raises(FailClosed):
        admin_ops.register_agent(ADMIN, registration())
    assert _count(engine) == 0


def test_audit_is_not_called_inside_the_write_transaction(
    engine: Engine, people: FakePrincipals
) -> None:
    """The ATTEMPT is written before the transaction and the RESULT after it. The probe
    opens its own write transaction on the same database from inside the audit call; on
    the shared in-memory connection that fails if the registry's transaction is open."""
    writes: list[str] = []

    class Probe(FakeAudit):
        def append(self, event: AuditEvent) -> AuditReceipt:
            with engine.begin() as conn:
                conn.execute(select(1))
            writes.append(event.outcome.value)
            return super().append(event)

    ops = AgentAdmin(engine, FixedClock(), Probe(), people)
    ops.register_agent(ADMIN, registration())
    assert writes == ["attempt", "success"]


# -- class rules ---------------------------------------------------------------------


def test_employee_agent_needs_an_operator(admin_ops: AgentAdmin, engine: Engine) -> None:
    with pytest.raises(AgentsConflict) as err:
        admin_ops.register_agent(ADMIN, registration(operator=None))
    assert err.value.code is RefusalCode.OPERATOR_REQUIRED
    assert _count(engine) == 0


def test_organizational_agent_needs_an_owner(admin_ops: AgentAdmin) -> None:
    with pytest.raises(AgentsConflict) as err:
        admin_ops.register_agent(ADMIN, registration(AgentClass.ORGANIZATIONAL, operator=None))
    assert err.value.code is RefusalCode.OWNER_REQUIRED
    org = admin_ops.register_agent(
        ADMIN, registration(AgentClass.ORGANIZATIONAL, owner=ALICE_REF, operator=None)
    )
    assert org.owner_ref == ALICE_REF


def test_unknown_class_cannot_be_registered(admin_ops: AgentAdmin, audit: FakeAudit) -> None:
    with pytest.raises(AgentsConflict) as err:
        admin_ops.register_agent(ADMIN, registration(AgentClass.UNKNOWN, operator=None))
    assert err.value.code is RefusalCode.CLASS_UNKNOWN
    assert audit.find("agents.agent.register")[-1].details["reason"] == "class_unknown"


def test_clearing_the_operator_of_an_employee_agent_is_refused(
    admin_ops: AgentAdmin, approved_agent: AgentRecord
) -> None:
    with pytest.raises(AgentsConflict) as err:
        admin_ops.set_operator(ADMIN, approved_agent.id, None)
    assert err.value.code is RefusalCode.OPERATOR_REQUIRED
    changed = admin_ops.set_operator(ADMIN, approved_agent.id, BOB_REF)
    assert changed.operator_ref == BOB_REF


def test_set_owner(admin_ops: AgentAdmin, approved_agent: AgentRecord) -> None:
    assert admin_ops.set_owner(ADMIN, approved_agent.id, BOB_REF).owner_ref == BOB_REF


def test_observed_agent_must_be_classified_before_approval(
    admin_ops: AgentAdmin, registry: AgentRegistry, make_action: ActionFactory
) -> None:
    ref = registry.attribute(make_action()).agent_ref
    assert ref is not None
    agent_id = ref.split(":")[1]
    with pytest.raises(AgentsConflict) as err:
        admin_ops.approve(ADMIN, agent_id)
    assert err.value.code is RefusalCode.CLASS_UNKNOWN
    with pytest.raises(AgentsConflict) as err:
        admin_ops.classify(ADMIN, agent_id, AgentClass.EMPLOYEE_OPERATED)
    assert err.value.code is RefusalCode.OPERATOR_REQUIRED
    admin_ops.classify(ADMIN, agent_id, AgentClass.EMPLOYEE_OPERATED, operator_ref=ALICE_REF)
    approved = admin_ops.approve(ADMIN, agent_id)
    assert approved.status is AgentStatus.APPROVED
    assert approved.agent_class is AgentClass.EMPLOYEE_OPERATED


def test_bad_person_reference_is_refused(admin_ops: AgentAdmin) -> None:
    with pytest.raises(ValueError, match="person reference"):
        admin_ops.register_agent(ADMIN, registration(operator="agent:agt_x"))


# -- status changes ------------------------------------------------------------------


def test_approve_twice_is_wrong_status(admin_ops: AgentAdmin, approved_agent: AgentRecord) -> None:
    with pytest.raises(AgentsConflict) as err:
        admin_ops.approve(ADMIN, approved_agent.id)
    assert err.value.code is RefusalCode.WRONG_STATUS


@pytest.mark.parametrize("who", [ALICE])
def test_operator_may_suspend_own_agent(
    admin_ops: AgentAdmin, approved_agent: AgentRecord, audit: FakeAudit, who: str
) -> None:
    suspended = admin_ops.suspend(who, approved_agent.id)
    assert suspended.status is AgentStatus.SUSPENDED
    assert _outcomes(audit, "agents.agent.suspend") == [AuditOutcome.ATTEMPT, AuditOutcome.SUCCESS]


def test_owner_may_suspend_own_agent(admin_ops: AgentAdmin) -> None:
    org = admin_ops.register_agent(
        ADMIN, registration(AgentClass.ORGANIZATIONAL, owner=BOB_REF, operator=None)
    )
    assert admin_ops.suspend(BOB, org.id).status is AgentStatus.SUSPENDED


def test_someone_else_may_not_suspend(
    admin_ops: AgentAdmin, approved_agent: AgentRecord, audit: FakeAudit
) -> None:
    with pytest.raises(AgentsRefused) as err:
        admin_ops.suspend(BOB, approved_agent.id)
    assert err.value.code is RefusalCode.NOT_RESPONSIBLE_FOR_AGENT
    assert _outcomes(audit, "agents.agent.suspend") == [AuditOutcome.ATTEMPT, AuditOutcome.DENIED]
    assert audit.find("agents.agent.suspend")[-1].details["reason"] == "not_responsible_for_agent"


def test_non_human_operator_cannot_suspend(
    admin_ops: AgentAdmin, approved_agent: AgentRecord, people: FakePrincipals
) -> None:
    people.register(make_principal(ALICE, ActorType.SERVICE))
    with pytest.raises(AgentsRefused) as err:
        admin_ops.suspend(ALICE, approved_agent.id)
    assert err.value.code is RefusalCode.CALLER_NOT_HUMAN


def test_admin_may_suspend_any_agent(admin_ops: AgentAdmin, approved_agent: AgentRecord) -> None:
    assert admin_ops.suspend(ADMIN, approved_agent.id).status is AgentStatus.SUSPENDED


def test_unsuspend_is_admin_only_and_restores_status(
    admin_ops: AgentAdmin, approved_agent: AgentRecord
) -> None:
    admin_ops.suspend(ALICE, approved_agent.id)
    with pytest.raises(AgentsRefused) as err:
        admin_ops.unsuspend(ALICE, approved_agent.id)
    assert err.value.code is RefusalCode.CALLER_NOT_SECURITY_ADMIN
    back = admin_ops.unsuspend(ADMIN, approved_agent.id)
    assert back.status is AgentStatus.APPROVED
    assert back.status_before_suspension is None


def test_unsuspend_of_an_active_agent_is_wrong_status(
    admin_ops: AgentAdmin, approved_agent: AgentRecord
) -> None:
    with pytest.raises(AgentsConflict) as err:
        admin_ops.unsuspend(ADMIN, approved_agent.id)
    assert err.value.code is RefusalCode.WRONG_STATUS


def test_retire_is_final(admin_ops: AgentAdmin, approved_agent: AgentRecord) -> None:
    assert admin_ops.retire(ADMIN, approved_agent.id).status is AgentStatus.RETIRED
    for op in (admin_ops.retire, admin_ops.approve, admin_ops.suspend):
        with pytest.raises(AgentsConflict):
            op(ADMIN, approved_agent.id)


def test_missing_agent(admin_ops: AgentAdmin, audit: FakeAudit) -> None:
    with pytest.raises(AgentsNotFound) as err:
        admin_ops.approve(ADMIN, "agt_missing")
    assert err.value.code is RefusalCode.AGENT_NOT_FOUND
    assert _outcomes(audit, "agents.agent.approve") == [AuditOutcome.ATTEMPT, AuditOutcome.FAILED]


# -- bindings ------------------------------------------------------------------------


def test_bind_and_unbind(admin_ops: AgentAdmin, registry: AgentRegistry, audit: FakeAudit) -> None:
    binding = admin_ops.bind_claim(ADMIN, "os_account", "CORP\\alice", ALICE_REF)
    assert binding.bound_by == ADMIN
    assert registry.list_bindings(ALICE_REF) == (binding,)
    done = admin_ops.unbind_claim(ADMIN, binding.id)
    assert done.unbound_by == ADMIN
    assert registry.list_bindings(ALICE_REF) == ()
    assert len(registry.list_bindings(ALICE_REF, include_unbound=True)) == 1
    assert _outcomes(audit, "agents.binding.bind") == [AuditOutcome.ATTEMPT, AuditOutcome.SUCCESS]
    with pytest.raises(AgentsNotFound) as err:
        admin_ops.unbind_claim(ADMIN, binding.id)
    assert err.value.code is RefusalCode.BINDING_NOT_FOUND


def test_a_claim_has_one_active_binding(admin_ops: AgentAdmin) -> None:
    first = admin_ops.bind_claim(ADMIN, "os_account", "CORP\\alice", ALICE_REF)
    with pytest.raises(AgentsConflict) as err:
        admin_ops.bind_claim(ADMIN, "os_account", "CORP\\alice", BOB_REF)
    assert err.value.code is RefusalCode.BINDING_EXISTS
    admin_ops.unbind_claim(ADMIN, first.id)
    assert admin_ops.bind_claim(ADMIN, "os_account", "CORP\\alice", BOB_REF).person_ref == BOB_REF


def test_binding_is_admin_only(admin_ops: AgentAdmin) -> None:
    with pytest.raises(AgentsRefused) as err:
        admin_ops.bind_claim(ALICE, "os_account", "CORP\\alice", ALICE_REF)
    assert err.value.code is RefusalCode.CALLER_NOT_SECURITY_ADMIN


def test_unclean_subject_is_refused(admin_ops: AgentAdmin) -> None:
    with pytest.raises(ValueError, match="whitespace"):
        admin_ops.bind_claim(ADMIN, "os_account", "CORP\\alice\n", ALICE_REF)
