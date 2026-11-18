"""Reads the API will need (brief item 6)."""

from __future__ import annotations

import pytest
from tests.agents.conftest import ADMIN, ALICE_REF, BOB_REF, ActionFactory, registration

from ciso.agents import AgentAdmin, AgentRecord, AgentRegistry, AgentStatus
from ciso.common.activity import AgentClass
from ciso.common.enums import InformationState
from ciso.common.errors import NotFound

pytestmark = pytest.mark.unit


def test_get_agent(registry: AgentRegistry, approved_agent: AgentRecord) -> None:
    got = registry.get_agent(approved_agent.id)
    assert got == approved_agent
    assert got.facts[0].value == "WS-0142"
    with pytest.raises(NotFound):
        registry.get_agent("agt_missing")


def test_list_agents_filters(registry: AgentRegistry, admin_ops: AgentAdmin) -> None:
    a = admin_ops.register_agent(ADMIN, registration(device="A"))
    b = admin_ops.register_agent(ADMIN, registration(device="B", operator=BOB_REF))
    org = admin_ops.register_agent(
        ADMIN, registration(AgentClass.ORGANIZATIONAL, device="C", owner=ALICE_REF, operator=None)
    )
    admin_ops.approve(ADMIN, a.id)
    assert ids(registry.list_agents()) == {a.id, b.id, org.id}
    assert ids(registry.list_agents(agent_class=AgentClass.ORGANIZATIONAL)) == {org.id}
    assert ids(registry.list_agents(status=AgentStatus.APPROVED)) == {a.id}
    assert ids(registry.list_agents(operator_ref=BOB_REF)) == {b.id}
    assert len(registry.list_agents(limit=1)) == 1


def ids(agents: tuple[AgentRecord, ...]) -> set[str]:
    return {x.id for x in agents}


def test_coverage_gaps_list_observed_and_unknown_not_retired(
    registry: AgentRegistry, admin_ops: AgentAdmin, make_action: ActionFactory
) -> None:
    admin_ops.register_agent(ADMIN, registration(device="known"))
    first = registry.attribute(make_action(session="s1", device="X")).agent_ref
    second = registry.attribute(make_action(session="s2", device="Y")).agent_ref
    assert first is not None
    assert second is not None
    gaps = registry.list_coverage_gaps()
    assert {g.ref for g in gaps} == {first, second}
    admin_ops.retire(ADMIN, second.split(":")[1])
    assert {g.ref for g in registry.list_coverage_gaps()} == {first}


def test_sessions_for_person(
    registry: AgentRegistry, admin_ops: AgentAdmin, make_action: ActionFactory
) -> None:
    admin_ops.bind_claim(ADMIN, "os_account", "CORP\\alice", ALICE_REF)
    registry.attribute(make_action(session="s1", claims=(("os_account", "CORP\\alice", False),)))
    registry.attribute(make_action(session="s2", claims=(("os_account", "CORP\\alice", False),)))
    registry.attribute(make_action(session="s3"))
    sessions = registry.list_sessions_for_person(ALICE_REF)
    assert {s.session_id for s in sessions} == {"s1", "s2"}
    assert all(s.state is InformationState.DECLARED for s in sessions)
    assert registry.list_sessions_for_person(BOB_REF) == ()


def test_get_session(registry: AgentRegistry, make_action: ActionFactory) -> None:
    result = registry.attribute(make_action())
    session = registry.get_session("sess-1")
    assert session.agent_ref == result.agent_ref
    assert session.device == "WS-0142"
    assert session.surface == "cli"
    with pytest.raises(NotFound):
        registry.get_session("nope")


def test_person_filter_must_be_a_person_ref(registry: AgentRegistry) -> None:
    with pytest.raises(ValueError, match="person reference"):
        registry.list_sessions_for_person("agent:agt_x")
