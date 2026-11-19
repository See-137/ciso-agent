"""Attribution rules (brief item 4). Each rule has a test that reaches it and one that
shows the neighbouring allowed path."""

from __future__ import annotations

import pytest
from sqlalchemy import Engine, func, select, text
from tests.agents.conftest import (
    ADMIN,
    ALICE_REF,
    BOB_REF,
    ActionFactory,
    registration,
)
from tests.fakes.core import FakeAudit

from ciso.agents import AgentAdmin, AgentFact, AgentRecord, AgentRegistry, AgentStatus, Registration
from ciso.agents import tables as t
from ciso.common.activity import ActivitySource, AgentClass, AttributionResolver
from ciso.common.clock import FixedClock
from ciso.common.enums import InformationState
from ciso.common.errors import FailClosed

pytestmark = pytest.mark.unit

OS = ("os_account", "CORP\\alice")
ACCOUNT = ("assistant_account", "alice@corp.example")
BOB_OS = ("os_account", "CORP\\bob")
#: Only the signed central gate vouches for an assistant account (review M5).
GATE = ActivitySource.CENTRAL_GATE


@pytest.fixture
def bound(admin_ops: AgentAdmin) -> None:
    admin_ops.bind_claim(ADMIN, *OS, ALICE_REF)
    admin_ops.bind_claim(ADMIN, *ACCOUNT, ALICE_REF)
    admin_ops.bind_claim(ADMIN, *BOB_OS, BOB_REF)


def test_registry_is_an_attribution_resolver(registry: AgentRegistry) -> None:
    assert isinstance(registry, AttributionResolver)


# -- person rules --------------------------------------------------------------------


@pytest.mark.usefixtures("bound")
def test_verified_bound_claim_gives_verified_person(
    registry: AgentRegistry, make_action: ActionFactory
) -> None:
    result = registry.attribute(make_action(claims=((*ACCOUNT, True),), source=GATE))
    assert result.person_ref == ALICE_REF
    assert result.state is InformationState.VERIFIED


@pytest.mark.usefixtures("bound")
def test_only_unverified_bound_claims_give_declared(
    registry: AgentRegistry, make_action: ActionFactory
) -> None:
    result = registry.attribute(make_action(claims=((*OS, False), (*ACCOUNT, False))))
    assert result.person_ref == ALICE_REF
    assert result.state is InformationState.DECLARED


@pytest.mark.usefixtures("bound")
def test_claims_naming_different_people_in_one_action_are_disputed(
    registry: AgentRegistry, make_action: ActionFactory
) -> None:
    result = registry.attribute(make_action(claims=((*ACCOUNT, True), (*BOB_OS, False))))
    assert result.person_ref is None
    assert result.state is InformationState.DISPUTED
    assert "conflicting_identity_claims" in result.reasons


@pytest.mark.usefixtures("bound")
def test_conflict_with_an_earlier_claim_in_the_session_is_disputed(
    registry: AgentRegistry, make_action: ActionFactory
) -> None:
    first = registry.attribute(make_action(claims=((*ACCOUNT, True),), source=GATE))
    assert first.state is InformationState.VERIFIED
    later = registry.attribute(make_action(claims=((*BOB_OS, False),)))
    assert later.person_ref is None
    assert later.state is InformationState.DISPUTED
    assert "conflicting_identity_claims" in later.reasons
    # The dispute sticks: the next action with only Alice's claim is still disputed.
    again = registry.attribute(make_action(claims=((*ACCOUNT, True),)))
    assert again.state is InformationState.DISPUTED


@pytest.mark.usefixtures("bound")
def test_earlier_verified_claim_still_counts_for_the_session(
    registry: AgentRegistry, make_action: ActionFactory
) -> None:
    registry.attribute(make_action(claims=((*ACCOUNT, True),), source=GATE))
    later = registry.attribute(make_action(claims=((*OS, False),)))
    assert later.state is InformationState.VERIFIED


def test_no_bound_claim_is_unknown(registry: AgentRegistry, make_action: ActionFactory) -> None:
    result = registry.attribute(make_action(claims=((*OS, True),)))
    assert result.person_ref is None
    assert result.state is InformationState.UNKNOWN
    assert "no_bound_identity_claim" in result.reasons


@pytest.mark.usefixtures("bound")
def test_unbinding_stops_attribution(
    registry: AgentRegistry, admin_ops: AgentAdmin, make_action: ActionFactory
) -> None:
    binding = next(b for b in registry.list_bindings(ALICE_REF) if b.kind == "os_account")
    admin_ops.unbind_claim(ADMIN, binding.id)
    result = registry.attribute(make_action(session="s2", claims=((*OS, False),)))
    assert result.state is InformationState.UNKNOWN


@pytest.mark.usefixtures("bound")
def test_session_claim_overflow_is_disputed(
    registry: AgentRegistry, make_action: ActionFactory
) -> None:
    for batch in range(4):
        claims = tuple(("api_key", f"key-{batch}-{i}", False) for i in range(16))
        registry.attribute(make_action(claims=claims))
    full = registry.get_session("sess-1")
    assert len(full.claims) == 64
    result = registry.attribute(
        make_action(claims=((*ACCOUNT, True), ("api_key", "one-more", False)))
    )
    assert result.state is InformationState.DISPUTED
    assert "session_claim_limit_reached" in result.reasons
    assert len(registry.get_session("sess-1").claims) == 64


@pytest.mark.usefixtures("bound")
def test_claims_seen_are_kept_not_overwritten(
    registry: AgentRegistry, make_action: ActionFactory, clock: FixedClock
) -> None:
    registry.attribute(make_action(claims=((*OS, False),)))
    first_seen = clock.now()
    clock.advance(minutes=5)
    registry.attribute(make_action(claims=((*OS, False), (*ACCOUNT, True)), source=GATE))
    registry.attribute(make_action(claims=()))
    session = registry.get_session("sess-1")
    seen = {(c.kind, c.subject, c.verified): c.first_seen for c in session.claims}
    assert seen == {(*OS, False): first_seen, (*ACCOUNT, True): clock.now()}
    assert session.first_seen == first_seen
    assert session.last_seen == clock.now()
    assert session.person_ref == ALICE_REF
    assert session.state is InformationState.VERIFIED


# -- agent rules ---------------------------------------------------------------------


@pytest.mark.usefixtures("bound")
def test_registered_agent_matches_by_device_and_surface(
    registry: AgentRegistry, approved_agent: AgentRecord, make_action: ActionFactory
) -> None:
    result = registry.attribute(make_action(claims=((*ACCOUNT, True),), source=GATE))
    assert result.agent_ref == f"agent:{approved_agent.id}"
    assert result.agent_class is AgentClass.EMPLOYEE_OPERATED
    assert result.state is InformationState.VERIFIED
    assert result.reasons == ()


@pytest.mark.usefixtures("approved_agent")
def test_other_surface_does_not_match(registry: AgentRegistry, make_action: ActionFactory) -> None:
    result = registry.attribute(make_action(surface="ide"))
    agent = registry.get_agent(result.agent_ref.split(":")[1])  # type: ignore[union-attr]
    assert agent.status is AgentStatus.OBSERVED


def test_unknown_agent_creates_one_observed_record_per_session(
    registry: AgentRegistry, make_action: ActionFactory, audit: FakeAudit, engine: Engine
) -> None:
    first = registry.attribute(make_action())
    second = registry.attribute(make_action())
    assert first.agent_class is AgentClass.UNKNOWN
    assert first.agent_ref is not None
    assert first.agent_ref == second.agent_ref
    assert "agent_unknown" in first.reasons
    agent = registry.get_agent(first.agent_ref.split(":")[1])
    assert agent.status is AgentStatus.OBSERVED
    assert agent.agent_class is AgentClass.UNKNOWN
    assert agent.owner_ref is None
    assert agent.operator_ref is None
    assert agent.observed_session_id == "sess-1"
    assert [e.target for e in audit.find("agents.agent.observed")] == [agent.id]
    with engine.connect() as conn:
        assert conn.execute(select(func.count()).select_from(t.agents)).scalar_one() == 1


def test_session_without_facts_gets_one_observed_record_that_matches_nothing_else(
    registry: AgentRegistry, make_action: ActionFactory, engine: Engine
) -> None:
    bare = registry.attribute(make_action(session="bare", device=None))
    again = registry.attribute(make_action(session="bare", device=None))
    other = registry.attribute(make_action(session="other", device=None))
    assert bare.agent_ref is not None
    assert bare.agent_ref == again.agent_ref
    assert other.agent_ref not in {None, bare.agent_ref}
    with engine.connect() as conn:
        assert conn.execute(select(func.count()).select_from(t.agents)).scalar_one() == 2


def test_suspended_agent_is_returned_with_reason(
    registry: AgentRegistry,
    admin_ops: AgentAdmin,
    approved_agent: AgentRecord,
    make_action: ActionFactory,
) -> None:
    admin_ops.suspend(ADMIN, approved_agent.id)
    result = registry.attribute(make_action())
    assert result.agent_ref == f"agent:{approved_agent.id}"
    assert result.agent_class is AgentClass.EMPLOYEE_OPERATED
    assert "agent_suspended" in result.reasons


def test_suspension_reaches_a_session_already_tied_to_the_agent(
    registry: AgentRegistry,
    admin_ops: AgentAdmin,
    approved_agent: AgentRecord,
    make_action: ActionFactory,
) -> None:
    assert "agent_suspended" not in registry.attribute(make_action()).reasons
    admin_ops.suspend(ADMIN, approved_agent.id)
    assert "agent_suspended" in registry.attribute(make_action()).reasons


@pytest.mark.usefixtures("bound")
def test_operator_mismatch_caps_state_at_inferred(
    registry: AgentRegistry, approved_agent: AgentRecord, make_action: ActionFactory
) -> None:
    result = registry.attribute(make_action(claims=(("os_account", "CORP\\bob", True),)))
    assert result.person_ref == BOB_REF
    assert result.agent_ref == f"agent:{approved_agent.id}"
    assert "operator_mismatch" in result.reasons
    assert result.state is InformationState.INFERRED


@pytest.mark.usefixtures("bound")
def test_operator_match_keeps_state(
    registry: AgentRegistry, approved_agent: AgentRecord, make_action: ActionFactory
) -> None:
    result = registry.attribute(make_action(claims=((*OS, False),)))
    assert "operator_mismatch" not in result.reasons
    assert result.state is InformationState.DECLARED


@pytest.mark.usefixtures("bound")
def test_organizational_agent_has_no_operator_rule(
    registry: AgentRegistry, admin_ops: AgentAdmin, make_action: ActionFactory
) -> None:
    org = admin_ops.register_agent(
        ADMIN,
        registration(
            AgentClass.ORGANIZATIONAL,
            owner=ALICE_REF,
            operator=None,
            extra=(AgentFact(kind="device_actor", value="svc_build"),),
        ),
    )
    admin_ops.approve(ADMIN, org.id)
    # The device name fact is a client claim: an organizational agent needs every fact
    # verified, so it is matched only once the device name is dropped from its facts.
    named = registry.attribute(
        make_action(session="n", claims=((*BOB_OS, False),), device_actor="svc_build")
    )
    assert named.agent_class is not AgentClass.ORGANIZATIONAL
    bot = admin_ops.register_agent(
        ADMIN,
        Registration(
            display_name="Release bot",
            agent_class=AgentClass.ORGANIZATIONAL,
            surface="cli",
            facts=(AgentFact(kind="device_actor", value="svc_build"),),
            owner_ref=ALICE_REF,
        ),
    )
    admin_ops.approve(ADMIN, bot.id)
    result = registry.attribute(make_action(claims=((*BOB_OS, False),), device_actor="svc_build"))
    assert result.agent_ref == bot.ref
    assert result.agent_class is AgentClass.ORGANIZATIONAL
    assert result.person_ref == BOB_REF
    # No operator rule; Bob is not assigned to the build device, so he stays declared.
    assert result.state is InformationState.DECLARED
    assert result.reasons == ("person_not_assigned_to_device",)


def test_declared_agent_is_flagged_not_approved(
    registry: AgentRegistry, admin_ops: AgentAdmin, make_action: ActionFactory
) -> None:
    admin_ops.register_agent(ADMIN, registration())
    assert "agent_not_approved" in registry.attribute(make_action()).reasons


def test_two_registered_matches_are_ambiguous(
    registry: AgentRegistry, admin_ops: AgentAdmin, make_action: ActionFactory, engine: Engine
) -> None:
    admin_ops.register_agent(ADMIN, registration())
    admin_ops.register_agent(ADMIN, registration())
    result = registry.attribute(make_action())
    assert result.agent_ref is None
    assert result.agent_class is AgentClass.UNKNOWN
    assert "agent_ambiguous" in result.reasons
    with engine.connect() as conn:
        assert conn.execute(select(func.count()).select_from(t.agents)).scalar_one() == 2


def test_registered_agent_wins_over_an_observed_one(
    registry: AgentRegistry, admin_ops: AgentAdmin, make_action: ActionFactory
) -> None:
    observed = registry.attribute(make_action(session="old"))
    agent = admin_ops.register_agent(ADMIN, registration())
    result = registry.attribute(make_action(session="new"))
    assert result.agent_ref == f"agent:{agent.id}" != observed.agent_ref


def test_agent_needs_every_fact(
    registry: AgentRegistry, admin_ops: AgentAdmin, make_action: ActionFactory
) -> None:
    from ciso.agents import AgentFact

    agent = admin_ops.register_agent(
        ADMIN, registration(extra=(AgentFact(kind="api_key", value="key-1"),))
    )
    without = registry.attribute(make_action(session="a"))
    with_key = registry.attribute(make_action(session="b", claims=(("api_key", "key-1", False),)))
    assert without.agent_ref != f"agent:{agent.id}"
    assert with_key.agent_ref == f"agent:{agent.id}"


def test_retired_agent_is_not_matched(
    registry: AgentRegistry,
    admin_ops: AgentAdmin,
    approved_agent: AgentRecord,
    make_action: ActionFactory,
) -> None:
    admin_ops.retire(ADMIN, approved_agent.id)
    result = registry.attribute(make_action())
    assert result.agent_ref != f"agent:{approved_agent.id}"
    assert result.agent_class is AgentClass.UNKNOWN


def test_device_change_within_a_session_is_flagged(
    registry: AgentRegistry, make_action: ActionFactory
) -> None:
    registry.attribute(make_action())
    assert "session_device_changed" in registry.attribute(make_action(device="WS-9")).reasons
    assert registry.get_session("sess-1").device == "WS-0142"


# -- fail closed ---------------------------------------------------------------------


def test_unreadable_registry_fails_closed(
    registry: AgentRegistry, make_action: ActionFactory, engine: Engine
) -> None:
    with engine.begin() as conn:
        conn.execute(text("DROP TABLE agents_session_claims"))
    with pytest.raises(FailClosed):
        registry.attribute(make_action())


def test_corrupt_session_reference_fails_closed(
    registry: AgentRegistry, make_action: ActionFactory, engine: Engine
) -> None:
    registry.attribute(make_action())
    with engine.begin() as conn:
        conn.execute(t.sessions.update().values(agent_ref="agent:agt_missing"))
    with pytest.raises(FailClosed):
        registry.attribute(make_action())


def test_unauditable_observed_agent_fails_closed(
    registry: AgentRegistry, make_action: ActionFactory, audit: FakeAudit
) -> None:
    audit.fail = True
    with pytest.raises(FailClosed):
        registry.attribute(make_action())
