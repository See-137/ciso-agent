"""Regression tests for the adversarial review of the skill core (H3, H4, M5).

Each test replays the reviewer's sequence against the real registry: who vouches for a
person, which facts may match an organizational agent, and what a reused session id gets.
"""

from __future__ import annotations

import pytest
from tests.agents.conftest import (
    ADMIN,
    ALICE_REF,
    BOB_REF,
    DEVICE_A,
    DEVICE_B,
    ActionFactory,
)

from ciso.agents import AgentAdmin, AgentFact, AgentRecord, AgentRegistry, Registration
from ciso.common.activity import ActivitySource, AgentClass
from ciso.common.enums import InformationState

pytestmark = pytest.mark.unit

ALICE_OS = ("os_account", "CORP\\alice")
BOB_OS = ("os_account", "CORP\\bob")
ALICE_ACCOUNT = ("assistant_account", "alice@corp.example")
BOT_KEY = ("api_key", "key_release_bot")
BUILD_HOST = "BUILD-01"
GATE = ActivitySource.CENTRAL_GATE


@pytest.fixture
def bound(admin_ops: AgentAdmin) -> None:
    admin_ops.bind_claim(ADMIN, *ALICE_OS, ALICE_REF)
    admin_ops.bind_claim(ADMIN, *ALICE_ACCOUNT, ALICE_REF)
    admin_ops.bind_claim(ADMIN, *BOB_OS, BOB_REF)


def _org_agent(admin_ops: AgentAdmin, *facts: AgentFact) -> AgentRecord:
    agent = admin_ops.register_agent(
        ADMIN,
        Registration(
            display_name="Release bot",
            agent_class=AgentClass.ORGANIZATIONAL,
            surface="cli",
            facts=facts,
            owner_ref=ALICE_REF,
        ),
    )
    return admin_ops.approve(ADMIN, agent.id)


# -- H3: organizational agents match only through verified facts ----------------------


@pytest.mark.usefixtures("bound")
def test_h3_unverified_claims_do_not_make_an_organizational_agent(
    registry: AgentRegistry, admin_ops: AgentAdmin, make_action: ActionFactory
) -> None:
    bot = _org_agent(
        admin_ops,
        AgentFact(kind="api_key", value=BOT_KEY[1]),
        AgentFact(kind="device", value=BUILD_HOST),
    )
    result = registry.attribute(
        make_action(
            claims=((*ALICE_OS, False), (*BOT_KEY, False)), device=BUILD_HOST, device_actor=DEVICE_A
        )
    )
    assert result.agent_ref != bot.ref
    assert result.agent_class is not AgentClass.ORGANIZATIONAL
    assert result.person_ref == ALICE_REF


@pytest.mark.usefixtures("bound")
def test_h3_organizational_agent_matches_through_the_verified_device_actor(
    registry: AgentRegistry, admin_ops: AgentAdmin, make_action: ActionFactory
) -> None:
    bot = _org_agent(admin_ops, AgentFact(kind="device_actor", value=DEVICE_B))
    own = registry.attribute(make_action(session="bot", device_actor=DEVICE_B))
    assert own.agent_ref == bot.ref
    assert own.agent_class is AgentClass.ORGANIZATIONAL
    # A client that claims the bot's device actor without the token gets nothing from it.
    forged = registry.attribute(
        make_action(
            session="forged",
            claims=(("device_actor", DEVICE_B, False), (*ALICE_OS, False)),
            device_actor=DEVICE_A,
        )
    )
    assert forged.agent_ref != bot.ref
    assert forged.agent_class is not AgentClass.ORGANIZATIONAL


def test_h3_organizational_agent_matches_through_a_signed_assistant_account(
    registry: AgentRegistry, admin_ops: AgentAdmin, make_action: ActionFactory
) -> None:
    bot = _org_agent(admin_ops, AgentFact(kind="assistant_account", value="bot@corp.example"))
    claim = (("assistant_account", "bot@corp.example", True),)
    signed = registry.attribute(make_action(session="g", claims=claim, device=None, source=GATE))
    assert signed.agent_ref == bot.ref
    # The same claim marked verified by a hook report is not signed by anyone.
    hooked = registry.attribute(make_action(session="h", claims=claim, device_actor=DEVICE_A))
    assert hooked.agent_ref != bot.ref


# -- M5: the attribution layer decides what is verified --------------------------------


@pytest.mark.usefixtures("bound")
def test_m5_a_client_marked_verified_claim_is_only_declared(
    registry: AgentRegistry, make_action: ActionFactory
) -> None:
    result = registry.attribute(make_action(claims=((*BOB_OS, True),), device_actor=DEVICE_A))
    assert result.person_ref == BOB_REF
    assert result.state is InformationState.DECLARED


@pytest.mark.usefixtures("bound")
def test_m5_assigned_device_makes_the_os_account_verified(
    registry: AgentRegistry, admin_ops: AgentAdmin, make_action: ActionFactory
) -> None:
    admin_ops.assign_device(ADMIN, DEVICE_A, [ALICE_REF])
    alice = registry.attribute(
        make_action(session="a", claims=((*ALICE_OS, False),), device_actor=DEVICE_A)
    )
    assert alice.person_ref == ALICE_REF
    assert alice.state is InformationState.VERIFIED
    bob = registry.attribute(
        make_action(session="b", claims=((*BOB_OS, False),), device_actor=DEVICE_A)
    )
    assert bob.person_ref == BOB_REF
    assert bob.state is InformationState.DECLARED
    assert "person_not_assigned_to_device" in bob.reasons
    # The assignment counts only through the verified device actor, not a device name.
    named = registry.attribute(make_action(session="c", claims=((*ALICE_OS, False),)))
    assert named.state is InformationState.DECLARED


@pytest.mark.usefixtures("bound")
def test_m5_signed_assistant_account_stays_verified(
    registry: AgentRegistry, make_action: ActionFactory
) -> None:
    result = registry.attribute(
        make_action(claims=((*ALICE_ACCOUNT, True),), device=None, source=GATE)
    )
    assert result.person_ref == ALICE_REF
    assert result.state is InformationState.VERIFIED


def test_m5_a_device_actor_bound_as_a_person_claim_vouches_for_nobody(
    registry: AgentRegistry, admin_ops: AgentAdmin, make_action: ActionFactory
) -> None:
    admin_ops.bind_claim(ADMIN, "device_actor", DEVICE_A, ALICE_REF)
    result = registry.attribute(make_action(device_actor=DEVICE_A))
    assert result.person_ref is None
    assert result.state is InformationState.UNKNOWN


# -- H4: a session is bound to the device actor that first reported it -----------------


@pytest.fixture
def bob_session(
    bound: None, registry: AgentRegistry, admin_ops: AgentAdmin, make_action: ActionFactory
) -> str:
    admin_ops.assign_device(ADMIN, DEVICE_B, [BOB_REF])
    first = registry.attribute(
        make_action(session="bob-s", claims=((*BOB_OS, False),), device_actor=DEVICE_B)
    )
    assert first.state is InformationState.VERIFIED
    return "bob-s"


def test_h4_reused_session_from_another_device_is_disputed(
    registry: AgentRegistry, make_action: ActionFactory, bob_session: str
) -> None:
    stolen = registry.attribute(make_action(session=bob_session, device_actor=DEVICE_A))
    assert stolen.person_ref is None
    assert stolen.agent_ref is None
    assert stolen.state is InformationState.DISPUTED
    assert stolen.reasons == ("session_device_mismatch",)


def test_h4_reused_session_without_a_device_actor_is_disputed(
    registry: AgentRegistry, make_action: ActionFactory, bob_session: str
) -> None:
    stolen = registry.attribute(make_action(session=bob_session, device="WS-9"))
    assert stolen.person_ref is None
    assert stolen.state is InformationState.DISPUTED
    assert "session_device_mismatch" in stolen.reasons


def test_h4_the_owning_device_keeps_the_session_and_is_not_poisoned(
    registry: AgentRegistry, make_action: ActionFactory, bob_session: str
) -> None:
    registry.attribute(
        make_action(session=bob_session, claims=((*ALICE_OS, False),), device_actor=DEVICE_A)
    )
    again = registry.attribute(make_action(session=bob_session, device_actor=DEVICE_B))
    assert again.person_ref == BOB_REF
    assert again.state is InformationState.VERIFIED
    session = registry.get_session(bob_session)
    assert session.device_actor == DEVICE_B
    assert ALICE_OS not in {(c.kind, c.subject) for c in session.claims}


def test_h4_a_signed_gate_report_joins_a_device_session_on_its_own_claim(
    registry: AgentRegistry, make_action: ActionFactory, bob_session: str
) -> None:
    unsigned = registry.attribute(make_action(session=bob_session, device=None, source=GATE))
    assert unsigned.state is InformationState.DISPUTED
    assert "session_device_mismatch" in unsigned.reasons
    signed = registry.attribute(
        make_action(session=bob_session, claims=((*ALICE_ACCOUNT, True),), device=None, source=GATE)
    )
    # Alice's signed account on Bob's session: never Bob, never Alice alone.
    assert signed.person_ref is None
    assert signed.state is InformationState.DISPUTED


@pytest.mark.usefixtures("bound")
def test_h4_a_device_binds_a_session_first_seen_through_the_gate(
    registry: AgentRegistry, admin_ops: AgentAdmin, make_action: ActionFactory
) -> None:
    admin_ops.assign_device(ADMIN, DEVICE_A, [ALICE_REF])
    gate = registry.attribute(
        make_action(session="mix", claims=((*ALICE_ACCOUNT, True),), device=None, source=GATE)
    )
    assert gate.state is InformationState.VERIFIED
    hook = registry.attribute(
        make_action(session="mix", claims=((*ALICE_OS, False),), device_actor=DEVICE_A)
    )
    assert hook.person_ref == ALICE_REF
    assert hook.state is InformationState.VERIFIED
    other = registry.attribute(make_action(session="mix", device_actor=DEVICE_B))
    assert other.state is InformationState.DISPUTED


@pytest.mark.usefixtures("bound")
def test_h3_an_unverified_device_actor_claim_is_no_fact_for_any_agent(
    registry: AgentRegistry, admin_ops: AgentAdmin, make_action: ActionFactory
) -> None:
    mine = admin_ops.register_agent(
        ADMIN,
        Registration(
            display_name="Bob's agent",
            agent_class=AgentClass.EMPLOYEE_OPERATED,
            surface="cli",
            facts=(AgentFact(kind="device_actor", value=DEVICE_B),),
            operator_ref=BOB_REF,
        ),
    )
    forged = registry.attribute(
        make_action(claims=(("device_actor", DEVICE_B, False),), device_actor=DEVICE_A)
    )
    assert forged.agent_ref != mine.ref
    own = registry.attribute(make_action(session="own", device_actor=DEVICE_B))
    assert own.agent_ref == mine.ref
