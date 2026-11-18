"""Agent registry fixtures. Importing the tables module first registers them before `engine`."""

from __future__ import annotations

from collections.abc import Callable

import pytest
from sqlalchemy import Engine
from tests.fakes.core import FakeAudit, FakePrincipals, make_principal

from ciso.agents import AgentAdmin, AgentFact, AgentRecord, AgentRegistry, Registration
from ciso.common.activity import (
    ActionKind,
    ActivitySource,
    AgentClass,
    IdentityClaim,
    ObservedAction,
    Phase,
)
from ciso.common.clock import FixedClock
from ciso.common.enums import ActorType, Role
from ciso.common.ids import new_id
from ciso.common.principal import RoleGrant

ADMIN = "human_admin"
#: Two ordinary people whose agents the registry attributes.
ALICE = "act_alice"
BOB = "act_bob"
ALICE_REF = f"actor:{ALICE}"
BOB_REF = f"actor:{BOB}"
SCOPED_ADMIN = "act_scoped_admin"


@pytest.fixture
def people(principals: FakePrincipals) -> FakePrincipals:
    principals.register(make_principal(ALICE, ActorType.HUMAN, Role.EMPLOYEE))
    principals.register(make_principal(BOB, ActorType.HUMAN, Role.EMPLOYEE))
    principals.register(
        make_principal(
            SCOPED_ADMIN,
            ActorType.HUMAN,
            Role.SECURITY_ADMIN,
            grants=(RoleGrant(role=Role.SECURITY_ADMIN, scope={"system": {"app:x"}}),),
        )
    )
    return principals


@pytest.fixture
def registry(engine: Engine, clock: FixedClock, audit: FakeAudit) -> AgentRegistry:
    return AgentRegistry(engine, clock, audit)


@pytest.fixture
def admin_ops(
    engine: Engine, clock: FixedClock, audit: FakeAudit, people: FakePrincipals
) -> AgentAdmin:
    return AgentAdmin(engine, clock, audit, people)


ActionFactory = Callable[..., ObservedAction]


@pytest.fixture
def make_action(clock: FixedClock) -> ActionFactory:
    def build(
        session: str = "sess-1",
        claims: tuple[tuple[str, str, bool], ...] = (),
        device: str | None = "WS-0142",
        surface: str = "cli",
    ) -> ObservedAction:
        return ObservedAction(
            action_id=new_id("obs"),
            session_id=session,
            source=ActivitySource.HOOK,
            phase=Phase.BEFORE,
            kind=ActionKind.SHELL_COMMAND,
            surface=surface,
            received_at=clock.now(),
            identity_claims=tuple(
                IdentityClaim(kind=k, subject=s, verified=v) for k, s, v in claims
            ),
            target={"device": device} if device else {},
        )

    return build


def registration(
    agent_class: AgentClass = AgentClass.EMPLOYEE_OPERATED,
    *,
    device: str = "WS-0142",
    surface: str = "cli",
    owner: str | None = None,
    operator: str | None = ALICE_REF,
    extra: tuple[AgentFact, ...] = (),
) -> Registration:
    return Registration(
        display_name="Coding agent",
        agent_class=agent_class,
        surface=surface,
        facts=(AgentFact(kind="device", value=device), *extra),
        owner_ref=owner,
        operator_ref=operator,
    )


@pytest.fixture
def approved_agent(admin_ops: AgentAdmin) -> AgentRecord:
    agent = admin_ops.register_agent(ADMIN, registration())
    return admin_ops.approve(ADMIN, agent.id)
