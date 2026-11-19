"""Device assignments (review H3/H4/M5): an admin says which people use a device actor.

Who may act, what the targets must be, audit order, and the reads the API route needs.
"""

from __future__ import annotations

import pytest
from tests.agents.conftest import (
    ADMIN,
    ALICE,
    ALICE_REF,
    BOB_REF,
    DEVICE_A,
    DEVICE_B,
    SCOPED_ADMIN,
    ActionFactory,
)
from tests.fakes.core import FakeAudit, FakePrincipals

from ciso.agents import (
    AgentAdmin,
    AgentRegistry,
    AgentsConflict,
    AgentsNotFound,
    AgentsRefused,
    DeviceAssignment,
    RefusalCode,
)
from ciso.common.enums import AuditOutcome, InformationState
from ciso.common.errors import FailClosed, ValidationFailed

pytestmark = pytest.mark.unit

ASSIGN = "agents.device.assign"
UNASSIGN = "agents.device.unassign"


def _outcomes(audit: FakeAudit, action: str) -> list[AuditOutcome]:
    return [e.outcome for e in audit.find(action)]


def test_admin_assigns_a_device_to_two_people(
    admin_ops: AgentAdmin, registry: AgentRegistry, audit: FakeAudit
) -> None:
    made = admin_ops.assign_device(ADMIN, DEVICE_A, [ALICE_REF, BOB_REF])
    assert [(a.device_actor, a.person_ref) for a in made] == [
        (DEVICE_A, ALICE_REF),
        (DEVICE_A, BOB_REF),
    ]
    assert all(isinstance(a, DeviceAssignment) and a.assigned_by == ADMIN for a in made)
    assert _outcomes(audit, ASSIGN) == [AuditOutcome.ATTEMPT, AuditOutcome.SUCCESS]
    assert {a.person_ref for a in registry.list_device_assignments(device_actor=DEVICE_A)} == {
        ALICE_REF,
        BOB_REF,
    }
    assert [a.device_actor for a in registry.list_device_assignments(person_ref=BOB_REF)] == [
        DEVICE_A
    ]
    assert registry.list_device_assignments(device_actor=DEVICE_B) == ()


@pytest.mark.parametrize("caller", [ALICE, SCOPED_ADMIN, "nobody"])
def test_only_an_unnarrowed_security_admin_assigns(
    admin_ops: AgentAdmin, registry: AgentRegistry, audit: FakeAudit, caller: str
) -> None:
    with pytest.raises(AgentsRefused):
        admin_ops.assign_device(caller, DEVICE_A, [ALICE_REF])
    assert _outcomes(audit, ASSIGN) == [AuditOutcome.DENIED]
    assert registry.list_device_assignments() == ()


@pytest.mark.parametrize(
    ("device", "persons", "code"),
    [
        (ALICE, [BOB_REF], RefusalCode.DEVICE_NOT_A_SERVICE),
        ("svc_unknown", [BOB_REF], RefusalCode.DEVICE_NOT_A_SERVICE),
        (DEVICE_A, [f"actor:{DEVICE_B}"], RefusalCode.PERSON_NOT_HUMAN),
        (DEVICE_A, ["actor:act_nobody"], RefusalCode.PERSON_NOT_HUMAN),
    ],
)
def test_targets_are_resolved_now(
    admin_ops: AgentAdmin,
    registry: AgentRegistry,
    audit: FakeAudit,
    device: str,
    persons: list[str],
    code: RefusalCode,
) -> None:
    with pytest.raises(AgentsRefused) as caught:
        admin_ops.assign_device(ADMIN, device, persons)
    assert caught.value.code is code
    assert _outcomes(audit, ASSIGN) == [AuditOutcome.ATTEMPT, AuditOutcome.DENIED]
    assert registry.list_device_assignments() == ()


@pytest.mark.parametrize("persons", [[], [ALICE_REF, ALICE_REF], ["person:x"]])
def test_bad_people_lists_are_refused_before_anything(
    admin_ops: AgentAdmin, audit: FakeAudit, persons: list[str]
) -> None:
    with pytest.raises(ValidationFailed):
        admin_ops.assign_device(ADMIN, DEVICE_A, persons)
    assert audit.find(ASSIGN) == []


def test_an_active_assignment_is_not_made_twice(
    admin_ops: AgentAdmin, registry: AgentRegistry
) -> None:
    admin_ops.assign_device(ADMIN, DEVICE_A, [ALICE_REF])
    with pytest.raises(AgentsConflict) as caught:
        admin_ops.assign_device(ADMIN, DEVICE_A, [BOB_REF, ALICE_REF])
    assert caught.value.code is RefusalCode.ASSIGNMENT_EXISTS
    assert [a.person_ref for a in registry.list_device_assignments()] == [ALICE_REF]


def test_unassign_ends_the_vouching(
    admin_ops: AgentAdmin,
    registry: AgentRegistry,
    audit: FakeAudit,
    make_action: ActionFactory,
) -> None:
    admin_ops.bind_claim(ADMIN, "os_account", "CORP\\alice", ALICE_REF)
    (made,) = admin_ops.assign_device(ADMIN, DEVICE_A, [ALICE_REF])
    claim = (("os_account", "CORP\\alice", False),)
    before = registry.attribute(make_action(session="1", claims=claim, device_actor=DEVICE_A))
    assert before.state is InformationState.VERIFIED
    ended = admin_ops.unassign_device(ADMIN, made.id)
    assert ended.unassigned_by == ADMIN
    assert ended.unassigned_at is not None
    assert _outcomes(audit, UNASSIGN) == [AuditOutcome.ATTEMPT, AuditOutcome.SUCCESS]
    after = registry.attribute(make_action(session="2", claims=claim, device_actor=DEVICE_A))
    assert after.state is InformationState.DECLARED
    assert registry.list_device_assignments() == ()
    assert len(registry.list_device_assignments(include_ended=True)) == 1
    with pytest.raises(AgentsNotFound):
        admin_ops.unassign_device(ADMIN, made.id)
    # After it ended the same pair can be assigned again.
    assert len(admin_ops.assign_device(ADMIN, DEVICE_A, [ALICE_REF])) == 1


def test_unreachable_identity_store_refuses(
    admin_ops: AgentAdmin, people: FakePrincipals, registry: AgentRegistry
) -> None:
    people.broken = True
    with pytest.raises(FailClosed):
        admin_ops.assign_device(ADMIN, DEVICE_A, [ALICE_REF])
    people.broken = False
    assert registry.list_device_assignments() == ()
