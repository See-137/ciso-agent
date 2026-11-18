"""Gate 5: what the broker demands of an approval before a tool runs.

Blueprint 9.5 (evaluate approval immediately before execution), 19.3 (expired approval,
wrong role); FR-025; plan row T2.3 "missing or mismatched approval"; gaps G3, G12, G33.
"""

from __future__ import annotations

from typing import Any

import pytest
from tests.execution.broker_world import L2_OP, L4_OP, World

from ciso.approvals import ApprovalStatus
from ciso.common.enums import ActorType, Role
from ciso.common.errors import FailClosed
from ciso.execution import (
    APPROVAL_SUBJECT_KIND,
    BROKER_ACTOR_ID,
    ExecutionRefused,
    ExecutionState,
    RefusalReason,
    approval_binding,
    approval_target,
)

pytestmark = pytest.mark.broker

R = RefusalReason


def refused(world: World, envelope: Any, approval_id: Any, **parts: Any) -> ExecutionRefused:
    with pytest.raises(ExecutionRefused) as excinfo:
        world.broker(**parts).execute(envelope, approval_id)
    assert len(world.l4.calls) == 0, "the tool ran without a usable approval"
    return excinfo.value


def status(world: World, approval_id: str) -> ApprovalStatus:
    return world.approvals.get(approval_id).status  # type: ignore[no-any-return]


def test_an_approved_l4_action_runs_and_spends_the_approval(world: World) -> None:
    envelope = world.envelope(L4_OP)
    approval_id = world.approve(envelope)
    record = world.broker().execute(envelope, approval_id)
    assert record.state is ExecutionState.VERIFIED
    assert len(world.l4.calls) == 1
    assert record.approval_ref == f"approval:{approval_id}"
    spent = world.approvals.get(approval_id)
    assert spent.status is ApprovalStatus.CONSUMED
    assert spent.consumed_by == BROKER_ACTOR_ID


def test_the_binding_names_operation_request_and_idempotency_key(world: World) -> None:
    envelope = world.envelope(L4_OP)
    assert APPROVAL_SUBJECT_KIND == "action_envelope"
    assert approval_binding(envelope) == {
        "operation": "change.push",
        "request_id": envelope.request_id,
        "idempotency_key": "idem-1",
    }
    assert approval_target(envelope) == {
        "system": "system:s1",
        "resource": "asset:a1",
        "tenant": "t1",
        "environment": "staging",
        "boundary": "internal",
    }


@pytest.mark.parametrize("missing", [None, "", 7])
def test_require_approval_without_an_approval_id_refuses(world: World, missing: Any) -> None:
    error = refused(world, world.envelope(L4_OP), missing)
    assert error.reason is R.APPROVAL_REQUIRED


def test_an_unknown_approval_id_refuses(world: World) -> None:
    error = refused(world, world.envelope(L4_OP), "apr_doesnotexist")
    assert error.reason is R.APPROVAL_INVALID
    assert error.codes == ("not_found",)


def test_an_approval_for_another_envelope_cannot_be_reused(world: World) -> None:
    approved = world.envelope(L4_OP, key="k1")
    approval_id = world.approve(approved)
    other = world.envelope(L4_OP, key="k1", arguments={"note": "something bigger"})
    error = refused(world, other, approval_id)
    assert error.reason is R.APPROVAL_INVALID
    assert error.codes == ("subject_mismatch",)
    assert status(world, approval_id) is ApprovalStatus.APPROVED


def test_an_approval_with_another_binding_refuses(world: World) -> None:
    envelope = world.envelope(L4_OP)
    approval_id = world.approve(envelope, binding={"operation": "change.push"})
    error = refused(world, envelope, approval_id)
    assert error.reason is R.APPROVAL_INVALID
    assert error.codes == ("binding_mismatch",)


def test_a_pending_approval_refuses(world: World) -> None:
    envelope = world.envelope(L4_OP)
    made = world.approvals.request(
        subject_kind=APPROVAL_SUBJECT_KIND,
        subject_hash=envelope.envelope_hash(),
        binding=approval_binding(envelope),
        requested_by=envelope.actor_id,
        requested_by_type=envelope.actor_type,
        required_roles=(Role.SYSTEM_OWNER,),
        target=approval_target(envelope),
    )
    error = refused(world, envelope, made.approval_id)
    assert error.reason is R.APPROVAL_INVALID
    assert error.codes == ("not_approved",)


def test_after_a_final_state_the_key_replays_and_the_spent_approval_buys_nothing(
    world: World,
) -> None:
    envelope = world.envelope(L4_OP, key="k1")
    approval_id = world.approve(envelope)
    world.l4.run_error = RuntimeError("boom")  # ends rolled back: a final state
    first = world.broker().execute(envelope, approval_id)
    assert first.state is ExecutionState.ROLLED_BACK
    world.l4.run_error = None
    world.l4.calls.clear()
    # the same envelope under the same key is a replay, never a second run
    assert world.broker().execute(envelope, approval_id) == first
    assert len(world.l4.calls) == 0


def test_an_expired_approval_refuses(world: World) -> None:
    envelope = world.envelope(L4_OP)
    approval_id = world.approve(envelope)
    world.clock.advance(minutes=61)
    late = world.envelope(L4_OP)  # a fresh envelope would not help: the hash differs
    assert refused(world, late, approval_id).codes == ("expired",)


def test_a_role_revoked_after_approval_refuses(world: World) -> None:
    """Plan gap G12: validity is computed when the approval is used."""
    envelope = world.envelope(L4_OP)
    approval_id = world.approve(envelope)
    world.principals.remove("human_owner")
    error = refused(world, envelope, approval_id)
    assert error.reason is R.APPROVAL_INVALID
    assert error.codes == ("approver_unknown",)


def test_an_approval_requested_for_someone_elses_action_refuses(world: World) -> None:
    envelope = world.envelope(L4_OP)
    approval_id = world.approve(
        envelope, requested_by="human_admin", requested_by_type=ActorType.HUMAN
    )
    error = refused(world, envelope, approval_id)
    assert error.reason is R.APPROVAL_REQUESTER_MISMATCH
    assert status(world, approval_id) is ApprovalStatus.APPROVED  # not spent


def test_an_approval_requested_by_another_actor_of_the_same_type_refuses(world: World) -> None:
    envelope = world.envelope(L4_OP)
    approval_id = world.approve(envelope, requested_by="agent_other")
    error = refused(world, envelope, approval_id)
    assert error.reason is R.APPROVAL_REQUESTER_MISMATCH
    assert status(world, approval_id) is ApprovalStatus.APPROVED


def test_an_approval_with_the_right_actor_id_but_another_actor_type_refuses(world: World) -> None:
    envelope = world.envelope(L4_OP)
    approval_id = world.approve(envelope, requested_by_type=ActorType.SERVICE)
    assert refused(world, envelope, approval_id).reason is R.APPROVAL_REQUESTER_MISMATCH


def test_an_approval_open_to_a_role_the_decision_does_not_name_refuses(world: World) -> None:
    envelope = world.envelope(L4_OP)
    approval_id = world.approve(envelope, required_roles=(Role.SYSTEM_OWNER,))
    world.policy.replace = lambda d: d.model_copy(
        update={"required_approver_roles": (Role.EXECUTIVE_RISK_OWNER,)}
    )
    error = refused(world, envelope, approval_id)
    assert error.reason is R.APPROVAL_ROLE_MISMATCH
    assert status(world, approval_id) is ApprovalStatus.APPROVED
    world.policy.replace = None
    assert world.broker().execute(envelope, approval_id).state is ExecutionState.VERIFIED


def test_an_approval_requested_for_another_target_refuses(world: World) -> None:
    envelope = world.envelope(L4_OP)
    approval_id = world.approve(envelope, target={"system": "system:somewhere_else"})
    error = refused(world, envelope, approval_id)
    assert error.reason is R.APPROVAL_TARGET_MISMATCH
    assert status(world, approval_id) is ApprovalStatus.APPROVED


def test_an_approval_supplied_for_a_plainly_allowed_action_is_not_consumed(world: World) -> None:
    envelope = world.envelope(L2_OP)
    approval_id = world.approve(envelope)
    record = world.broker().execute(envelope, approval_id)
    assert record.state is ExecutionState.VERIFIED
    assert record.approval_ref is None
    assert status(world, approval_id) is ApprovalStatus.APPROVED


class Approvals:
    """Stands in for the service: `check` passes, `consume` behaves as told."""

    def __init__(self, world: World, on_consume: Any) -> None:
        self._real = world.approvals
        self._on_consume = on_consume
        self.consumed = 0

    def check(self, approval_id: str, **use: Any) -> Any:
        return self._real.check(approval_id, **use)

    def consume(self, approval_id: str, **use: Any) -> Any:
        self.consumed += 1
        if isinstance(self._on_consume, Exception):
            raise self._on_consume
        return self._on_consume


@pytest.mark.parametrize(
    "on_consume", [RuntimeError("approval store down"), None, "consumed"], ids=repr
)
def test_anything_but_a_consumed_record_refuses(world: World, on_consume: Any) -> None:
    envelope = world.envelope(L4_OP)
    approval_id = world.approve(envelope)
    stand_in = Approvals(world, on_consume)
    error = refused(world, envelope, approval_id, approvals=stand_in)
    assert error.reason is R.APPROVAL_UNAVAILABLE
    assert isinstance(error, FailClosed)
    assert stand_in.consumed == 1


def test_the_approval_audit_path_down_refuses(world: World) -> None:
    envelope = world.envelope(L4_OP)
    approval_id = world.approve(envelope)
    world.audit.fail_if = lambda e: e.action == "approval.consume"
    error = refused(world, envelope, approval_id)
    assert error.reason is R.APPROVAL_UNAVAILABLE
    assert error.codes == ("audit_unavailable",)


def test_consume_is_called_only_after_check_and_the_match(world: World) -> None:
    """Without the match step an approval for another requester would be spent."""
    envelope = world.envelope(L4_OP)
    approval_id = world.approve(
        envelope, requested_by="human_admin", requested_by_type=ActorType.HUMAN
    )
    stand_in = Approvals(world, RuntimeError("must not be reached"))
    error = refused(world, envelope, approval_id, approvals=stand_in)
    assert error.reason is R.APPROVAL_REQUESTER_MISMATCH
    assert stand_in.consumed == 0
