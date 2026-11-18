"""Each broker gate: a test that reaches it and refuses, and the allowed path past it.

Blueprint 9.4, 9.5, 11.2, 19.3 (execution broker: allowlist, idempotency, rate limit,
kill switch); plan row T2.3; gaps G5, G12, G14, G20. The approval gate has its own file.
"""

from __future__ import annotations

from datetime import timedelta
from typing import Any

import pytest
from sqlalchemy import func, select
from tests.execution.broker_world import L2_OP, L3_OP, L4_OP, NoteArgs, World
from tests.fakes.core import FakePrincipals

from ciso.common.enums import AuditOutcome, AuthorityLevel, KillCapability
from ciso.common.errors import FailClosed
from ciso.common.principal import Principal
from ciso.execution import (
    DUPLICATE_ACTION,
    EXECUTE_ACTION,
    ExecutionBroker,
    ExecutionRefused,
    ExecutionState,
    ExecutionUnavailable,
    RefusalReason,
    ToolRegistry,
)
from ciso.execution.tables import execution_run
from ciso.policy import (
    EnvelopeValidator,
    OperationCatalog,
    OperationSpec,
)

pytestmark = pytest.mark.broker

R = RefusalReason


def refused(broker: ExecutionBroker, envelope: Any, approval_id: str | None = None) -> Any:
    with pytest.raises(ExecutionRefused) as excinfo:
        broker.execute(envelope, approval_id)
    return excinfo.value


def rows(world: World) -> int:
    with world.engine.begin() as conn:
        return int(conn.execute(select(func.count()).select_from(execution_run)).scalar_one())


# --- the allowed path ----------------------------------------------------------------


def test_an_allowed_l2_action_runs_once_and_is_verified(world: World) -> None:
    record = world.broker().execute(world.envelope())
    assert record.state is ExecutionState.VERIFIED
    assert record.succeeded
    assert len(world.l2.calls) == 1
    assert len(world.l2.verified) == 1
    assert record.references == ("draft:d1",)
    assert record.observed == ("draft:d1",)
    assert record.verification_matches is True
    assert record.residual_risk == ""
    assert record.attempt_audit_ref
    assert record.result_audit_ref
    assert world.audit.outcomes(EXECUTE_ACTION) == [AuditOutcome.ATTEMPT, AuditOutcome.SUCCESS]
    assert rows(world) == 1
    assert world.broker().get(record.execution_id) == record


def test_a_refusal_is_audited_as_denied_and_leaves_no_row(world: World) -> None:
    world.context.in_scope = False
    error = refused(world.broker(), world.envelope())
    assert error.reason is R.POLICY_DENIED
    denied = world.audit.find(EXECUTE_ACTION)
    assert [e.outcome for e in denied] == [AuditOutcome.DENIED]
    assert denied[0].details["reason"] == "policy_denied"
    assert denied[0].actor_id == "agent_ciso"
    assert "arguments" not in denied[0].details
    assert rows(world) == 0
    assert world.tool_calls() == 0


def test_only_an_action_envelope_is_accepted(world: World) -> None:
    error = refused(world.broker(), {"operation": "note.write"})
    assert error.reason is R.INVALID_REQUEST
    assert world.tool_calls() == 0


def test_the_broker_needs_a_sealed_registry(world: World) -> None:
    with pytest.raises(ValueError, match="sealed"):
        world.broker(registry=ToolRegistry())


# --- gate 1: kill switch -------------------------------------------------------------


def test_kill_switch_engaged_refuses_every_level_counted(world: World) -> None:
    world.killswitch.blocked.add(KillCapability.WRITES)
    broker = world.broker()
    refusals = [
        refused(broker, world.envelope(op, key=f"k-{op.name}")) for op in (L2_OP, L3_OP, L4_OP)
    ]
    assert [e.reason for e in refusals] == [R.KILL_SWITCH_ENGAGED] * 3
    assert all(isinstance(e, FailClosed) for e in refusals)
    assert world.tool_calls() == 0
    assert rows(world) == 0
    assert world.policy.calls == 0
    world.killswitch.blocked.clear()
    assert broker.execute(world.envelope(key="k-after")).state is ExecutionState.VERIFIED


def test_kill_switch_read_error_refuses(world: World) -> None:
    class Unreadable:
        def is_blocked(self, capability: KillCapability) -> bool:
            raise RuntimeError("state unreadable")

    error = refused(world.broker(killswitch=Unreadable()), world.envelope())
    assert error.reason is R.KILL_SWITCH_UNREADABLE
    assert isinstance(error, ExecutionUnavailable)
    assert world.tool_calls() == 0


def test_a_broken_reader_or_a_non_boolean_answer_counts_as_blocked(world: World) -> None:
    world.killswitch.broken = True
    assert refused(world.broker(), world.envelope()).reason is R.KILL_SWITCH_ENGAGED

    class Vague:
        def is_blocked(self, capability: KillCapability) -> Any:
            return None

    assert (
        refused(world.broker(killswitch=Vague()), world.envelope()).reason is R.KILL_SWITCH_ENGAGED
    )
    assert world.tool_calls() == 0


def test_l3_runs_engaged_stops_l3_and_leaves_l2_running(world: World) -> None:
    world.killswitch.blocked.add(KillCapability.L3_RUNS)
    broker = world.broker()
    assert refused(broker, world.envelope(L3_OP, key="k3")).reason is R.L3_RUNS_BLOCKED
    assert len(world.l3.calls) == 0
    assert broker.execute(world.envelope(L2_OP, key="k2")).state is ExecutionState.VERIFIED
    assert world.killswitch.reads.count(KillCapability.L3_RUNS) == 1  # not read for L2
    world.killswitch.blocked.clear()
    assert broker.execute(world.envelope(L3_OP, key="k3b")).state is ExecutionState.VERIFIED


def test_l3_runs_is_checked_by_the_tools_level_not_the_claimed_one(world: World) -> None:
    """The registry's level decides too: the read happens even before validation."""
    world.killswitch.blocked.add(KillCapability.L3_RUNS)
    understated = world.envelope(L3_OP, authority_level=AuthorityLevel.L2_COORDINATE)
    assert refused(world.broker(), understated).reason is R.L3_RUNS_BLOCKED


# --- gate 2: envelope and allowlist --------------------------------------------------


@pytest.mark.parametrize(
    ("fields", "code"),
    [
        ({"risk_class": "nonsense"}, "unknown_risk_class"),
        ({"operation": "note.erase"}, "unknown_operation"),
        ({"arguments": {"note": 7}}, "invalid_arguments"),
        ({"arguments": {"note": "x", "shell": "rm"}}, "invalid_arguments"),
        ({"supporting_evidence": ()}, "evidence_required"),
    ],
)
def test_an_invalid_envelope_is_refused(world: World, fields: dict[str, Any], code: str) -> None:
    error = refused(world.broker(), world.envelope(**fields))
    assert error.reason is R.ENVELOPE_INVALID
    assert error.codes == (code,)
    assert world.tool_calls() == 0
    assert world.policy.calls == 0


def test_an_envelope_expired_on_arrival_is_refused(world: World) -> None:
    envelope = world.envelope()
    world.clock.advance(minutes=6)
    assert refused(world.broker(), envelope).reason is R.ENVELOPE_EXPIRED
    assert world.policy.calls == 0


def test_an_operation_in_the_catalog_without_a_tool_is_refused(world: World) -> None:
    extra = OperationSpec(
        name="note.archive",
        authority_level=AuthorityLevel.L2_COORDINATE,
        args_model=NoteArgs,
        writes=True,
        agent_requestable=True,
    )
    wider = EnvelopeValidator(
        OperationCatalog([*world.registry.operation_specs(), extra]),
        world.clock,
        timedelta(hours=1),
        risk_classes=("low",),
    )
    error = refused(world.broker(validator=wider), world.envelope(operation="note.archive"))
    assert error.reason is R.UNKNOWN_TOOL
    assert world.tool_calls() == 0


# --- gate 3: idempotency -------------------------------------------------------------


def test_a_duplicate_key_returns_the_prior_result_without_rerunning(world: World) -> None:
    broker = world.broker()
    envelope = world.envelope()
    first = broker.execute(envelope)
    again = broker.execute(envelope)
    assert again == first
    assert again.state is ExecutionState.VERIFIED
    assert len(world.l2.calls) == 1
    assert len(world.l2.verified) == 1
    assert world.policy.calls == 1
    assert rows(world) == 1
    replay = world.audit.find(DUPLICATE_ACTION)
    assert len(replay) == 1
    assert replay[0].details["execution"] == first.ref


def test_a_duplicate_of_a_failed_verification_is_not_rerun_either(world: World) -> None:
    world.l2.matches = False
    broker = world.broker()
    envelope = world.envelope()
    first = broker.execute(envelope)
    world.l2.matches = True
    assert broker.execute(envelope).state is ExecutionState.VERIFICATION_FAILED
    assert first.state is ExecutionState.VERIFICATION_FAILED
    assert len(world.l2.calls) == 1


def test_the_same_key_with_a_different_envelope_is_a_conflict(world: World) -> None:
    broker = world.broker()
    broker.execute(world.envelope(arguments={"note": "one"}))
    error = refused(broker, world.envelope(arguments={"note": "two"}))
    assert error.reason is R.IDEMPOTENCY_CONFLICT
    assert len(world.l2.calls) == 1
    assert rows(world) == 1


def test_a_replay_that_cannot_be_audited_is_refused(world: World) -> None:
    broker = world.broker()
    envelope = world.envelope()
    broker.execute(envelope)
    world.audit.fail_on(DUPLICATE_ACTION, AuditOutcome.SUCCESS)
    assert refused(broker, envelope).reason is R.AUDIT_UNAVAILABLE


# --- gate 4: policy, now -------------------------------------------------------------


def test_policy_unavailable_refuses(world: World) -> None:
    world.policy.error = FailClosed("policy engine down")
    error = refused(world.broker(), world.envelope())
    assert error.reason is R.POLICY_UNAVAILABLE
    assert isinstance(error, FailClosed)
    assert world.tool_calls() == 0


def test_deny_and_hold_carry_the_decisions_reason_codes(world: World) -> None:
    world.context.in_scope = False
    denied = refused(world.broker(), world.envelope(key="k1"))
    assert denied.reason is R.POLICY_DENIED
    assert denied.codes == ("out_of_scope",)
    world.context.in_scope = True
    world.context.fresh = False
    held = refused(world.broker(), world.envelope(key="k2"))
    assert held.reason is R.POLICY_HOLD
    assert "stale_facts" in held.codes
    assert world.tool_calls() == 0


def test_policy_is_evaluated_at_every_execution_never_reused(world: World) -> None:
    broker = world.broker()
    broker.execute(world.envelope(key="k1"))
    world.context.in_scope = False  # the answer changes between two requests
    assert refused(broker, world.envelope(key="k2")).reason is R.POLICY_DENIED
    assert world.policy.calls == 2
    assert len(world.l2.calls) == 1


@pytest.mark.parametrize(
    "swap",
    [
        lambda d: None,
        lambda d: "allow",
        lambda d: d.model_copy(update={"envelope_hash": "0" * 64}),
        lambda d: d.model_copy(update={"request_id": "req_other"}),
    ],
    ids=["none", "string", "other-hash", "other-request"],
)
def test_an_answer_that_is_not_a_decision_for_this_envelope_refuses(
    world: World, swap: Any
) -> None:
    world.policy.replace = swap
    assert refused(world.broker(), world.envelope()).reason is R.POLICY_UNAVAILABLE
    assert world.tool_calls() == 0


class FadingPrincipals(FakePrincipals):
    """Answers the first `good` lookups, then behaves as told."""

    def __init__(self, good: int, *principals: Principal) -> None:
        super().__init__(*principals)
        self.good = good
        self.then: Any = None

    def resolve(self, actor_id: str) -> Principal | None:
        self.good -= 1
        if self.good >= 0:
            return super().resolve(actor_id)
        if isinstance(self.then, Exception):
            raise self.then
        return self.then  # type: ignore[no-any-return]


@pytest.mark.parametrize(
    ("then", "reason"),
    [
        (None, R.ACTOR_INACTIVE),
        (RuntimeError("identity down"), R.IDENTITY_UNAVAILABLE),
        ("human", R.ACTOR_INACTIVE),
    ],
)
def test_the_broker_resolves_the_actor_itself_after_policy(
    world: World, agent: Principal, admin: Principal, then: Any, reason: RefusalReason
) -> None:
    """The policy engine saw the actor; a moment later identity says otherwise (G12).
    The broker's first lookup (before the idempotency lookup) still succeeds here."""
    people = FadingPrincipals(1, agent)
    people.then = admin.model_copy(update={"actor_id": "agent_ciso"}) if then == "human" else then
    assert refused(world.broker(principals=people), world.envelope()).reason is reason
    assert world.tool_calls() == 0
    assert world.policy.calls == 1
    # before the lookup, after policy, at the last look: three answers are needed
    people.good, world.policy.calls = 3, 0
    assert world.broker(principals=people).execute(world.envelope(key="k2")).succeeded
    assert people.good == 0
