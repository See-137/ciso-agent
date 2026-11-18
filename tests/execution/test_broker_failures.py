"""What the broker records when something fails at or after the side effect.

Blueprint 9.5 (independent verification, fail closed), 11.2 (suspend broker credentials),
19.3 (rollback, partial failure, verification mismatch); plan row T2.3; gaps G5, G20.
"""

from __future__ import annotations

from typing import Any

import pytest
from tests.execution.broker_world import L2_OP, L3_OP, WRITE_TOKEN, WRITE_TOKEN_REF, World
from tests.fakes.core import FakeKillSwitch, FakeSecrets

from ciso.common.enums import AuditOutcome, KillCapability
from ciso.common.errors import AuthorizationError, FailClosed, KillSwitchEngaged
from ciso.execution import (
    EXECUTE_ACTION,
    ExecutionRecord,
    ExecutionRefused,
    ExecutionState,
    KillSwitchGatedCredentials,
    RefusalReason,
    ResultNotRecorded,
    ToolCall,
    ToolOutcome,
)

pytestmark = pytest.mark.broker

R = RefusalReason
S = ExecutionState


def refused(world: World, envelope: Any) -> ExecutionRefused:
    with pytest.raises(ExecutionRefused) as excinfo:
        world.broker().execute(envelope)
    return excinfo.value


def stored(world: World, key: str = "idem-1") -> ExecutionRecord:
    return world.row(key)


def force_state(world: World, state: ExecutionState, key: str = "idem-1") -> None:
    """Another holder of the row key moves the row (the store keeps it readable)."""
    world.force(key, state=state)


# --- gate 9: the attempt must be audited before the side effect ----------------------


def test_attempt_audit_failure_never_calls_the_tool_and_aborts_the_row(world: World) -> None:
    world.audit.fail_on(EXECUTE_ACTION, AuditOutcome.ATTEMPT)
    envelope = world.envelope()
    error = refused(world, envelope)
    assert error.reason is R.ATTEMPT_AUDIT_FAILED
    assert isinstance(error, FailClosed)
    assert len(world.l2.calls) == 0
    assert len(world.l2.verified) == 0
    row = stored(world)
    assert row.state is S.ABORTED
    assert row.attempt_audit_ref is None
    assert row.error_kind == "attempt_not_audited"
    assert row.settled
    # an aborted run never called its tool: it is not replayed as a result, and the same
    # envelope runs once the audit log is back (review finding L2)
    world.audit.fail_if = None
    assert world.broker().execute(envelope).state is S.VERIFIED
    assert len(world.l2.calls) == 1


def test_the_attempt_is_audited_before_the_tool_is_called(world: World) -> None:
    seen: list[int] = []
    world.audit.during = lambda e: (
        seen.append(len(world.l2.calls))
        if (e.action, e.outcome) == (EXECUTE_ACTION, AuditOutcome.ATTEMPT)
        else None
    )
    world.l2.on_run = lambda call: seen.append(len(world.audit.find(EXECUTE_ACTION)) + 100)
    world.broker().execute(world.envelope())
    assert seen == [0, 101]  # attempt audited with 0 calls; the tool saw 1 audit record


def test_an_attempt_that_cannot_be_stored_on_the_row_never_calls_the_tool(world: World) -> None:
    """The row is taken away between the audit record and storing its id."""
    world.audit.during = lambda e: (
        force_state(world, S.ABORTED)
        if (e.action, e.outcome) == (EXECUTE_ACTION, AuditOutcome.ATTEMPT)
        else None
    )
    error = refused(world, world.envelope())
    assert error.reason is R.STORE_UNAVAILABLE
    assert len(world.l2.calls) == 0
    assert stored(world).attempt_audit_ref is None


# --- gate 10: the tool ---------------------------------------------------------------


def test_a_tool_that_raises_leaves_unknown_outcome(world: World) -> None:
    world.l2.run_error = RuntimeError("connection lost after sending")
    envelope = world.envelope()
    record = world.broker().execute(envelope)
    assert record.state is S.UNKNOWN_OUTCOME
    assert not record.succeeded
    assert not record.settled
    assert record.error_kind == "RuntimeError"
    assert "may have happened" in record.residual_risk
    assert "connection lost" not in record.model_dump_json()
    assert len(world.l2.verified) == 0
    assert len(world.l2.rolled_back) == 0
    result = world.audit.find(EXECUTE_ACTION)[-1]
    assert result.outcome is AuditOutcome.FAILED
    assert result.details["state"] == "unknown_outcome"
    assert result.details["residual_risk"]
    # no retry until it has been verified
    world.l2.run_error = None
    assert refused(world, envelope).reason is R.PRIOR_UNVERIFIED
    assert len(world.l2.calls) == 1


def test_a_tool_that_returns_something_else_leaves_unknown_outcome(world: World) -> None:
    world.l2.outcome = None  # type: ignore[assignment]  # no valid reply can be built
    record = world.broker().execute(world.envelope())
    assert record.state is S.UNKNOWN_OUTCOME
    assert record.error_kind == "ValidationError"


def test_an_execution_in_flight_is_not_run_again(world: World) -> None:
    envelope = world.envelope()
    world.l2.on_run = lambda call: seen.append(refused(world, envelope).reason)
    seen: list[RefusalReason] = []
    assert world.broker().execute(envelope).state is S.VERIFIED
    assert seen == [R.PRIOR_IN_FLIGHT]
    assert len(world.l2.calls) == 1


def test_a_key_claimed_between_the_lookup_and_the_claim_is_not_run_twice(world: World) -> None:
    """Two requests race: both pass the lookup, one claims the key, the other is refused."""
    envelope = world.envelope()
    raced: list[ExecutionState] = []

    def other_request_wins() -> None:
        world.policy.after = None
        raced.append(world.broker().execute(envelope).state)

    world.policy.after = other_request_wins
    assert refused(world, envelope).reason is R.PRIOR_IN_FLIGHT
    assert raced == [S.VERIFIED]
    assert len(world.l2.calls) == 1


# --- gate 11: independent verification -----------------------------------------------


def test_a_verification_mismatch_is_recorded_with_residual_risk(world: World) -> None:
    world.l2.matches = False
    record = world.broker().execute(world.envelope())
    assert record.state is S.VERIFICATION_FAILED
    assert not record.succeeded
    assert record.tool_outcome is ToolOutcome.SUCCEEDED  # the claim is kept, not believed
    assert record.verification_matches is False
    assert "does not show the result" in record.residual_risk
    assert stored(world).residual_risk == record.residual_risk
    result = world.audit.find(EXECUTE_ACTION)[-1]
    assert result.outcome is AuditOutcome.FAILED
    assert result.details["residual_risk"] == record.residual_risk
    assert result.details["verification_matches"] is False
    assert len(world.l2.rolled_back) == 0


def test_the_tools_reply_is_never_trusted(world: World) -> None:
    world.l2.outcome = ToolOutcome.FAILED  # says it failed; the target shows the result
    record = world.broker().execute(world.envelope())
    assert record.state is S.VERIFIED
    assert record.tool_outcome is ToolOutcome.FAILED
    assert len(world.l2.verified) == 1


def test_a_verifier_that_raises_never_yields_verified(world: World) -> None:
    world.l2.verify_error = RuntimeError("target unreachable")
    envelope = world.envelope()
    record = world.broker().execute(envelope)
    assert record.state is S.EXECUTED_UNVERIFIED
    assert not record.succeeded
    assert record.verification_matches is None
    assert record.error_kind == "RuntimeError"
    assert "could not be verified" in record.residual_risk
    assert world.audit.find(EXECUTE_ACTION)[-1].outcome is AuditOutcome.FAILED
    assert refused(world, envelope).reason is R.PRIOR_UNVERIFIED


# --- level 3: rollback ---------------------------------------------------------------


def test_an_l3_success_is_verified_and_not_rolled_back(world: World) -> None:
    record = world.broker().execute(world.envelope(L3_OP))
    assert record.state is S.VERIFIED
    assert len(world.l3.rolled_back) == 0


def test_an_l3_tool_that_raises_is_rolled_back(world: World) -> None:
    world.l3.run_error = RuntimeError("half applied")
    record = world.broker().execute(world.envelope(L3_OP))
    assert record.state is S.ROLLED_BACK
    assert record.error_kind == "RuntimeError"
    assert [result for _, result in world.l3.rolled_back] == [None]
    assert "rolled back" in record.residual_risk
    assert record.settled


def test_an_l3_tool_that_reports_failure_is_rolled_back(world: World) -> None:
    world.l3.outcome = ToolOutcome.FAILED
    record = world.broker().execute(world.envelope(L3_OP))
    assert record.state is S.ROLLED_BACK
    ((_, result),) = world.l3.rolled_back
    assert result is not None
    assert result.outcome is ToolOutcome.FAILED


def test_an_l3_verification_mismatch_is_rolled_back(world: World) -> None:
    world.l3.matches = False
    record = world.broker().execute(world.envelope(L3_OP))
    assert record.state is S.ROLLED_BACK
    assert record.verification_matches is False
    assert len(world.l3.rolled_back) == 1
    assert "verification did not match" in record.residual_risk
    assert world.audit.find(EXECUTE_ACTION)[-1].outcome is AuditOutcome.FAILED


@pytest.mark.parametrize("how", ["raises", "reports-failure"])
def test_a_rollback_that_fails_gets_its_own_state(world: World, how: str) -> None:
    world.l3.matches = False
    if how == "raises":
        world.l3.rollback_error = RuntimeError("cannot undo")
    else:
        world.l3.rollback_outcome = ToolOutcome.FAILED
    record = world.broker().execute(world.envelope(L3_OP))
    assert record.state is S.ROLLBACK_FAILED
    assert record.state is not S.ROLLED_BACK
    assert "partial change" in record.residual_risk
    assert len(world.l3.rolled_back) == 1


# --- gate 12: the result -------------------------------------------------------------


def test_result_audit_failure_raises_and_the_row_still_tells_the_truth(world: World) -> None:
    world.audit.fail_on(EXECUTE_ACTION, AuditOutcome.SUCCESS)
    envelope = world.envelope()
    with pytest.raises(ResultNotRecorded) as excinfo:
        world.broker().execute(envelope)
    assert isinstance(excinfo.value, FailClosed)
    assert excinfo.value.record.state is S.VERIFIED
    row = stored(world)
    assert row.state is S.VERIFIED
    assert row.result_audit_ref is None
    assert row.attempt_audit_ref
    assert len(world.l2.calls) == 1
    # the owed record is delivered later, and nothing runs twice
    world.audit.fail_if = None
    delivered = world.recovery().audit_owed_results()
    assert [r.execution_id for r in delivered] == [row.execution_id]
    assert stored(world).result_audit_ref
    assert world.recovery().audit_owed_results() == ()
    assert world.audit.find(EXECUTE_ACTION)[-1].details["late"] is True
    assert world.broker().execute(envelope).state is S.VERIFIED
    assert len(world.l2.calls) == 1


def test_an_owed_result_record_stays_owed_while_the_audit_log_refuses(world: World) -> None:
    world.audit.fail_on(EXECUTE_ACTION, AuditOutcome.SUCCESS)
    with pytest.raises(ResultNotRecorded):
        world.broker().execute(world.envelope())
    with pytest.raises(FailClosed, match="1 execution results"):
        world.recovery().audit_owed_results()
    assert stored(world).result_audit_ref is None


def test_a_result_that_cannot_be_stored_raises_and_is_never_reported_done(world: World) -> None:
    world.l2.on_run = lambda call: force_state(world, S.UNKNOWN_OUTCOME)
    with pytest.raises(ResultNotRecorded) as excinfo:
        world.broker().execute(world.envelope())
    assert excinfo.value.record.state is S.UNKNOWN_OUTCOME
    last = world.audit.find(EXECUTE_ACTION)[-1]
    assert last.outcome is AuditOutcome.FAILED
    assert last.details["problem"] == "result_not_stored"


# --- G20: write credentials behind the kill switch -----------------------------------


def fetch(found: list[Any]) -> Any:
    def body(call: ToolCall) -> None:
        found.append(call.credentials.get(WRITE_TOKEN_REF).reveal())

    return body


def test_a_tool_gets_its_declared_credential_through_the_gated_accessor(world: World) -> None:
    found: list[Any] = []
    world.l2.on_run = fetch(found)
    assert world.broker().execute(world.envelope()).state is S.VERIFIED
    assert found == [WRITE_TOKEN]
    assert world.secret_requests() == [WRITE_TOKEN_REF]
    # gate 1, the last look before the tool call, the credential fetch inside the tool
    assert world.killswitch.reads == [KillCapability.WRITES] * 3
    assert WRITE_TOKEN not in str([e.details for e in world.audit.events])


def test_engaging_the_switch_after_gate_one_stops_the_credential_fetch(world: World) -> None:
    found: list[Any] = []

    def body(call: ToolCall) -> None:
        world.killswitch.blocked.add(KillCapability.WRITES)  # the operator hits stop now
        fetch(found)(call)

    world.l2.on_run = body
    record = world.broker().execute(world.envelope())
    assert found == []
    assert world.secret_requests() == []
    assert record.state is S.UNKNOWN_OUTCOME
    assert record.error_kind == "KillSwitchEngaged"


def test_a_tool_cannot_fetch_a_credential_it_did_not_declare(world: World) -> None:
    def body(call: ToolCall) -> None:
        call.credentials.get("secret://someone_elses")

    world.l2.on_run = body
    record = world.broker().execute(world.envelope())
    assert record.error_kind == "AuthorizationError"
    assert world.secret_requests() == []


def test_the_gated_accessor_checks_the_switch_on_every_get() -> None:
    switch, vault = FakeKillSwitch(), FakeSecrets({WRITE_TOKEN_REF: WRITE_TOKEN})
    gated = KillSwitchGatedCredentials(switch, vault)
    assert gated.get(WRITE_TOKEN_REF).reveal() == WRITE_TOKEN
    assert gated.get(WRITE_TOKEN_REF).reveal() == WRITE_TOKEN
    assert switch.reads == [KillCapability.WRITES] * 2
    switch.blocked.add(KillCapability.WRITES)
    with pytest.raises(KillSwitchEngaged):
        gated.get(WRITE_TOKEN_REF)
    assert len(vault.requested) == 2
    assert WRITE_TOKEN not in repr(gated)


def test_the_gated_accessor_fails_closed_when_the_switch_cannot_be_read() -> None:
    class Unreadable:
        def is_blocked(self, capability: KillCapability) -> bool:
            raise RuntimeError("state unreadable")

    class Vague:
        def is_blocked(self, capability: KillCapability) -> Any:
            return 0

    vault = FakeSecrets({WRITE_TOKEN_REF: WRITE_TOKEN})
    with pytest.raises(FailClosed):
        KillSwitchGatedCredentials(Unreadable(), vault).get(WRITE_TOKEN_REF)
    with pytest.raises(KillSwitchEngaged):
        KillSwitchGatedCredentials(Vague(), vault).get(WRITE_TOKEN_REF)
    assert vault.requested == []
    assert not issubclass(AuthorizationError, FailClosed)


def test_l2_is_never_rolled_back(world: World) -> None:
    world.l2.run_error = RuntimeError("boom")
    world.broker().execute(world.envelope(L2_OP))
    assert len(world.l2.rolled_back) == 0
