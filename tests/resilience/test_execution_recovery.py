"""Executions that were in flight when the process stopped (plan gap G5; NFR-018).

Blueprint 19.3 (resilience: service restart; execution broker: partial failure); plan row
T2.4: in-flight executions at restart become `unknown_outcome`; retry without
verification is refused. Every test stops a "process" by disposing its engine and opens
the same database file again with brand-new objects.
"""

from __future__ import annotations

from collections.abc import Callable, Iterator
from datetime import timedelta
from pathlib import Path
from typing import Any

import pytest
from sqlalchemy import Engine, update
from tests.execution.broker_world import (
    L2_OP,
    L3_OP,
    SENSITIVE,
    WRITE_TOKEN_REF,
    PickyAudit,
    World,
)
from tests.fakes.core import FakePrincipals, FakeRedactor

from ciso.common.clock import FixedClock
from ciso.common.db import create_db_engine, init_operational_schema
from ciso.common.enums import AuditOutcome, KillCapability
from ciso.common.errors import Conflict, FailClosed, IntegrityFailure, NotFound
from ciso.common.principal import Principal
from ciso.execution import (
    EXECUTE_ACTION,
    OUTBOX_OPERATIONS,
    RECOVER_ACTION,
    TICKET_DRAFT_OPERATION,
    VERIFY_ACTION,
    ChannelRegistry,
    ExecutionRecord,
    ExecutionRefused,
    ExecutionState,
    ExecutionStoreError,
    RefusalReason,
    ResultNotRecorded,
    SkippedExecution,
    StoredEnvelopeRedacted,
    Tool,
    ToolCall,
    ToolOutcome,
    ToolRegistry,
    ToolResult,
    build_outbox_tools,
)
from ciso.execution.tables import execution_run

pytestmark = pytest.mark.resilience

R = RefusalReason
S = ExecutionState


class Crash(BaseException):
    """The process dies here. Not an `Exception`, so nothing in the broker handles it."""


Boot = Callable[..., World]


@pytest.fixture
def boot(
    tmp_path: Path, clock: FixedClock, principals: FakePrincipals, system_owner: Principal
) -> Iterator[Boot]:
    """Start a fresh process on the same database file. The previous one is stopped."""
    audit = PickyAudit(clock)  # the audit log is a separate store and outlives a restart
    engines: list[Engine] = []

    def start(tools: Callable[[Engine], tuple[Tool, ...]] = lambda engine: ()) -> World:
        for old in engines:
            old.dispose()
        engine = create_db_engine(tmp_path / "data" / "operational.db")
        init_operational_schema(engine)
        engines.append(engine)
        return World(engine, clock, audit, principals, system_owner, tools(engine))

    yield start
    for engine in engines:
        engine.dispose()


def crash_in_tool(world: World, key: str = "idem-1") -> Any:
    def die(call: Any) -> None:
        raise Crash

    world.l2.on_run = die
    envelope = world.envelope(L2_OP, key=key)
    with pytest.raises(Crash):
        world.broker().execute(envelope)
    return envelope


def only_row(world: World) -> ExecutionRecord:
    with world.engine.begin() as conn:
        row = conn.execute(execution_run.select()).one()
    found = world.broker().get(row.execution_id)
    assert found is not None
    return found


def refusal(world: World, envelope: Any) -> RefusalReason:
    with pytest.raises(ExecutionRefused) as excinfo:
        world.broker().execute(envelope)
    return excinfo.value.reason


def test_an_execution_in_flight_at_restart_becomes_unknown_outcome(boot: Boot) -> None:
    before = boot()
    envelope = crash_in_tool(before)
    assert only_row(before).state is S.PENDING
    assert only_row(before).attempt_audit_ref

    after = boot()
    assert after.engine is not before.engine
    assert only_row(after).state is S.PENDING  # the row survived the restart as it was
    changed = after.recover()
    assert [r.state for r in changed] == [S.UNKNOWN_OUTCOME]
    row = only_row(after)
    assert row.state is S.UNKNOWN_OUTCOME
    assert "restart" in row.residual_risk
    records = after.audit.find(RECOVER_ACTION)
    assert [e.outcome for e in records] == [AuditOutcome.ATTEMPT, AuditOutcome.SUCCESS]
    assert records[-1].details["state"] == "unknown_outcome"
    assert records[-1].details["from_state"] == "pending"
    assert records[-1].details["execution"] == row.ref
    assert after.recover() == ()  # nothing left in flight

    # a retry without verification is refused and the tool is not called
    assert refusal(after, envelope) is R.PRIOR_UNVERIFIED
    assert len(after.l2.calls) == 0


def test_without_recovery_the_in_flight_row_still_blocks_a_retry(boot: Boot) -> None:
    envelope = crash_in_tool(boot())
    after = boot()
    assert refusal(after, envelope) is R.PRIOR_IN_FLIGHT
    assert len(after.l2.calls) == 0


@pytest.mark.parametrize(
    ("target_shows_it", "state", "outcome"),
    [(True, S.VERIFIED, AuditOutcome.SUCCESS), (False, S.VERIFICATION_FAILED, AuditOutcome.FAILED)],
)
def test_a_verification_pass_settles_an_unknown_outcome(
    boot: Boot, target_shows_it: bool, state: ExecutionState, outcome: AuditOutcome
) -> None:
    envelope = crash_in_tool(boot())
    after = boot()
    recovery = after.recovery()
    (unknown,) = after.recover()
    after.l2.matches = target_shows_it
    settled = recovery.verify(unknown.execution_id)
    assert settled.state is state
    assert settled.verification_matches is target_shows_it
    assert bool(settled.residual_risk) is not target_shows_it
    assert len(after.l2.verified) == 1
    assert len(after.l2.calls) == 0
    # the verifier got the call the broker had built, rebuilt from the stored envelope
    assert after.l2.verified[0].envelope_hash == envelope.envelope_hash()
    assert after.l2.verified[0].arguments.model_dump() == {"note": "hello"}
    records = after.audit.find(VERIFY_ACTION)
    assert [e.outcome for e in records] == [AuditOutcome.ATTEMPT, outcome]
    assert settled.result_audit_ref
    assert recovery.unknown() == ()
    # now the key replays the settled result; still nothing runs again
    assert after.broker().execute(envelope).state is state
    assert len(after.l2.calls) == 0


def test_a_verifier_that_cannot_answer_leaves_the_outcome_unknown(boot: Boot) -> None:
    envelope = crash_in_tool(boot())
    after = boot()
    recovery = after.recovery()
    (unknown,) = after.recover()
    after.l2.verify_error = RuntimeError("target unreachable")
    still = recovery.verify(unknown.execution_id)
    assert still.state is S.UNKNOWN_OUTCOME
    assert still.error_kind == "RuntimeError"
    assert after.audit.find(VERIFY_ACTION)[-1].outcome is AuditOutcome.FAILED
    assert refusal(after, envelope) is R.PRIOR_UNVERIFIED
    after.l2.verify_error = None
    assert [r.state for r in recovery.verify_all().settled] == [S.VERIFIED]


def test_a_crash_during_verification_is_recovered_as_unknown_too(boot: Boot) -> None:
    before = boot()
    before.l2.verify_error = Crash()  # type: ignore[assignment]
    with pytest.raises(Crash):
        before.broker().execute(before.envelope())
    assert only_row(before).state is S.EXECUTED_UNVERIFIED
    after = boot()
    (changed,) = after.recover()
    assert changed.state is S.UNKNOWN_OUTCOME
    assert after.audit.find(RECOVER_ACTION)[-1].details["from_state"] == "executed_unverified"


def test_a_row_whose_attempt_was_never_audited_is_aborted_not_unknown(boot: Boot) -> None:
    """The broker calls a tool only after the attempt's audit id is on the row."""
    before = boot()

    def die(event: Any) -> None:
        if (event.action, event.outcome) == (EXECUTE_ACTION, AuditOutcome.ATTEMPT):
            raise Crash

    before.audit.during = die
    envelope = before.envelope()
    with pytest.raises(Crash):
        before.broker().execute(envelope)
    before.audit.during = None
    assert only_row(before).attempt_audit_ref is None
    assert len(before.l2.calls) == 0
    after = boot()
    (changed,) = after.recover()
    assert changed.state is S.ABORTED
    assert changed.residual_risk == ""
    assert after.recovery().unknown() == ()
    assert only_row(after).attempt_audit_ref is None
    # an aborted run is not replayed as a result: the same envelope runs (finding L2)
    assert after.broker().execute(envelope).state is S.VERIFIED
    assert len(after.l2.calls) == 1
    assert only_row(after).execution_id == changed.execution_id


def test_recovery_that_cannot_be_audited_changes_nothing(boot: Boot) -> None:
    envelope = crash_in_tool(boot())
    after = boot()
    after.audit.fail_on(RECOVER_ACTION, AuditOutcome.ATTEMPT)
    with pytest.raises(FailClosed):
        after.recover()
    assert only_row(after).state is S.PENDING
    assert refusal(after, envelope) is R.PRIOR_IN_FLIGHT


def test_a_recovery_whose_result_cannot_be_audited_still_blocks_the_retry(boot: Boot) -> None:
    envelope = crash_in_tool(boot())
    after = boot()
    after.audit.fail_on(RECOVER_ACTION, AuditOutcome.SUCCESS)
    with pytest.raises(FailClosed):
        after.recover()
    assert only_row(after).state is S.UNKNOWN_OUTCOME
    assert refusal(after, envelope) is R.PRIOR_UNVERIFIED


def test_settled_executions_are_left_alone_and_the_rate_count_survives(boot: Boot) -> None:
    before = boot()
    done = before.broker(tool_rate_limit_per_minute=2).execute(before.envelope(key="a"))
    crash_in_tool(before, key="b")
    after = boot()
    assert [r.idempotency_key for r in after.recover()] == ["b"]
    assert after.broker().get(done.execution_id) == done
    # two calls were claimed in this minute before the restart; a third is refused
    limited = after.broker(tool_rate_limit_per_minute=2)
    with pytest.raises(ExecutionRefused) as excinfo:
        limited.execute(after.envelope(key="c"))
    assert excinfo.value.reason is R.RATE_LIMITED
    assert len(after.l2.calls) == 0


def test_verify_refuses_what_it_cannot_stand_behind(boot: Boot) -> None:
    before = boot()
    done = before.broker().execute(before.envelope(key="done"))
    crash_in_tool(before, key="lost")
    after = boot()
    recovery = after.recovery()
    (unknown,) = after.recover()
    with pytest.raises(NotFound):
        recovery.verify("exe_nope")
    with pytest.raises(Conflict):
        recovery.verify(done.execution_id)
    with after.engine.begin() as conn:
        row = conn.execute(
            execution_run.select().where(execution_run.c.execution_id == unknown.execution_id)
        ).one()
        conn.execute(
            update(execution_run)
            .where(execution_run.c.execution_id == unknown.execution_id)
            .values(envelope=row.envelope.replace('"note":"hello"', '"note":"else"'))
        )
    with pytest.raises(IntegrityFailure):
        recovery.verify(unknown.execution_id)
    assert len(after.l2.verified) == 0
    assert only_row_state(after, unknown.execution_id) is S.UNKNOWN_OUTCOME


def only_row_state(world: World, execution_id: str) -> ExecutionState:
    found = world.broker().get(execution_id)
    assert found is not None
    return found.state


def test_recovery_needs_a_sealed_registry(boot: Boot) -> None:
    with pytest.raises(ValueError, match="sealed"):
        boot().recovery(registry=ToolRegistry())


# =====================================================================================
# Review `docs/reviews/m2-execution-broker.md`: the findings whose sequence needs a
# restart or a verification pass. Tests are named after the finding.
# =====================================================================================


def crash_in(tool: Any) -> None:
    def die(call: Any) -> None:
        raise Crash

    tool.on_run = die


def verify_records(world: World) -> list[Any]:
    return world.audit.find(VERIFY_ACTION)  # type: ignore[no-any-return]


# --- H2 / M7: recovery leaves alone what it cannot read ------------------------------


def test_h2_recovery_goes_on_past_a_row_it_cannot_authenticate(boot: Boot) -> None:
    before = boot()
    crash_in_tool(before, key="bad")
    crash_in_tool(before, key="good")
    after = boot()
    after.tamper("bad", approval_ref="approval:forged")
    with pytest.raises(FailClosed, match="1 executions could not be recovered"):
        after.recover()
    assert after.row("good").state is S.UNKNOWN_OUTCOME
    assert after.raw("bad").state == "pending"  # untouched
    skipped = [e for e in after.audit.find(RECOVER_ACTION) if e.details.get("skipped")]
    assert [e.details["problem"] for e in skipped] == ["ExecutionStoreError"]


def test_h2_recovery_takes_the_row_so_the_old_run_token_is_dead(boot: Boot) -> None:
    before = boot()
    crash_in_tool(before)
    token = before.raw().run_token
    assert token.startswith("run_")
    after = boot()
    (changed,) = after.recover()
    assert changed.run_token != token
    assert str(changed.run_token).startswith("rec_")


# --- M4: verification from the redacted stored request -------------------------------


def test_m4_recovery_refuses_to_verify_from_redacted_arguments(boot: Boot) -> None:
    before = boot()
    crash_in(before.l2)
    envelope = before.envelope(arguments={"note": f"password is {SENSITIVE}"})
    with pytest.raises(Crash):
        before.broker().execute(envelope)
    assert SENSITIVE not in before.raw().envelope
    after = boot()
    (unknown,) = after.recover()
    with pytest.raises(StoredEnvelopeRedacted, match=r"note\.write.*original arguments"):
        after.recovery().verify(unknown.execution_id)
    assert len(after.l2.verified) == 0
    assert after.row().state is S.UNKNOWN_OUTCOME
    assert verify_records(after) == []  # refused before anything was announced
    done = after.recovery().verify_all()
    assert done.settled == ()
    assert done.skipped == (
        SkippedExecution(execution_id=unknown.execution_id, problem="StoredEnvelopeRedacted"),
    )


def test_m4_a_declared_operation_is_verified_from_the_redacted_request(boot: Boot) -> None:
    """The mechanism on its own: the verifier gets the redacted arguments and the hash of
    the request as it was submitted."""
    before = boot()
    crash_in(before.l2)
    envelope = before.envelope(arguments={"note": f"password is {SENSITIVE}"})
    with pytest.raises(Crash):
        before.broker().execute(envelope)
    after = boot()
    (unknown,) = after.recover()
    recovery = after.recovery(verifiable_from_redacted={"note.write"})
    assert recovery.verify(unknown.execution_id).state is S.VERIFIED
    (call,) = after.l2.verified
    assert call.arguments.model_dump() == {"note": "password is [REDACTED]"}
    assert call.envelope_hash == envelope.envelope_hash()
    assert call.idempotency_key == envelope.idempotency_key


def outbox_tools(tmp_path: Path, world_parts: dict[str, Any], crash: bool) -> Any:
    """The shipped tools on this database; `crash` kills the process right after the
    ticket draft reached the outbox."""

    def build(engine: Engine) -> tuple[Tool, ...]:
        channels = ChannelRegistry(
            engine, world_parts["clock"], world_parts["audit"], world_parts["principals"]
        )
        if not channels.is_approved("sec_tickets"):
            seen = channels.propose("agent_ciso", "sec_tickets", "security_queue", "tickets")
            channels.approve(
                "human_admin",
                "sec_tickets",
                seen.target,
                version=seen.version,
                purpose_digest=seen.purpose_digest,
            )
        world_parts["channels"] = channels
        ticket, notice = build_outbox_tools(tmp_path / "outbox", channels, world_parts["redactor"])
        if not crash:
            return (ticket, notice)

        def write_then_die(call: ToolCall) -> ToolResult:
            assert ticket.run(call).outcome is ToolOutcome.SUCCEEDED
            raise Crash

        return (Tool(spec=ticket.spec, run=write_then_die, verify=ticket.verify), notice)

    return build


@pytest.mark.parametrize(("altered", "state"), [(False, S.VERIFIED), (True, S.VERIFICATION_FAILED)])
def test_m4_an_outbox_draft_is_verified_after_a_restart_from_the_redacted_request(
    boot: Boot,
    tmp_path: Path,
    clock: FixedClock,
    principals: FakePrincipals,
    altered: bool,
    state: ExecutionState,
) -> None:
    parts: dict[str, Any] = {"clock": clock, "principals": principals}
    parts["redactor"] = FakeRedactor(SENSITIVE)
    probe = boot()  # only to reach the shared audit sink
    parts["audit"] = probe.audit
    before = boot(outbox_tools(tmp_path, parts, crash=True))
    before.context.is_channel_approved = parts["channels"].is_approved  # type: ignore[method-assign]
    spec = before.registry.get(TICKET_DRAFT_OPERATION).spec
    envelope = before.envelope(
        spec,
        arguments={
            "channel": "sec_tickets",
            "title": "Rotate the key",
            "body": f"password is {SENSITIVE}",
        },
    )
    with pytest.raises(Crash):
        before.broker().execute(envelope)
    (draft,) = [p for p in (tmp_path / "outbox").rglob("*") if p.is_file()]
    assert SENSITIVE not in draft.read_text(encoding="utf-8")
    assert SENSITIVE not in before.raw().envelope

    after = boot(outbox_tools(tmp_path, parts, crash=False))
    (unknown,) = after.recover()
    with pytest.raises(StoredEnvelopeRedacted):  # not declared: refused, not guessed
        after.recovery().verify(unknown.execution_id)
    if altered:  # a draft changed on disk is still caught from the redacted request
        draft.write_bytes(draft.read_bytes() + b" ")
    settled = after.recovery(verifiable_from_redacted=OUTBOX_OPERATIONS).verify(
        unknown.execution_id
    )
    assert settled.state is state
    assert settled.observed == (() if altered else (f"draft:{draft.stem}",))
    assert {"ticket.create_draft", "owner.notify_draft"} == OUTBOX_OPERATIONS


# --- M6: a verifier that failed once can be asked again without a restart ------------


def test_m6_a_row_left_unverified_by_a_failing_verifier_can_be_verified_later(
    boot: Boot,
) -> None:
    world = boot()
    world.l2.verify_error = RuntimeError("target unreachable")
    envelope = world.envelope()
    left = world.broker().execute(envelope)
    assert left.state is S.EXECUTED_UNVERIFIED
    assert left.error_kind == "RuntimeError"
    assert left.awaiting_verification
    recovery = world.recovery()
    assert [r.execution_id for r in recovery.unknown()] == [left.execution_id]
    assert refusal(world, envelope) is R.PRIOR_UNVERIFIED
    # still unreachable: nothing changes, and it stays listed
    assert recovery.verify(left.execution_id).state is S.EXECUTED_UNVERIFIED
    assert len(recovery.unknown()) == 1
    world.l2.verify_error = None
    settled = recovery.verify(left.execution_id)
    assert settled.state is S.VERIFIED
    assert settled.error_kind == ""
    assert settled.residual_risk == ""
    assert recovery.unknown() == ()
    assert len(world.l2.calls) == 1
    assert world.broker().execute(envelope).state is S.VERIFIED
    assert len(world.l2.calls) == 1


def test_m6_a_row_still_held_by_its_run_is_not_taken_by_a_verification_pass(boot: Boot) -> None:
    world = boot()
    world.l2.verify_error = Crash()  # type: ignore[assignment]
    with pytest.raises(Crash):
        world.broker().execute(world.envelope())
    row = only_row(world)
    assert row.state is S.EXECUTED_UNVERIFIED
    assert row.error_kind == ""
    assert not row.awaiting_verification
    recovery = world.recovery()
    assert recovery.unknown() == ()
    world.l2.verify_error = None
    with pytest.raises(Conflict):
        recovery.verify(row.execution_id)
    done = recovery.verify_all()
    assert (done.settled, done.skipped) == ((), ())
    assert len(world.l2.verified) == 1  # only the run's own call, the one that crashed


def test_m6_a_verification_pass_takes_the_row_from_the_earlier_run(boot: Boot) -> None:
    world = boot()
    world.l2.verify_error = RuntimeError("target unreachable")
    left = world.broker().execute(world.envelope())
    world.l2.verify_error = None
    settled = world.recovery().verify(left.execution_id)
    assert settled.run_token != left.run_token
    assert world.store().change(left, world.clock.now(), error_kind="late") is None


# --- L1: a recovered level 3 run that does not verify is rolled back ----------------


@pytest.mark.parametrize(
    ("undo", "state"), [(None, S.ROLLED_BACK), (RuntimeError("cannot undo"), S.ROLLBACK_FAILED)]
)
def test_l1_a_recovered_l3_run_that_does_not_verify_is_rolled_back(
    boot: Boot, undo: Exception | None, state: ExecutionState
) -> None:
    before = boot()
    crash_in(before.l3)
    envelope = before.envelope(L3_OP)
    with pytest.raises(Crash):
        before.broker().execute(envelope)
    after = boot()
    (unknown,) = after.recover()
    after.l3.matches = False
    after.l3.rollback_error = undo
    settled = after.recovery().verify(unknown.execution_id)
    assert settled.state is state
    assert settled.verification_matches is False
    assert [result for _, result in after.l3.rolled_back] == [None]
    assert len(after.l3.calls) == 0
    closing = verify_records(after)[-1]
    assert closing.outcome is AuditOutcome.FAILED
    assert closing.details["state"] == state.value
    assert settled.result_audit_ref
    assert after.broker().execute(envelope).state is state  # replayed, never run again


def test_l1_a_recovered_l3_run_that_verifies_is_not_rolled_back(boot: Boot) -> None:
    before = boot()
    crash_in(before.l3)
    with pytest.raises(Crash):
        before.broker().execute(before.envelope(L3_OP))
    after = boot()
    (unknown,) = after.recover()
    assert after.recovery().verify(unknown.execution_id).state is S.VERIFIED
    assert after.l3.rolled_back == []


def test_l1_a_recovered_l2_mismatch_is_still_not_rolled_back(boot: Boot) -> None:
    crash_in_tool(boot())
    after = boot()
    (unknown,) = after.recover()
    after.l2.matches = False
    assert after.recovery().verify(unknown.execution_id).state is S.VERIFICATION_FAILED
    assert after.l2.rolled_back == []


# --- L4: one bad row does not stop the pass -----------------------------------------


def test_l4_verify_all_goes_on_past_rows_it_cannot_handle(boot: Boot) -> None:
    before = boot()
    for key in ("a-envelope", "b-mac", "c-good"):
        crash_in_tool(before, key=key)
    after = boot()
    assert len(after.recover()) == 3
    ids = {key: after.execution_id(key) for key in ("a-envelope", "b-mac", "c-good")}
    after.tamper("a-envelope", envelope='{"not": "the request"}')
    after.tamper("b-mac", state="verified")  # also takes it out of the waiting list
    after.tamper("b-mac", state="unknown_outcome", approval_ref="approval:forged")
    done = after.recovery().verify_all()
    assert [r.idempotency_key for r in done.settled] == ["c-good"]
    assert done.settled[0].state is S.VERIFIED
    assert done.skipped == (
        SkippedExecution(execution_id=ids["a-envelope"], problem="IntegrityFailure"),
        SkippedExecution(execution_id=ids["b-mac"], problem="ExecutionStoreError"),
    )
    noted = [e for e in verify_records(after) if e.details.get("skipped")]
    assert [e.details["execution"] for e in noted] == [
        f"execution:{ids['a-envelope']}",
        f"execution:{ids['b-mac']}",
    ]
    assert all(e.outcome is AuditOutcome.FAILED for e in noted)
    assert after.raw("a-envelope").state == "unknown_outcome"
    with pytest.raises(ExecutionStoreError):
        after.recovery().unknown()  # the strict listing does not hide the bad row


# --- M8: recovery guards that had no failing test ------------------------------------


def test_m8_an_aborted_row_with_no_audited_attempt_is_owed_no_result_record(boot: Boot) -> None:
    world = boot()
    world.audit.fail_on(EXECUTE_ACTION, AuditOutcome.ATTEMPT)
    assert refusal(world, world.envelope()) is R.ATTEMPT_AUDIT_FAILED
    world.audit.fail_if = None
    row = only_row(world)
    assert (row.state, row.attempt_audit_ref, row.result_audit_ref) == (S.ABORTED, None, None)
    assert world.recovery().audit_owed_results() == ()
    assert world.audit.find(EXECUTE_ACTION) == []
    assert only_row(world).result_audit_ref is None


def test_m8_an_owed_record_is_not_delivered_for_a_row_that_is_not_settled(boot: Boot) -> None:
    world = boot()
    world.l2.run_error = RuntimeError("connection lost")
    world.audit.fail_on(EXECUTE_ACTION, AuditOutcome.FAILED)
    with pytest.raises(ResultNotRecorded):
        world.broker().execute(world.envelope())
    world.audit.fail_if = None
    row = only_row(world)
    assert (row.state, row.result_audit_ref) == (S.UNKNOWN_OUTCOME, None)
    assert row.attempt_audit_ref
    assert world.recovery().audit_owed_results() == ()
    assert world.audit.outcomes(EXECUTE_ACTION) == [AuditOutcome.ATTEMPT]
    # once verified, the verification pass writes and links the closing record itself
    world.l2.run_error = None
    assert world.recovery().verify(row.execution_id).result_audit_ref
    assert world.recovery().audit_owed_results() == ()


def test_m8_a_late_abort_whose_closing_record_failed_is_delivered_later(boot: Boot) -> None:
    world = boot()

    def engage(event: Any) -> None:
        if (event.action, event.outcome) == (EXECUTE_ACTION, AuditOutcome.ATTEMPT):
            world.killswitch.blocked.add(KillCapability.WRITES)

    world.audit.during = engage
    world.audit.fail_on(EXECUTE_ACTION, AuditOutcome.DENIED)
    assert refusal(world, world.envelope()) is R.KILL_SWITCH_ENGAGED
    world.audit.fail_if = None
    row = only_row(world)
    assert (row.state, row.result_audit_ref) == (S.ABORTED, None)
    assert row.attempt_audit_ref
    (delivered,) = world.recovery().audit_owed_results()
    assert delivered.result_audit_ref
    late = world.audit.find(EXECUTE_ACTION)[-1]
    assert (late.outcome, late.details["late"], late.details["state"]) == (
        AuditOutcome.FAILED,
        True,
        "aborted",
    )


def test_m8_a_verification_that_cannot_be_audited_fails_closed(boot: Boot) -> None:
    crash_in_tool(boot())
    after = boot()
    (unknown,) = after.recover()
    after.audit.fail_on(VERIFY_ACTION, AuditOutcome.SUCCESS)
    with pytest.raises(FailClosed, match="could not be audited"):
        after.recovery().verify(unknown.execution_id)
    after.audit.fail_if = None
    row = only_row(after)
    assert row.state is S.VERIFIED  # the row holds what was learned
    assert row.result_audit_ref is None  # and still owes its record
    (delivered,) = after.recovery().audit_owed_results()
    assert delivered.result_audit_ref


def test_m8_recoverys_verifier_gets_its_credential_through_the_kill_switch(boot: Boot) -> None:
    crash_in_tool(boot())
    after = boot()
    (unknown,) = after.recover()
    fetched: list[str] = []
    after.l2.on_verify = lambda call: fetched.append(call.credentials.get(WRITE_TOKEN_REF).reveal())
    after.killswitch.blocked.add(KillCapability.WRITES)
    still = after.recovery().verify(unknown.execution_id)
    assert still.state is S.UNKNOWN_OUTCOME
    assert still.error_kind == "KillSwitchEngaged"
    assert fetched == []
    assert after.secret_requests() == []
    after.killswitch.blocked.clear()
    assert after.recovery().verify(unknown.execution_id).state is S.VERIFIED
    assert len(fetched) == 1
    assert after.secret_requests() == [WRITE_TOKEN_REF]


# --- H2: each recovery update is conditional on the row still being a dead run's -----


@pytest.mark.parametrize("attempt_audited", [True, False], ids=["in-flight", "never-called"])
def test_h2_recovery_leaves_a_row_that_was_claimed_again_while_it_worked(
    boot: Boot, attempt_audited: bool
) -> None:
    """Between recovery's listing and its update the row gets a newer claim. The update
    carries its own condition and must miss."""
    before = boot()
    if attempt_audited:
        crash_in_tool(before)
    else:

        def die_at_the_attempt(event: Any) -> None:
            if (event.action, event.outcome) == (EXECUTE_ACTION, AuditOutcome.ATTEMPT):
                raise Crash

        before.audit.during = die_at_the_attempt
        with pytest.raises(Crash):
            before.broker().execute(before.envelope())
        before.audit.during = None
        assert only_row(before).attempt_audit_ref is None
    after = boot()
    started = after.clock.now() + timedelta(seconds=1)

    def claim_again(event: Any) -> None:
        if (event.action, event.outcome) == (RECOVER_ACTION, AuditOutcome.ATTEMPT):
            after.force(claimed_at=started + timedelta(seconds=5))

    after.audit.during = claim_again
    assert after.recover(started) == ()
    row = only_row(after)
    assert row.state is S.PENDING
    assert str(row.run_token).startswith("run_")
    assert [e.outcome for e in after.audit.find(RECOVER_ACTION)] == [AuditOutcome.ATTEMPT]


# --- M4: redaction that damages the identifying fields is refused --------------------


class SwapsText:
    """A redactor that rewrites one piece of text into another."""

    def __init__(self, old: str, new: str) -> None:
        self._old, self._new = old, new

    def redact(self, text: str) -> str:
        return text.replace(self._old, self._new)

    def redact_value(self, value: Any) -> Any:
        if isinstance(value, str):
            return self.redact(value)
        if isinstance(value, dict):
            return {key: self.redact_value(item) for key, item in value.items()}
        if isinstance(value, list):
            return [self.redact_value(item) for item in value]
        return value


@pytest.mark.parametrize(
    ("new", "message"),
    [("idem-2", "identifies the call"), ("not a key", "cannot be read back")],
    ids=["another-key", "unreadable"],
)
def test_m4_a_stored_request_whose_identifiers_were_redacted_is_not_verified(
    boot: Boot, new: str, message: str
) -> None:
    redactor = SwapsText("idem-1", new)
    before = boot()
    crash_in(before.l2)
    with pytest.raises(Crash):
        before.broker(redactor=redactor).execute(before.envelope())
    after = boot()
    (unknown,) = after.recover()
    recovery = after.recovery(redactor=redactor, verifiable_from_redacted={"note.write"})
    with pytest.raises(StoredEnvelopeRedacted, match=message):
        recovery.verify(unknown.execution_id)
    assert len(after.l2.verified) == 0
    assert only_row(after).state is S.UNKNOWN_OUTCOME


# --- L2: the store takes up an aborted row only for the same envelope hash -----------


def test_l2_the_store_takes_up_an_aborted_row_only_for_the_same_envelope_hash(boot: Boot) -> None:
    world = boot()
    world.audit.fail_on(EXECUTE_ACTION, AuditOutcome.ATTEMPT)
    assert refusal(world, world.envelope()) is R.ATTEMPT_AUDIT_FAILED
    world.audit.fail_if = None
    aborted = only_row(world)
    assert aborted.state is S.ABORTED
    store = world.store()
    now = world.clock.now()
    fresh = aborted.model_copy(
        update={"execution_id": "exe_other", "state": S.PENDING, "run_token": "run_new"}
    )
    other = fresh.model_copy(update={"envelope_hash": "0" * 64})
    window = now - timedelta(minutes=1)
    refused_claim = store.claim(other, "{}", limit=5, window_start=window)
    assert (refused_claim.outcome.value, refused_claim.record) == ("duplicate", None)
    assert only_row(world) == aborted
    taken = store.claim(fresh, "{}", limit=5, window_start=window)
    assert taken.outcome.value == "claimed"
    assert taken.record is not None
    assert taken.record.execution_id == aborted.execution_id  # the same row, taken up again
    assert only_row(world).run_token == "run_new"
    # and a row that is not aborted is never taken up, whatever the hash
    again = store.claim(fresh, "{}", limit=5, window_start=window)
    assert again.outcome.value == "duplicate"


def test_m6_a_verification_that_loses_the_row_while_starting_asks_no_verifier(boot: Boot) -> None:
    """Someone else takes the row between the ATTEMPT record and the take-over."""
    crash_in_tool(boot())
    after = boot()
    (unknown,) = after.recover()

    def taken(event: Any) -> None:
        if (event.action, event.outcome) == (VERIFY_ACTION, AuditOutcome.ATTEMPT):
            after.force(run_token="rec_someone_else")

    after.audit.during = taken
    with pytest.raises(Conflict, match="changed while its verification was starting"):
        after.recovery().verify(unknown.execution_id)
    after.audit.during = None
    assert len(after.l2.verified) == 0
    row = only_row(after)
    assert (row.state, row.run_token) == (S.UNKNOWN_OUTCOME, "rec_someone_else")
    assert after.recovery().verify(unknown.execution_id).state is S.VERIFIED  # allowed path
