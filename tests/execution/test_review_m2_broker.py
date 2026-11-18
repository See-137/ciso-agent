"""Regression tests for the M2 review of the execution broker
(`docs/reviews/m2-execution-broker.md`). Each test is named after the finding it closes
and replays the reviewer's sequence.

Findings whose sequence needs a process restart (M4 recovery, M6, L1, L4 and the recovery
rows of M8) are in `tests/resilience/test_execution_recovery.py`; the outbox ones (L5, L8
and the outbox rows of M8) are in `test_outbox_tools.py`.
"""

from __future__ import annotations

import threading
import traceback
from collections.abc import Iterator
from datetime import timedelta
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from sqlalchemy import Engine, event, func, select, text
from tests.execution.broker_world import (
    L2_OP,
    L3_OP,
    L4_OP,
    ROW_KEY_REF,
    SENSITIVE,
    WRITE_TOKEN_REF,
    PickyAudit,
    World,
)
from tests.execution.conftest import LockSpy, WorldFactory
from tests.fakes.core import FakePrincipals, FakeRedactor, FakeSecrets, make_principal

from ciso.approvals import ApprovalStatus
from ciso.common.clock import FixedClock
from ciso.common.db import create_db_engine, init_operational_schema
from ciso.common.enums import ActorType, AuditOutcome, AuthorityLevel, KillCapability
from ciso.common.errors import FailClosed
from ciso.common.principal import Principal
from ciso.execution import (
    BROKER_ACTOR_ID,
    DUPLICATE_ACTION,
    EXECUTE_ACTION,
    RECOVER_ACTION,
    ExecutionRefused,
    ExecutionState,
    ExecutionStoreError,
    RefusalReason,
    ResultNotRecorded,
    ToolCall,
)
from ciso.execution.approval_gate import require_matching_approval
from ciso.execution.integrity import MIN_ROW_KEY_BYTES, RowSeal
from ciso.execution.refusals import (
    REFUSALS_SUPPRESSED_ACTION,
    UNVERIFIED_REFUSAL_AUDIT_CAP,
    UNVERIFIED_REFUSAL_WINDOW,
)
from ciso.execution.sanitize import MAX_DETAIL, MAX_REFERENCES, safe_refs, safe_text
from ciso.execution.store import ExecutionStore
from ciso.execution.tables import execution_run
from ciso.policy import ActionEnvelope

pytestmark = pytest.mark.broker

R = RefusalReason
S = ExecutionState
ATTEMPT = (EXECUTE_ACTION, AuditOutcome.ATTEMPT)


def refused(
    world: World, envelope: Any, approval_id: str | None = None, **parts: Any
) -> ExecutionRefused:
    with pytest.raises(ExecutionRefused) as excinfo:
        world.broker(**parts).execute(envelope, approval_id)
    return excinfo.value


def rows(world: World) -> int:
    with world.engine.begin() as conn:
        return int(conn.execute(select(func.count()).select_from(execution_run)).scalar_one())


def status(world: World, approval_id: str) -> ApprovalStatus:
    return world.approvals.get(approval_id).status  # type: ignore[no-any-return]


def at_attempt(world: World, act: Any) -> None:
    """Run `act` while the broker's ATTEMPT record is being appended: after every gate
    and before the tool call."""
    world.audit.during = lambda e: act() if (e.action, e.outcome) == ATTEMPT else None


@pytest.fixture
def file_world(
    tmp_path: Path, clock: FixedClock, principals: FakePrincipals, system_owner: Principal
) -> Iterator[World]:
    """A world on a database file, so two threads really hold two connections."""
    engine: Engine = create_db_engine(tmp_path / "data" / "operational.db")
    init_operational_schema(engine)
    yield World(engine, clock, PickyAudit(clock), principals, system_owner)
    engine.dispose()


# --- H1: an approval for one envelope spent on different arguments -------------------


def test_h1_a_subclass_that_lies_about_its_hash_is_refused(world: World) -> None:
    approved = world.envelope(L4_OP, key="k1", arguments={"note": "approved text"})
    approval_id = world.approve(approved)

    class Evil(ActionEnvelope):
        def envelope_hash(self) -> str:
            return approved.envelope_hash()

    evil = Evil(**{**approved.model_dump(), "arguments": {"note": "NOT WHAT WAS APPROVED"}})
    assert evil.envelope_hash() == approved.envelope_hash()
    error = refused(world, evil, approval_id)
    assert error.reason is R.INVALID_REQUEST
    assert len(world.l4.calls) == 0
    assert status(world, approval_id) is ApprovalStatus.APPROVED
    assert rows(world) == 0
    # the honest envelope still runs on that approval
    assert world.broker().execute(approved, approval_id).state is S.VERIFIED
    assert world.l4.calls[0].arguments.model_dump() == {"note": "approved text"}


def test_h1_an_envelope_changed_between_the_gates_cannot_borrow_an_approval(world: World) -> None:
    approved = world.envelope(L4_OP, key="k1", arguments={"note": "approved text"})
    approval_id = world.approve(approved)
    evil = ActionEnvelope(**{**approved.model_dump(), "arguments": {"note": "EVIL ARGS"}})
    swapped: list[bool] = []

    def swap(conn: Any, cursor: Any, statement: str, *rest: Any) -> None:
        # the idempotency lookup: after the tool call was built, before policy
        if "execution_run" in statement and not swapped:
            swapped.append(True)
            evil.__dict__["arguments"] = approved.arguments

    event.listen(world.engine, "before_cursor_execute", swap)
    try:
        error = refused(world, evil, approval_id)
    finally:
        event.remove(world.engine, "before_cursor_execute", swap)
    assert swapped == [True]
    assert evil.envelope_hash() == approved.envelope_hash()  # the caller's object now lies
    assert error.reason is R.APPROVAL_INVALID
    assert error.codes == ("subject_mismatch",)
    assert len(world.l4.calls) == 0
    assert status(world, approval_id) is ApprovalStatus.APPROVED


def test_h1_the_broker_works_on_its_own_copy_of_the_envelope(world: World) -> None:
    envelope = world.envelope(L2_OP, arguments={"note": "as submitted"})
    submitted_hash = envelope.envelope_hash()
    world.policy.after = lambda: envelope.__dict__.__setitem__("arguments", {"note": "later"})
    record = world.broker().execute(envelope)
    assert record.state is S.VERIFIED
    assert record.envelope_hash == submitted_hash
    assert world.l2.calls[0].arguments.model_dump() == {"note": "as submitted"}
    assert world.l2.calls[0].envelope_hash == submitted_hash


# --- H2: start-up recovery overlapping a live broker ---------------------------------


def overlap(world: World, started_at: Any) -> tuple[Any, Any]:
    """The reviewer's interleaving (P4): recovery reads the row while the broker is
    writing its ATTEMPT record, and acts once the tool is running. Returns what the
    broker's caller got and what recovery returned or raised."""
    recovery_reached_its_attempt, tool_running = threading.Event(), threading.Event()
    recovered: list[Any] = []

    def recover() -> None:
        try:
            recovered.append(world.recover(started_at))
        except Exception as exc:
            recovered.append(exc)
        finally:
            recovery_reached_its_attempt.set()

    thread = threading.Thread(target=recover)

    def during(e: Any) -> None:
        if (e.action, e.outcome) == ATTEMPT:
            thread.start()
            assert recovery_reached_its_attempt.wait(20)
        if (e.action, e.outcome) == (RECOVER_ACTION, AuditOutcome.ATTEMPT):
            recovery_reached_its_attempt.set()
            assert tool_running.wait(20)

    def on_run(call: ToolCall) -> None:
        tool_running.set()
        thread.join(20)
        assert not thread.is_alive()

    world.audit.during = during
    world.l2.on_run = on_run
    try:
        outcome: Any = world.broker().execute(world.envelope(L2_OP, key="k-race"))
    except ResultNotRecorded as exc:
        outcome = exc
    world.audit.during = None
    world.l2.on_run = None
    return outcome, recovered[0]


def test_h2_recovery_refuses_when_a_row_was_claimed_after_its_process_started(
    file_world: World,
) -> None:
    world = file_world
    started = world.clock.now() - timedelta(seconds=1)
    outcome, recovered = overlap(world, started)
    assert isinstance(recovered, FailClosed)
    assert "claimed after" in str(recovered)
    assert world.audit.find(RECOVER_ACTION) == []  # it changed and announced nothing
    assert getattr(outcome, "state", None) is S.VERIFIED
    assert len(world.l2.calls) == 1
    assert world.row("k-race").state is S.VERIFIED


def test_h2_recovery_that_overlaps_a_live_run_never_records_aborted(file_world: World) -> None:
    """The unsupported case made concrete: a second process that started after the claim.
    The row must not end `aborted` once the tool was called."""
    world = file_world
    outcome, recovered = overlap(world, world.clock.now() + timedelta(seconds=1))
    assert len(world.l2.calls) == 1
    row = world.row("k-race")
    assert row.state is S.UNKNOWN_OUTCOME
    assert row.attempt_audit_ref
    assert isinstance(outcome, ResultNotRecorded)
    assert outcome.record.state is S.UNKNOWN_OUTCOME
    assert [r.state for r in recovered] == [S.UNKNOWN_OUTCOME]
    # the key is blocked until someone verifies; it never replays "nothing happened"
    again = refused(world, world.envelope(L2_OP, key="k-race", request_id=_request_id(world)))
    assert again.reason is R.IDEMPOTENCY_CONFLICT or again.reason is R.PRIOR_UNVERIFIED


def _request_id(world: World) -> str:
    return str(world.raw("k-race").request_id)


def test_h2_a_broker_that_finds_its_row_taken_and_aborted_records_unknown_outcome(
    world: World,
) -> None:
    """Whatever took the row while the tool ran, the broker does not leave a row that
    says the tool was never called."""
    world.l2.on_run = lambda call: world.force(state=S.ABORTED, run_token="run_someone_else")
    with pytest.raises(ResultNotRecorded) as excinfo:
        world.broker().execute(world.envelope())
    assert excinfo.value.record.state is S.UNKNOWN_OUTCOME
    assert world.row().state is S.UNKNOWN_OUTCOME
    last = world.audit.find(EXECUTE_ACTION)[-1]
    assert last.outcome is AuditOutcome.FAILED
    assert last.details["problem"] == "result_not_stored"


def test_h2_a_state_change_needs_the_run_token_that_claimed_the_row(world: World) -> None:
    world.broker().execute(world.envelope())
    store = ExecutionStore(world.engine, RowSeal(world.secrets, ROW_KEY_REF))
    seen = store.find(world.execution_id())
    assert seen is not None
    assert seen.run_token
    assert seen.claimed_at == world.clock.now()
    stranger = seen.model_copy(update={"run_token": "run_someone_else"})
    assert store.change(stranger, world.clock.now(), error_kind="x") is None
    assert world.row().error_kind == ""
    assert store.change(seen, world.clock.now(), error_kind="x") is not None  # allowed path
    assert world.row().error_kind == "x"


# --- M1: the controls are read again immediately before the tool call ----------------


@pytest.mark.parametrize(
    ("op", "change", "reason"),
    [
        (L2_OP, lambda w: w.killswitch.blocked.add(KillCapability.WRITES), R.KILL_SWITCH_ENGAGED),
        (L3_OP, lambda w: w.killswitch.blocked.add(KillCapability.L3_RUNS), R.L3_RUNS_BLOCKED),
        (L2_OP, lambda w: w.clock.advance(minutes=10), R.ENVELOPE_EXPIRED),
        (L2_OP, lambda w: w.principals.remove("agent_ciso"), R.ACTOR_INACTIVE),
    ],
    ids=["writes-engaged", "l3-runs-engaged", "expired", "actor-removed"],
)
def test_m1_a_control_that_changes_after_the_gates_stops_the_tool_call(
    world: World, op: Any, change: Any, reason: RefusalReason
) -> None:
    at_attempt(world, lambda: change(world))
    error = refused(world, world.envelope(op))
    assert error.reason is reason
    assert world.tool_calls() == 0
    row = world.row()
    assert row.state is S.ABORTED
    assert row.error_kind == f"late_{reason.value}"
    assert row.attempt_audit_ref
    closing = world.audit.find(EXECUTE_ACTION)[-1]
    assert closing.outcome is AuditOutcome.DENIED
    assert closing.details["reason"] == reason.value
    assert closing.details["execution"] == row.ref
    assert row.result_audit_ref  # the closing record is linked from the row


def test_m1_l3_runs_engaged_late_does_not_stop_a_level_2_call(world: World) -> None:
    at_attempt(world, lambda: world.killswitch.blocked.add(KillCapability.L3_RUNS))
    assert world.broker().execute(world.envelope(L2_OP)).state is S.VERIFIED
    assert KillCapability.L3_RUNS not in world.killswitch.reads


def test_m1_the_last_look_reads_the_switch_once_more(world: World) -> None:
    world.broker().execute(world.envelope(L3_OP))
    assert world.killswitch.reads == [
        KillCapability.WRITES,
        KillCapability.L3_RUNS,
        KillCapability.WRITES,
        KillCapability.L3_RUNS,
    ]


# --- M2: the approval is spent only when the tool is about to run --------------------


def test_m2_an_unset_rate_limit_leaves_the_approval_unspent(world: World) -> None:
    envelope = world.envelope(L4_OP)
    approval_id = world.approve(envelope)
    error = refused(world, envelope, approval_id, tool_rate_limit_per_minute=None)
    assert error.reason is R.RATE_LIMIT_UNSET
    assert status(world, approval_id) is ApprovalStatus.APPROVED
    assert world.broker().execute(envelope, approval_id).state is S.VERIFIED
    assert status(world, approval_id) is ApprovalStatus.CONSUMED


def test_m2_a_full_rate_window_leaves_the_approval_unspent(world: World) -> None:
    other = world.envelope(L4_OP, key="other")
    world.broker(tool_rate_limit_per_minute=1).execute(other, world.approve(other))
    envelope = world.envelope(L4_OP, key="victim")
    approval_id = world.approve(envelope)
    error = refused(world, envelope, approval_id, tool_rate_limit_per_minute=1)
    assert error.reason is R.RATE_LIMITED
    assert status(world, approval_id) is ApprovalStatus.APPROVED
    world.clock.advance(seconds=61)
    record = world.broker(tool_rate_limit_per_minute=1).execute(envelope, approval_id)
    assert record.state is S.VERIFIED


def test_m2_a_stale_precondition_leaves_the_approval_unspent(world: World) -> None:
    envelope = world.envelope(L4_OP)
    approval_id = world.approve(envelope)
    world.l4.precondition_holds = False
    assert refused(world, envelope, approval_id).reason is R.PRECONDITION_FAILED
    assert status(world, approval_id) is ApprovalStatus.APPROVED
    world.l4.precondition_holds = True
    assert world.broker().execute(envelope, approval_id).state is S.VERIFIED


def test_m2_an_envelope_that_expires_at_the_gates_leaves_the_approval_unspent(
    world: World,
) -> None:
    envelope = world.envelope(L4_OP)
    approval_id = world.approve(envelope)
    world.policy.after = lambda: world.clock.advance(minutes=10)
    assert refused(world, envelope, approval_id).reason is R.ENVELOPE_EXPIRED
    assert status(world, approval_id) is ApprovalStatus.APPROVED


def test_m2_the_approval_is_spent_before_the_tool_runs_and_only_once(world: World) -> None:
    envelope = world.envelope(L4_OP)
    approval_id = world.approve(envelope)
    seen: list[ApprovalStatus] = []
    at_attempt(world, lambda: seen.append(status(world, approval_id)))
    world.l4.on_run = lambda call: seen.append(status(world, approval_id))
    assert world.broker().execute(envelope, approval_id).state is S.VERIFIED
    assert seen == [ApprovalStatus.APPROVED, ApprovalStatus.CONSUMED]
    assert world.audit.outcomes("approval.consume").count(AuditOutcome.SUCCESS) == 1


def test_m2_a_consume_that_fails_aborts_the_row_and_the_tool_is_not_called(world: World) -> None:
    envelope = world.envelope(L4_OP)
    approval_id = world.approve(envelope)
    at_attempt(world, lambda: world.principals.remove("human_owner"))  # approver loses the role
    error = refused(world, envelope, approval_id)
    assert error.reason is R.APPROVAL_INVALID
    assert len(world.l4.calls) == 0
    assert world.row().state is S.ABORTED
    assert world.row().error_kind == "late_approval_invalid"


# --- M3: nothing a tool returns can leave the row `pending` --------------------------


def test_m3_a_lone_surrogate_in_the_tools_reply_is_stored_safely(world: World) -> None:
    world.l2.detail = "bad \ud800 text"
    record = world.broker().execute(world.envelope())
    assert record.state is S.VERIFIED
    assert record.tool_detail == "bad ? text"
    assert world.row().state is S.VERIFIED
    assert world.audit.outcomes(EXECUTE_ACTION) == [AuditOutcome.ATTEMPT, AuditOutcome.SUCCESS]


def test_m3_a_lone_surrogate_from_the_verifier_is_stored_safely(world: World) -> None:
    world.l2.verify_detail = "seen \udfff"
    world.l2.matches = False
    record = world.broker().execute(world.envelope())
    assert record.state is S.VERIFICATION_FAILED
    assert record.verification_detail == "seen ?"


def test_m3_any_exception_after_the_tool_call_ends_in_a_recorded_state(world: World) -> None:
    class BrokenOnce:
        """A clock that fails once, right after the tool returned."""

        def __init__(self, inner: FixedClock) -> None:
            self._inner = inner
            self.armed = False

        def now(self) -> Any:
            if self.armed:
                self.armed = False
                raise RuntimeError("clock broke")
            return self._inner.now()

    clock = BrokenOnce(world.clock)
    world.l2.on_run = lambda call: setattr(clock, "armed", True)
    with pytest.raises(ResultNotRecorded) as excinfo:
        world.broker(clock=clock).execute(world.envelope())
    assert excinfo.value.record.state is S.UNKNOWN_OUTCOME
    assert world.row().state is S.UNKNOWN_OUTCOME
    assert "clock broke" not in str(excinfo.value)
    closing = world.audit.find(EXECUTE_ACTION)[-1]
    assert closing.outcome is AuditOutcome.FAILED
    assert closing.details["problem"] == "result_not_stored"
    assert refused(world, world.envelope()).reason in (R.IDEMPOTENCY_CONFLICT, R.PRIOR_UNVERIFIED)


def test_m3_a_store_failure_of_any_kind_is_an_execution_store_error(world: World) -> None:
    """M8 row 5 too: a row that cannot be read back is `ExecutionStoreError`."""
    world.broker().execute(world.envelope())
    execution_id = world.execution_id()
    world.tamper(result_references="not json")
    with pytest.raises(ExecutionStoreError):
        world.broker().get(execution_id)
    world.tamper(result_references="[]", authority_level=99)
    with pytest.raises(ExecutionStoreError):
        world.broker().get(execution_id)


# --- M4: the stored request holds no secret ------------------------------------------


def test_m4_the_stored_envelope_is_redacted_and_keeps_the_original_hash(world: World) -> None:
    envelope = world.envelope(arguments={"note": f"password is {SENSITIVE}"})
    record = world.broker().execute(envelope)
    assert record.state is S.VERIFIED
    assert world.l2.calls[0].arguments.note == f"password is {SENSITIVE}"  # the tool got it
    raw = world.raw()
    assert SENSITIVE not in raw.envelope
    assert "[REDACTED]" in raw.envelope
    assert SENSITIVE not in str(tuple(raw))
    assert raw.envelope_hash == envelope.envelope_hash()
    assert record.stored_envelope_hash != ""
    assert record.stored_envelope_hash != record.envelope_hash


def test_m4_an_envelope_without_secrets_is_stored_as_received(world: World) -> None:
    envelope = world.envelope()
    world.broker().execute(envelope)
    stored = ActionEnvelope.model_validate_json(world.raw().envelope)
    assert stored.envelope_hash() == envelope.envelope_hash()


def test_m4_a_redactor_that_fails_refuses_before_anything_is_stored(world: World) -> None:
    class Broken:
        def redact(self, text_: str) -> str:
            raise RuntimeError("redactor down")

        def redact_value(self, value: Any) -> Any:
            raise RuntimeError("redactor down")

    error = refused(world, world.envelope(), redactor=Broken())
    assert error.reason is R.REDACTION_UNAVAILABLE
    assert isinstance(error, FailClosed)
    assert rows(world) == 0
    assert world.tool_calls() == 0


# --- M5: verifier text is bounded, redacted and validated ----------------------------


def test_m5_verifier_text_is_bounded_and_redacted_before_row_and_audit(world: World) -> None:
    world.l2.matches = False
    world.l2.verify_detail = f"target said {SENSITIVE} " + "x" * 100_000
    world.l2.detail = f"tool said {SENSITIVE}"
    world.l2.observed = (
        f"draft:{SENSITIVE}",
        *(f"draft:d{n}" for n in range(MAX_REFERENCES + 20)),
    )
    record = world.broker().execute(world.envelope())
    assert record.state is S.VERIFICATION_FAILED
    assert len(record.verification_detail) <= MAX_DETAIL
    assert len(record.observed) == MAX_REFERENCES
    assert f"draft:{SENSITIVE}" not in record.observed
    assert record.residual_risk == (
        "the target does not show the result the tool was asked for (the tool reported succeeded)"
    )
    everything = record.model_dump_json() + str(tuple(world.raw()))
    assert SENSITIVE not in everything
    result = world.audit.find(EXECUTE_ACTION)[-1]
    assert SENSITIVE not in str(result.details)
    assert len(str(result.details)) < 4000
    assert "verification_detail" not in result.details


def test_m5_ordinary_verifier_answers_are_kept(world: World) -> None:
    record = world.broker().execute(world.envelope())
    assert record.verification_detail == "read back"
    assert record.tool_detail == "done"
    assert record.observed == ("draft:d1",)
    assert record.references == ("draft:d1",)


def test_m5_a_redactor_that_fails_never_lets_tool_text_through(world: World) -> None:
    class BreaksOnDetail:
        def redact(self, text_: str) -> str:
            raise RuntimeError("redactor down")

        def redact_value(self, value: Any) -> Any:
            return value

    record = world.broker(redactor=BreaksOnDetail()).execute(world.envelope())
    assert record.state is S.VERIFIED
    assert record.tool_detail == "[withheld: redaction unavailable]"
    assert record.verification_detail == "[withheld: redaction unavailable]"
    assert record.observed == ()


# --- M7: rows carry a MAC ------------------------------------------------------------


def test_m7_without_a_row_key_reference_every_execution_is_refused(world: World) -> None:
    error = refused(world, world.envelope(), row_key_ref=None)
    assert error.reason is R.ROW_KEY_UNSET
    assert isinstance(error, FailClosed)
    assert world.tool_calls() == 0
    assert rows(world) == 0
    assert world.policy.calls == 0
    assert world.broker().execute(world.envelope()).state is S.VERIFIED  # allowed path


@pytest.mark.parametrize("value", ["", "short", "x" * (MIN_ROW_KEY_BYTES - 1), None])
def test_m7_an_unusable_row_key_refuses(world: World, value: str | None) -> None:
    held = {} if value is None else {ROW_KEY_REF: value}
    error = refused(world, world.envelope(), secrets=FakeSecrets(held))
    assert error.reason is R.ROW_KEY_UNAVAILABLE
    assert world.tool_calls() == 0
    assert rows(world) == 0


@pytest.mark.parametrize("bad", ["row_key", "secret://", "secret://Row Key", 7])
def test_m7_a_row_key_reference_must_be_a_secret_reference(world: World, bad: Any) -> None:
    with pytest.raises(ValueError, match="secret://"):
        world.broker(row_key_ref=bad)


def test_m7_a_row_edited_without_the_key_is_unreadable_not_a_success(world: World) -> None:
    """The reviewer's P14: a failed run rewritten to `verified` by a database writer."""
    world.l2.matches = False
    envelope = world.envelope()
    first = world.broker().execute(envelope)
    assert first.state is S.VERIFICATION_FAILED
    world.tamper(state="verified")
    # replay
    error = refused(world, envelope)
    assert error.reason is R.STORE_UNAVAILABLE
    assert isinstance(error, FailClosed)
    assert world.audit.find(DUPLICATE_ACTION) == []
    # direct read
    with pytest.raises(ExecutionStoreError, match="integrity"):
        world.broker().get(first.execution_id)
    # the rate limiter counts only rows it can authenticate
    world.l2.matches = True
    assert refused(world, world.envelope(key="k2")).reason is R.STORE_UNAVAILABLE
    # recovery
    with pytest.raises(ExecutionStoreError):
        world.recovery().verify(first.execution_id)
    assert len(world.l2.calls) == 1


@pytest.mark.parametrize(
    "column",
    ["envelope_hash", "approval_ref", "attempt_audit_ref", "result_audit_ref", "run_token"],
)
def test_m7_each_security_column_is_covered(world: World, column: str) -> None:
    record = world.broker().execute(world.envelope())
    world.tamper(**{column: "f" * 64})
    with pytest.raises(ExecutionStoreError, match="integrity"):
        world.broker().get(record.execution_id)


def test_m7_a_row_signed_with_another_key_is_unreadable(world: World) -> None:
    record = world.broker().execute(world.envelope())
    other = FakeSecrets({ROW_KEY_REF: "another-key-of-sufficient-length-0123456789"})
    with pytest.raises(ExecutionStoreError, match="integrity"):
        world.broker(secrets=other).get(record.execution_id)
    assert world.broker().get(record.execution_id) == record  # allowed path


def test_m7_known_limit_a_deleted_row_is_not_detected(world: World) -> None:
    """A MAC authenticates a row that exists. It cannot show that a row is missing: the
    audit log is the record that survives. This test pins the limit so nobody reads the
    MAC as more than it is."""
    envelope = world.envelope()
    world.broker().execute(envelope)
    with world.engine.begin() as conn:
        conn.execute(execution_run.delete())
    assert world.broker().execute(envelope).state is S.VERIFIED
    assert len(world.l2.calls) == 2
    assert world.audit.outcomes(EXECUTE_ACTION).count(AuditOutcome.SUCCESS) == 2


# --- M8: guards that had no failing test (broker rows) -------------------------------


def test_m8_the_resolved_actor_must_be_the_actor_the_envelope_names(
    world: World, agent: Principal
) -> None:
    class Substituting(FakePrincipals):
        def resolve(self, actor_id: str) -> Principal | None:
            found = super().resolve(actor_id)
            return None if found is None else found.model_copy(update={"actor_id": "agent_x"})

    people = Substituting(agent)
    error = refused(world, world.envelope(), principals=people)
    assert error.reason is R.ACTOR_INACTIVE
    assert world.tool_calls() == 0
    assert people.lookups == ["agent_ciso"]


def test_m8_an_approval_that_names_no_approver_role_is_refused(world: World) -> None:
    envelope = world.envelope(L4_OP)
    decision = world.policy.evaluate(envelope, world.context)
    good = world.approvals.get(world.approve(envelope))
    require_matching_approval(good, envelope, decision)  # allowed path
    empty = SimpleNamespace(
        required_roles=(),
        requested_by=good.requested_by,
        requested_by_type=good.requested_by_type,
        target=good.target,
    )
    with pytest.raises(ExecutionRefused) as excinfo:
        require_matching_approval(empty, envelope, decision)  # type: ignore[arg-type]
    assert excinfo.value.reason is R.APPROVAL_ROLE_MISMATCH


def test_m8_the_attempt_and_result_audit_ids_are_stored_only_once(world: World) -> None:
    record = world.broker().execute(world.envelope())
    store = ExecutionStore(world.engine, RowSeal(world.secrets, ROW_KEY_REF))
    seen = store.find(record.execution_id)
    assert seen is not None
    assert seen.attempt_audit_ref
    assert seen.result_audit_ref
    assert store.mark_result_audited(seen, "aud_other", world.clock.now()) is None
    assert store.mark_attempt_audited(seen, "aud_other", world.clock.now()) is None
    assert world.row() == record


def test_m8_l3_runs_is_checked_on_the_level_the_envelope_claims(world: World) -> None:
    """A level 2 tool, an envelope that claims level 3: `l3_runs` applies."""
    world.killswitch.blocked.add(KillCapability.L3_RUNS)
    overstated = world.envelope(L2_OP, authority_level=AuthorityLevel.L3_EXECUTE)
    assert refused(world, overstated).reason is R.L3_RUNS_BLOCKED
    assert world.tool_calls() == 0
    assert world.broker().execute(world.envelope(L2_OP, key="k2")).state is S.VERIFIED


# --- M9: refusals before the actor is confirmed --------------------------------------


def test_m9_a_refusal_before_identity_is_not_audited_under_the_claimed_name(world: World) -> None:
    world.killswitch.blocked.add(KillCapability.WRITES)
    refused(world, world.envelope(actor_id="human_admin", actor_type=ActorType.HUMAN))
    (denied,) = world.audit.find(EXECUTE_ACTION)
    assert denied.outcome is AuditOutcome.DENIED
    assert denied.actor_id == BROKER_ACTOR_ID
    assert denied.actor_type is ActorType.SERVICE
    assert denied.details["claimed_actor_id"] == "human_admin"
    assert denied.details["reason"] == "kill_switch_engaged"
    assert world.principals.lookups == []


def test_m9_an_actor_that_does_not_resolve_is_refused_before_policy(world: World) -> None:
    envelope = world.envelope(actor_id="nobody_at_all")
    error = refused(world, envelope)
    assert error.reason is R.ACTOR_INACTIVE
    assert world.policy.calls == 0
    (denied,) = world.audit.find(EXECUTE_ACTION)
    assert denied.actor_id == BROKER_ACTOR_ID
    assert denied.details["claimed_actor_id"] == "nobody_at_all"


def test_m9_a_refusal_after_identity_names_the_actor(world: World) -> None:
    world.context.in_scope = False
    refused(world, world.envelope())
    (denied,) = world.audit.find(EXECUTE_ACTION)
    assert denied.actor_id == "agent_ciso"
    assert "claimed_actor_id" not in denied.details


def test_m9_unconfirmed_refusal_records_are_capped_per_window(world: World) -> None:
    """The reviewer's P10: 51 refused envelopes under names nobody checked."""
    world.killswitch.blocked.add(KillCapability.WRITES)
    broker = world.broker()
    extra = 31
    for n in range(UNVERIFIED_REFUSAL_AUDIT_CAP + extra):
        with pytest.raises(ExecutionRefused):
            broker.execute(world.envelope(key=f"k{n}", actor_id="human_admin"))
    assert len(world.audit.find(EXECUTE_ACTION)) == UNVERIFIED_REFUSAL_AUDIT_CAP
    (summary,) = world.audit.find(REFUSALS_SUPPRESSED_ACTION)
    assert summary.actor_id == BROKER_ACTOR_ID
    assert summary.details["cap"] == UNVERIFIED_REFUSAL_AUDIT_CAP
    # the next window opens with the count of what was left out, then records again
    world.clock.advance(UNVERIFIED_REFUSAL_WINDOW + timedelta(seconds=1))
    with pytest.raises(ExecutionRefused):
        broker.execute(world.envelope(key="later", actor_id="human_admin"))
    closing = world.audit.find(REFUSALS_SUPPRESSED_ACTION)[-1]
    assert closing.details["suppressed"] == extra
    assert len(world.audit.find(EXECUTE_ACTION)) == UNVERIFIED_REFUSAL_AUDIT_CAP + 1


def test_m9_the_cap_does_not_touch_refusals_of_a_confirmed_actor(world: World) -> None:
    world.context.in_scope = False
    broker = world.broker()
    for n in range(UNVERIFIED_REFUSAL_AUDIT_CAP + 5):
        with pytest.raises(ExecutionRefused):
            broker.execute(world.envelope(key=f"k{n}"))
    assert len(world.audit.find(EXECUTE_ACTION)) == UNVERIFIED_REFUSAL_AUDIT_CAP + 5
    assert world.audit.find(REFUSALS_SUPPRESSED_ACTION) == []


def test_m9_something_that_is_not_an_envelope_is_audited_under_the_broker(world: World) -> None:
    error = refused(world, {"operation": "note.write", "actor_id": "human_admin"})
    assert error.reason is R.INVALID_REQUEST
    (denied,) = world.audit.find(EXECUTE_ACTION)
    assert denied.actor_id == BROKER_ACTOR_ID
    assert denied.details == {"reason": "invalid_request", "codes": [], "request_type": "dict"}


# --- L2: an audit outage at the attempt does not burn the key or the approval --------


def test_l2_an_aborted_run_can_be_run_again_with_the_same_envelope(world: World) -> None:
    envelope = world.envelope(L4_OP)
    approval_id = world.approve(envelope)
    world.audit.fail_on(*ATTEMPT)
    error = refused(world, envelope, approval_id)
    assert error.reason is R.ATTEMPT_AUDIT_FAILED
    aborted = world.row()
    assert aborted.state is S.ABORTED
    assert status(world, approval_id) is ApprovalStatus.APPROVED  # not spent
    world.audit.fail_if = None
    record = world.broker().execute(envelope, approval_id)
    assert record.state is S.VERIFIED
    assert record.execution_id == aborted.execution_id
    assert record.error_kind == ""
    assert len(world.l4.calls) == 1
    assert rows(world) == 1
    assert world.audit.find(DUPLICATE_ACTION) == []


def test_l2_an_aborted_key_still_conflicts_with_a_different_envelope(world: World) -> None:
    world.audit.fail_on(*ATTEMPT)
    first = world.envelope(arguments={"note": "one"})
    assert refused(world, first).reason is R.ATTEMPT_AUDIT_FAILED
    world.audit.fail_if = None
    other = world.envelope(arguments={"note": "two"})
    assert refused(world, other).reason is R.IDEMPOTENCY_CONFLICT
    assert world.tool_calls() == 0
    assert world.row().state is S.ABORTED


def test_l2_a_rerun_of_an_aborted_row_passes_every_gate_again(world: World) -> None:
    world.audit.fail_on(*ATTEMPT)
    envelope = world.envelope()
    refused(world, envelope)
    world.audit.fail_if = None
    world.context.in_scope = False
    assert refused(world, envelope).reason is R.POLICY_DENIED
    assert world.row().state is S.ABORTED
    assert world.tool_calls() == 0


def test_l2_the_replay_of_a_failed_run_is_not_audited_as_success(world: World) -> None:
    world.l2.matches = False
    envelope = world.envelope()
    world.broker().execute(envelope)
    assert world.broker().execute(envelope).state is S.VERIFICATION_FAILED
    assert world.audit.outcomes(DUPLICATE_ACTION) == [AuditOutcome.FAILED]
    world.l2.matches = True
    good = world.envelope(key="k2")
    world.broker().execute(good)
    world.broker().execute(good)
    assert world.audit.outcomes(DUPLICATE_ACTION) == [AuditOutcome.FAILED, AuditOutcome.SUCCESS]


# --- L3: idempotency keys are scoped to the requesting actor -------------------------


def test_l3_another_actor_using_the_key_first_does_not_block_its_owner(world: World) -> None:
    world.principals.register(make_principal("agent_other", ActorType.AGENT))
    theirs = world.envelope(key="shared", actor_id="agent_other", arguments={"note": "theirs"})
    assert world.broker().execute(theirs).state is S.VERIFIED
    mine = world.envelope(key="shared", arguments={"note": "mine"})
    record = world.broker().execute(mine)
    assert record.state is S.VERIFIED
    assert rows(world) == 2
    assert [c.arguments.note for c in world.l2.calls] == ["theirs", "mine"]
    assert world.broker().execute(mine) == record  # each actor replays its own row
    assert world.row("shared", "agent_other").actor_id == "agent_other"


def test_l3_a_replay_is_answered_only_to_an_actor_that_still_resolves(world: World) -> None:
    world.principals.register(make_principal("agent_other", ActorType.AGENT))
    envelope = world.envelope(actor_id="agent_other")
    world.broker().execute(envelope)
    world.principals.remove("agent_other")
    error = refused(world, envelope)
    assert error.reason is R.ACTOR_INACTIVE
    assert world.audit.find(DUPLICATE_ACTION) == []
    assert world.policy.calls == 1


# --- L5: the envelope has a size bound -----------------------------------------------


def test_l5_an_oversized_envelope_is_refused_at_gate_two(world: World) -> None:
    from ciso.execution.gates import MAX_ENVELOPE_BYTES

    many = tuple(f"evidence:{'e' * 120}{n}" for n in range(MAX_ENVELOPE_BYTES // 120))
    error = refused(world, world.envelope(supporting_evidence=many))
    assert error.reason is R.ENVELOPE_INVALID
    assert error.codes == ("envelope_too_large",)
    assert world.policy.calls == 0
    assert rows(world) == 0
    few = many[:10]
    assert world.broker().execute(world.envelope(supporting_evidence=few)).state is S.VERIFIED


# --- L6: the credential accessor checks `l3_runs` for level 3 calls ------------------


def test_l6_l3_runs_engaged_mid_run_withholds_a_level_3_credential(world: World) -> None:
    found: list[str] = []

    def body(call: ToolCall) -> None:
        world.killswitch.blocked.add(KillCapability.L3_RUNS)
        found.append(call.credentials.get(WRITE_TOKEN_REF).reveal())

    world.l3.on_run = body
    record = world.broker().execute(world.envelope(L3_OP))
    assert found == []
    assert world.secret_requests() == []
    assert record.error_kind == "KillSwitchEngaged"
    assert record.state is S.ROLLED_BACK


def test_l6_l3_runs_engaged_does_not_withhold_a_level_2_credential(world: World) -> None:
    found: list[str] = []

    def body(call: ToolCall) -> None:
        world.killswitch.blocked.add(KillCapability.L3_RUNS)
        found.append(call.credentials.get(WRITE_TOKEN_REF).reveal())

    world.l2.on_run = body
    assert world.broker().execute(world.envelope(L2_OP)).state is S.VERIFIED
    assert len(found) == 1


# --- L7: a store error carries no SQL parameters -------------------------------------


def test_l7_a_store_error_carries_no_statement_parameters(world: World) -> None:
    with world.engine.begin() as conn:
        conn.execute(
            text(
                "CREATE TRIGGER no_insert BEFORE INSERT ON execution_run "
                "BEGIN SELECT RAISE(ABORT, 'no'); END"
            )
        )
    envelope = world.envelope(arguments={"note": "SENSITIVE-ARGUMENT-TEXT"})
    error = refused(world, envelope)
    assert error.reason is R.STORE_UNAVAILABLE
    printed = "".join(traceback.format_exception(error))
    assert "[parameters:" not in printed
    assert "[SQL:" not in printed
    assert "SENSITIVE-ARGUMENT-TEXT" not in printed
    assert "IntegrityError" in printed  # the kind of failure is still named
    assert world.tool_calls() == 0


# --- rule 2: the row key is resolved outside the database write lock -----------------


def test_m7_the_row_key_is_never_resolved_inside_a_write_transaction(
    world_factory: WorldFactory, lock_spy: LockSpy
) -> None:
    world = world_factory(lock_spy)

    class Watched(FakeSecrets):
        checked = 0

        def get(self, ref: str) -> Any:
            Watched.checked += 1
            assert lock_spy.open_writes == 0, f"{ref} resolved inside a write lock"
            return world.secrets.get(ref)

    watched = Watched()
    envelope = world.envelope(L4_OP)
    record = world.broker(secrets=watched).execute(envelope, world.approve(envelope))
    assert record.state is S.VERIFIED
    world.l2.run_error = RuntimeError("boom")
    lost = world.broker(secrets=watched).execute(world.envelope(L2_OP, key="k2"))
    world.l2.run_error = None
    assert world.recovery(secrets=watched).verify(lost.execution_id).state is S.VERIFIED
    assert Watched.checked >= 10
    assert lock_spy.writes_seen >= 6


def test_m5_references_must_be_entity_references() -> None:
    """Checked here as well as in the registry, so the bound does not depend on it."""
    redactor = FakeRedactor(SENSITIVE)
    assert safe_refs(("not a ref", "draft:d1", 7, "a:b:c", "draft:d2"), redactor) == (
        "draft:d1",
        "draft:d2",
    )
    assert safe_refs("draft:d1", redactor) == ()
    assert safe_refs(None, redactor) == ()
    assert safe_text(None, redactor) == ""
    assert safe_text(f"x {SENSITIVE} y", redactor) == "x [REDACTED] y"


# --- smaller guards added with the fixes ---------------------------------------------


def test_m2_a_check_that_returns_another_approval_is_refused(world: World) -> None:
    """The check step must hand back the record for the id that was presented."""
    envelope = world.envelope(L4_OP)
    approval_id = world.approve(envelope)
    other = world.envelope(L4_OP, key="other")
    other_record = world.approvals.get(world.approve(other))

    class Confused:
        consumed = 0

        def check(self, presented: str, **use: Any) -> Any:
            return other_record.model_copy(update={"target": world.approvals.get(presented).target})

        def consume(self, presented: str, **use: Any) -> Any:
            Confused.consumed += 1
            return world.approvals.get(presented)

    error = refused(world, envelope, approval_id, approvals=Confused())
    assert error.reason is R.APPROVAL_UNAVAILABLE
    assert Confused.consumed == 0
    assert rows(world) == 0
    assert world.broker().execute(envelope, approval_id).state is S.VERIFIED  # allowed path


def test_m4_a_redactor_that_returns_something_else_refuses(world: World) -> None:
    class Flattening:
        def redact(self, text_: str) -> str:
            return text_

        def redact_value(self, value: Any) -> Any:
            return str(value)

    error = refused(world, world.envelope(), redactor=Flattening())
    assert error.reason is R.REDACTION_UNAVAILABLE
    assert rows(world) == 0
    assert world.tool_calls() == 0


def test_m5_text_is_withheld_when_the_redactor_returns_no_text() -> None:
    class Silent:
        def redact(self, text_: str) -> Any:
            return None

        def redact_value(self, value: Any) -> Any:
            return value

    assert safe_text("tool said something", Silent()) == "[withheld: redaction unavailable]"
    assert safe_text("tool said something", FakeRedactor()) == "tool said something"
