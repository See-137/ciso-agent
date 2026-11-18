"""Execution recovery (plan gap G5; blueprint 9.5, 19.3 resilience; NFR-018; ADR-0010;
review findings H2, M4, M6, L1, L4).

START-UP CONTRACT. `recover_in_flight(process_started_at)` is a start-up step. The
composition root calls it once, with the time this process started on the same clock the
broker uses, BEFORE any `ExecutionBroker` is constructed on the engine. One broker
process per operational database: a second live process is not supported and nothing
here makes it safe. Two checks back the contract up; neither replaces it:

- it refuses (`FailClosed`, nothing changed, nothing audited) when any in-flight row was
  claimed at or after `process_started_at`: that row belongs to a run of this process,
  so a broker is already live;
- every change it makes is a compare-and-swap on the row's state and run token, only for
  a row claimed before `process_started_at`, and it replaces the run token, so a broker
  that was running after all can no longer write over what recovery recorded (it then
  records `unknown_outcome` itself and raises `ResultNotRecorded`).

A broker run in ANOTHER process that claimed its row before this process started cannot
be told from a dead one. That is the unsupported case; the direction of the error is
bounded as follows.

What it does to an in-flight row:

- `pending` with no audited attempt: the broker calls a tool only after storing the
  attempt's audit id, so the tool was not called. The row becomes `aborted`, by an
  update that requires the attempt id to be absent still. If that update misses, the
  row is read again and treated as in flight;
- `pending` with an audited attempt, and `executed_unverified`: in flight; each becomes
  `unknown_outcome`.

Every change is audited: ATTEMPT, a short transaction, then the result. A change that
could not be audited afterwards still stands: `unknown_outcome` blocks its key until it
is verified, and `aborted` is never replayed as a result (the same envelope must pass
every gate again). The failure is raised as `FailClosed` once all rows were handled. A
row that cannot be read or fails its integrity check is left alone and counted in that
same `FailClosed`.

`verify(execution_id)` is the verification pass, at any time, no restart needed. It
takes an `unknown_outcome` row, or an `executed_unverified` row whose verifier already
failed to answer, asks the tool's own verifier, and records `verified` or
`verification_failed`. It never calls the tool. For a level 3 or higher tool a mismatch
is rolled back, exactly as in the live path, ending `rolled_back` or `rollback_failed`.
A verifier or rollback that needs a credential gets it through the kill-switch-gated
accessor like any other tool code.

The call is rebuilt from the request stored in the row, which is the REDACTED request
(`ciso.execution.gates`). When the redactor changed nothing, the rebuilt call is the
original. When it removed something, the original arguments no longer exist anywhere,
and the pass refuses with `StoredEnvelopeRedacted` unless the operation is listed in
`verifiable_from_redacted`: operations whose verifier compares against content that was
itself built from redacted arguments, so the redacted request gives the same answer.
The shipped outbox tools are such operations (`OUTBOX_OPERATIONS`); a tool that compares
raw arguments with its target is not, and must not be listed.

`verify_all()` runs the pass over every waiting row and keeps going past one it cannot
handle. `audit_owed_results()` writes closing records the broker could not write.

Nothing here decides a privilege: who may trigger a verification pass is for the caller.
"""

from __future__ import annotations

import logging
from collections.abc import Iterable
from datetime import datetime

from pydantic import PrivateAttr
from sqlalchemy import Engine

from ciso.common.clock import Clock, ensure_utc
from ciso.common.enums import AuditOutcome
from ciso.common.errors import CisoError, Conflict, FailClosed, IntegrityFailure, NotFound
from ciso.common.ids import new_id
from ciso.common.protocols import AuditSink, KillSwitchReader, Redactor, SecretResolver
from ciso.common.schemas import sha256_hex
from ciso.execution.auditing import record_event, skipped_event
from ciso.execution.credentials import KillSwitchGatedCredentials
from ciso.execution.effects import Effects, is_reversible
from ciso.execution.integrity import RowSeal
from ciso.execution.records import (
    IN_FLIGHT_STATES,
    RECOVER_ACTION,
    VERIFY_ACTION,
    ExecutionRecord,
    ExecutionState,
    ExecutionStoreError,
    SkippedExecution,
    StoredEnvelopeRedacted,
    VerificationPass,
)
from ciso.execution.store import ExecutionStore
from ciso.execution.tools import ToolCall, ToolRegistry
from ciso.policy.envelope import ActionEnvelope, CheckedEnvelope

logger = logging.getLogger(__name__)

RISK_INTERRUPTED = "interrupted by a restart; the side effect may have happened"
RECOVERY_PREFIX = "rec"
_WAITING = (ExecutionState.UNKNOWN_OUTCOME, ExecutionState.EXECUTED_UNVERIFIED)


class _StoredEnvelope(ActionEnvelope):
    """A request read back from a row in its redacted form. Its own hash would be the
    hash of the redacted text; the call must carry the hash of the request as it was
    submitted, which the authenticated row holds. Never accepted by the broker, which
    takes exactly `ActionEnvelope`."""

    _submitted_hash: str = PrivateAttr(default="")

    def envelope_hash(self) -> str:
        return self._submitted_hash


class ExecutionRecovery:
    """See the module docstring. `row_key_ref` must be the broker's. `None` (the
    default) means no row can be authenticated and every method raises
    `ExecutionStoreError`. `verifiable_from_redacted` names the operations whose
    verifier works from a redacted request; the default is none."""

    def __init__(
        self,
        *,
        engine: Engine,
        clock: Clock,
        audit: AuditSink,
        registry: ToolRegistry,
        killswitch: KillSwitchReader,
        secrets: SecretResolver,
        redactor: Redactor,
        row_key_ref: str | None = None,
        verifiable_from_redacted: Iterable[str] = (),
    ) -> None:
        if not registry.sealed:
            raise ValueError("recovery needs a sealed tool registry")
        self._store = ExecutionStore(engine, RowSeal(secrets, row_key_ref))
        self._clock = clock
        self._audit = audit
        self._registry = registry
        self._killswitch = killswitch
        self._secrets = secrets
        self._from_redacted = frozenset(verifiable_from_redacted)
        self._effects = Effects(
            store=self._store, clock=clock, registry=registry, redactor=redactor
        )

    # --- start-up --------------------------------------------------------------------

    def recover_in_flight(self, process_started_at: datetime) -> tuple[ExecutionRecord, ...]:
        """Move every row a dead run left in flight to `unknown_outcome` or `aborted`.
        Returns the rows it changed, as they are afterwards. See the START-UP CONTRACT
        in the module docstring: call it before any broker exists on this engine."""
        started = ensure_utc(process_started_at)
        found: list[ExecutionRecord] = []
        problems = 0
        for execution_id in self._store.ids_in_states(IN_FLIGHT_STATES):
            try:
                record = self._store.find(execution_id)
            except ExecutionStoreError:
                problems += 1
                self._note_skipped(execution_id, RECOVER_ACTION, "ExecutionStoreError")
                continue
            if record is not None and record.state in IN_FLIGHT_STATES:
                found.append(record)
        live = [r for r in found if r.claimed_at is None or r.claimed_at >= started]
        if live:
            raise FailClosed(
                f"{len(live)} in-flight executions were claimed after this process started: "
                "a broker is already running on this database; nothing was changed"
            )
        changed: list[ExecutionRecord] = []
        for record in found:
            moved = self._recover(record, started)
            if moved is None:
                continue
            changed.append(moved)
            try:
                self._audit.append(
                    record_event(
                        moved,
                        AuditOutcome.SUCCESS,
                        action=RECOVER_ACTION,
                        as_broker=True,
                        from_state=record.state.value,
                    )
                )
            except Exception as exc:
                problems += 1
                logger.error(
                    "execution %s: recovery not audited (%s)",
                    record.execution_id,
                    type(exc).__name__,
                )
        if problems:
            raise FailClosed(
                f"{problems} executions could not be recovered or their recovery not audited"
            )
        return tuple(changed)

    def _recover(self, record: ExecutionRecord, started: datetime) -> ExecutionRecord | None:
        """One row: ATTEMPT record, then the compare-and-swap. `aborted` only while the
        attempt id is still absent; otherwise, or when that misses, `unknown_outcome`."""

        def dead(row: ExecutionRecord) -> bool:
            return row.claimed_at is not None and row.claimed_at < started

        token = new_id(RECOVERY_PREFIX)
        never_called = record.state is ExecutionState.PENDING and not record.attempt_audit_ref
        target = ExecutionState.ABORTED if never_called else ExecutionState.UNKNOWN_OUTCOME
        self._attempt(record, RECOVER_ACTION, to_state=target.value)
        if never_called:
            aborted = self._store.change(
                record,
                self._clock.now(),
                only_if=lambda row: dead(row) and row.attempt_audit_ref is None,
                state=ExecutionState.ABORTED,
                error_kind="interrupted",
                residual_risk="",
                run_token=token,
            )
            if aborted is not None:
                return aborted
            latest = self._store.find(record.execution_id)
            if latest is None or latest.state not in IN_FLIGHT_STATES:
                return None
            record = latest
        return self._store.change(
            record,
            self._clock.now(),
            only_if=dead,
            state=ExecutionState.UNKNOWN_OUTCOME,
            residual_risk=RISK_INTERRUPTED,
            error_kind="interrupted",
            run_token=token,
        )

    # --- verification pass -----------------------------------------------------------

    def unknown(self) -> tuple[ExecutionRecord, ...]:
        """Rows waiting for verification, oldest first: every `unknown_outcome`, and
        every `executed_unverified` whose verifier already failed to answer. Raises
        `ExecutionStoreError` if one of them cannot be read; `verify_all` goes on past
        such a row and reports it."""
        waiting = []
        for execution_id in self._store.ids_in_states(_WAITING):
            record = self._store.find(execution_id)
            if record is not None and record.awaiting_verification:
                waiting.append(record)
        return tuple(waiting)

    def verify(self, execution_id: str) -> ExecutionRecord:
        """Ask the tool's verifier about a waiting row and record the answer.

        Returns the row afterwards: `verified`, `verification_failed`, `rolled_back` or
        `rollback_failed` (level 3 and above, on a mismatch), or unchanged in state when
        the verifier could not answer. `NotFound` for an unknown id; `Conflict` for a
        row that is not waiting (settled, or still held by the run that called the
        tool); `ExecutionStoreError` for a row that fails its integrity check;
        `IntegrityFailure` when the stored request does not match its recorded hash;
        `StoredEnvelopeRedacted` when the original arguments are needed and gone."""
        record = self._store.find(execution_id) if isinstance(execution_id, str) else None
        if record is None:
            raise NotFound("no such execution")
        if not record.awaiting_verification:
            raise Conflict(f"execution is {record.state.value}, not waiting for verification")
        call = self._call_for(record)
        self._attempt(record, VERIFY_ACTION)
        held = self._store.change(record, self._clock.now(), run_token=new_id(RECOVERY_PREFIX))
        if held is None:
            raise Conflict("the execution changed while its verification was starting")
        final = self._effects.confirm(held, call, None, undo_on_mismatch=is_reversible(held))
        outcome = AuditOutcome.SUCCESS if final.succeeded else AuditOutcome.FAILED
        try:
            receipt = self._audit.append(
                record_event(final, outcome, action=VERIFY_ACTION, as_broker=True)
            )
        except Exception as exc:
            raise FailClosed(
                "the verification was stored on the row and could not be audited"
            ) from exc
        if final.settled:
            self._store.mark_result_audited(final, receipt.record_id, self._clock.now())
        return self._store.find(execution_id) or final

    def verify_all(self) -> VerificationPass:
        """`verify` for every waiting row, oldest first. A row that cannot be read, fails
        its integrity check or cannot be verified from what is stored does not stop the
        pass: it is audited as skipped and listed in the result with the error's type
        name. Check `skipped`; an empty tuple is the only all-clear."""
        settled: list[ExecutionRecord] = []
        skipped: list[SkippedExecution] = []
        for execution_id in self._store.ids_in_states(_WAITING):
            try:
                record = self._store.find(execution_id)
                if record is None or not record.awaiting_verification:
                    continue
                settled.append(self.verify(execution_id))
            except CisoError as exc:
                problem = type(exc).__name__
                logger.error("execution %s: not verified (%s)", execution_id, problem)
                skipped.append(SkippedExecution(execution_id=execution_id, problem=problem))
                self._note_skipped(execution_id, VERIFY_ACTION, problem)
        return VerificationPass(settled=tuple(settled), skipped=tuple(skipped))

    def _call_for(self, record: ExecutionRecord) -> ToolCall:
        """The call for the verifier, rebuilt from the stored request."""
        stored = self._store.stored_envelope(record.execution_id)
        if stored is None or sha256_hex(stored) != record.stored_envelope_hash:
            raise IntegrityFailure("the stored envelope does not match its recorded hash")
        try:
            envelope: ActionEnvelope = ActionEnvelope.model_validate_json(stored)
        except ValueError:
            raise StoredEnvelopeRedacted(
                "the stored request cannot be read back as an envelope after redaction"
            ) from None
        if envelope.envelope_hash() != record.envelope_hash:
            envelope = self._as_submitted(stored, envelope, record)
        tool = self._registry.get(envelope.operation)
        checked = CheckedEnvelope.model_construct(
            envelope=envelope,
            spec=tool.spec,
            arguments=self._registry.bind_arguments(tool.name, envelope.arguments),
            authority_level=tool.spec.authority_level,
            channel=None,
        )
        credentials = KillSwitchGatedCredentials(
            self._killswitch, self._secrets, l3=is_reversible(record)
        )
        return self._registry.call_for(checked, credentials)

    def _as_submitted(
        self, stored: str, envelope: ActionEnvelope, record: ExecutionRecord
    ) -> ActionEnvelope:
        """The redacted request, carrying the submitted request's hash. Only for an
        operation declared verifiable from redacted arguments, and only when the fields
        that identify the call survived redaction unchanged."""
        if record.operation not in self._from_redacted:
            raise StoredEnvelopeRedacted(
                f"the stored request for {record.operation} had secrets removed and its "
                "verifier needs the original arguments; verify this execution by hand"
            )
        same_call = (
            envelope.operation == record.operation
            and envelope.request_id == record.request_id
            and envelope.idempotency_key == record.idempotency_key
            and envelope.actor_id == record.actor_id
            and envelope.target_resource == record.target_resource
        )
        if not same_call:
            raise StoredEnvelopeRedacted(
                "redaction changed a field that identifies the call; verify by hand"
            )
        rebuilt = _StoredEnvelope.model_validate_json(stored)
        rebuilt._submitted_hash = record.envelope_hash
        return rebuilt

    # --- owed closing records --------------------------------------------------------

    def audit_owed_results(self) -> tuple[ExecutionRecord, ...]:
        """Write the closing record for every finished row that has an audited attempt
        and no closing record. A row that is not settled yet is left for the
        verification pass, which writes its own record. A row the audit log still
        refuses stays owed; `FailClosed` is raised after the others."""
        delivered: list[ExecutionRecord] = []
        failed = 0
        for execution_id in self._store.ids_owing_result_audit():
            try:
                record = self._store.find(execution_id)
            except ExecutionStoreError:
                failed += 1
                self._note_skipped(execution_id, RECOVER_ACTION, "ExecutionStoreError")
                continue
            if record is None or not record.settled or record.result_audit_ref:
                continue
            outcome = AuditOutcome.SUCCESS if record.succeeded else AuditOutcome.FAILED
            try:
                receipt = self._audit.append(record_event(record, outcome, late=True))
            except Exception as exc:
                failed += 1
                logger.error(
                    "execution %s: result still not audited (%s)",
                    record.execution_id,
                    type(exc).__name__,
                )
                continue
            self._store.mark_result_audited(record, receipt.record_id, self._clock.now())
            delivered.append(self._store.find(record.execution_id) or record)
        if failed:
            raise FailClosed(f"{failed} execution results are still not audited")
        return tuple(delivered)

    # --- internals -------------------------------------------------------------------

    def _attempt(self, record: ExecutionRecord, action: str, **extra: str) -> None:
        try:
            self._audit.append(
                record_event(record, AuditOutcome.ATTEMPT, action=action, as_broker=True, **extra)
            )
        except Exception as exc:
            raise FailClosed(f"{action} could not be audited; nothing changed") from exc

    def _note_skipped(self, execution_id: str, action: str, problem: str) -> None:
        try:
            self._audit.append(skipped_event(execution_id, action, problem))
        except Exception as exc:
            logger.error("execution %s: skip not audited (%s)", execution_id, type(exc).__name__)
