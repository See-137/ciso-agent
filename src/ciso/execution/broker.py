"""The execution broker (blueprint 5.1 #12, 9.4, 9.5, 11.2; FR-026, FR-027; ADR-0010,
ADR-0018; plan gaps G5, G12, G14, G20; review `docs/reviews/m2-execution-broker.md`).

`ExecutionBroker.execute` is the way the platform runs a tool for an action envelope. It
holds no reference to the model or the orchestrator and consults every control itself.
It is not the only code that can reach a tool: `ToolRegistry.invoke` is an ordinary
method, recovery calls verifiers and rollbacks, and in one process (ADR-0010) the
boundary is a convention kept by import tests. What it takes from its caller is exactly
two things, the envelope and an approval id; it takes no decision from the caller, and
it does not keep working on the caller's object: the first step makes a private copy.

The order:

 0. the request: exactly an `ActionEnvelope`, within the size bound, validated again
    into a private copy whose hash is computed once; the row key must be configured
 1. kill switch: `writes` (and `l3_runs` at level 3 and above); unreadable is a refusal
 2. envelope against the catalog, and the allowlist has a tool for the operation
 3. identity: the requesting actor resolves, now, to an active principal of the claimed
    type. Refusals up to here are audited in the broker's name (`claimed_actor_id` in
    the details, a bounded number per minute); from here on in the actor's name
 4. idempotency lookup, per actor: a finished earlier run for the same key and envelope
    hash is returned as recorded and nothing runs; another hash is a conflict; an
    earlier run that is in flight or unverified is refused; an `aborted` one goes on
 5. policy evaluated now; unavailable, deny and hold all refuse; the actor is resolved
    again
 6. approval, when the decision is `require_approval`: checked and matched against the
    decision. Nothing is spent yet (`ciso.execution.approval_gate`)
 7. envelope expiry against the clock
 8. preconditions, through the tool's own checker
 9. rate limit per tool per minute (unset refuses) and the `pending` row, one
    transaction; the row holds the redacted request, a run token and a MAC
10. the ATTEMPT audit record, then the attempt's audit id stored on the row
11. the approval is spent
12. the last look: kill switch, expiry and the actor, read again
13. the tool call; credentials only through `KillSwitchGatedCredentials`
14. independent verification; rollback at level 3 and above
15. final state on the row, then the result audit record

A refusal raises `ExecutionRefused` with a `RefusalReason` and the tool is not called.
Refusals in 0 to 8 leave no row. A refusal in 10 to 12 leaves the row `aborted`: the
tool was not called in that run, and the same envelope may be submitted again (it passes
every gate again and takes the same row). A refusal is audited as DENIED, except the two
that mean the audit log itself is down (`attempt_audit_failed`, `audit_unavailable`);
a record for an unconfirmed actor can also be left out by the per-minute bound, which
writes a summary instead (`ciso.execution.refusals`).

Failure directions (plan gap G5):

- ATTEMPT audit fails: the tool is not called; the row becomes `aborted` and the
  approval is not spent. If even that write fails the row stays `pending` with no
  attempt id, which start-up recovery turns into `aborted`, since the tool is only ever
  called after the id is stored.
- Anything fails after the tool was called (the store, a clock, text the database cannot
  take, the row taken by someone else): the broker tries to leave the row in
  `unknown_outcome`, writes a FAILED record, and raises `ResultNotRecorded`. A row that
  says `pending` or `aborted` is overwritten with `unknown_outcome`; a row somebody else
  already moved further is left as they wrote it.
- Result audit fails after the tool ran: the row already holds the true final state and
  has no `result_audit_ref`; `ResultNotRecorded` is raised. The record is owed and
  `ExecutionRecovery.audit_owed_results` delivers it.

`execute` returns the `ExecutionRecord` for every run that reached the tool, whatever
its state: check `record.succeeded`. Only `verified` is success.

One broker process per operational database. Start-up recovery must have run before the
first broker is constructed on an engine (`ciso.execution.recovery`); the broker's state
changes are conditional on its run token so that a recovery which ran anyway cannot be
overwritten, but two live processes on one database are not supported.

The audit sink, the identity resolver, the policy engine, approvals, the secret resolver
and the tool are never called inside a database transaction.
"""

from __future__ import annotations

import logging

from sqlalchemy import Engine

from ciso.approvals import ApprovalService
from ciso.common.clock import Clock
from ciso.common.enums import AuditOutcome
from ciso.common.protocols import (
    AuditEvent,
    AuditSink,
    KillSwitchReader,
    PrincipalResolver,
    Redactor,
    SecretResolver,
)
from ciso.execution.approval_gate import ApprovalGate, ApprovalUse
from ciso.execution.auditing import invalid_request_event, record_event, refusal_event
from ciso.execution.effects import RISK_UNKNOWN, Effects
from ciso.execution.gates import Gates, Request, private_copy
from ciso.execution.integrity import RowKeyUnset, RowSeal
from ciso.execution.records import (
    DUPLICATE_ACTION,
    ExecutionRecord,
    ExecutionRefused,
    ExecutionState,
    ExecutionStoreError,
    RefusalReason,
    ResultNotRecorded,
    refusal,
)
from ciso.execution.refusals import UnconfirmedRefusals
from ciso.execution.store import ExecutionStore
from ciso.execution.tools import ToolCall, ToolRegistry
from ciso.policy.context import PolicyContext
from ciso.policy.engine import PolicyEngine
from ciso.policy.envelope import ActionEnvelope, EnvelopeValidator

logger = logging.getLogger(__name__)

#: Refusals raised because the audit path is down; auditing them again cannot work.
_NOT_AUDITABLE = frozenset({RefusalReason.ATTEMPT_AUDIT_FAILED, RefusalReason.AUDIT_UNAVAILABLE})
#: States a row must not be left in once the tool was called.
_NOT_CALLED = (ExecutionState.PENDING, ExecutionState.ABORTED)
NOT_STORED = "result_not_stored"


class _Run:
    """What one `execute` call has established so far."""

    def __init__(self, request: Request) -> None:
        self.request = request
        self.actor_confirmed = False
        self.record: ExecutionRecord | None = None


class ExecutionBroker:
    """Runs allowlisted tools for action envelopes. See the module docstring.

    `killswitch` is the composition root's gated reader, never the switch itself.
    `validator` must be built on the same catalog the policy engine uses.
    `redactor` cleans the request before it is stored and every text a tool hands back.
    `row_key_ref` (`secret://<name>`, resolved through `secrets`) is the key that
    authenticates `execution_run` rows; `None` (the default) refuses every execution.
    Recovery must be given the same reference.
    `tool_rate_limit_per_minute=None` (the default) refuses every call (G14).
    """

    def __init__(
        self,
        *,
        engine: Engine,
        clock: Clock,
        audit: AuditSink,
        principals: PrincipalResolver,
        killswitch: KillSwitchReader,
        policy: PolicyEngine,
        context: PolicyContext,
        approvals: ApprovalService,
        registry: ToolRegistry,
        secrets: SecretResolver,
        validator: EnvelopeValidator,
        redactor: Redactor,
        row_key_ref: str | None = None,
        tool_rate_limit_per_minute: int | None = None,
    ) -> None:
        if not registry.sealed:
            raise ValueError("the broker needs a sealed tool registry")
        self._store = ExecutionStore(engine, RowSeal(secrets, row_key_ref))
        self._clock = clock
        self._audit = audit
        self._gates = Gates(
            store=self._store,
            clock=clock,
            principals=principals,
            killswitch=killswitch,
            validator=validator,
            policy=policy,
            context=context,
            registry=registry,
            secrets=secrets,
            redactor=redactor,
            tool_rate_limit_per_minute=tool_rate_limit_per_minute,
        )
        self._approval = ApprovalGate(approvals)
        self._effects = Effects(
            store=self._store, clock=clock, registry=registry, redactor=redactor
        )
        self._unconfirmed = UnconfirmedRefusals(audit, clock)

    def get(self, execution_id: str) -> ExecutionRecord | None:
        """The stored record. Makes no permission decision: the caller does. Raises
        `ExecutionStoreError` for a row that fails its integrity check."""
        return self._store.find(execution_id)

    def execute(self, envelope: ActionEnvelope, approval_id: str | None = None) -> ExecutionRecord:
        """Run the envelope's operation once, or refuse. See the module docstring."""
        try:
            run = _Run(private_copy(envelope))
        except ExecutionRefused as refused:
            self._unconfirmed.record(invalid_request_event(envelope, refused))
            raise
        try:
            admitted = self._admit(run, approval_id)
            if isinstance(admitted, ExecutionRecord):
                return admitted
            record, call, approval = admitted
            record = self._record_attempt(run, record)
            self._last_steps(run, record, approval)
        except ExecutionRefused as refused:
            self._audit_refusal(run, refused)
            raise
        return self._finish(record, call)

    # --- steps 0 to 9 ----------------------------------------------------------------

    def _admit(
        self, run: _Run, approval_id: str | None
    ) -> ExecutionRecord | tuple[ExecutionRecord, ToolCall, ApprovalUse | None]:
        gates, request = self._gates, run.request
        self._require_row_key()
        gates.kill_switch(request)
        prepared = gates.validate(request)
        gates.identity(request)
        run.actor_confirmed = True
        prior = gates.prior(request)
        if prior is not None:
            return self._replay(prior)
        decision = gates.policy(request)
        approval = self._approval.check(request.envelope, request.digest, decision, approval_id)
        gates.expiry(request)
        gates.preconditions(request, prepared.call)
        record = gates.claim(
            request, prepared, decision, None if approval is None else approval.ref
        )
        run.record = record
        return record, prepared.call, approval

    def _require_row_key(self) -> None:
        try:
            self._store.require_key()
        except RowKeyUnset as exc:
            raise refusal(RefusalReason.ROW_KEY_UNSET, str(exc)) from None
        except ExecutionStoreError as exc:
            raise refusal(RefusalReason.ROW_KEY_UNAVAILABLE, str(exc)) from None

    def _replay(self, prior: ExecutionRecord) -> ExecutionRecord:
        """Hand back the earlier result for a repeated idempotency key. Audited, so the
        log shows the repeat, with the outcome the earlier run had: SUCCESS only for a
        `verified` one. Nothing is run."""
        outcome = AuditOutcome.SUCCESS if prior.succeeded else AuditOutcome.FAILED
        try:
            self._audit.append(record_event(prior, outcome, action=DUPLICATE_ACTION, replayed=True))
        except Exception as exc:
            raise refusal(
                RefusalReason.AUDIT_UNAVAILABLE, "the repeated request could not be audited"
            ) from exc
        return prior

    # --- step 10 ---------------------------------------------------------------------

    def _record_attempt(self, run: _Run, record: ExecutionRecord) -> ExecutionRecord:
        """Audit the attempt and store its audit id on the row. The tool is called only
        after both. On failure the row is aborted and the call refused."""
        try:
            receipt = self._audit.append(record_event(record, AuditOutcome.ATTEMPT))
        except Exception as exc:
            self._abort(run, record, "attempt_not_audited")
            raise refusal(
                RefusalReason.ATTEMPT_AUDIT_FAILED,
                "the attempt could not be audited; the tool was not called",
            ) from exc
        try:
            marked = self._store.mark_attempt_audited(record, receipt.record_id, self._clock.now())
        except ExecutionStoreError:
            marked = None
        if marked is None:
            self._abort(run, record, "attempt_not_stored")
            raise refusal(
                RefusalReason.STORE_UNAVAILABLE,
                "the attempt could not be stored; the tool was not called",
            )
        return marked

    # --- steps 11 and 12 -------------------------------------------------------------

    def _last_steps(self, run: _Run, record: ExecutionRecord, approval: ApprovalUse | None) -> None:
        """Spend the approval, then look at the kill switch, the expiry and the actor
        once more. A refusal here aborts the row: the tool is not called."""
        run.record = record
        try:
            if approval is not None:
                self._approval.consume(approval)
            self._gates.last_look(run.request)
        except ExecutionRefused as refused:
            self._abort(run, record, f"late_{refused.reason.value}")
            raise

    def _abort(self, run: _Run, record: ExecutionRecord, why: str) -> None:
        """`pending` to `aborted`, only while this run still holds the row. `run.record`
        becomes the row as it is afterwards, as far as it can be read."""
        try:
            self._store.change(
                record, self._clock.now(), state=ExecutionState.ABORTED, error_kind=why
            )
        except ExecutionStoreError as exc:
            logger.error(
                "execution %s could not be marked aborted (%s)",
                record.execution_id,
                type(exc).__name__,
            )
        run.record = self._latest(record)

    # --- steps 13 to 15 --------------------------------------------------------------

    def _finish(self, record: ExecutionRecord, call: ToolCall) -> ExecutionRecord:
        try:
            final = self._effects.perform(record, call)
        except Exception as exc:
            # The tool was called. Whatever failed afterwards, the row must not go on
            # saying `pending`, and the caller must not see a clean return.
            logger.error(
                "execution %s: result not stored (%s)", record.execution_id, type(exc).__name__
            )
            latest = self._salvage(record)
            self._audit_quietly(record_event(latest, AuditOutcome.FAILED, problem=NOT_STORED))
            raise ResultNotRecorded(
                "the tool was called and its result could not be stored", latest
            ) from None
        outcome = AuditOutcome.SUCCESS if final.succeeded else AuditOutcome.FAILED
        try:
            receipt = self._audit.append(record_event(final, outcome))
        except Exception as exc:
            raise ResultNotRecorded(
                "the result could not be audited; the row holds the true state", final
            ) from exc
        return self._link_result(final, receipt.record_id)

    def _salvage(self, record: ExecutionRecord) -> ExecutionRecord:
        """After a failure past the tool call: make the row say `unknown_outcome` unless
        it already says something a later step or another component learned. Returns the
        latest row that could be read."""
        latest = record
        for _ in range(2):
            latest = self._latest(latest)
            if latest.state not in _NOT_CALLED:
                return latest
            try:
                moved = self._store.change(
                    latest,
                    self._clock.now(),
                    state=ExecutionState.UNKNOWN_OUTCOME,
                    residual_risk=RISK_UNKNOWN,
                    error_kind=NOT_STORED,
                )
            except Exception as exc:
                logger.error(
                    "execution %s: could not record unknown_outcome (%s)",
                    record.execution_id,
                    type(exc).__name__,
                )
                return latest
            if moved is not None:
                return moved
        return self._latest(latest)

    def _link_result(self, final: ExecutionRecord, audit_ref: str) -> ExecutionRecord:
        try:
            linked = self._store.mark_result_audited(final, audit_ref, self._clock.now())
        except Exception as exc:
            logger.error(
                "execution %s: result audit id not stored (%s)",
                final.execution_id,
                type(exc).__name__,
            )
            linked = None
        return linked or self._latest(final)

    def _latest(self, record: ExecutionRecord) -> ExecutionRecord:
        try:
            return self._store.find(record.execution_id) or record
        except ExecutionStoreError:
            return record

    # --- audit helpers ---------------------------------------------------------------

    def _audit_refusal(self, run: _Run, refused: ExecutionRefused) -> None:
        """A refusal is raised whether or not its record can be written. Once a row with
        an audited attempt exists, the refusal record closes it and is linked from it."""
        if refused.reason in _NOT_AUDITABLE:
            return
        request, record = run.request, run.record
        event = refusal_event(
            request.envelope,
            request.digest,
            refused,
            actor_confirmed=run.actor_confirmed,
            record=record,
        )
        if not run.actor_confirmed:
            self._unconfirmed.record(event)
            return
        try:
            receipt = self._audit.append(event)
        except Exception as exc:
            logger.error("execution: denied record could not be audited (%s)", type(exc).__name__)
            return
        if record is not None and record.attempt_audit_ref:
            self._link_result(record, receipt.record_id)

    def _audit_quietly(self, event: AuditEvent) -> None:
        try:
            self._audit.append(event)
        except Exception as exc:
            logger.error(
                "execution: %s record could not be audited (%s)",
                event.outcome.value,
                type(exc).__name__,
            )
