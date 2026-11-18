"""Execution states, refusal codes, errors and the execution record.

Blueprint 9.4 (`execution_result / residual_risk`), 9.5; plan gaps G5, G12, G20; ADR-0010.

State machine (plan gap G5). A row exists only once every gate before the side effect has
passed; refusals before that leave no row.

    pending --attempt audit failed, a control changed at the last look, the approval
              could not be spent, or found at start-up with no audited attempt--> aborted
    aborted --the same actor submits the same envelope again and passes every gate-->
              pending   (the same row, a new run token)
    pending --tool returned--> executed_unverified
    pending --tool raised--> unknown_outcome            (rollback-capable tool: see below)
    pending / executed_unverified --found in flight at start-up--> unknown_outcome
    pending --the broker could not record what the tool did--> unknown_outcome
    executed_unverified --independent read matches--> verified
    executed_unverified --independent read differs--> verification_failed
    executed_unverified --verifier raised--> executed_unverified (stays; never `verified`;
              `error_kind` is set, and `ExecutionRecovery.verify` can settle it later)
    unknown_outcome --later verification pass--> verified | verification_failed
    level 3 and above, on tool failure or verification mismatch (live or recovered):
        --rollback reported success--> rolled_back
        --rollback raised or reported failure--> rollback_failed

`verified`, `verification_failed`, `rolled_back` and `rollback_failed` are final and are
replayed to a caller that repeats the key. `aborted` means the broker did not call the
tool in that run; it is not replayed, the same envelope may be run again. `pending`,
`executed_unverified` and `unknown_outcome` are not final: the broker refuses to run the
same idempotency key again until the outcome has been verified.

`aborted` is written only by a compare-and-swap that proves the tool was not called: the
broker's own run aborts before its tool call, and start-up recovery aborts only a row
that still has no audited attempt (the broker calls a tool only after storing it). A
broker that finds its row changed by someone else after the tool call writes
`unknown_outcome` over `aborted` or `pending`.
"""

from __future__ import annotations

from enum import StrEnum

from ciso.common.enums import ActorType, AuthorityLevel, PolicyOutcome
from ciso.common.errors import CisoError, FailClosed
from ciso.common.schemas import Model, UtcDatetime
from ciso.execution.tools import ToolOutcome
from ciso.policy.envelope import ActionEnvelope

#: Audit action names. Values are a wire format: do not rename.
EXECUTE_ACTION = "execution.execute"
DUPLICATE_ACTION = "execution.duplicate"
RECOVER_ACTION = "execution.recover"
VERIFY_ACTION = "execution.verify"

#: The approval subject kind the broker checks and consumes (ciso.approvals).
APPROVAL_SUBJECT_KIND = "action_envelope"
#: The identity the broker names when it checks or consumes an approval, when it audits
#: recovery work that has no requesting actor, and when it audits a refusal made before
#: the requesting actor was confirmed by the identity store.
BROKER_ACTOR_ID = "execution_broker"

EXECUTION_KIND = "execution"
ID_PREFIX = "exe"


class ExecutionState(StrEnum):
    """What is known about one execution. Values are a wire format: do not rename."""

    PENDING = "pending"
    #: The broker did not call the tool in this run. Not replayed; may be run again.
    ABORTED = "aborted"
    EXECUTED_UNVERIFIED = "executed_unverified"
    VERIFIED = "verified"
    VERIFICATION_FAILED = "verification_failed"
    UNKNOWN_OUTCOME = "unknown_outcome"
    ROLLED_BACK = "rolled_back"
    #: A rollback was needed and did not succeed. Final; needs a person.
    ROLLBACK_FAILED = "rollback_failed"


#: States in which the side effect may exist and nobody has confirmed it either way.
UNSETTLED_STATES: frozenset[ExecutionState] = frozenset(
    {ExecutionState.PENDING, ExecutionState.EXECUTED_UNVERIFIED, ExecutionState.UNKNOWN_OUTCOME}
)
#: States recovery treats as "was in flight" at start-up.
IN_FLIGHT_STATES: frozenset[ExecutionState] = frozenset(
    {ExecutionState.PENDING, ExecutionState.EXECUTED_UNVERIFIED}
)


class RefusalReason(StrEnum):
    """Why the broker refused. Values are a wire format."""

    INVALID_REQUEST = "invalid_request"
    ROW_KEY_UNSET = "row_key_unset"
    ROW_KEY_UNAVAILABLE = "row_key_unavailable"
    # kill switch (first gate, and again at the last look)
    KILL_SWITCH_ENGAGED = "kill_switch_engaged"
    KILL_SWITCH_UNREADABLE = "kill_switch_unreadable"
    L3_RUNS_BLOCKED = "l3_runs_blocked"
    # envelope and allowlist
    ENVELOPE_INVALID = "envelope_invalid"
    UNKNOWN_TOOL = "unknown_tool"
    # identity (before idempotency, after policy, and again at the last look)
    ACTOR_INACTIVE = "actor_inactive"
    IDENTITY_UNAVAILABLE = "identity_unavailable"
    # idempotency
    IDEMPOTENCY_CONFLICT = "idempotency_conflict"
    PRIOR_IN_FLIGHT = "prior_in_flight"
    PRIOR_UNVERIFIED = "prior_unverified"
    # policy
    POLICY_UNAVAILABLE = "policy_unavailable"
    POLICY_DENIED = "policy_denied"
    POLICY_HOLD = "policy_hold"
    # approval (checked at its gate, spent just before the tool call)
    APPROVAL_REQUIRED = "approval_required"
    APPROVAL_INVALID = "approval_invalid"
    APPROVAL_UNAVAILABLE = "approval_unavailable"
    APPROVAL_ROLE_MISMATCH = "approval_role_mismatch"
    APPROVAL_REQUESTER_MISMATCH = "approval_requester_mismatch"
    APPROVAL_TARGET_MISMATCH = "approval_target_mismatch"
    # expiry (at its gate, and again at the last look)
    ENVELOPE_EXPIRED = "envelope_expired"
    # preconditions
    PRECONDITION_FAILED = "precondition_failed"
    PRECONDITION_UNAVAILABLE = "precondition_unavailable"
    # rate limit and the row
    RATE_LIMIT_UNSET = "rate_limit_unset"
    RATE_LIMITED = "rate_limited"
    REDACTION_UNAVAILABLE = "redaction_unavailable"
    STORE_UNAVAILABLE = "store_unavailable"
    # attempt audit
    ATTEMPT_AUDIT_FAILED = "attempt_audit_failed"
    AUDIT_UNAVAILABLE = "audit_unavailable"


#: Refusals that mean "a control could not be consulted" (blueprint 9.5).
UNAVAILABLE_REASONS: frozenset[RefusalReason] = frozenset(
    {
        RefusalReason.ROW_KEY_UNSET,
        RefusalReason.ROW_KEY_UNAVAILABLE,
        RefusalReason.KILL_SWITCH_ENGAGED,
        RefusalReason.KILL_SWITCH_UNREADABLE,
        RefusalReason.L3_RUNS_BLOCKED,
        RefusalReason.POLICY_UNAVAILABLE,
        RefusalReason.IDENTITY_UNAVAILABLE,
        RefusalReason.APPROVAL_UNAVAILABLE,
        RefusalReason.PRECONDITION_UNAVAILABLE,
        RefusalReason.RATE_LIMIT_UNSET,
        RefusalReason.REDACTION_UNAVAILABLE,
        RefusalReason.STORE_UNAVAILABLE,
        RefusalReason.ATTEMPT_AUDIT_FAILED,
        RefusalReason.AUDIT_UNAVAILABLE,
    }
)


class ExecutionRefused(CisoError):
    """The broker refused and no tool was called. `reason` is the stable code to branch
    on. `codes` carries the codes of the control that said no (policy reason codes, the
    approval reason, the envelope check that failed); it may be empty."""

    def __init__(
        self, reason: RefusalReason, detail: str = "", codes: tuple[str, ...] = ()
    ) -> None:
        super().__init__(detail or reason.value)
        self.reason = reason
        self.detail = detail or reason.value
        self.codes = codes


class ExecutionUnavailable(ExecutionRefused, FailClosed):
    """A refusal because a control was engaged against the call or could not be
    consulted: kill switch, policy, identity, approvals, audit, store, an unset limit."""


def refusal(
    reason: RefusalReason, detail: str = "", codes: tuple[str, ...] = ()
) -> ExecutionRefused:
    """The refusal error for `reason`, of the fail-closed type where that applies."""
    kind = ExecutionUnavailable if reason in UNAVAILABLE_REASONS else ExecutionRefused
    return kind(reason, detail, codes)


class ExecutionStoreError(FailClosed):
    """The execution table could not be read or written, or a row in it failed its
    integrity check. The message names the kind of failure and never holds statement
    parameters."""


class StoredEnvelopeRedacted(FailClosed):
    """A verification pass was asked for a row whose stored request had secrets removed,
    and the tool's verifier is not declared able to work from the redacted form. The
    original arguments are gone on purpose; verify this one by hand."""


class ExecutionRecord(Model):
    """One execution and everything known about its result.

    `state` says what is known about the side effect. `tool_outcome`, `references` and
    `tool_detail` are what the tool claimed; `verification_matches`, `observed` and
    `verification_detail` are what an independent read showed. Tool and verifier text is
    redacted and bounded before it is stored. `residual_risk` is fixed wording, set
    whenever the state is not `verified`. `error_kind` is the type name of the exception
    that ended a step, or a short code, never a message.

    `envelope_hash` is the hash of the request as it was submitted. `stored_envelope_hash`
    is the SHA-256 of the request text kept in the row, which is the redacted form; the
    two differ in kind and are never compared with each other.

    `run_token` names the run that holds the row: the broker's own state changes are
    conditional on it, and anything that takes the row over replaces it. `claimed_at` is
    when that run claimed the row, on the injected clock; the rate limit counts it and
    start-up recovery uses it to tell a dead run from a live one.
    """

    execution_id: str
    idempotency_key: str
    envelope_hash: str
    stored_envelope_hash: str = ""
    request_id: str
    operation: str
    authority_level: AuthorityLevel
    actor_id: str
    actor_type: ActorType
    target_resource: str
    state: ExecutionState
    policy_outcome: PolicyOutcome
    ruleset_hash: str = ""
    approval_ref: str | None = None
    run_token: str | None = None
    claimed_at: UtcDatetime | None = None
    attempt_audit_ref: str | None = None
    tool_outcome: ToolOutcome | None = None
    references: tuple[str, ...] = ()
    tool_detail: str = ""
    verification_matches: bool | None = None
    verification_detail: str = ""
    observed: tuple[str, ...] = ()
    residual_risk: str = ""
    error_kind: str = ""
    result_audit_ref: str | None = None
    created_at: UtcDatetime
    updated_at: UtcDatetime

    @property
    def ref(self) -> str:
        """`execution:<id>`, the form other modules store."""
        return f"{EXECUTION_KIND}:{self.execution_id}"

    @property
    def succeeded(self) -> bool:
        """True only when an independent read confirmed the result."""
        return self.state is ExecutionState.VERIFIED

    @property
    def settled(self) -> bool:
        return self.state not in UNSETTLED_STATES

    @property
    def awaiting_verification(self) -> bool:
        """True when no run holds the row and an independent read is still owed: an
        `unknown_outcome`, or an `executed_unverified` whose verifier already failed to
        answer (`error_kind` set). An `executed_unverified` row without `error_kind` is
        still in the hands of the run that called the tool."""
        if self.state is ExecutionState.UNKNOWN_OUTCOME:
            return True
        return self.state is ExecutionState.EXECUTED_UNVERIFIED and bool(self.error_kind)


class SkippedExecution(Model):
    """A row a verification pass could not handle. `problem` is an error type name."""

    execution_id: str
    problem: str


class VerificationPass(Model):
    """What `ExecutionRecovery.verify_all` did: the rows it asked a verifier about, as
    they are afterwards, and the rows it had to leave, each with the reason."""

    settled: tuple[ExecutionRecord, ...] = ()
    skipped: tuple[SkippedExecution, ...] = ()


class ResultNotRecorded(FailClosed):
    """The tool was called, and what happened afterwards could not be fully recorded.

    Raised instead of returning, so a caller never treats the run as cleanly finished.
    `record` is the latest row the broker could read. The broker tries to leave it in
    `unknown_outcome`. When that write fails too, the row keeps what it held: a
    `pending` row is turned into `unknown_outcome` by start-up recovery; a row that
    something else had set to `aborted` while the tool ran stays `aborted`, and that one
    case is not repaired by anything here. So treat this exception itself as "the side
    effect may have happened", whatever `record.state` says, and do not retry with a new
    idempotency key.
    """

    def __init__(self, detail: str, record: ExecutionRecord) -> None:
        super().__init__(detail)
        self.record = record


def approval_binding(envelope: ActionEnvelope) -> dict[str, str]:
    """The binding an approval for this envelope must carry, and that the broker passes
    to `ApprovalService.check` / `consume`. Whoever requests the approval must use this
    function, with `APPROVAL_SUBJECT_KIND` and `subject_hash=envelope.envelope_hash()`."""
    return {
        "operation": envelope.operation,
        "request_id": envelope.request_id,
        "idempotency_key": envelope.idempotency_key,
    }


def approval_target(envelope: ActionEnvelope) -> dict[str, str]:
    """The target attributes an approval for this envelope must be requested with: the
    envelope's own scope attributes, unknown ones left out. The broker refuses an
    approval whose target differs, so an approver's grant is always matched against the
    place the action really lands."""
    attributes = envelope.scope.attributes(envelope.target_resource)
    return {name: value for name, value in attributes.items() if value is not None}
