"""The broker's gates before the side effect (blueprint 9.5; ADR-0010; gaps G5, G12, G14;
review findings H1, M1, M4, L3, L5).

Each method is one gate. It returns when the gate passes and raises `ExecutionRefused`
with a stable `RefusalReason` when it does not. No gate holds a database transaction
while it consults another component: the store methods open and close their own.
`ExecutionBroker.execute` calls them in the documented order. The approval steps live in
`ciso.execution.approval_gate`.

Every gate works on a `Request`: the broker's own validated copy of the envelope and the
hash computed once from that copy. Nothing here reads the object the caller submitted.
"""

from __future__ import annotations

from datetime import timedelta
from typing import NamedTuple

from ciso.common.clock import Clock
from ciso.common.enums import AuthorityLevel, KillCapability, PolicyOutcome
from ciso.common.errors import PreconditionFailed
from ciso.common.ids import new_id
from ciso.common.principal import Principal
from ciso.common.protocols import KillSwitchReader, PrincipalResolver, Redactor, SecretResolver
from ciso.common.schemas import canonical_json, sha256_hex
from ciso.execution.credentials import KillSwitchGatedCredentials
from ciso.execution.records import (
    ID_PREFIX,
    ExecutionRecord,
    ExecutionState,
    ExecutionStoreError,
    RefusalReason,
    refusal,
)
from ciso.execution.store import ClaimOutcome, ExecutionStore
from ciso.execution.tools import InvalidToolCall, ToolCall, ToolRegistry, UnknownTool
from ciso.policy.context import PolicyContext
from ciso.policy.decision import PolicyDecision, ReasonCode
from ciso.policy.engine import PolicyEngine
from ciso.policy.envelope import (
    ActionEnvelope,
    CheckedEnvelope,
    EnvelopeRejected,
    EnvelopeValidator,
)

RATE_WINDOW = timedelta(minutes=1)
#: Largest request the broker copies, in bytes of JSON. A structural bound on what one
#: call can make the broker validate and store, not an operator setting.
MAX_ENVELOPE_BYTES = 65_536
TOO_LARGE = "envelope_too_large"
RUN_PREFIX = "run"


class Request(NamedTuple):
    """The broker's private copy of a submitted envelope, and its hash, computed once."""

    envelope: ActionEnvelope
    digest: str


class Prepared(NamedTuple):
    checked: CheckedEnvelope
    call: ToolCall


def private_copy(submitted: object) -> Request:
    """Accept only an object whose type is exactly `ActionEnvelope` and validate it again
    into a new object the caller holds no reference to (review finding H1).

    A subclass can answer `envelope_hash()` with another envelope's hash, and a frozen
    model's fields can still be swapped through `__dict__` between two gates. After this
    function neither matters: every later gate, the hash, the stored row and the tool
    call come from the copy."""
    if type(submitted) is not ActionEnvelope:
        raise refusal(RefusalReason.INVALID_REQUEST, "an ActionEnvelope is required")
    try:
        text = submitted.model_dump_json()
        too_large = len(text.encode("utf-8")) > MAX_ENVELOPE_BYTES
        own = None if too_large else ActionEnvelope.model_validate_json(text, strict=True)
        digest = "" if own is None else own.envelope_hash()
    except Exception as exc:
        raise refusal(
            RefusalReason.INVALID_REQUEST, f"the envelope is not valid ({type(exc).__name__})"
        ) from None
    if own is None:
        raise refusal(
            RefusalReason.ENVELOPE_INVALID,
            f"the envelope is larger than {MAX_ENVELOPE_BYTES} bytes",
            (TOO_LARGE,),
        )
    return Request(own, digest)


def check_rate_limit(value: int | None) -> int | None:
    """`None` is allowed and means "refuse every call"; a set value is a positive int."""
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise ValueError("tool_rate_limit_per_minute must be a positive integer or None")
    return value


class Gates:
    def __init__(
        self,
        *,
        store: ExecutionStore,
        clock: Clock,
        principals: PrincipalResolver,
        killswitch: KillSwitchReader,
        validator: EnvelopeValidator,
        policy: PolicyEngine,
        context: PolicyContext,
        registry: ToolRegistry,
        secrets: SecretResolver,
        redactor: Redactor,
        tool_rate_limit_per_minute: int | None,
    ) -> None:
        self._store = store
        self._clock = clock
        self._principals = principals
        self._killswitch = killswitch
        self._validator = validator
        self._policy = policy
        self._context = context
        self._registry = registry
        self._secrets = secrets
        self._redactor = redactor
        self._rate_limit = check_rate_limit(tool_rate_limit_per_minute)

    # --- kill switch -----------------------------------------------------------------

    def kill_switch(self, request: Request) -> None:
        """`writes` must read clear for every execution; `l3_runs` too when the envelope
        claims level 3 or above, or the registered tool is level 3 or above. Only an
        answer that is exactly `False` is clear (blueprint 11.2; ADR-0018)."""
        self._require_clear(KillCapability.WRITES, RefusalReason.KILL_SWITCH_ENGAGED)
        if self._is_l3(request.envelope):
            self._require_clear(KillCapability.L3_RUNS, RefusalReason.L3_RUNS_BLOCKED)

    def _require_clear(self, capability: KillCapability, engaged: RefusalReason) -> None:
        try:
            blocked = self._killswitch.is_blocked(capability)
        except Exception as exc:
            raise refusal(
                RefusalReason.KILL_SWITCH_UNREADABLE,
                f"kill switch could not be read ({type(exc).__name__})",
            ) from exc
        if blocked is not False:
            raise refusal(engaged, f"kill switch blocks {capability.value}")

    def _is_l3(self, envelope: ActionEnvelope) -> bool:
        if envelope.authority_level >= AuthorityLevel.L3_EXECUTE:
            return True
        return self._tool_is_l3(envelope.operation)

    def _tool_is_l3(self, operation: str) -> bool:
        if operation not in self._registry:
            return False
        level = self._registry.get(operation).spec.authority_level
        return level >= AuthorityLevel.L3_EXECUTE

    # --- envelope and allowlist ------------------------------------------------------

    def validate(self, request: Request) -> Prepared:
        """Envelope against the catalog, then against the allowlist: the operation must
        have a registered tool whose spec is the catalog's (blueprint 9.4). The call's
        credential accessor is gated on `writes`, and on `l3_runs` too for a level 3 or
        higher tool (review finding L6)."""
        envelope = request.envelope
        try:
            checked = self._validator.validate(envelope)
            credentials = KillSwitchGatedCredentials(
                self._killswitch, self._secrets, l3=self._tool_is_l3(envelope.operation)
            )
            call = self._registry.call_for(checked, credentials)
        except EnvelopeRejected as exc:
            reason = (
                RefusalReason.ENVELOPE_EXPIRED
                if exc.code is ReasonCode.ENVELOPE_EXPIRED
                else RefusalReason.ENVELOPE_INVALID
            )
            raise refusal(reason, exc.detail, (exc.code.value,)) from exc
        except UnknownTool as exc:
            raise refusal(RefusalReason.UNKNOWN_TOOL, "no tool is registered for it") from exc
        except InvalidToolCall as exc:
            raise refusal(RefusalReason.ENVELOPE_INVALID, exc.detail, (exc.code.value,)) from exc
        except Exception as exc:
            raise refusal(
                RefusalReason.ENVELOPE_INVALID, f"validation failed ({type(exc).__name__})"
            ) from exc
        return Prepared(checked, call)

    # --- identity --------------------------------------------------------------------

    def identity(self, request: Request) -> None:
        """The requesting actor must resolve, right now, to an active principal with the
        same id and the claimed type. Asked of the identity store by id; nothing a
        caller holds is consulted (plan gap G12). Called before the idempotency lookup,
        again after policy, and again at the last look."""
        envelope = request.envelope
        try:
            resolved = self._principals.resolve(envelope.actor_id)
        except Exception as exc:
            raise refusal(
                RefusalReason.IDENTITY_UNAVAILABLE,
                f"identity could not be checked ({type(exc).__name__})",
            ) from exc
        if (
            not isinstance(resolved, Principal)
            or resolved.actor_id != envelope.actor_id
            or resolved.actor_type is not envelope.actor_type
        ):
            raise refusal(RefusalReason.ACTOR_INACTIVE, "the requesting actor is not active")

    # --- idempotency -----------------------------------------------------------------

    def prior(self, request: Request) -> ExecutionRecord | None:
        """The finished earlier run to hand back for this actor's idempotency key, or
        None when the request should go on through the gates.

        Keys are scoped to the requesting actor. Same key with another envelope hash is
        a conflict, whatever the earlier row's state. An earlier run that is still
        `pending`, `executed_unverified` or `unknown_outcome` is refused: nothing is run
        again until that outcome has been verified (plan gap G5). An `aborted` earlier
        run never called its tool, so the same envelope goes on through every gate and
        takes the row up again at the claim."""
        envelope = request.envelope
        try:
            found = self._store.find_by_key(envelope.actor_id, envelope.idempotency_key)
        except ExecutionStoreError as exc:
            raise refusal(RefusalReason.STORE_UNAVAILABLE, str(exc)) from exc
        if found is None:
            return None
        if found.envelope_hash != request.digest:
            raise refusal(
                RefusalReason.IDEMPOTENCY_CONFLICT,
                "the idempotency key was used for a different envelope",
            )
        if found.state is ExecutionState.ABORTED:
            return None
        if found.state is ExecutionState.PENDING:
            raise refusal(RefusalReason.PRIOR_IN_FLIGHT, f"{found.ref} is in flight")
        if not found.settled:
            raise refusal(
                RefusalReason.PRIOR_UNVERIFIED,
                f"{found.ref} is {found.state.value}; verify it before any retry",
            )
        return found

    # --- policy ----------------------------------------------------------------------

    def policy(self, request: Request) -> PolicyDecision:
        """Evaluate policy NOW. The decision is never taken from the caller. Returns only
        an `allow` or `require_approval` decision made for this exact envelope, and only
        while the requesting actor still resolves (blueprint 9.5; plan gap G12)."""
        envelope = request.envelope
        try:
            decision = self._policy.evaluate(envelope, self._context)
        except Exception as exc:
            raise refusal(
                RefusalReason.POLICY_UNAVAILABLE,
                f"policy could not be evaluated ({type(exc).__name__})",
            ) from exc
        if (
            not isinstance(decision, PolicyDecision)
            or decision.envelope_hash != request.digest
            or decision.request_id != envelope.request_id
        ):
            raise refusal(
                RefusalReason.POLICY_UNAVAILABLE, "policy returned no decision for this envelope"
            )
        codes = tuple(code.value for code in decision.reason_codes)
        if decision.outcome is PolicyOutcome.HOLD:
            raise refusal(RefusalReason.POLICY_HOLD, "policy holds this action", codes)
        if decision.outcome not in (PolicyOutcome.ALLOW, PolicyOutcome.REQUIRE_APPROVAL):
            raise refusal(RefusalReason.POLICY_DENIED, "policy denies this action", codes)
        self.identity(request)
        return decision

    # --- expiry ----------------------------------------------------------------------

    def expiry(self, request: Request) -> None:
        """The envelope must still be inside its validity window right before use; the
        earlier gates may have taken time (blueprint 9.4 `expiry`)."""
        if request.envelope.expiry <= self._clock.now():
            raise refusal(RefusalReason.ENVELOPE_EXPIRED, "envelope has expired")

    # --- preconditions ---------------------------------------------------------------

    def preconditions(self, request: Request, call: ToolCall) -> None:
        try:
            self._registry.require_preconditions(call, request.envelope.preconditions)
        except PreconditionFailed as exc:
            raise refusal(RefusalReason.PRECONDITION_FAILED, str(exc)) from exc
        except Exception as exc:
            raise refusal(
                RefusalReason.PRECONDITION_UNAVAILABLE,
                f"preconditions could not be checked ({type(exc).__name__})",
            ) from exc

    # --- rate limit and the row ------------------------------------------------------

    def claim(
        self,
        request: Request,
        prepared: Prepared,
        decision: PolicyDecision,
        approval_ref: str | None,
    ) -> ExecutionRecord:
        """Rate limit and `pending` row in one write transaction.

        The limit is per tool per minute on the injected clock, counted over the stored
        rows by `claimed_at`, so it survives a restart. Unset means refuse (G14). Every
        claimed row counts, including one that is later aborted, until the same envelope
        takes that row up again.

        The row stores the request after the `Redactor` (review finding M4) and a new
        run token; the broker's later state changes are conditional on that token."""
        if self._rate_limit is None:
            raise refusal(
                RefusalReason.RATE_LIMIT_UNSET, "tool_rate_limit_per_minute is not set; refusing"
            )
        envelope = request.envelope
        stored = self._storable(envelope)
        now = self._clock.now()
        record = ExecutionRecord(
            execution_id=new_id(ID_PREFIX),
            idempotency_key=envelope.idempotency_key,
            envelope_hash=request.digest,
            stored_envelope_hash=sha256_hex(stored),
            request_id=envelope.request_id,
            operation=envelope.operation,
            authority_level=prepared.checked.spec.authority_level,
            actor_id=envelope.actor_id,
            actor_type=envelope.actor_type,
            target_resource=envelope.target_resource,
            state=ExecutionState.PENDING,
            policy_outcome=decision.outcome,
            ruleset_hash=decision.ruleset_hash,
            approval_ref=approval_ref,
            run_token=new_id(RUN_PREFIX),
            claimed_at=now,
            created_at=now,
            updated_at=now,
        )
        try:
            claimed = self._store.claim(
                record, stored, limit=self._rate_limit, window_start=now - RATE_WINDOW
            )
        except ExecutionStoreError as exc:
            raise refusal(RefusalReason.STORE_UNAVAILABLE, str(exc)) from exc
        if claimed.outcome is ClaimOutcome.RATE_LIMITED:
            raise refusal(
                RefusalReason.RATE_LIMITED,
                f"{envelope.operation} reached {self._rate_limit} calls in the last minute",
            )
        if claimed.outcome is not ClaimOutcome.CLAIMED or claimed.record is None:
            raise refusal(
                RefusalReason.PRIOR_IN_FLIGHT, "the idempotency key was claimed meanwhile"
            )
        return claimed.record

    def _storable(self, envelope: ActionEnvelope) -> str:
        """The request as it is kept in the row: canonical JSON with every string passed
        through the redactor. A redactor that cannot answer refuses the call; the
        unredacted request is never stored instead."""
        try:
            redacted = self._redactor.redact_value(envelope.model_dump(mode="json"))
            if not isinstance(redacted, dict):
                raise TypeError("redactor returned no mapping")
            text = canonical_json(redacted)
            text.encode("utf-8")
        except Exception as exc:
            raise refusal(
                RefusalReason.REDACTION_UNAVAILABLE,
                f"the request could not be redacted for storage ({type(exc).__name__})",
            ) from None
        return text

    # --- the last look ---------------------------------------------------------------

    def last_look(self, request: Request) -> None:
        """Immediately before the tool call: the kill switch (`writes`, and `l3_runs` at
        level 3 and above), the envelope's expiry and the requesting actor, all read
        again. The gates before this one, two database transactions and an audit append
        have taken time since they were first read (blueprint 9.5 "immediately before
        execution", 11.2; review finding M1)."""
        self.kill_switch(request)
        self.expiry(request)
        self.identity(request)
