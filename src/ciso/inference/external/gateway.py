"""The external model path, steps 1 to 7, behind one object (blueprint 8.4; FR-018; gaps
G1, G2, G3, G12, G26; ADR-0006).

Only the human-facing API router and the composition root may import this module. Nothing
in normal inference routing can reach it, so a local failure can never end here.

The gateway is the only producer of bytes that leave. Payload text is not stored, so the
caller presents the PROPOSAL again at each step; the gateway checks it against the record
`propose` left (same request id, requester, provider, model, purpose and items), then
minimizes and serialises it ITSELF, with its own scheme, allowed labels and redactor. A
preview object handed in by a caller is never authorized and never sent.

Order inside `request_approval` and `transmit`, each refusal with a stable `GateReason`
and an audit record: feature flag, kill switch, approver role, transport, allowed
classifications, payload limit, response limit, actor (resolved now, human), digest key,
proposal well-formed, proposal recorded, proposal unchanged, caller is the proposer,
minimize, something sendable, labels allowed, payload within the limit. `transmit` goes
on: authorization found, binding equal to it, caller is who filed it, approval usable,
approval not decided by the caller, approval consumed (single use). Then the attempt is
audited and recorded, the kill switch is read once more, and only then is the transport
called, once, with exactly the bytes built here.

Once the approval is consumed it stays consumed, whatever happens next: an attempt that
cannot be audited, a kill switch engaged at the last moment, a transport that raises, an
unusable answer. There is no retry and no other provider. A new send needs a new approval.

The audit sink is never called inside a database transaction.
"""

from __future__ import annotations

from collections.abc import Sequence

from sqlalchemy import Engine

from ciso.approvals import Approval, ApprovalService
from ciso.common.classification import UNKNOWN_LABEL, ClassificationScheme
from ciso.common.clock import Clock
from ciso.common.enums import AuditOutcome, Role
from ciso.common.errors import FailClosed, ValidationFailed
from ciso.common.protocols import (
    AuditSink,
    KillSwitchReader,
    PrincipalResolver,
    Redactor,
    SecretResolver,
)
from ciso.inference.external.approving import ApprovalDesk
from ciso.inference.external.auditing import GateAudit
from ciso.inference.external.binding import new_record, payload_details, same_binding
from ciso.inference.external.delivery import Courier, Job
from ciso.inference.external.gates import Caller, Gates, byte_limit
from ciso.inference.external.ledger import ExternalLedger
from ciso.inference.external.minimize import PayloadPreview
from ciso.inference.external.preparing import Preparer
from ciso.inference.external.proposal import ContextItem, ExternalRequestProposal
from ciso.inference.external.records import (
    ACTION_AUTHORIZE,
    ACTION_TRANSMIT,
    ExternalAuthorization,
    ExternalResult,
    ExternalTransmissionRecord,
    GateReason,
    binding_fields,
)
from ciso.inference.external.service import ExternalProposalService
from ciso.inference.external.transport import ExternalTransport


class ExternalInferenceGateway:
    """Proposes, previews, authorizes and sends one payload to an external model, or
    refuses (blueprint 8.4). The one object the API router talks to for this path.

    Every default refuses: `enabled=False`, `approver_role=None`, no allowed
    classifications, `transport=None`, `max_payload_bytes=None`,
    `max_response_bytes=None`. `approver_role` must be one of `APPROVER_ROLES`. The two
    byte limits are safety settings with no built-in value: the payload limit bounds what
    may be authorized and sent, the response limit bounds the answer that is read (a
    larger answer is discarded and recorded as a failure; a transport should also stop
    reading at its own limit). `digest_key_ref` names the secret that keys the stored
    digests (answer and per-item text); with `None` only the answer's size is stored and
    item digests are plain SHA-256.

    What the router must do: authenticate the caller and pass that actor's id. This class
    resolves the id again, requires a human, and requires the SAME actor to propose, to
    file the approval request and to transmit; the approver must be somebody else. It
    makes no permission decision on reads or on who may look at a preview.
    """

    def __init__(
        self,
        *,
        engine: Engine,
        clock: Clock,
        audit: AuditSink,
        redactor: Redactor,
        principals: PrincipalResolver,
        killswitch: KillSwitchReader,
        approvals: ApprovalService,
        scheme: ClassificationScheme | None = None,
        allowed_classifications: tuple[str, ...] = (),
        enabled: bool = False,
        approver_role: Role | None = None,
        transport: ExternalTransport | None = None,
        secrets: SecretResolver | None = None,
        digest_key_ref: str | None = None,
        max_payload_bytes: int | None = None,
        max_response_bytes: int | None = None,
    ) -> None:
        if digest_key_ref is not None and secrets is None:
            raise ValueError("digest_key_ref needs a secret resolver")
        for label in allowed_classifications:
            if scheme is None or label == UNKNOWN_LABEL or label not in scheme.labels:
                raise ValidationFailed(
                    "allowed classifications must be labels of the configured scheme"
                )
        max_payload = byte_limit(max_payload_bytes, "max_payload_bytes")
        max_response = byte_limit(max_response_bytes, "max_response_bytes")
        self._ledger = ExternalLedger(engine)
        self._clock = clock
        self._audit = GateAudit(audit)
        self._allowed = frozenset(allowed_classifications)
        self._approver_role = approver_role
        self._gates = Gates(
            principals=principals,
            killswitch=killswitch,
            enabled=enabled,
            approver_role=approver_role,
            allowed_classifications=self._allowed,
            has_transport=transport is not None,
            max_payload_bytes=max_payload,
            max_response_bytes=max_response,
        )
        self._transport = transport
        self._desk = ApprovalDesk(approvals, self._audit)
        self._preparer = Preparer(
            gates=self._gates, ledger=self._ledger, audit=self._audit, redactor=redactor,
            scheme=scheme, allowed_classifications=self._allowed, max_payload_bytes=max_payload,
            secrets=secrets, digest_key_ref=digest_key_ref,
        )  # fmt: skip
        self._proposals = ExternalProposalService(
            engine=engine, clock=clock, audit=audit, redactor=redactor, principals=principals,
            scheme=scheme, allowed_classifications=tuple(allowed_classifications),
            enabled=enabled, secrets=secrets, digest_key_ref=digest_key_ref,
        )  # fmt: skip
        self._courier = Courier(
            ledger=self._ledger, clock=clock, audit=self._audit, redactor=redactor,
            gates=self._gates, max_response_bytes=max_response,
        )  # fmt: skip

    # --- reads (no permission decision: the caller makes it) ---------------------------

    def get_authorization(self, approval_id: str) -> ExternalAuthorization | None:
        return self._ledger.find_authorization(approval_id)

    def get_record(self, record_id: str) -> ExternalTransmissionRecord | None:
        return self._ledger.get_record(record_id)

    def records_for_request(self, request_id: str) -> tuple[ExternalTransmissionRecord, ...]:
        return self._ledger.records_for_request(request_id)

    # --- steps 1 to 3: propose, preview ------------------------------------------------

    def propose(
        self,
        *,
        requester_actor_id: str,
        purpose: str,
        provider_name: str,
        model_name: str,
        items: Sequence[ContextItem],
        correlation_id: str = "",
    ) -> ExternalRequestProposal:
        """Step 1: record and audit a proposal. See `ExternalProposalService.propose`.
        Keep what is returned: it is presented again to every later step."""
        return self._proposals.propose(
            requester_actor_id=requester_actor_id, purpose=purpose, provider_name=provider_name,
            model_name=model_name, items=items, correlation_id=correlation_id,
        )  # fmt: skip

    def preview(
        self, proposal: ExternalRequestProposal, *, actor_id: str, correlation_id: str = ""
    ) -> PayloadPreview:
        """Steps 2 and 3: what would be sent, for a human to look at. Display only; see
        `ExternalProposalService.preview`."""
        return self._proposals.preview(proposal, actor_id=actor_id, correlation_id=correlation_id)

    # --- step 4: authorize -------------------------------------------------------------

    def request_approval(
        self, proposal: ExternalRequestProposal, *, actor_id: str, correlation_id: str = ""
    ) -> ExternalAuthorization:
        """File an approval request for what this proposal minimizes to (8.4 step 4, G2).

        `proposal` is the object `propose` returned; `actor_id` must be its requester. The
        approval covers the payload hash, provider, model, purpose and request id, names
        the proposer as requester, and must be decided by a human holding the configured
        approver role who is somebody else (ADR-0016). Returns what was recorded;
        `approval_id` is what the approver decides and what `transmit` takes. Raises
        `ExternalGateRefused`, `ValidationFailed` (bad actor or correlation id) or
        `FailClosed`; in every case no usable approval is left behind.
        """
        ready = self._preparer.prepare(ACTION_AUTHORIZE, proposal, actor_id, correlation_id)
        caller, target, correlation = ready.caller, ready.target, ready.correlation_id
        role = self._approver_role
        if role is None:
            self._audit.refuse(
                ACTION_AUTHORIZE, caller, target, GateReason.APPROVER_ROLE_UNSET, correlation
            )
        binding, preview = ready.binding, ready.preview
        details = payload_details(preview, binding, ready.raw)
        self._audit.emit(
            ACTION_AUTHORIZE, caller, target, AuditOutcome.ATTEMPT, details, correlation
        )
        approval = self._desk.file(ready, role)
        fields = binding_fields(binding)
        authorization = ExternalAuthorization(
            approval_id=approval.approval_id,
            request_id=binding.request_id,
            subject_hash=binding.subject_hash(),
            provider_name=binding.provider_name,
            model_name=binding.model_name,
            purpose=binding.purpose,
            purpose_sha256=fields["purpose_sha256"],
            payload_sha256=binding.payload_hash,
            payload_bytes=len(ready.raw),
            payload_classification=preview.classification,
            kept=preview.kept,
            dropped=preview.dropped,
            requested_by=approval.requested_by,
            required_role=role,
            created_at=self._clock.now(),
            correlation_id=correlation,
        )
        details = {**details, "approval_ref": approval.ref, "required_role": role.value}
        try:
            self._ledger.insert_authorization(authorization)
        except FailClosed:
            # Close the attempt, and do not leave a pending approval nobody can use.
            failed = {
                **details,
                "reason": "authorization_not_recorded",
                "approval_withdrawn": self._desk.drop(approval, caller),
            }
            self._audit.emit(
                ACTION_AUTHORIZE, caller, target, AuditOutcome.FAILED, failed, correlation
            )
            raise
        try:
            self._audit.emit(
                ACTION_AUTHORIZE, caller, target, AuditOutcome.SUCCESS, details, correlation
            )
        except FailClosed as exc:
            # No audit record, no authorization: take both rows back.
            if not self._retract(authorization, approval, caller):
                raise FailClosed(
                    "authorization could not be audited and could not be withdrawn"
                ) from exc
            raise
        return authorization

    # --- steps 5 to 7: transmit, record, reintegrate -----------------------------------

    def transmit(
        self,
        proposal: ExternalRequestProposal,
        approval_id: str,
        *,
        actor_id: str,
        correlation_id: str = "",
    ) -> ExternalResult:
        """Send the approved payload once and return the answer wrapped as untrusted.

        `proposal` is the object `propose` returned; the bytes are built from it again
        here and must hash to what was authorized. `actor_id` must be the actor who
        proposed and filed the request, and must not be the approver. Raises
        `ExternalGateRefused` (nothing was sent), `FailClosed` (a control or the record
        could not be reached; treat the approval as spent and, when the message says so,
        the payload as sent) or `ExternalTransmitFailed` (sent, no usable answer). Never
        retries.
        """
        ready = self._preparer.prepare(ACTION_TRANSMIT, proposal, actor_id, correlation_id)
        caller, target, correlation = ready.caller, ready.target, ready.correlation_id
        transport = self._transport
        stored = self._ledger.find_authorization(approval_id) if transport is not None else None
        refusal: GateReason | None = None
        if transport is None:
            refusal = GateReason.TRANSPORT_ABSENT
        elif stored is None:
            refusal = GateReason.AUTHORIZATION_NOT_FOUND
        elif not same_binding(stored, ready.binding):
            refusal = GateReason.BINDING_MISMATCH
        elif stored.requested_by != caller.actor_id:
            refusal = GateReason.NOT_REQUESTER
        if refusal is not None or stored is None or transport is None:
            self._audit.refuse(
                ACTION_TRANSMIT, caller, target, refusal or GateReason.AUTHORIZATION_NOT_FOUND,
                correlation,
            )  # fmt: skip
        approval = self._desk.spend(approval_id, ready)
        record = new_record(
            stored=stored,
            approval=approval,
            transmitted_by=caller.actor_id,
            preview=ready.preview,
            payload_bytes=len(ready.raw),
            approver_role=self._approver_role,
            allowed_classifications=self._allowed,
            now=self._clock.now(),
            correlation_id=correlation,
        )
        details = {
            **payload_details(ready.preview, ready.binding, ready.raw),
            "record_id": record.id,
            "approval_ref": approval.ref,
            "approver": record.approver,
        }
        # Attempt first: if it cannot be audited or recorded, the transport is not called.
        self._audit.emit(
            ACTION_TRANSMIT, caller, target, AuditOutcome.ATTEMPT, details, correlation
        )
        try:
            self._ledger.insert_record(record)
        except FailClosed:
            failed = {**details, "sent": False, "reason": "record_not_written"}
            self._audit.emit(
                ACTION_TRANSMIT, caller, target, AuditOutcome.FAILED, failed, correlation
            )
            raise
        return self._courier.deliver(
            transport, Job(record, ready.raw, ready.key, caller, target, details)
        )

    # --- internals ---------------------------------------------------------------------

    def _retract(
        self, authorization: ExternalAuthorization, approval: Approval, caller: Caller
    ) -> bool:
        """Take back an authorization that could not be audited. True when the approval
        can no longer be used here: its authorization row is gone or it is void."""
        try:
            removed = self._ledger.withdraw_authorization(authorization.approval_id)
        except FailClosed:
            removed = False
        voided = self._desk.drop(approval, caller)
        return removed or voided
