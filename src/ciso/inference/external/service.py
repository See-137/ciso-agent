"""Steps 1 to 3 of the external model path: propose, preview, minimize (blueprint 8.4).

`ExternalProposalService` is owned by `ExternalInferenceGateway`, which is the one object
the human-facing API router talks to; it is not wired on its own. It refuses while the
feature flag is off (the default), refuses any requester that is not a human right now,
and fails closed when the audit path or the ledger is down. It holds no transport and
sends nothing.

`propose` leaves a durable record (ids, hashes, per-item ref, label and text digest), so
that a later step can tell a proposal that went through here from one that did not. A
preview is for display: nothing later trusts a preview object.

Audit details carry refs, labels, counts and hashes. They never carry item text or the
purpose text.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any

from pydantic import ValidationError
from sqlalchemy import Engine

from ciso.common.classification import ClassificationScheme
from ciso.common.clock import Clock
from ciso.common.enums import ActorType, AuditOutcome
from ciso.common.errors import FailClosed, ValidationFailed
from ciso.common.ids import entity_ref, new_id
from ciso.common.principal import Principal
from ciso.common.protocols import (
    AuditEvent,
    AuditSink,
    PrincipalResolver,
    Redactor,
    SecretResolver,
)
from ciso.common.schemas import sha256_hex
from ciso.inference.external.ledger import ExternalLedger
from ciso.inference.external.minimize import PayloadPreview, build_preview, minimize
from ciso.inference.external.proposal import (
    REQUEST_ID_PREFIX,
    REQUEST_REF_KIND,
    ContextItem,
    ExternalReason,
    ExternalRequestProposal,
    ExternalRequestRefused,
    capped_refs,
    classify,
    clean_actor,
    clean_correlation,
    request_target,
)
from ciso.inference.external.proposals import match_refusal, proposal_record, revalidated
from ciso.vault import resolve_key_bytes

ACTION_PROPOSE = "inference.external.propose"
ACTION_PREVIEW = "inference.external.preview"


class ExternalProposalService:
    """Propose and preview an external model request. Disabled unless told otherwise.

    `digest_key_ref` names the secret that keys the per-item text digests in the proposal
    record; with `None` they are plain SHA-256.
    """

    def __init__(
        self,
        *,
        engine: Engine,
        clock: Clock,
        audit: AuditSink,
        redactor: Redactor,
        principals: PrincipalResolver,
        scheme: ClassificationScheme | None = None,
        allowed_classifications: tuple[str, ...] = (),
        enabled: bool = False,
        secrets: SecretResolver | None = None,
        digest_key_ref: str | None = None,
    ) -> None:
        if digest_key_ref is not None and secrets is None:
            raise ValueError("digest_key_ref needs a secret resolver")
        self._ledger = ExternalLedger(engine)
        self._clock = clock
        self._audit = audit
        self._redactor = redactor
        self._principals = principals
        self._scheme = scheme
        self._allowed = tuple(allowed_classifications)
        self._enabled = enabled
        self._secrets = secrets
        self._digest_key_ref = digest_key_ref

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
        """Step 1. Returns the proposal only after it has been recorded and audited.

        Raises `ExternalRequestRefused` (feature off; requester unknown or not human, as
        resolved now), `ValidationFailed` (bad actor or correlation id, blank purpose, bad
        names, no items, too many or too long items, repeated refs) or `FailClosed`
        (identity, audit, ledger or digest key unavailable; no record is left behind).
        Secrets in the purpose are redacted before it is stored. Each item's label is
        normalised: missing or unrecognised becomes `unknown`.
        """
        actor, correlation = clean_actor(requester_actor_id), clean_correlation(correlation_id)
        request_id = new_id(REQUEST_ID_PREFIX)
        target = entity_ref(REQUEST_REF_KIND, request_id)
        principal = self._gate(ACTION_PROPOSE, actor, target, correlation)
        try:
            proposal = ExternalRequestProposal(
                request_id=request_id,
                requester_actor_id=principal.actor_id,
                requester_actor_type=principal.actor_type,
                purpose=self._redactor.redact(purpose),
                provider_name=provider_name,
                model_name=model_name,
                items=tuple(
                    item.model_copy(
                        update={"classification": classify(self._scheme, item.classification)}
                    )
                    for item in items
                ),
                created_at=self._clock.now(),
            )
        except ValidationError as exc:
            # The pydantic error quotes its input; name the fields only.
            where = sorted({str(error["loc"][0]) if error["loc"] else "" for error in exc.errors()})
            raise ValidationFailed(f"invalid external request proposal at: {where}") from None
        record = proposal_record(proposal, key=self._key(), correlation_id=correlation)
        details: dict[str, Any] = {
            "request_id": proposal.request_id,
            "provider": proposal.provider_name,
            "model": proposal.model_name,
            "purpose_sha256": sha256_hex(proposal.purpose),
            "item_count": len(proposal.items),
            **capped_refs(
                "items",
                [
                    {"ref": item.ref, "classification": item.classification, "source": item.source}
                    for item in proposal.items
                ],
            ),
        }
        self._record(principal, ACTION_PROPOSE, target, AuditOutcome.ATTEMPT, details, correlation)
        try:
            self._ledger.insert_proposal(record)
        except FailClosed:
            failed = {**details, "reason": "proposal_not_recorded"}
            self._record(
                principal, ACTION_PROPOSE, target, AuditOutcome.FAILED, failed, correlation
            )
            raise
        try:
            self._record(
                principal, ACTION_PROPOSE, target, AuditOutcome.SUCCESS, details, correlation
            )
        except FailClosed as exc:
            # No audit record, no proposal: later steps will not know this request id.
            if not self._ledger.withdraw_proposal(request_id):
                raise FailClosed(
                    "proposal could not be audited and its record could not be withdrawn"
                ) from exc
            raise
        return proposal

    def preview(
        self, proposal: ExternalRequestProposal, *, actor_id: str, correlation_id: str = ""
    ) -> PayloadPreview:
        """Steps 2 and 3. Minimize the recorded proposal and return the exact bytes and
        their hash, for a human to look at.

        `proposal` must be the one `propose` returned: an unknown request id or a changed
        proposal is refused (`PROPOSAL_UNKNOWN`, `PROPOSAL_MISMATCH`, `PROPOSAL_INVALID`).
        A blocked result (nothing may be sent) is returned, not raised, so the human sees
        what was dropped and why; it carries no bytes and no hash. The viewer must be a
        human, resolved now; whether this viewer may see this request is the router's
        decision (the approver has to see it too).
        """
        actor, correlation = clean_actor(actor_id), clean_correlation(correlation_id)
        target = request_target(proposal)
        principal = self._gate(ACTION_PREVIEW, actor, target, correlation)
        try:
            checked = revalidated(proposal)
            reason = match_refusal(
                self._ledger.find_proposal(checked.request_id), checked, self._key()
            )
            if reason is not None:
                raise ExternalRequestRefused(reason)
        except ExternalRequestRefused as refusal:
            self._record(
                principal, ACTION_PREVIEW, target, AuditOutcome.DENIED,
                {"reason": refusal.reason.value}, correlation,
            )  # fmt: skip
            raise
        payload = minimize(
            checked,
            scheme=self._scheme,
            allowed_classifications=self._allowed,
            redactor=self._redactor,
        )
        preview = build_preview(payload)
        raw = preview.preview_bytes
        details: dict[str, Any] = {
            "request_id": preview.request_id,
            "provider": preview.provider_name,
            "model": preview.model_name,
            "purpose_sha256": sha256_hex(preview.purpose),
            "payload_sha256": preview.payload_hash,
            "payload_bytes": 0 if raw is None else len(raw),
            "payload_classification": preview.classification,
            "sendable": preview.sendable,
            "blocked_reason": preview.blocked_reason.value if preview.blocked_reason else None,
            **capped_refs(
                "kept", [{"ref": i.ref, "classification": i.classification} for i in preview.kept]
            ),
            **capped_refs(
                "dropped",
                [
                    {"ref": i.ref, "classification": i.classification, "reason": i.reason.value}
                    for i in preview.dropped
                ],
            ),
        }
        self._record(principal, ACTION_PREVIEW, target, AuditOutcome.SUCCESS, details, correlation)
        return preview

    def _key(self) -> bytes | None:
        """The key for item digests, or None when none is configured. A configured key
        that cannot be resolved stops the call."""
        if self._digest_key_ref is None or self._secrets is None:
            return None
        try:
            return resolve_key_bytes(self._secrets, self._digest_key_ref)
        except Exception as exc:
            raise FailClosed(
                f"digest key unavailable ({type(exc).__name__}); external inference step refused"
            ) from exc

    def _gate(self, action: str, actor_id: str, target: str, correlation_id: str) -> Principal:
        """Refuse unless the feature is on and the actor is a human as of now.

        The actor id is resolved through the identity store; a `Principal` object handed in
        by a caller would only be a snapshot. A resolver that raises stops the call.
        """
        principal = self._principals.resolve(actor_id)
        reason: ExternalReason | None = None
        if self._enabled is not True:
            reason = ExternalReason.FEATURE_DISABLED
        elif principal is None:
            reason = ExternalReason.REQUESTER_UNKNOWN
        elif principal.actor_type is not ActorType.HUMAN:
            reason = ExternalReason.REQUESTER_NOT_HUMAN
        if reason is not None or principal is None:
            reason = reason or ExternalReason.REQUESTER_UNKNOWN
            self._append(
                AuditEvent(
                    actor_id=actor_id,
                    actor_type=ActorType.ANONYMOUS if principal is None else principal.actor_type,
                    action=action,
                    target=target,
                    outcome=AuditOutcome.DENIED,
                    correlation_id=correlation_id,
                    details={"reason": reason.value},
                )
            )
            raise ExternalRequestRefused(reason)
        return principal

    def _record(
        self,
        principal: Principal,
        action: str,
        target: str,
        outcome: AuditOutcome,
        details: dict[str, Any],
        correlation_id: str,
    ) -> None:
        self._append(
            AuditEvent(
                actor_id=principal.actor_id,
                actor_type=principal.actor_type,
                action=action,
                target=target,
                outcome=outcome,
                correlation_id=correlation_id,
                details=details,
            )
        )

    def _append(self, event: AuditEvent) -> None:
        """No audit record, no result (blueprint 9.5)."""
        try:
            self._audit.append(event)
        except FailClosed:
            raise
        except Exception as exc:
            raise FailClosed("audit path unavailable; external inference step refused") from exc
