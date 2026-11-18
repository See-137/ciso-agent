"""Every check on the external path that needs no approval, and then the bytes
(blueprint 8.4 steps 2 and 3 as the gateway performs them; review finding C1).

`Preparer.prepare` is the only place a sendable byte string is made. It takes whatever the
caller presented, accepts only a proposal that `propose` recorded and that is unchanged,
and then minimizes and serialises it with the gateway's own scheme, allowed labels and
redactor. A preview object from outside never gets past `revalidated`.
"""

from __future__ import annotations

from typing import NamedTuple

from ciso.common.classification import ClassificationScheme
from ciso.common.protocols import Redactor, SecretResolver
from ciso.inference.external.auditing import GateAudit
from ciso.inference.external.binding import fresh_binding
from ciso.inference.external.gates import Caller, Gates
from ciso.inference.external.ledger import ExternalLedger
from ciso.inference.external.minimize import (
    ApprovalBinding,
    PayloadPreview,
    build_preview,
    minimize,
)
from ciso.inference.external.proposal import (
    ExternalRequestProposal,
    ExternalRequestRefused,
    clean_actor,
    clean_correlation,
    request_target,
)
from ciso.inference.external.proposals import match_refusal, revalidated
from ciso.inference.external.records import GateReason
from ciso.vault import resolve_key_bytes


class Ready(NamedTuple):
    """A proposal that passed every stateless gate, and the bytes built from it here."""

    caller: Caller
    target: str
    correlation_id: str
    proposal: ExternalRequestProposal
    preview: PayloadPreview
    raw: bytes
    binding: ApprovalBinding
    key: bytes | None


class Preparer:
    def __init__(
        self,
        *,
        gates: Gates,
        ledger: ExternalLedger,
        audit: GateAudit,
        redactor: Redactor,
        scheme: ClassificationScheme | None,
        allowed_classifications: frozenset[str],
        max_payload_bytes: int | None,
        secrets: SecretResolver | None,
        digest_key_ref: str | None,
    ) -> None:
        self._gates = gates
        self._ledger = ledger
        self._audit = audit
        self._redactor = redactor
        self._scheme = scheme
        self._allowed = allowed_classifications
        self._max_payload = max_payload_bytes
        self._secrets = secrets
        self._digest_key_ref = digest_key_ref

    def prepare(self, action: str, candidate: object, actor_id: str, correlation_id: str) -> Ready:
        """Refuse (audited as DENIED under `action`) or return what may go on.

        Raises `ValidationFailed` for an actor or correlation id that is not an
        identifier, `ExternalGateRefused` for every gate, `FailClosed` when the ledger or
        the audit path cannot be reached.
        """
        correlation = clean_correlation(correlation_id)
        target = request_target(candidate)
        caller = self._gates.who(clean_actor(actor_id))
        reason = self._gates.refusal(caller)
        if reason is not None:
            self._audit.refuse(action, caller, target, reason, correlation)
        key = self._digest_key(action, caller, target, correlation)
        try:
            proposal = revalidated(candidate)
            unknown = match_refusal(self._ledger.find_proposal(proposal.request_id), proposal, key)
            if unknown is not None:
                raise ExternalRequestRefused(unknown)
        except ExternalRequestRefused as refused:
            self._audit.refuse(
                action, caller, target, GateReason(refused.reason.value), correlation
            )
        if caller.actor_id != proposal.requester_actor_id:
            self._audit.refuse(action, caller, target, GateReason.NOT_REQUESTER, correlation)
        preview, failure = self._build(proposal)
        if preview is None:
            self._audit.refuse(
                action, caller, target, GateReason.MINIMIZE_FAILED, correlation,
                extra={"cause_type": failure},
            )  # fmt: skip
        raw = preview.preview_bytes
        if raw is None or not preview.sendable:
            blocked = preview.blocked_reason.value if preview.blocked_reason else None
            self._audit.refuse(
                action, caller, target, GateReason.NOT_SENDABLE, correlation,
                extra={"blocked_reason": blocked, "dropped_count": len(preview.dropped)},
            )  # fmt: skip
        labels = {item.classification for item in preview.kept} | {preview.classification}
        if not labels <= self._allowed:
            self._audit.refuse(
                action, caller, target, GateReason.CLASSIFICATION_NOT_ALLOWED, correlation
            )
        if self._max_payload is None or len(raw) > self._max_payload:
            self._audit.refuse(
                action, caller, target, GateReason.PAYLOAD_TOO_LARGE, correlation,
                extra={"payload_bytes": len(raw)},
            )  # fmt: skip
        binding = fresh_binding(preview, raw)
        return Ready(caller, target, correlation, proposal, preview, raw, binding, key)

    def _build(self, proposal: ExternalRequestProposal) -> tuple[PayloadPreview | None, str]:
        """Minimize and serialise with the gateway's own settings. On failure: None and
        the exception's type name only, since a redactor's message could quote the text."""
        try:
            payload = minimize(
                proposal,
                scheme=self._scheme,
                allowed_classifications=tuple(sorted(self._allowed)),
                redactor=self._redactor,
            )
            return build_preview(payload), ""
        except Exception as exc:
            return None, type(exc).__name__

    def _digest_key(
        self, action: str, caller: Caller, target: str, correlation_id: str
    ) -> bytes | None:
        if self._digest_key_ref is None or self._secrets is None:
            return None
        try:
            return resolve_key_bytes(self._secrets, self._digest_key_ref)
        except Exception as exc:
            self._audit.refuse(
                action, caller, target, GateReason.DIGEST_KEY_UNAVAILABLE, correlation_id,
                cause=exc,
            )  # fmt: skip
