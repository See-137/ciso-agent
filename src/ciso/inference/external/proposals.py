"""The durable trace of a proposal, and the check a re-presented proposal must pass
(blueprint 8.4 step 1; review finding C1).

Item text is not stored anywhere, so the caller presents the proposal again at each later
step. What makes that safe is this record: a request id that `propose` never recorded is
refused, and so is a proposal that differs in requester, provider, model, purpose or any
item (ref, label, text) from the one recorded. The record holds digests, never text.
"""

from __future__ import annotations

import hmac

from pydantic import ValidationError

from ciso.common.classification import UNKNOWN_LABEL
from ciso.common.schemas import Model, UtcDatetime, canonical_json, sha256_hex
from ciso.inference.external.proposal import (
    ExternalReason,
    ExternalRequestProposal,
    ExternalRequestRefused,
)


class ProposedItem(Model):
    """What is kept of one offered item: its ref, its normalised label and a digest of
    its text."""

    ref: str
    classification: str
    text_digest: str


class ExternalProposalRecord(Model):
    request_id: str
    requester_actor_id: str
    provider_name: str
    model_name: str
    purpose_sha256: str
    items: tuple[ProposedItem, ...]
    created_at: UtcDatetime
    correlation_id: str = ""

    def fingerprint(self) -> str:
        """One hash over everything a re-presented proposal must reproduce."""
        return sha256_hex(canonical_json(self.model_dump(exclude={"created_at", "correlation_id"})))


def text_digest(text: str, key: bytes | None) -> str:
    """Digest of one item's text: HMAC-SHA-256 under `key` when one is configured (an
    unkeyed hash of a short text reveals it to anyone who can guess it), else SHA-256."""
    raw = text.encode("utf-8")
    return sha256_hex(raw) if key is None else hmac.new(key, raw, "sha256").hexdigest()


def proposal_record(
    proposal: ExternalRequestProposal, *, key: bytes | None, correlation_id: str = ""
) -> ExternalProposalRecord:
    """The record of a proposal. A missing label is stored as `unknown`."""
    return ExternalProposalRecord(
        request_id=proposal.request_id,
        requester_actor_id=proposal.requester_actor_id,
        provider_name=proposal.provider_name,
        model_name=proposal.model_name,
        purpose_sha256=sha256_hex(proposal.purpose),
        items=tuple(
            ProposedItem(
                ref=item.ref,
                classification=item.classification or UNKNOWN_LABEL,
                text_digest=text_digest(item.text, key),
            )
            for item in proposal.items
        ),
        created_at=proposal.created_at,
        correlation_id=correlation_id,
    )


def revalidated(candidate: object) -> ExternalRequestProposal:
    """The candidate as a freshly validated proposal. Anything else (another type, an
    object built around the validators) is refused as `PROPOSAL_INVALID`. The error never
    quotes the candidate."""
    if not isinstance(candidate, ExternalRequestProposal):
        raise ExternalRequestRefused(ExternalReason.PROPOSAL_INVALID)
    try:
        return ExternalRequestProposal.model_validate(candidate.model_dump())
    except (ValidationError, ValueError, TypeError, AttributeError):
        raise ExternalRequestRefused(ExternalReason.PROPOSAL_INVALID) from None


def match_refusal(
    stored: ExternalProposalRecord | None, proposal: ExternalRequestProposal, key: bytes | None
) -> ExternalReason | None:
    """Why the presented proposal is not the recorded one, or None."""
    if stored is None:
        return ExternalReason.PROPOSAL_UNKNOWN
    presented = proposal_record(proposal, key=key)
    if not hmac.compare_digest(stored.fingerprint(), presented.fingerprint()):
        return ExternalReason.PROPOSAL_MISMATCH
    return None
