"""Pure helpers that tie a preview to its authorization and build the step-6 record
(blueprint 8.4 steps 4 and 6, gap G2). No database, no audit, no clock.
"""

from __future__ import annotations

import hmac
from datetime import datetime
from typing import Any

from ciso.approvals import Approval
from ciso.common.enums import Role
from ciso.common.errors import FailClosed
from ciso.common.ids import new_id
from ciso.common.schemas import sha256_hex
from ciso.inference.external.minimize import ApprovalBinding, PayloadPreview
from ciso.inference.external.proposal import capped_refs
from ciso.inference.external.records import (
    RECORD_ID_PREFIX,
    ExternalAuthorization,
    ExternalTransmissionRecord,
    TransmitOutcome,
    binding_fields,
)


def fresh_binding(preview: PayloadPreview, raw: bytes) -> ApprovalBinding:
    """The five bound values, with the hash taken again over the bytes that would go
    out. The hash the preview carries is not trusted."""
    return ApprovalBinding(
        request_id=preview.request_id,
        provider_name=preview.provider_name,
        model_name=preview.model_name,
        purpose=preview.purpose,
        payload_hash=sha256_hex(raw),
    )


def same_binding(stored: ExternalAuthorization, binding: ApprovalBinding) -> bool:
    """True when payload, provider, model, purpose and request id are all what was
    authorized."""
    fields = binding_fields(binding)
    pairs = (
        (stored.subject_hash, binding.subject_hash()),
        (stored.payload_sha256, fields["payload_sha256"]),
        (stored.purpose_sha256, fields["purpose_sha256"]),
        (stored.provider_name, fields["provider"]),
        (stored.model_name, fields["model"]),
        (stored.request_id, fields["request_id"]),
    )
    return all(hmac.compare_digest(left.encode(), right.encode()) for left, right in pairs)


def payload_details(
    preview: PayloadPreview, binding: ApprovalBinding, raw: bytes
) -> dict[str, Any]:
    """Audit details: sizes, hashes, and a capped list of refs and labels with the count
    and a digest of the full list. Never item text or purpose text."""
    fields = binding_fields(binding)
    return {
        "request_id": binding.request_id,
        "provider": binding.provider_name,
        "model": binding.model_name,
        "purpose_sha256": fields["purpose_sha256"],
        "payload_sha256": binding.payload_hash,
        "payload_bytes": len(raw),
        "payload_classification": preview.classification,
        "subject_hash": binding.subject_hash(),
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


def new_record(
    *,
    stored: ExternalAuthorization,
    approval: Approval,
    transmitted_by: str,
    preview: PayloadPreview,
    payload_bytes: int,
    approver_role: Role | None,
    allowed_classifications: frozenset[str],
    now: datetime,
    correlation_id: str,
) -> ExternalTransmissionRecord:
    """The record as it stands before the transport is called (outcome `attempted`).
    Raises `FailClosed` for an approval that names no approver or decision time: the
    record never invents either."""
    if not approval.decided_by or approval.decided_at is None:
        raise FailClosed("the consumed approval names no approver; nothing is sent")
    return ExternalTransmissionRecord(
        id=new_id(RECORD_ID_PREFIX),
        request_id=stored.request_id,
        approval_ref=approval.ref,
        requested_by=approval.requested_by,
        transmitted_by=transmitted_by,
        approver=approval.decided_by,
        approver_roles=approval.decided_roles,
        approved_at=approval.decided_at,
        provider_name=stored.provider_name,
        model_name=stored.model_name,
        purpose=stored.purpose,
        purpose_sha256=stored.purpose_sha256,
        payload_sha256=stored.payload_sha256,
        payload_bytes=payload_bytes,
        payload_classification=preview.classification,
        kept=preview.kept,
        policy_decision={
            "decision": "allow",
            "basis": "per_request_human_approval",
            "feature_enabled": True,
            "kill_switch_blocked": False,
            "approver_role": None if approver_role is None else approver_role.value,
            "allowed_classifications": sorted(allowed_classifications),
            "approval_subject_hash": approval.subject_hash,
            "approval_expires_at": approval.expires_at.isoformat(),
            "self_approved": approval.self_approved,
        },
        attempted_at=now,
        outcome=TransmitOutcome.ATTEMPTED,
        correlation_id=correlation_id,
    )
