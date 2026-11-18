"""External model use: explicit, per-request, human opt-in (blueprint 8.4).

Only the human-facing API router and the composition root may import this package
(gap G1). `ExternalInferenceGateway` is the one object they talk to: it proposes,
previews, authorizes and transmits, and it is the only producer of bytes that leave. The
package defines the transport interface and ships no implementation of it, so it opens no
connection.
"""

from __future__ import annotations

from ciso.inference.external.gateway import ExternalInferenceGateway
from ciso.inference.external.minimize import (
    PAYLOAD_SCHEMA_VERSION,
    ApprovalBinding,
    DroppedItem,
    ItemLabel,
    KeptItem,
    MinimizedPayload,
    PayloadPreview,
    approval_binding,
    build_preview,
    minimize,
    parse_payload,
    preview_bytes,
)
from ciso.inference.external.proposal import (
    MAX_AUDIT_REFS,
    MAX_ITEM_TEXT_CHARS,
    MAX_ITEMS,
    REQUEST_ID_PREFIX,
    REQUEST_REF_KIND,
    ContextItem,
    ExternalReason,
    ExternalRequestProposal,
    ExternalRequestRefused,
    classify,
)
from ciso.inference.external.proposals import ExternalProposalRecord, ProposedItem
from ciso.inference.external.records import (
    ACTION_AUTHORIZE,
    ACTION_TRANSMIT,
    APPROVAL_SUBJECT_KIND,
    RECORD_ID_PREFIX,
    RESULT_REF_KIND,
    ExternalAuthorization,
    ExternalGateRefused,
    ExternalResult,
    ExternalTransmissionRecord,
    ExternalTransmitFailed,
    GateReason,
    TransmitOutcome,
    binding_fields,
)
from ciso.inference.external.service import (
    ACTION_PREVIEW,
    ACTION_PROPOSE,
    ExternalProposalService,
)
from ciso.inference.external.transport import ExternalTransport, TransportResponse

__all__ = [
    "ACTION_AUTHORIZE",
    "ACTION_PREVIEW",
    "ACTION_PROPOSE",
    "ACTION_TRANSMIT",
    "APPROVAL_SUBJECT_KIND",
    "MAX_AUDIT_REFS",
    "MAX_ITEMS",
    "MAX_ITEM_TEXT_CHARS",
    "PAYLOAD_SCHEMA_VERSION",
    "RECORD_ID_PREFIX",
    "REQUEST_ID_PREFIX",
    "REQUEST_REF_KIND",
    "RESULT_REF_KIND",
    "ApprovalBinding",
    "ContextItem",
    "DroppedItem",
    "ExternalAuthorization",
    "ExternalGateRefused",
    "ExternalInferenceGateway",
    "ExternalProposalRecord",
    "ExternalProposalService",
    "ExternalReason",
    "ExternalRequestProposal",
    "ExternalRequestRefused",
    "ExternalResult",
    "ExternalTransmissionRecord",
    "ExternalTransmitFailed",
    "ExternalTransport",
    "GateReason",
    "ItemLabel",
    "KeptItem",
    "MinimizedPayload",
    "PayloadPreview",
    "ProposedItem",
    "TransmitOutcome",
    "TransportResponse",
    "approval_binding",
    "binding_fields",
    "build_preview",
    "classify",
    "minimize",
    "parse_payload",
    "preview_bytes",
]
