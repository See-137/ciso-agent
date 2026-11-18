"""Reason codes, errors and record types for steps 4 to 7 of the external model path
(blueprint 8.4: authorize, transmit, record, reintegrate).

Nothing here holds payload bytes, context item text or answer text, except
`ExternalResult.output`, which is the answer wrapped as untrusted model output and is
handed to the caller, never stored.
"""

from __future__ import annotations

from enum import StrEnum

from pydantic import ConfigDict, Field

from ciso.common.enums import Role
from ciso.common.errors import CisoError, ExternalInferenceBlocked
from ciso.common.schemas import FrozenJson, FrozenMap, Model, UtcDatetime, sha256_hex
from ciso.inference.external.minimize import ApprovalBinding, DroppedItem, ItemLabel
from ciso.inference.records import UntrustedModelOutput

#: Audit action names. Values are a wire format: do not rename.
ACTION_AUTHORIZE = "inference.external.authorize"
ACTION_TRANSMIT = "inference.external.transmit"

#: Subject kind of an approval that covers one external model request.
APPROVAL_SUBJECT_KIND = "external_inference"
RECORD_ID_PREFIX = "xtx"
#: `EntityRef` kind of a returned result (`external_result:<record id>`).
RESULT_REF_KIND = "external_result"


class GateReason(StrEnum):
    """Why authorize or transmit refused. Values are a wire format: do not rename."""

    #: The feature flag is off (the default).
    FEATURE_DISABLED = "feature_disabled"
    #: The kill switch blocks external inference, or its state cannot be read.
    KILL_SWITCH_ENGAGED = "kill_switch_engaged"
    #: Reading the kill switch raised.
    KILL_SWITCH_UNAVAILABLE = "kill_switch_unavailable"
    #: No approver role is configured (gap G26).
    APPROVER_ROLE_UNSET = "approver_role_unset"
    #: The configured approver role is not one that may approve (ADR-0021).
    APPROVER_ROLE_NOT_ALLOWED = "approver_role_not_allowed"
    #: No transport is wired. This build ships none.
    TRANSPORT_ABSENT = "transport_absent"
    #: The identity store could not be asked.
    IDENTITY_UNAVAILABLE = "identity_unavailable"
    #: The actor id does not resolve to a known, enabled actor right now.
    ACTOR_UNKNOWN = "actor_unknown"
    #: The actor is an agent or a service. The path is never automatic.
    ACTOR_NOT_HUMAN = "actor_not_human"
    #: `max_payload_bytes` is not configured: nothing can be measured, nothing is sent.
    PAYLOAD_LIMIT_UNSET = "payload_limit_unset"
    #: `max_response_bytes` is not configured.
    RESPONSE_LIMIT_UNSET = "response_limit_unset"
    #: What was presented is not a well-formed proposal (for example a hand-built preview).
    PROPOSAL_INVALID = "proposal_invalid"
    #: No proposal with this request id was ever recorded by `propose`.
    PROPOSAL_UNKNOWN = "proposal_unknown"
    #: The proposal differs from the one recorded under its request id.
    PROPOSAL_MISMATCH = "proposal_mismatch"
    #: The caller is not the actor who proposed (and, at transmit, filed) the request.
    NOT_REQUESTER = "not_requester"
    #: Minimizing or serialising the proposal failed (for example the redactor raised).
    MINIMIZE_FAILED = "minimize_failed"
    #: After minimization nothing is left to send.
    NOT_SENDABLE = "not_sendable"
    #: The minimized payload is larger than `max_payload_bytes`.
    PAYLOAD_TOO_LARGE = "payload_too_large"
    #: The approval was decided by the actor now trying to transmit.
    TRANSMITTER_IS_APPROVER = "transmitter_is_approver"
    #: No classification scheme, or no allowed classifications, is configured.
    NO_ALLOWED_CLASSIFICATIONS = "no_allowed_classifications"
    #: The preview holds an item whose label may not leave under today's settings.
    CLASSIFICATION_NOT_ALLOWED = "classification_not_allowed"
    #: No authorization was recorded for this approval id.
    AUTHORIZATION_NOT_FOUND = "authorization_not_found"
    #: Payload, provider, model, purpose or request id differ from what was authorized.
    BINDING_MISMATCH = "binding_mismatch"
    #: The key for the stored answer digest could not be resolved.
    DIGEST_KEY_UNAVAILABLE = "digest_key_unavailable"
    #: The approvals module refused; `approval_reason` carries its own code.
    APPROVAL_REFUSED = "approval_refused"
    #: The approvals module failed in a way it did not name.
    APPROVAL_UNAVAILABLE = "approval_unavailable"


class ExternalGateRefused(ExternalInferenceBlocked):
    """Authorize or transmit refused. Nothing was sent. Branch on `reason`;
    `approval_reason` is the approvals module's code when it was the one that refused."""

    def __init__(self, reason: GateReason, approval_reason: str | None = None) -> None:
        detail = f" ({approval_reason})" if approval_reason else ""
        super().__init__(f"external inference refused: {reason.value}{detail}")
        self.reason = reason
        self.approval_reason = approval_reason


class TransmitOutcome(StrEnum):
    """What became of one transmission. Values are a wire format: do not rename."""

    #: Written before the transport is called. A row left in this state means the
    #: process stopped mid-call: treat the payload as possibly sent.
    ATTEMPTED = "attempted"
    SENT = "sent"
    TRANSPORT_ERROR = "transport_error"
    MALFORMED_RESPONSE = "malformed_response"
    EMPTY_RESPONSE = "empty_response"
    #: The answer was larger than `max_response_bytes` and was discarded unread.
    RESPONSE_TOO_LARGE = "response_too_large"
    #: The answer arrived but redacting or wrapping it failed; nothing was returned.
    RESULT_NOT_PROCESSED = "result_not_processed"
    #: The kill switch was found engaged immediately before the transport call. The
    #: transport was not called. The approval is spent all the same.
    NOT_SENT = "not_sent"
    #: The payload was handed to the transport, and the closing record is incomplete:
    #: this row could not be completed or the closing audit event could not be written.
    #: `error_type` says which. Treat the payload as sent.
    SENT_UNRECORDED = "sent_unrecorded"


class ExternalTransmitFailed(CisoError):
    """The payload was handed to the transport and no usable answer came back. The
    approval is spent. Nothing else was tried."""

    def __init__(self, outcome: TransmitOutcome, record_id: str) -> None:
        super().__init__(f"external inference failed: {outcome.value}")
        self.outcome = outcome
        self.record_id = record_id


def binding_fields(binding: ApprovalBinding) -> dict[str, str]:
    """The string fields an approval stores and compares again at use (gap G2).

    The purpose goes in as its hash: the approvals module copies binding fields into
    audit details, which never carry purpose text. The approval's subject hash covers the
    purpose text itself.
    """
    return {
        "request_id": binding.request_id,
        "provider": binding.provider_name,
        "model": binding.model_name,
        "purpose_sha256": sha256_hex(binding.purpose),
        "payload_sha256": binding.payload_hash,
    }


class ExternalAuthorization(Model):
    """What was previewed when approval was requested (8.4 step 4). No payload text."""

    approval_id: str
    request_id: str
    subject_hash: str
    provider_name: str
    model_name: str
    purpose: str
    purpose_sha256: str
    payload_sha256: str
    payload_bytes: int
    payload_classification: str
    kept: tuple[ItemLabel, ...]
    dropped: tuple[DroppedItem, ...]
    requested_by: str
    required_role: Role
    created_at: UtcDatetime
    correlation_id: str = ""

    @property
    def approval_ref(self) -> str:
        return f"approval:{self.approval_id}"


class ExternalTransmissionRecord(Model):
    """The step-6 record of one transmission (blueprint 8.4). Metadata only."""

    id: str
    request_id: str
    approval_ref: str
    requested_by: str
    transmitted_by: str
    approver: str
    approver_roles: tuple[Role, ...]
    approved_at: UtcDatetime
    provider_name: str
    model_name: str
    purpose: str
    purpose_sha256: str
    payload_sha256: str
    payload_bytes: int
    payload_classification: str
    kept: tuple[ItemLabel, ...]
    #: The settings and checks this transmission was allowed under.
    policy_decision: FrozenJson
    attempted_at: UtcDatetime
    completed_at: UtcDatetime | None = None
    outcome: TransmitOutcome
    error_type: str | None = None
    response_bytes: int | None = None
    #: Keyed digest of the returned (redacted) text; None when no key is configured.
    response_digest: str | None = None
    response_metadata: FrozenMap[str, str] = Field(default_factory=dict)
    result_ref: str | None = None
    correlation_id: str = ""


class ExternalResult(Model):
    """What the caller gets back (8.4 step 7). `output` is untrusted model output: it
    was redacted and wrapped, not interpreted. Validate it locally and send any action it
    proposes through the normal policy engine."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    record_id: str
    request_id: str
    approval_ref: str
    result_ref: str
    output: UntrustedModelOutput
    provider_name: str
    model_name: str
    response_bytes: int
    response_digest: str | None
    response_metadata: FrozenMap[str, str] = Field(default_factory=dict)
