"""Approval record, statuses, reason codes and errors.

Blueprint 8.4 step 4, 9.5, FR-025; gaps G2, G3, G12, G33; ADR-0016, ADR-0021.
"""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Protocol, runtime_checkable

from pydantic import Field

from ciso.common.enums import ActorType, AuditOutcome, Role
from ciso.common.errors import (
    ApprovalRequired,
    AuthorizationError,
    CisoError,
    Conflict,
    FailClosed,
    NotFound,
    ValidationFailed,
)
from ciso.common.schemas import FrozenMap, Model, UtcDatetime

#: Audit action names. Values are a wire format: do not rename.
REQUEST_ACTION = "approval.request"
APPROVE_ACTION = "approval.approve"
REJECT_ACTION = "approval.reject"
CHECK_ACTION = "approval.check"
CONSUME_ACTION = "approval.consume"
WITHDRAW_ACTION = "approval.withdraw"

#: Entity kind used in audit targets and cross-module references (`approval:<id>`).
APPROVAL_KIND = "approval"
ID_PREFIX = "apr"


class ApprovalStatus(StrEnum):
    """What is stored. "Valid" and "expired" are never stored: they are computed when an
    approval is checked (gap G12). Values are a wire format: do not rename."""

    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"
    CONSUMED = "consumed"
    #: Cancelled by the service because a step could not be audited. Never usable.
    VOID = "void"


class ApprovalReason(StrEnum):
    """Why a call was refused. Values are a wire format: do not rename."""

    # bad input (ApprovalInputInvalid)
    INVALID_SUBJECT = "invalid_subject"
    INVALID_BINDING = "invalid_binding"
    INVALID_REQUESTER = "invalid_requester"
    INVALID_PARTIES = "invalid_parties"
    INVALID_ROLES = "invalid_roles"
    INVALID_TARGET = "invalid_target"
    INVALID_ACTOR = "invalid_actor"
    INVALID_TEXT = "invalid_text"
    INVALID_SETTING = "invalid_setting"
    # lookup (ApprovalNotFound)
    NOT_FOUND = "not_found"
    # state (ApprovalConflict on decide; ApprovalInvalid on check and consume)
    ALREADY_DECIDED = "already_decided"
    NOT_APPROVED = "not_approved"
    REJECTED = "rejected"
    VOIDED = "voided"
    ALREADY_CONSUMED = "already_consumed"
    EXPIRED = "expired"
    GRANT_NOT_AUDITED = "grant_not_audited"
    SUBJECT_MISMATCH = "subject_mismatch"
    BINDING_MISMATCH = "binding_mismatch"
    # approver (ApprovalForbidden on decide; ApprovalInvalid on check and consume)
    APPROVER_UNKNOWN = "approver_unknown"
    APPROVER_NOT_HUMAN = "approver_not_human"
    APPROVER_LACKS_ROLE = "approver_lacks_role"
    SELF_APPROVAL = "self_approval"
    CREDENTIAL_ISSUER_UNKNOWN = "credential_issuer_unknown"
    #: The credential was issued by the requester or by a named party.
    CREDENTIAL_ISSUED_BY_REQUESTER = "credential_issued_by_requester"
    #: The `Principal` handed in disagrees with the identity store about its own actor.
    PRINCIPAL_MISMATCH = "principal_mismatch"
    # a control could not be consulted (ApprovalUnavailable)
    TTL_UNSET = "ttl_unset"
    IDENTITY_UNAVAILABLE = "identity_unavailable"
    AUDIT_UNAVAILABLE = "audit_unavailable"
    STORE_UNAVAILABLE = "store_unavailable"
    RECORD_UNREADABLE = "record_unreadable"
    #: The clock reads earlier than a time already stored on the approval.
    CLOCK_UNRELIABLE = "clock_unreliable"
    REDACTOR_UNAVAILABLE = "redactor_unavailable"
    #: A request or grant had to be cancelled and could not be: it may still be usable.
    VOID_FAILED = "void_failed"


class ApprovalFault(CisoError):
    """Base of every error this package raises. `reason` is the stable code to branch on;
    the message is for people and may change."""

    def __init__(self, reason: ApprovalReason, message: str = "") -> None:
        super().__init__(message or reason.value)
        self.reason = reason


class ApprovalInputInvalid(ApprovalFault, ValidationFailed):
    """An argument or a setting is malformed."""


class ApprovalNotFound(ApprovalFault, NotFound):
    """No approval has this id."""


class ApprovalConflict(ApprovalFault, Conflict):
    """The approval is not in the state the call needs (already decided)."""


class ApprovalForbidden(ApprovalFault, AuthorizationError):
    """This actor may not decide this approval."""


class ApprovalInvalid(ApprovalFault, ApprovalRequired):
    """The approval cannot be used for this subject now. A new approval is needed."""


class ApprovalUnavailable(ApprovalFault, FailClosed):
    """Identity, audit, the store or a required setting could not be consulted."""


class AuditRecordView(Model):
    """The four fields of a stored audit record that `AuditRecordLookup` hands back."""

    action: str
    target: str
    outcome: AuditOutcome
    actor_id: str


@runtime_checkable
class AuditRecordLookup(Protocol):
    """Read access to the audit log by record id. The composition root wires an adapter
    over the audit module; this package never imports it."""

    def find(self, record_id: str) -> AuditRecordView | None:
        """The stored record, or None when the log holds no record with this id. Raise
        when the log cannot be read: the caller then refuses."""
        ...


class Approval(Model):
    """One approval request and what became of it.

    `status` is what is stored; whether the approval can be used is decided by
    `ApprovalService.check` / `consume` at the moment of use, never read from here.
    `binding` and `target` cannot be changed in place. `decision_audit_ref` is the audit
    record id of the grant: an approved row without it is not usable.
    """

    approval_id: str
    subject_kind: str
    subject_hash: str
    binding: FrozenMap[str, str] = Field(default_factory=dict)
    requested_by: str
    requested_by_type: ActorType
    #: Actor ids, besides the requester, who may not decide this request (for example the
    #: author of what is being approved when somebody else filed it). ADR-0016.
    parties: tuple[str, ...] = ()
    required_roles: tuple[Role, ...]
    target: FrozenMap[str, str] = Field(default_factory=dict)
    status: ApprovalStatus
    requested_at: UtcDatetime
    expires_at: UtcDatetime
    correlation_id: str = ""
    decided_by: str | None = None
    decided_at: UtcDatetime | None = None
    #: The required roles the approver held, reaching the target, when deciding.
    decided_roles: tuple[Role, ...] = ()
    decision_note: str = ""
    #: True when the approver is the requester or a named party (only possible with
    #: `allow_self_approval`).
    self_approved: bool = False
    approver_credential_issuer: str | None = None
    decision_audit_ref: str | None = None
    consumed_at: UtcDatetime | None = None
    consumed_by: str | None = None

    @property
    def ref(self) -> str:
        """`approval:<id>`, the form other modules store."""
        return f"{APPROVAL_KIND}:{self.approval_id}"

    def is_expired(self, now: datetime) -> bool:
        return now >= self.expires_at
