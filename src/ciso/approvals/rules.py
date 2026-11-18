"""Pure checks that decide who may approve and whether an approval can be used. No
database, no audit, no clock: callers pass what was read. Input shapes are in `inputs`.

Blueprint 8.4 step 4, 9.5; gaps G2, G12, G33; ADR-0016, ADR-0021.
"""

from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime

from ciso.approvals.inputs import (
    MAX_ACTOR,
    MAX_BINDING_FIELDS,
    MAX_CORRELATION,
    MAX_FIELD,
    MAX_KEY,
    MAX_NOTE,
    MAX_PARTIES,
    check_actor,
    check_binding,
    check_correlation,
    check_issuer,
    check_note,
    check_parties,
    check_requester,
    check_roles,
    check_subject,
    check_target,
    check_ttl,
)
from ciso.approvals.models import (
    APPROVE_ACTION,
    Approval,
    ApprovalReason,
    ApprovalStatus,
    AuditRecordView,
)
from ciso.common.enums import APPROVER_ROLES, ActorType, AuditOutcome, Role
from ciso.common.principal import Principal

__all__ = [
    "MAX_ACTOR",
    "MAX_BINDING_FIELDS",
    "MAX_CORRELATION",
    "MAX_FIELD",
    "MAX_KEY",
    "MAX_NOTE",
    "MAX_PARTIES",
    "approver_refusal",
    "check_actor",
    "check_binding",
    "check_correlation",
    "check_issuer",
    "check_note",
    "check_parties",
    "check_requester",
    "check_roles",
    "check_subject",
    "check_target",
    "check_ttl",
    "clock_behind",
    "covering_roles",
    "grant_record_refusal",
    "is_party",
    "may_list_for",
    "separation_refusal",
    "snapshot_refusal",
    "state_refusal",
    "subject_refusal",
]

_STATE_REASONS = {
    ApprovalStatus.PENDING: ApprovalReason.NOT_APPROVED,
    ApprovalStatus.REJECTED: ApprovalReason.REJECTED,
    ApprovalStatus.VOID: ApprovalReason.VOIDED,
    ApprovalStatus.CONSUMED: ApprovalReason.ALREADY_CONSUMED,
}


def covering_roles(record: Approval, resolved: Principal) -> tuple[Role, ...]:
    """Required roles the actor holds NOW through a grant that reaches the target. A
    stored role outside `APPROVER_ROLES` never counts."""
    wanted = frozenset(record.required_roles) & APPROVER_ROLES
    return tuple(sorted(resolved.covering_roles(wanted, record.target)))


def may_list_for(record: Approval, role: Role) -> bool:
    """True when a holder of `role` could decide this request: the role is stored on it
    and is an approver role (a stored role outside `APPROVER_ROLES` decides nothing)."""
    return role in APPROVER_ROLES and role in record.required_roles


def approver_refusal(record: Approval, resolved: Principal | None) -> ApprovalReason | None:
    """Why the freshly resolved actor may not stand as approver, or None.

    `resolved` is what `PrincipalResolver.resolve` returned just now; None means unknown
    or disabled.
    """
    if resolved is None:
        return ApprovalReason.APPROVER_UNKNOWN
    if resolved.actor_type is not ActorType.HUMAN:
        return ApprovalReason.APPROVER_NOT_HUMAN
    if not covering_roles(record, resolved):
        return ApprovalReason.APPROVER_LACKS_ROLE
    return None


def snapshot_refusal(claimed: Principal, resolved: Principal) -> ApprovalReason | None:
    """Refuse a `Principal` object that disagrees with the identity store about its own
    actor: another actor type, or a role the actor does not hold now. Sign-in did not
    produce such an object for this actor as it is today (review finding H1)."""
    if claimed.actor_type is not resolved.actor_type or not claimed.roles <= resolved.roles:
        return ApprovalReason.PRINCIPAL_MISMATCH
    return None


def is_party(record: Approval, actor_id: str) -> bool:
    """True for the requester and for every named party."""
    return actor_id == record.requested_by or actor_id in record.parties


def separation_refusal(
    record: Approval, approver_id: str, credential_issuer: str | None, *, allow_self: bool
) -> ApprovalReason | None:
    """The requester/approver rule (ADR-0016), applied when deciding and again when used.

    The approver must be neither the requester nor a named party unless self-approval is
    switched on. Any other approver must have signed in with a credential whose issuer is
    known and is neither the requester nor a party: an administrator can mint a token for
    another person (ADR-0004), and that must not turn one person into two.

    Not covered, by design (ADR-0016, ADR-0004): the mirror case (the approver issued the
    requester's credential, which cannot be seen from the approver's side), an issuer
    chain longer than one hop, and one person holding two actor records.
    """
    if is_party(record, approver_id):
        return None if allow_self else ApprovalReason.SELF_APPROVAL
    if not credential_issuer:
        return ApprovalReason.CREDENTIAL_ISSUER_UNKNOWN
    if is_party(record, credential_issuer):
        return ApprovalReason.CREDENTIAL_ISSUED_BY_REQUESTER
    return None


def clock_behind(record: Approval, now: datetime) -> bool:
    """True when the clock reads earlier than a time already stored on the approval. Such
    a clock is not trusted for expiry either (review finding L1). A clock set back to a
    time at or after the stored ones cannot be told apart from an honest one."""
    if now < record.requested_at:
        return True
    return record.decided_at is not None and now < record.decided_at


def state_refusal(record: Approval, now: datetime) -> ApprovalReason | None:
    """Why the stored state does not allow use right now, or None."""
    if record.status is not ApprovalStatus.APPROVED:
        return _STATE_REASONS.get(record.status, ApprovalReason.NOT_APPROVED)
    if record.consumed_at is not None:
        return ApprovalReason.ALREADY_CONSUMED
    if not record.decision_audit_ref or not record.decided_by:
        return ApprovalReason.GRANT_NOT_AUDITED
    if record.is_expired(now):
        return ApprovalReason.EXPIRED
    return None


def grant_record_refusal(record: Approval, found: AuditRecordView | None) -> ApprovalReason | None:
    """Compare the audit record that `decision_audit_ref` names with the stored grant: it
    must be a successful `approval.approve` of this approval by the stored approver."""
    if (
        found is None
        or found.action != APPROVE_ACTION
        or found.outcome is not AuditOutcome.SUCCESS
        or found.target != record.ref
        or found.actor_id != record.decided_by
    ):
        return ApprovalReason.GRANT_NOT_AUDITED
    return None


def subject_refusal(
    record: Approval, subject_kind: str, subject_hash: str, binding: Mapping[str, str]
) -> ApprovalReason | None:
    """The approval covers exactly one subject and one set of binding fields (gap G2)."""
    if record.subject_kind != subject_kind or record.subject_hash != subject_hash:
        return ApprovalReason.SUBJECT_MISMATCH
    if dict(record.binding) != dict(binding):
        return ApprovalReason.BINDING_MISMATCH
    return None
