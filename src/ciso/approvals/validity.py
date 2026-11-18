"""The checks the approval service makes with its collaborators: the expiry setting, the
clock, the identity resolver and the audit read-back. Holds no database handle, so none
of these can be reached while the write lock is held. Pure rules are in `rules`.
"""

from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime, timedelta

from ciso.approvals import rules
from ciso.approvals.models import (
    Approval,
    ApprovalConflict,
    ApprovalInvalid,
    ApprovalReason,
    ApprovalStatus,
    ApprovalUnavailable,
    AuditRecordLookup,
    AuditRecordView,
)
from ciso.common.clock import Clock
from ciso.common.principal import Principal
from ciso.common.protocols import PrincipalResolver


class Validity:
    def __init__(
        self,
        *,
        clock: Clock,
        principals: PrincipalResolver,
        ttl: timedelta | None,
        allow_self: bool,
        audit_records: AuditRecordLookup | None,
    ) -> None:
        self._clock = clock
        self._principals = principals
        self._ttl = ttl
        self._allow_self = allow_self
        self._audit_records = audit_records

    def require_ttl(self) -> timedelta:
        if self._ttl is None:
            raise ApprovalUnavailable(
                ApprovalReason.TTL_UNSET, "approval expiry window is not set; refusing"
            )
        return self._ttl

    def now_for(self, record: Approval) -> datetime:
        """The time, refused when it is earlier than a time this approval already holds:
        a clock that went backwards must not revive an expired approval."""
        now = self._clock.now()
        if rules.clock_behind(record, now):
            raise ApprovalUnavailable(
                ApprovalReason.CLOCK_UNRELIABLE,
                "the clock reads earlier than a time stored on this approval; refusing",
            )
        return now

    def resolve(self, actor_id: str) -> Principal | None:
        try:
            return self._principals.resolve(actor_id)
        except Exception as exc:
            raise ApprovalUnavailable(
                ApprovalReason.IDENTITY_UNAVAILABLE,
                f"identity could not be checked ({type(exc).__name__})",
            ) from exc

    def open_for_decision(self, record: Approval, *, granting: bool) -> datetime:
        """The decision time, or a raise when the request cannot be decided now."""
        if granting:
            self.require_ttl()
        now = self.now_for(record)
        if record.status is not ApprovalStatus.PENDING:
            raise ApprovalConflict(ApprovalReason.ALREADY_DECIDED, "approval is not pending")
        if record.is_expired(now):
            raise ApprovalInvalid(ApprovalReason.EXPIRED, "approval request has expired")
        return now

    def approver_reason(
        self, record: Approval, approver: Principal, resolved: Principal | None, issuer: str
    ) -> ApprovalReason | None:
        """Why this approver may not decide, or None. `approver` is the object the caller
        handed in; `resolved` is the same actor id as the identity store sees it now."""
        why = rules.approver_refusal(record, resolved)
        if why is not None or resolved is None:
            return why or ApprovalReason.APPROVER_UNKNOWN
        return rules.snapshot_refusal(approver, resolved) or rules.separation_refusal(
            record, approver.actor_id, issuer, allow_self=self._allow_self
        )

    def use_reason(
        self, record: Approval, kind: str, digest: str, fields: Mapping[str, str]
    ) -> ApprovalReason | None:
        """Why the approval cannot be used for this subject right now, or None. Raises
        `ApprovalUnavailable` when a control (setting, clock, identity, audit log) cannot
        be consulted."""
        self.require_ttl()
        now = self.now_for(record)
        why = rules.state_refusal(record, now) or rules.subject_refusal(
            record, kind, digest, fields
        )
        if why is not None:
            return why
        approver = record.decided_by or ""
        return (
            rules.approver_refusal(record, self.resolve(approver))
            or rules.separation_refusal(
                record, approver, record.approver_credential_issuer, allow_self=self._allow_self
            )
            or self._grant_reason(record)
        )

    def _grant_reason(self, record: Approval) -> ApprovalReason | None:
        """With an audit lookup wired: is `decision_audit_ref` really the grant?"""
        if self._audit_records is None:
            return None
        try:
            found = self._audit_records.find(record.decision_audit_ref or "")
        except Exception as exc:
            raise ApprovalUnavailable(
                ApprovalReason.AUDIT_UNAVAILABLE,
                f"the grant's audit record could not be read ({type(exc).__name__})",
            ) from exc
        if not isinstance(found, AuditRecordView):
            found = None
        return rules.grant_record_refusal(record, found)
