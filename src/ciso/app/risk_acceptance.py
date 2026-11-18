"""Accepting a finding's risk through a bound, single-use human approval (spec rule 7;
blueprint 9.5, ADR-0016).

1. `request`: a current admin (the findings service's own read check: only an admin or
   an auditor may read any finding, and the route needs `finding.update`, which the
   auditor lacks) files an approval for THIS finding. Subject kind
   `finding_risk_acceptance`, subject hash over the finding id and its fingerprint,
   binding naming both; routed to `executive_risk_owner`; the requester is a party, so
   the approvals service refuses them as approver.
2. `accept`: the finding is read again (same check), the approval must not have been
   decided by the caller, the approval is SPENT through `ApprovalService.consume` with
   that subject and binding (single use; another finding's approval, a pending, rejected,
   expired or spent one is refused there), and only then does the findings service record
   the acceptance. Any approvals error refuses (`RiskAcceptanceRefused`, 409, with a
   reason code); nothing from the error is shown.

Known limit: if the findings service fails after the approval was spent, the approval is
gone and the finding is unchanged; a new approval is needed. That errs on refusing.
"""

from __future__ import annotations

import logging
from enum import StrEnum
from typing import Final

from ciso.approvals import Approval, ApprovalService
from ciso.common.enums import Role
from ciso.common.errors import PreconditionFailed
from ciso.common.principal import Principal
from ciso.common.schemas import content_hash
from ciso.findings import ACTIVE_STATUSES, Finding, FindingsService

logger = logging.getLogger(__name__)

RISK_SUBJECT_KIND: Final = "finding_risk_acceptance"


class RiskRefusal(StrEnum):
    FINDING_CLOSED = "finding_closed"
    APPROVER_IS_CALLER = "approver_is_caller"
    APPROVAL_NOT_USABLE = "approval_not_usable"


class RiskAcceptanceRefused(PreconditionFailed):
    """`reason` is a stable code the API sends; the message carries nothing else."""

    def __init__(self, reason: RiskRefusal) -> None:
        super().__init__(f"risk acceptance refused: {reason.value}")
        self.reason = reason


def risk_subject(finding: Finding) -> tuple[str, dict[str, str]]:
    """The subject hash and binding an approval for this finding's risk must carry."""
    binding = {"finding_id": finding.finding_id, "fingerprint": finding.fingerprint}
    return content_hash({"kind": RISK_SUBJECT_KIND, **binding}), binding


class RiskAcceptance:
    def __init__(self, *, approvals: ApprovalService, findings: FindingsService) -> None:
        self._approvals = approvals
        self._findings = findings

    def request(self, by: Principal, finding_id: str) -> Approval:
        finding = self._findings.get(by.actor_id, finding_id)
        if finding.status not in ACTIVE_STATUSES:
            raise RiskAcceptanceRefused(RiskRefusal.FINDING_CLOSED)
        digest, binding = risk_subject(finding)
        return self._approvals.request(
            subject_kind=RISK_SUBJECT_KIND,
            subject_hash=digest,
            binding=binding,
            requested_by=by.actor_id,
            requested_by_type=by.actor_type,
            required_roles=(Role.EXECUTIVE_RISK_OWNER,),
            target={},
        )

    def accept(self, by: Principal, finding_id: str, approval_id: str) -> Finding:
        finding = self._findings.get(by.actor_id, finding_id)
        if finding.status not in ACTIVE_STATUSES:
            raise RiskAcceptanceRefused(RiskRefusal.FINDING_CLOSED)
        digest, binding = risk_subject(finding)
        try:
            granted = self._approvals.get(approval_id)
        except Exception as exc:
            logger.info("risk acceptance: approval unreadable (%s)", type(exc).__name__)
            raise RiskAcceptanceRefused(RiskRefusal.APPROVAL_NOT_USABLE) from None
        if granted.decided_by == by.actor_id:
            raise RiskAcceptanceRefused(RiskRefusal.APPROVER_IS_CALLER)
        try:
            self._approvals.consume(
                approval_id,
                subject_kind=RISK_SUBJECT_KIND,
                subject_hash=digest,
                binding=binding,
                actor_id=by.actor_id,
                actor_type=by.actor_type,
            )
        except Exception as exc:
            logger.info("risk acceptance: approval not usable (%s)", type(exc).__name__)
            raise RiskAcceptanceRefused(RiskRefusal.APPROVAL_NOT_USABLE) from None
        return self._findings.accept_risk(by.actor_id, finding_id, approval_id)
