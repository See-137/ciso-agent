"""The gateway's dealings with the approvals module (blueprint 8.4 step 4; ADR-0016;
review findings H2, M3, L5). Anything the approvals module raises becomes an audited
refusal: an exception from it always means "do not send".
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from typing import Any

from ciso.approvals import Approval, ApprovalFault, ApprovalReason, ApprovalService
from ciso.common.enums import ActorType, Role
from ciso.inference.external.auditing import GateAudit
from ciso.inference.external.gates import Caller
from ciso.inference.external.preparing import Ready
from ciso.inference.external.records import (
    ACTION_AUTHORIZE,
    ACTION_TRANSMIT,
    APPROVAL_SUBJECT_KIND,
    GateReason,
    binding_fields,
)

_LOG = logging.getLogger(__name__)


class ApprovalDesk:
    def __init__(self, approvals: ApprovalService, audit: GateAudit) -> None:
        self._approvals = approvals
        self._audit = audit

    def file(self, ready: Ready, role: Role) -> Approval:
        """Open the approval request. The requester on record is the PROPOSER, who is
        also the caller (the gateway refuses anybody else), so the author of the payload
        can never be its approver."""
        binding = ready.binding
        return self._ask(
            ACTION_AUTHORIZE,
            ready,
            lambda: self._approvals.request(
                subject_kind=APPROVAL_SUBJECT_KIND,
                subject_hash=binding.subject_hash(),
                binding=binding_fields(binding),
                requested_by=ready.proposal.requester_actor_id,
                requested_by_type=ActorType.HUMAN,
                required_roles=(role,),
                target={},
                correlation_id=ready.correlation_id,
            ),
        )

    def spend(self, approval_id: str, ready: Ready) -> Approval:
        """Check the approval, refuse one the caller decided, then consume it. Returns
        only when the approval was won; it is spent from then on, whatever follows."""
        binding = ready.binding
        use: dict[str, Any] = {
            "subject_kind": APPROVAL_SUBJECT_KIND,
            "subject_hash": binding.subject_hash(),
            "binding": binding_fields(binding),
            "actor_id": ready.caller.actor_id,
            "actor_type": ActorType.HUMAN,
        }
        current = self._ask(
            ACTION_TRANSMIT, ready, lambda: self._approvals.check(approval_id, **use)
        )
        if current.decided_by == ready.caller.actor_id:
            self._audit.refuse(
                ACTION_TRANSMIT, ready.caller, ready.target, GateReason.TRANSMITTER_IS_APPROVER,
                ready.correlation_id,
            )  # fmt: skip
        return self._ask(
            ACTION_TRANSMIT, ready, lambda: self._approvals.consume(approval_id, **use)
        )

    def drop(self, approval: Approval, caller: Caller) -> bool:
        """Withdraw an approval request that has no authorization. True when it is void."""
        try:
            self._approvals.withdraw(
                approval.approval_id, actor_id=caller.actor_id, actor_type=ActorType.HUMAN
            )
            return True
        except ApprovalFault as fault:
            # Withdrawn but that could not be audited: the request is void all the same.
            if fault.reason is ApprovalReason.AUDIT_UNAVAILABLE:
                return True
            _LOG.error("external inference: orphan approval not withdrawn (%s)", fault.reason)
        except Exception as exc:
            _LOG.error("external inference: orphan approval not withdrawn (%s)", type(exc).__name__)
        return False

    def _ask(self, action: str, ready: Ready, call: Callable[[], Approval]) -> Approval:
        refused: tuple[GateReason, str | None, BaseException]
        try:
            return call()
        except ApprovalFault as fault:
            refused = (GateReason.APPROVAL_REFUSED, fault.reason.value, fault)
        except Exception as exc:
            refused = (GateReason.APPROVAL_UNAVAILABLE, None, exc)
        self._audit.refuse(
            action, ready.caller, ready.target, refused[0], ready.correlation_id,
            approval_reason=refused[1], cause=refused[2],
        )  # fmt: skip
