"""The approval behind a `require_approval` decision (blueprint 9.5; FR-025; plan gaps
G3, G12, G33; review finding M2).

What an approval for an action is bound to:

- subject kind `action_envelope`, subject hash = the hash of the broker's own copy of the
  envelope (every request field, so any change to the envelope invalidates the approval);
- binding = `approval_binding(envelope)`: operation, request id, idempotency key;
- target = `approval_target(envelope)`: the envelope's own scope attributes, so the
  approver's role grant was matched against the place the action lands;
- required roles inside the roles the policy decision names NOW;
- requested by the actor the decision names.

The last three are checked here, on top of `ApprovalService.check`, because the approval
service is generic and cannot know them. Without them an approval that somebody requested
for another actor, for a narrower target or for roles the policy does not accept could be
spent on this action.

Two steps, at two different moments:

- `check` runs at the approval gate. It changes nothing and reserves nothing. A refusal
  at any later gate (expiry, preconditions, rate limit, the attempt's audit record)
  leaves the approval usable.
- `consume` runs once the row is claimed and the attempt is audited, immediately before
  the broker's last look and the tool call. It spends the approval and re-validates it,
  including that the approver still holds the role (G12). If the last look then refuses
  (kill switch, expiry, actor), the approval is spent and the tool was not called: that
  window is one call wide and is accepted.
"""

from __future__ import annotations

from collections.abc import Mapping
from types import MappingProxyType
from typing import Any, NamedTuple

from ciso.approvals import Approval, ApprovalFault, ApprovalService, ApprovalUnavailable
from ciso.common.enums import ActorType, PolicyOutcome
from ciso.execution.records import (
    APPROVAL_SUBJECT_KIND,
    BROKER_ACTOR_ID,
    ExecutionRefused,
    RefusalReason,
    approval_binding,
    approval_target,
    refusal,
)
from ciso.policy.decision import PolicyDecision
from ciso.policy.envelope import ActionEnvelope


class ApprovalUse(NamedTuple):
    """An approval that passed `check` and is still to be spent."""

    approval_id: str
    ref: str
    use: Mapping[str, Any]


def require_matching_approval(
    record: Approval, envelope: ActionEnvelope, decision: PolicyDecision
) -> None:
    """Refuse an approval that was not requested for this decision's roles, requester
    and target."""
    named = set(decision.required_approver_roles)
    if not record.required_roles or not set(record.required_roles) <= named:
        raise refusal(
            RefusalReason.APPROVAL_ROLE_MISMATCH,
            "the approval accepts approver roles the policy decision does not name",
        )
    if (
        record.requested_by != decision.requested_by
        or record.requested_by_type is not decision.requested_by_type
    ):
        raise refusal(
            RefusalReason.APPROVAL_REQUESTER_MISMATCH,
            "the approval was requested for a different actor",
        )
    if dict(record.target) != approval_target(envelope):
        raise refusal(
            RefusalReason.APPROVAL_TARGET_MISMATCH,
            "the approval was requested for a different target",
        )


def _refused(exc: Exception) -> ExecutionRefused:
    if isinstance(exc, ExecutionRefused):
        return exc
    if isinstance(exc, ApprovalUnavailable):
        return refusal(RefusalReason.APPROVAL_UNAVAILABLE, str(exc), (exc.reason.value,))
    if isinstance(exc, ApprovalFault):
        return refusal(RefusalReason.APPROVAL_INVALID, str(exc), (exc.reason.value,))
    return refusal(
        RefusalReason.APPROVAL_UNAVAILABLE,
        f"approvals could not be consulted ({type(exc).__name__})",
    )


class ApprovalGate:
    def __init__(self, approvals: ApprovalService) -> None:
        self._approvals = approvals

    def check(
        self,
        envelope: ActionEnvelope,
        envelope_hash: str,
        decision: PolicyDecision,
        approval_id: str | None,
    ) -> ApprovalUse | None:
        """The approval to spend later, or None when policy plainly allows (an approval
        id supplied anyway is then left untouched). Spends nothing. Raises on anything
        else. `envelope` is the broker's private copy and `envelope_hash` its hash."""
        if decision.outcome is not PolicyOutcome.REQUIRE_APPROVAL:
            return None
        if not isinstance(approval_id, str) or not approval_id:
            raise refusal(RefusalReason.APPROVAL_REQUIRED, "this action needs an approval id")
        use: Mapping[str, Any] = MappingProxyType(
            {
                "subject_kind": APPROVAL_SUBJECT_KIND,
                "subject_hash": envelope_hash,
                "binding": MappingProxyType(approval_binding(envelope)),
                "actor_id": BROKER_ACTOR_ID,
                "actor_type": ActorType.SERVICE,
            }
        )
        try:
            record = self._approvals.check(approval_id, **use)
            require_matching_approval(record, envelope, decision)
        except Exception as exc:
            raise _refused(exc) from exc
        if not isinstance(record, Approval) or record.approval_id != approval_id:
            raise refusal(RefusalReason.APPROVAL_UNAVAILABLE, "approvals returned no record")
        return ApprovalUse(approval_id, record.ref, use)

    def consume(self, pending: ApprovalUse) -> None:
        """Spend the approval. Returns only when the service handed back the consumed
        record for this id; anything else is a refusal and the tool must not run."""
        try:
            consumed = self._approvals.consume(pending.approval_id, **pending.use)
        except Exception as exc:
            raise _refused(exc) from exc
        if not isinstance(consumed, Approval) or consumed.approval_id != pending.approval_id:
            raise refusal(RefusalReason.APPROVAL_UNAVAILABLE, "approvals returned no record")
