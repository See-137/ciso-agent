"""Records the engine writes: the `policy.evaluate` audit event and the deny used when
evaluation itself failed. Both are built only from values that cannot raise."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from ciso.common.enums import ActorType, AuditOutcome, PolicyOutcome
from ciso.common.protocols import AuditEvent
from ciso.policy.decision import DecisionReason, PolicyDecision, ReasonCode
from ciso.policy.envelope import ActionEnvelope
from ciso.policy.rules import RuleSet


def safe_text(getter: Callable[[], Any]) -> str:
    try:
        value = getter()
    except Exception:
        return ""
    return value if isinstance(value, str) else ""


def internal_failure(envelope: ActionEnvelope, ruleset: RuleSet, exc: Exception) -> PolicyDecision:
    """A deny built only from values that cannot fail, for when evaluation itself failed."""
    claimed = getattr(envelope, "actor_type", None)
    return PolicyDecision(
        outcome=PolicyOutcome.DENY,
        reasons=(
            DecisionReason(
                code=ReasonCode.INTERNAL_ERROR,
                detail=f"evaluation failed: {type(exc).__name__}",
            ),
        ),
        ruleset_version=ruleset.version,
        ruleset_hash=ruleset.content_hash,
        evaluated_at=None,
        envelope_hash=safe_text(envelope.envelope_hash),
        request_id=safe_text(lambda: envelope.request_id),
        operation=safe_text(lambda: envelope.operation),
        authority_level=None,
        requested_by=safe_text(lambda: envelope.actor_id),
        requested_by_type=claimed if isinstance(claimed, ActorType) else ActorType.ANONYMOUS,
    )


def audit_event(envelope: ActionEnvelope, decision: PolicyDecision) -> AuditEvent:
    """The `policy.evaluate` record: references and codes only, never the arguments."""
    return AuditEvent(
        actor_id=decision.requested_by,
        actor_type=decision.requested_by_type,
        action="policy.evaluate",
        target=safe_text(lambda: envelope.target_resource),
        outcome=AuditOutcome.SUCCESS if decision.is_allowed else AuditOutcome.DENIED,
        correlation_id=decision.request_id,
        details={
            "decision": decision.outcome.value,
            "reason_codes": [code.value for code in decision.reason_codes],
            "rule_ids": list(decision.matched_rule_ids),
            "approver_roles": [role.value for role in decision.required_approver_roles],
            "envelope_hash": decision.envelope_hash,
            "operation": decision.operation,
            "authority_level": None
            if decision.authority_level is None
            else int(decision.authority_level),
            "ruleset_version": decision.ruleset_version,
            "ruleset_hash": decision.ruleset_hash,
        },
    )
