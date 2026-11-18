"""The policy decision record and its stable reason codes (blueprint 9.4 policy_decision).

The decision is a result, never an input: a requester cannot put one in its envelope.
"""

from __future__ import annotations

from enum import StrEnum

from ciso.common.enums import ActorType, AuthorityLevel, PolicyOutcome, Role
from ciso.common.schemas import Model, UtcDatetime


class ReasonCode(StrEnum):
    """Why a decision came out the way it did. Values are a wire format: do not rename."""

    RULESET_UNAVAILABLE = "ruleset_unavailable"
    UNKNOWN_OPERATION = "unknown_operation"
    INVALID_ARGUMENTS = "invalid_arguments"
    AUTHORITY_UNDERSTATED = "authority_understated"
    ENVELOPE_EXPIRED = "envelope_expired"
    ENVELOPE_TTL_EXCEEDED = "envelope_ttl_exceeded"
    ENVELOPE_TTL_UNSET = "envelope_ttl_unset"
    UNKNOWN_RISK_CLASS = "unknown_risk_class"
    EVIDENCE_REQUIRED = "evidence_required"
    PLAN_REQUIRED = "plan_required"
    PROTECTED_OPERATION = "protected_operation"
    ACTOR_INACTIVE = "actor_inactive"
    ACTOR_TYPE_MISMATCH = "actor_type_mismatch"
    IDENTITY_UNAVAILABLE = "identity_unavailable"
    NOT_AGENT_REQUESTABLE = "not_agent_requestable"
    OUT_OF_SCOPE = "out_of_scope"
    CHANNEL_UNAPPROVED = "channel_unapproved"
    PLAYBOOK_NOT_ACTIVE = "playbook_not_active"
    CONTEXT_UNAVAILABLE = "context_unavailable"
    STALE_FACTS = "stale_facts"
    NO_MATCHING_RULE = "no_matching_rule"
    RULE_ALLOW = "rule_allow"
    RULE_DENY = "rule_deny"
    RULE_HOLD = "rule_hold"
    RULE_REQUIRE_APPROVAL = "rule_require_approval"
    L4_REQUIRES_APPROVAL = "l4_requires_approval"
    NO_COMMON_APPROVER = "no_common_approver"
    INTERNAL_ERROR = "internal_error"
    AUDIT_UNAVAILABLE = "audit_unavailable"


class DecisionReason(Model):
    code: ReasonCode
    detail: str


class PolicyDecision(Model):
    """Outcome of one evaluation.

    `required_approver_roles` is non-empty only for require_approval. `requested_by` is the
    envelope's actor; the approvals module uses it to refuse self-approval (G33).
    `authority_level` is the effective level, or None when the operation is unknown.
    `evaluated_at` is None only when the clock itself failed (reason `internal_error`).
    """

    outcome: PolicyOutcome
    reasons: tuple[DecisionReason, ...]
    matched_rule_ids: tuple[str, ...] = ()
    required_approver_roles: tuple[Role, ...] = ()
    ruleset_version: str
    ruleset_hash: str
    evaluated_at: UtcDatetime | None
    envelope_hash: str
    request_id: str
    operation: str
    authority_level: AuthorityLevel | None
    requested_by: str
    requested_by_type: ActorType

    @property
    def is_allowed(self) -> bool:
        return self.outcome is PolicyOutcome.ALLOW

    @property
    def reason_codes(self) -> tuple[ReasonCode, ...]:
        return tuple(reason.code for reason in self.reasons)
