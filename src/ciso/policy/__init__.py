"""Action envelope and deterministic policy engine (blueprint 5.1 #11, 9; ADR-0009).

This package never imports inference, orchestration, the API or execution: execution
imports policy, not the other way round.
"""

from ciso.policy.catalog import (
    PROTECTED_FAMILIES,
    SUPPRESSION_VERBS,
    OperationCatalog,
    OperationSpec,
    is_protected_name,
)
from ciso.policy.context import PlaybookStatus, PolicyContext
from ciso.policy.decision import DecisionReason, PolicyDecision, ReasonCode
from ciso.policy.engine import PolicyEngine
from ciso.policy.envelope import (
    ActionEnvelope,
    CheckedEnvelope,
    EnvelopeRejected,
    EnvelopeScope,
    EnvelopeValidator,
    Precondition,
    RollbackPlan,
    VerificationPlan,
)
from ciso.policy.loader import DEFAULT_RULESET_PATH, load_default_ruleset, load_ruleset
from ciso.policy.rules import MatchFacts, Rule, RuleEffect, RuleMatch, RuleSet, pattern_matches

__all__ = [
    "DEFAULT_RULESET_PATH",
    "PROTECTED_FAMILIES",
    "SUPPRESSION_VERBS",
    "ActionEnvelope",
    "CheckedEnvelope",
    "DecisionReason",
    "EnvelopeRejected",
    "EnvelopeScope",
    "EnvelopeValidator",
    "MatchFacts",
    "OperationCatalog",
    "OperationSpec",
    "PlaybookStatus",
    "PolicyContext",
    "PolicyDecision",
    "PolicyEngine",
    "Precondition",
    "ReasonCode",
    "RollbackPlan",
    "Rule",
    "RuleEffect",
    "RuleMatch",
    "RuleSet",
    "VerificationPlan",
    "is_protected_name",
    "load_default_ruleset",
    "load_ruleset",
    "pattern_matches",
]
