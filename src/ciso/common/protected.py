"""Operation names that change the control plane itself (blueprint 9.2, last bullet).

The one list. The policy catalog (`ciso.policy.catalog`) marks such an operation
protected, the tool registry refuses a tool for one, and a write adapter may never
declare one (`ciso.write_adapters.protected`). All three use these objects, so the
sides cannot drift apart. Standard library only.
"""

from __future__ import annotations

#: First name segments that change the control plane itself (blueprint 9.2 last bullet):
#: policy, rules, identity, roles and their assignments, approvals and approvers,
#: playbooks, connectors, models, audit records, the kill switch, permissions, prompts.
#: Any family starting with `audit` counts too (`audit_log`, ...).
PROTECTED_FAMILIES: frozenset[str] = frozenset(
    {
        "policy",
        "policies",
        "rule",
        "rules",
        "identity",
        "role",
        "roles",
        "role_assignment",
        "role_assignments",
        "approval",
        "approvals",
        "approver",
        "approvers",
        "playbook",
        "playbooks",
        "connector",
        "connectors",
        "model",
        "models",
        "audit",
        "killswitch",
        "permission",
        "permissions",
        "prompt",
        "prompts",
    }
)

#: Verbs that hide or suppress security signal (blueprint 9.2: the model cannot suppress
#: findings). An operation is protected when any `_`-separated word of a segment after
#: the family is one of these, for example `finding.suppress` or `alert.mute_all`.
SUPPRESSION_VERBS: frozenset[str] = frozenset(
    {"suppress", "dismiss", "mute", "silence", "waive", "ignore", "hide"}
)


def is_protected_name(name: str) -> bool:
    """True when `name` belongs to a protected family or uses a suppression verb."""
    family, *rest = name.split(".")
    if family in PROTECTED_FAMILIES or family.startswith("audit"):
        return True
    return any(word in SUPPRESSION_VERBS for segment in rest for word in segment.split("_"))
