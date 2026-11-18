"""Role templates and attribute scope (blueprint 9.3: define roles now, assign people later).

RBAC gives the stable authority (the five templates below). ABAC narrows a single role
assignment to systems, environments and classification labels, plus a time window that
`IdentityService` applies when it builds a `Principal`.

Each current assignment becomes one `RoleGrant` on `Principal.grants`, with its scope as a
mapping of attribute name to allowed values. Decide with `Principal.covers`.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from types import MappingProxyType

from ciso.common.enums import Environment, Role
from ciso.common.errors import ValidationFailed
from ciso.common.principal import Principal
from ciso.common.schemas import Model

#: Every permission any template grants, with what it allows. Dotted `<area>.<verb>`.
PERMISSIONS: Mapping[str, str] = MappingProxyType(
    {
        "identity.manage": "Create and disable actors, assign and revoke roles, issue tokens.",
        "connector.configure": "Register, configure and pause read connectors.",
        "policy.read": "Read policy rules, versions and policy decisions.",
        "policy.manage": "Propose and activate policy rule versions.",
        "killswitch.engage": "Engage the operator emergency stop.",
        "killswitch.release": "Release the operator emergency stop.",
        "killswitch.read": "Read whether the operator emergency stop is engaged.",
        "audit.read": "Read the audit history.",
        "registry.read": "Read assets, systems, owners and their facts.",
        "finding.read": "Read findings and their evidence references.",
        "finding.update": "Change finding status, owner or remediation notes.",
        "evidence.read": "Read stored evidence objects.",
        "approval.decide": "Approve or reject an action that needs a human decision.",
        "approval.read": "Read approval requests and what became of them.",
        "external_inference.request": (
            "Propose, preview, file for approval and transmit an external model request."
        ),
        "external_inference.read": "Read external model authorizations and transmission records.",
        "scope.approve": "Approve a discovery or test scope for systems one owns.",
        "risk.accept": "Accept business risk or grant a policy exception.",
        "report.submit": "Report an issue, ask for guidance, declare ownership or context.",
        "report.read_own": "Read one's own reports and the instructions sent to oneself.",
        "finding.acknowledge": (
            "Acknowledge a finding. The findings service allows it only for an administrator "
            "or the person the finding is about."
        ),
        "governance.read": "Read the AI-agent registry, coverage gaps and governed sessions.",
        "agents.manage": (
            "Register, approve, classify, un-suspend and retire AI agents; bind identity claims."
        ),
        "agents.suspend": (
            "Suspend an AI agent. The registry allows it only for an administrator or the "
            "agent's own owner or operator."
        ),
        "governance.report": (
            "Report AI-agent activity and ask for a decision. Held only by registered device "
            "actors (ciso.app.devices); no role template grants it."
        ),
    }
)


class RoleTemplate(Model):
    role: Role
    title: str
    description: str
    permissions: frozenset[str]


ROLE_TEMPLATES: tuple[RoleTemplate, ...] = (
    RoleTemplate(
        role=Role.SECURITY_ADMIN,
        title="Security Administrator",
        description=(
            "Manages platform configuration, connectors, policies, model configuration, "
            "allowed tools and role mapping. A role, not a named person."
        ),
        permissions=frozenset(
            {
                "identity.manage",
                "connector.configure",
                "policy.read",
                "policy.manage",
                "killswitch.engage",
                "killswitch.release",
                "killswitch.read",
                "audit.read",
                "registry.read",
                "finding.read",
                "finding.update",
                "finding.acknowledge",
                "approval.read",
                "external_inference.request",
                "external_inference.read",
                "governance.read",
                "agents.manage",
                "agents.suspend",
            }
        ),
    ),
    RoleTemplate(
        role=Role.SYSTEM_OWNER,
        title="System Owner",
        description="Owns a system or service and approves scoped changes that affect it.",
        permissions=frozenset(
            {
                "registry.read",
                "finding.read",
                "finding.update",
                "finding.acknowledge",
                "agents.suspend",
                "approval.decide",
                "approval.read",
                "scope.approve",
                "policy.read",
                "external_inference.request",
                "external_inference.read",
            }
        ),
    ),
    RoleTemplate(
        role=Role.EXECUTIVE_RISK_OWNER,
        title="Executive Risk Owner",
        description=(
            "Accepts or rejects significant business risk and policy exceptions. "
            "Risk acceptance is a human business decision."
        ),
        permissions=frozenset(
            {
                "risk.accept",
                "approval.decide",
                "approval.read",
                "finding.read",
                "finding.acknowledge",
                "agents.suspend",
                "registry.read",
                "policy.read",
            }
        ),
    ),
    RoleTemplate(
        role=Role.EMPLOYEE,
        title="Employee",
        description=(
            "Reports issues, requests guidance, declares ownership and context, and receives "
            "security instructions. No access to other employees' sensitive information."
        ),
        permissions=frozenset(
            {"report.submit", "report.read_own", "finding.acknowledge", "agents.suspend"}
        ),
    ),
    RoleTemplate(
        role=Role.AUDITOR,
        title="Auditor / Reviewer",
        description=(
            "Read-only access to evidence, policy decisions, incidents and audit history "
            "where authorised."
        ),
        permissions=frozenset(
            {
                "audit.read",
                "policy.read",
                "finding.read",
                "registry.read",
                "evidence.read",
                "killswitch.read",
                "approval.read",
                "external_inference.read",
                "governance.read",
            }
        ),
    ),
)

_BY_ROLE: Mapping[Role, RoleTemplate] = MappingProxyType({t.role: t for t in ROLE_TEMPLATES})


def template_for(role: Role) -> RoleTemplate:
    return _BY_ROLE[role]


def permissions_for(roles: Iterable[Role]) -> frozenset[str]:
    """Union of the permissions of every role given. No roles, no permissions."""
    granted: frozenset[str] = frozenset()
    for role in roles:
        granted = granted | _BY_ROLE[role].permissions
    return granted


#: Attribute names a scope can narrow. `scope_matches` refuses any other name.
SCOPE_ATTRIBUTES: tuple[str, ...] = ("system", "environment", "classification")


class RoleScope(Model):
    """Attribute scope of one assignment. An empty set means that attribute is not narrowed.

    `systems` are `EntityRef` strings; `classifications` are labels of the configured
    `ClassificationScheme` (checked by `IdentityService`); matching is set membership.
    """

    systems: frozenset[str] = frozenset()
    environments: frozenset[Environment] = frozenset()
    classifications: frozenset[str] = frozenset()

    def as_attributes(self) -> dict[str, frozenset[str]]:
        """Only the narrowed attributes, keyed by `SCOPE_ATTRIBUTES` names."""
        raw = {
            "system": self.systems,
            "environment": frozenset(e.value for e in self.environments),
            "classification": self.classifications,
        }
        return {name: values for name, values in raw.items() if values}

    @property
    def is_unrestricted(self) -> bool:
        return not self.as_attributes()


def scope_matches(principal: Principal, role: Role, **attributes: str) -> bool:
    """True when `principal` holds `role` through a grant that covers `attributes`.

    A thin wrapper over `Principal.covers` that also refuses attribute names outside
    `SCOPE_ATTRIBUTES` (`ValidationFailed`), so a typo cannot silently match nothing narrowed.
    """
    unknown = set(attributes) - set(SCOPE_ATTRIBUTES)
    if unknown:
        raise ValidationFailed(f"unknown scope attribute(s): {', '.join(sorted(unknown))}")
    return principal.covers(role, attributes)
