"""Pure rules: which decisions make findings, the dedupe fingerprint, who may do what.

Spec section 4 steps 6-7; lane brief S6. No database, no clock, no audit here.
"""

from __future__ import annotations

from dataclasses import dataclass

from ciso.common.activity import (
    GovernanceDecision,
    InspectionFinding,
    InspectionResult,
    ObservedAction,
    Phase,
    Severity,
    Verdict,
)
from ciso.common.enums import Role
from ciso.common.errors import ValidationFailed
from ciso.common.principal import Principal
from ciso.common.schemas import content_hash
from ciso.findings.models import (
    MAX_EVIDENCE_REFS,
    FindingOrigin,
    FindingStatus,
)

_ORDER = list(Severity)

#: Inspection findings at or above this level become findings even when the action is
#: allowed. Below it they become findings only through a deny or ask (lane brief S6.2).
INSPECTION_THRESHOLD = Severity.MEDIUM
#: Levels whose new finding raises an alert (lane brief S6.3).
ALERT_LEVELS: frozenset[Severity] = frozenset({Severity.HIGH, Severity.CRITICAL})
#: Severity of the finding a deny or an ask itself creates. A label, not a threshold.
DECISION_SEVERITY: dict[Verdict, Severity] = {
    Verdict.DENY: Severity.MEDIUM,
    Verdict.ASK: Severity.LOW,
}
DECISION_CATEGORY = "policy"

#: status -> statuses it may move to. Anything missing is refused.
TRANSITIONS: dict[FindingStatus, frozenset[FindingStatus]] = {
    FindingStatus.OPEN: frozenset(
        {FindingStatus.ACKNOWLEDGED, FindingStatus.RISK_ACCEPTED, FindingStatus.FALSE_POSITIVE}
    ),
    FindingStatus.ACKNOWLEDGED: frozenset(
        {FindingStatus.RESOLVED, FindingStatus.RISK_ACCEPTED, FindingStatus.FALSE_POSITIVE}
    ),
    FindingStatus.RESOLVED: frozenset(),
    FindingStatus.RISK_ACCEPTED: frozenset(),
    FindingStatus.FALSE_POSITIVE: frozenset(),
}


def at_least(severity: Severity, floor: Severity) -> bool:
    return _ORDER.index(severity) >= _ORDER.index(floor)


def worse(a: Severity, b: Severity) -> Severity:
    return a if _ORDER.index(a) >= _ORDER.index(b) else b


@dataclass(frozen=True)
class Draft:
    """A finding to fold into the store: everything but ids, counters and times."""

    origin: FindingOrigin
    check_key: str
    category: str
    severity: Severity
    title: str
    location: str
    recommendation_key: str


def check_consistent(
    decision: GovernanceDecision, action: ObservedAction, inspection: InspectionResult | None
) -> None:
    """The three records must describe the same action and session."""
    if decision.action_id != action.action_id:
        raise ValidationFailed("decision and action name different actions")
    if decision.session_id != action.session_id:
        raise ValidationFailed("decision and action name different sessions")
    if decision.attribution.session_id != decision.session_id:
        raise ValidationFailed("attribution names a different session")
    if inspection is not None and inspection.action_id != action.action_id:
        raise ValidationFailed("inspection result names a different action")


def _inspection_draft(item: InspectionFinding, path: str) -> Draft:
    return Draft(
        origin=FindingOrigin.INSPECTION,
        check_key=item.check_id,
        category=item.category,
        severity=item.severity,
        title=f"{item.category}: {item.check_id}",
        location=item.location or path,
        recommendation_key=item.check_id,
    )


def drafts_for(
    decision: GovernanceDecision, action: ObservedAction, inspection: InspectionResult | None
) -> list[Draft]:
    """Deny or ask: one decision finding. Inspection findings of medium or worse: one each.
    An allowed action with nothing at medium or worse: nothing."""
    path = action.target.get("path", "")
    drafts: list[Draft] = []
    if decision.verdict in DECISION_SEVERITY:
        code = decision.reasons[0].code
        drafts.append(
            Draft(
                origin=FindingOrigin.DECISION,
                check_key=f"decision.{decision.verdict.value}.{code}",
                category=DECISION_CATEGORY,
                severity=DECISION_SEVERITY[decision.verdict],
                title=f"{decision.verdict.value} by rule: {code}",
                location=path,
                recommendation_key=code,
            )
        )
    if inspection is not None:
        drafts.extend(
            _inspection_draft(item, path)
            for item in inspection.findings
            if at_least(item.severity, INSPECTION_THRESHOLD)
        )
    return drafts


def fingerprint(draft: Draft, decision: GovernanceDecision, action: ObservedAction) -> str:
    """Same check, same location, same person and agent, same repository.

    An unattributed person is keyed by session, so two unknown people are never merged.
    """
    who = decision.attribution
    return content_hash(
        {
            "check": draft.check_key,
            "location": draft.location,
            "person": who.person_ref or f"session:{decision.session_id}",
            "agent": who.agent_ref or "",
            "repository": action.target.get("repository", ""),
        }
    )


def evidence_refs(
    decision_id: str, decision: GovernanceDecision, action: ObservedAction
) -> tuple[str, ...]:
    """References only: the decision, the action, its evidence item, the decision's refs."""
    refs = [f"decision:{decision_id}", f"action:{action.action_id}"]
    if action.evidence_ref:
        refs.append(action.evidence_ref)
    refs.extend(decision.finding_refs)
    return tuple(dict.fromkeys(refs))[:MAX_EVIDENCE_REFS]


def alerts_on_deny(decision: GovernanceDecision, action: ObservedAction) -> bool:
    return decision.verdict is Verdict.DENY and action.phase is Phase.BEFORE


# --- who may do what ------------------------------------------------------------------


def is_admin(principal: Principal) -> bool:
    """An unnarrowed security_admin grant. A grant scoped to some system does not reach
    findings, which carry no system attribute."""
    return principal.is_human and principal.covers(Role.SECURITY_ADMIN, {})


def may_read_all(principal: Principal) -> bool:
    return is_admin(principal) or (principal.is_human and principal.covers(Role.AUDITOR, {}))


def may_transition(
    principal: Principal,
    actor_person: str | None,
    finding_person: str | None,
    target: FindingStatus,
) -> bool:
    """security_admin: any transition. The person the finding is about: acknowledge only."""
    if is_admin(principal):
        return True
    return (
        target is FindingStatus.ACKNOWLEDGED
        and principal.is_human
        and actor_person is not None
        and actor_person == finding_person
    )
