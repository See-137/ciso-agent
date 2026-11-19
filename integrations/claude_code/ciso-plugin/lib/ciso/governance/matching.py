"""Match one rule against the facts of one action, with unknown facts made explicit.

Each condition answers yes, no or unknown. A rule matches when no condition says no, and
(for an allow rule) every condition says yes. See `ciso.governance.rules` for why.
"""

from __future__ import annotations

from collections.abc import Mapping
from enum import IntEnum
from typing import NamedTuple

from ciso.common.activity import (
    ActionKind,
    ActivitySource,
    AgentClass,
    InspectionResult,
    Phase,
    Severity,
)
from ciso.common.enums import InformationState, Role
from ciso.governance.classes import CommandClass
from ciso.governance.globs import SEPARATORS, glob_match, normalize_path
from ciso.governance.rules import Effect, InspectionMatch, Rule, TargetMatch

_SEVERITY_ORDER = list(Severity)


class Tri(IntEnum):
    NO = 0
    UNKNOWN = 1
    YES = 2


def _tri(value: bool) -> Tri:
    return Tri.YES if value else Tri.NO


class ActionFacts(NamedTuple):
    kind: ActionKind
    phase: Phase
    source: ActivitySource
    agent_class: AgentClass
    state: InformationState
    reasons: frozenset[str]
    person_known: bool
    roles: frozenset[Role]
    classes: frozenset[CommandClass]
    #: Attribute -> every value known for it (target and command); missing = unknown.
    targets: Mapping[str, frozenset[str]]
    inspection: InspectionResult | None


def _targets(match: TargetMatch, facts: ActionFacts, *, permissive: bool) -> Tri:
    answer = Tri.YES
    for key, patterns in match.items():
        values = facts.targets.get(key)
        if not values:
            answer = min(answer, Tri.UNKNOWN)
            continue
        separator = SEPARATORS[key]
        normalized = [normalize_path(v) if key == "path" else v for v in values]

        def hit(value: str, sep: str = separator, pats: tuple[str, ...] = patterns) -> bool:
            return any(glob_match(p, value, sep, casefold=not permissive) for p in pats)

        # An allow needs every known value to fit; a restriction needs any one.
        ok = all(map(hit, normalized)) if permissive else any(map(hit, normalized))
        if not ok:
            return Tri.NO
    return answer


def _inspection(match: InspectionMatch, inspection: InspectionResult | None) -> Tri:
    if inspection is None:
        return Tri.UNKNOWN
    if match.complete is not None and inspection.complete is not match.complete:
        return Tri.NO
    if match.min_severity is None and match.categories is None:
        return Tri.YES
    floor = _SEVERITY_ORDER.index(match.min_severity) if match.min_severity else 0
    found = any(
        _SEVERITY_ORDER.index(f.severity) >= floor
        and (match.categories is None or f.category in match.categories)
        for f in inspection.findings
    )
    if found:
        return Tri.YES
    # An incomplete inspection may have missed it.
    return Tri.NO if inspection.complete else Tri.UNKNOWN


def _conditions(rule: Rule, facts: ActionFacts, *, ignore_inspection: bool) -> list[Tri]:
    m = rule.match
    permissive = rule.effect is Effect.ALLOW
    out: list[Tri] = []
    simple = (
        (m.kinds, facts.kind),
        (m.phases, facts.phase),
        (m.sources, facts.source),
        (m.agent_classes, facts.agent_class),
        (m.attribution_states, facts.state),
    )
    out.extend(_tri(value in allowed) for allowed, value in simple if allowed is not None)
    if m.attribution_reasons is not None:
        out.append(_tri(bool(facts.reasons & set(m.attribution_reasons))))
    if m.person_known is not None:
        out.append(_tri(facts.person_known is m.person_known))
    if m.person_roles is not None:
        out.append(_tri(bool(facts.roles & set(m.person_roles))))
    if m.command_classes is not None:
        out.append(_tri(bool(facts.classes & set(m.command_classes))))
    if m.targets is not None:
        out.append(_targets(m.targets, facts, permissive=permissive))
    if m.inspection is not None and not ignore_inspection:
        out.append(_inspection(m.inspection, facts.inspection))
    return out


def rule_matches(rule: Rule, facts: ActionFacts, *, ignore_inspection: bool = False) -> bool:
    """True when `rule` applies. `ignore_inspection` leaves out the inspection condition
    (used when the inspection a rule requires is missing: the engine decides that case)."""
    answers = _conditions(rule, facts, ignore_inspection=ignore_inspection)
    if Tri.NO in answers:
        return False
    if rule.effect is Effect.ALLOW:
        return all(a is Tri.YES for a in answers)
    return True
