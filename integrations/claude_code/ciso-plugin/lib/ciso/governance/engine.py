"""The deterministic decision engine for observed agent actions (spec section 4, step 5).

`GovernanceEngine.decide` is a function of the action, its attribution, the inspection
result, the identity store's answer, the kill switch, the loaded ruleset and the clock.
Nothing here calls a model. Built-in invariants run before the rules and no rule can
override them:

1. The ruleset could not be loaded: deny everything.
2. The attribution belongs to another session: deny.
3. The kill switch blocks `writes`, or cannot be read: deny every action that is not a
   pure read or a prompt (`PURE_READ_KINDS`).
4. The attribution is `disputed`: deny every action that is not a pure read.
5. The inspection of this action found something `critical`: deny.
6. The action is an `agent_config_change` or a `security_tool_tamper`: deny.
7. The person's roles are resolved now through the `PrincipalResolver`; if it cannot
   answer: deny.

Then the rules (`ciso.governance.rules`). A matched rule that requires an inspection
which is missing or incomplete gives the ruleset's `missing_inspection` effect (deny
unless the file says ask). An `unparseable` command is never allowed: an allow becomes an
ask, and a deny that the command's other classes earn stays a deny (review M3).
Every decision is audited; if the audit write fails, a BEFORE-phase action is denied.
Any exception while deciding is a deny with reason `internal_error`.
"""

from __future__ import annotations

import logging
from collections.abc import Mapping
from datetime import UTC, datetime
from typing import Any, NamedTuple

from ciso.common.activity import (
    PERSON_REF_KIND,
    ActionKind,
    Attribution,
    DecisionReason,
    GovernanceDecision,
    InspectionResult,
    ObservedAction,
    Phase,
    Severity,
    Verdict,
)
from ciso.common.clock import Clock
from ciso.common.enums import (
    ActorType,
    AuditOutcome,
    InformationState,
    KillCapability,
    Role,
)
from ciso.common.ids import EntityRef, new_id
from ciso.common.principal import Principal
from ciso.common.protocols import AuditEvent, AuditSink, KillSwitchReader, PrincipalResolver
from ciso.governance.action_classes import action_analysis, shell_needs_inspection
from ciso.governance.classes import CommandClass
from ciso.governance.explanations import DETAILS, ReasonCode, explanation
from ciso.governance.globs import SEPARATORS
from ciso.governance.matching import ActionFacts, rule_matches
from ciso.governance.rules import (
    PURE_READ_KINDS,
    STRENGTH,
    Effect,
    GovernanceRuleSet,
    RuleSetDocument,
)

logger = logging.getLogger(__name__)

#: Timestamp used only if the clock itself fails (the decision is a deny anyway).
_EPOCH = datetime(1970, 1, 1, tzinfo=UTC)

_VERDICT = {Effect.ALLOW: Verdict.ALLOW, Effect.ASK: Verdict.ASK, Effect.DENY: Verdict.DENY}
_RULE_CODE = {
    Effect.ALLOW: ReasonCode.RULE_ALLOW,
    Effect.ASK: ReasonCode.RULE_ASK,
    Effect.DENY: ReasonCode.RULE_DENY,
}
_DEFAULT_CODE = {
    Effect.ALLOW: ReasonCode.DEFAULT_ALLOW,
    Effect.ASK: ReasonCode.DEFAULT_ASK,
    Effect.DENY: ReasonCode.DEFAULT_DENY,
}
_AUDIT_OUTCOME = {
    Verdict.ALLOW: AuditOutcome.SUCCESS,
    Verdict.ASK: AuditOutcome.ATTEMPT,
    Verdict.DENY: AuditOutcome.DENIED,
}


class _Outcome(NamedTuple):
    effect: Effect
    reasons: tuple[ReasonCode, ...]
    rule_ids: tuple[str, ...] = ()
    classes: frozenset[CommandClass] = frozenset()


class _IdentityDown(Exception):
    pass


def _deny(*codes: ReasonCode, classes: frozenset[CommandClass] = frozenset()) -> _Outcome:
    return _Outcome(Effect.DENY, codes, (), classes)


class GovernanceEngine:
    """Decides on observed actions. Dependencies are injected; nothing is global.

    `service_actor_id` is the actor id the audit records carry (this service).
    """

    def __init__(
        self,
        *,
        ruleset: GovernanceRuleSet,
        clock: Clock,
        audit: AuditSink,
        killswitch: KillSwitchReader,
        principals: PrincipalResolver,
        service_actor_id: str,
    ) -> None:
        if not service_actor_id:
            raise ValueError("service_actor_id is required")
        self._ruleset = ruleset
        self._clock = clock
        self._audit = audit
        self._killswitch = killswitch
        self._principals = principals
        self._actor = service_actor_id

    @property
    def ruleset(self) -> GovernanceRuleSet:
        return self._ruleset

    def decide(
        self,
        action: ObservedAction,
        attribution: Attribution,
        inspection: InspectionResult | None,
    ) -> GovernanceDecision:
        """Allow, deny or ask for `action`. Never raises for a problem in deciding."""
        try:
            now = self._clock.now()
        except Exception:
            logger.error("governance clock failed; denying")
            now = _EPOCH
            outcome = _deny(ReasonCode.INTERNAL_ERROR)
        else:
            try:
                outcome = self._decide(action, attribution, inspection)
            except Exception as exc:
                logger.error("governance decision failed internally: %s", type(exc).__name__)
                outcome = _deny(ReasonCode.INTERNAL_ERROR)
        decision = self._decision(action, attribution, outcome, now)
        return self._audited(action, decision, outcome)

    # --- deciding ------------------------------------------------------------

    def _decide(
        self, action: ObservedAction, attribution: Attribution, inspection: InspectionResult | None
    ) -> _Outcome:
        document = self._ruleset.document
        if self._ruleset.deny_all or document is None:
            return _deny(ReasonCode.RULESET_UNAVAILABLE)
        if attribution.session_id != action.session_id:
            return _deny(ReasonCode.ATTRIBUTION_MISMATCH)
        analysis = action_analysis(action, document.classifier_config())
        classes = analysis.classes
        own = (
            inspection
            if inspection is not None and inspection.action_id == action.action_id
            else None
        )
        blocked = self._invariants(action, attribution, own, classes)
        if blocked:
            return _deny(*blocked, classes=classes)
        try:
            known, roles = self._person(attribution, action.target)
        except _IdentityDown:
            return _deny(ReasonCode.IDENTITY_UNAVAILABLE, classes=classes)
        targets = _targets(action.target, analysis.branches, unknown_branch=analysis.unknown_branch)
        facts = ActionFacts(
            kind=action.kind,
            phase=action.phase,
            source=action.source,
            agent_class=attribution.agent_class,
            state=attribution.state,
            reasons=frozenset(attribution.reasons),
            person_known=known,
            roles=roles,
            classes=classes,
            targets=targets,
            inspection=own,
        )
        outcome = _apply_rules(document, facts, own)
        if outcome.effect is Effect.ALLOW and CommandClass.UNPARSEABLE in classes:
            outcome = _Outcome(
                Effect.ASK, (ReasonCode.UNPARSEABLE_COMMAND, *outcome.reasons), outcome.rule_ids
            )
        return outcome._replace(classes=classes)

    def _invariants(
        self,
        action: ObservedAction,
        attribution: Attribution,
        inspection: InspectionResult | None,
        classes: frozenset[CommandClass],
    ) -> list[ReasonCode]:
        pure_read = action.kind in PURE_READ_KINDS
        codes: list[ReasonCode] = []
        if not pure_read and self._writes_blocked():
            codes.append(ReasonCode.KILL_SWITCH_ENGAGED)
        if not pure_read and attribution.state is InformationState.DISPUTED:
            codes.append(ReasonCode.ATTRIBUTION_DISPUTED)
        if inspection is not None and inspection.worst is Severity.CRITICAL:
            codes.append(ReasonCode.CRITICAL_FINDING)
        if CommandClass.AGENT_CONFIG_CHANGE in classes:
            codes.append(ReasonCode.AGENT_CONFIG_CHANGE)
        if CommandClass.SECURITY_TOOL_TAMPER in classes:
            codes.append(ReasonCode.SECURITY_TOOL_TAMPER)
        return codes

    def _writes_blocked(self) -> bool:
        try:
            return self._killswitch.is_blocked(KillCapability.WRITES) is not False
        except Exception:
            logger.error("kill switch unreadable; treating writes as blocked")
            return True

    def _person(
        self, attribution: Attribution, target: Mapping[str, str]
    ) -> tuple[bool, frozenset[Role]]:
        """Whether the person resolves NOW to an active human, and the roles that reach
        this target. An unknown person has no roles."""
        if attribution.person_ref is None:
            return False, frozenset()
        try:
            ref = EntityRef.parse(attribution.person_ref)
        except ValueError:
            return False, frozenset()
        if ref.kind != PERSON_REF_KIND:
            return False, frozenset()
        try:
            principal = self._principals.resolve(ref.id)
        except Exception as exc:
            raise _IdentityDown from exc
        if (
            not isinstance(principal, Principal)
            or principal.actor_id != ref.id
            or principal.actor_type is not ActorType.HUMAN
        ):
            return False, frozenset()
        return True, principal.covering_roles(frozenset(Role), dict(target))

    # --- recording -----------------------------------------------------------

    def _decision(
        self, action: ObservedAction, attribution: Attribution, outcome: _Outcome, now: datetime
    ) -> GovernanceDecision:
        return GovernanceDecision(
            decision_id=new_id("dec"),
            action_id=action.action_id,
            session_id=action.session_id,
            verdict=_VERDICT[outcome.effect],
            reasons=tuple(DecisionReason(code=c.value, detail=DETAILS[c]) for c in outcome.reasons),
            matched_rule_ids=outcome.rule_ids[:32],
            ruleset_version=self._ruleset.version,
            ruleset_hash=self._ruleset.content_hash,
            decided_at=now,
            attribution=attribution,
            explanation=explanation(outcome.reasons[0]),
        )

    def _audited(
        self, action: ObservedAction, decision: GovernanceDecision, outcome: _Outcome
    ) -> GovernanceDecision:
        try:
            self._audit.append(self._event(action, decision, outcome))
        except Exception as exc:
            logger.error("governance.decide audit write failed: %s", type(exc).__name__)
            if action.phase is not Phase.BEFORE:
                return decision
            code = ReasonCode.AUDIT_UNAVAILABLE
            return decision.model_copy(
                update={
                    "verdict": Verdict.DENY,
                    "reasons": (
                        DecisionReason(code=code.value, detail=DETAILS[code]),
                        *decision.reasons,
                    )[:32],
                    "explanation": explanation(code),
                }
            )
        return decision

    def _event(
        self, action: ObservedAction, decision: GovernanceDecision, outcome: _Outcome
    ) -> AuditEvent:
        details: dict[str, Any] = {
            "decision_id": decision.decision_id,
            "action_id": action.action_id,
            "session_id": action.session_id,
            "kind": action.kind.value,
            "phase": action.phase.value,
            "source": action.source.value,
            "verdict": decision.verdict.value,
            "reason_codes": [r.code for r in decision.reasons],
            "matched_rule_ids": list(decision.matched_rule_ids),
            "ruleset_version": decision.ruleset_version,
            "ruleset_hash": decision.ruleset_hash,
            "command_classes": sorted(c.value for c in outcome.classes),
            "agent_class": decision.attribution.agent_class.value,
            "attribution_state": decision.attribution.state.value,
        }
        return AuditEvent(
            actor_id=self._actor,
            actor_type=ActorType.SERVICE,
            action="governance.decide",
            target=action.action_id,
            outcome=_AUDIT_OUTCOME[decision.verdict],
            correlation_id=action.session_id,
            details=details,
        )


def _targets(
    target: Mapping[str, str], branches: frozenset[str], *, unknown_branch: bool
) -> dict[str, frozenset[str]]:
    """Target facts for the rules. A push that names no destination makes the branch
    unknown (the reported current branch is not where it lands), and an unknown fact
    satisfies every restriction (review H5)."""
    out: dict[str, frozenset[str]] = {
        key: frozenset({value}) for key, value in target.items() if key in SEPARATORS and value
    }
    if branches:
        out["branch"] = out.get("branch", frozenset()) | branches
    if unknown_branch:
        out.pop("branch", None)
    return out


def _apply_rules(
    document: RuleSetDocument, facts: ActionFacts, inspection: InspectionResult | None
) -> _Outcome:
    usable = inspection is not None and inspection.complete
    effects: list[tuple[Effect, ReasonCode]] = []
    rule_ids: list[str] = []
    for rule in document.rules:
        if rule.requires_inspection and not usable:
            if rule_matches(rule, facts, ignore_inspection=True):
                rule_ids.append(rule.id)
                code = (
                    ReasonCode.INSPECTION_MISSING
                    if inspection is None
                    else ReasonCode.INSPECTION_INCOMPLETE
                )
                effects.append((Effect(document.missing_inspection), code))
            continue
        if rule_matches(rule, facts):
            rule_ids.append(rule.id)
            effects.append((rule.effect, _RULE_CODE[rule.effect]))
    if not effects:
        read_only = facts.kind in document.read_only_kinds
        effect = document.defaults.read_only if read_only else document.defaults.other
        return _Outcome(effect, (_DEFAULT_CODE[effect],))
    strongest = max((e for e, _ in effects), key=STRENGTH.__getitem__)
    codes = tuple(dict.fromkeys(code for e, code in effects if e is strongest))
    return _Outcome(strongest, codes, tuple(rule_ids))


def requires_inspection(action: ObservedAction) -> bool:
    """Whether the service should run the inspection lane before asking `decide`: file
    writes and edits that carry content, commits, pushes, and shell commands that commit
    or push."""
    if action.kind in (ActionKind.FILE_WRITE, ActionKind.FILE_EDIT):
        return action.content_sha256 is not None or action.content_bytes is not None
    if action.kind in (ActionKind.GIT_COMMIT, ActionKind.GIT_PUSH):
        return True
    if action.kind is ActionKind.SHELL_COMMAND:
        return shell_needs_inspection(action)
    return False
