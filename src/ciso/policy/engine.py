"""The deterministic policy engine (blueprint 5.1 #11, 9.2, 9.5; ADR-0009).

`PolicyEngine.evaluate` is a pure function of the envelope, the identity store's and the
context's answers, the loaded ruleset and the clock. It never calls a model. The actor is
resolved through the `PrincipalResolver` at every evaluation; nothing the requester wrote
about roles or scope is used. Built-in invariants run before the rules and no rule can
override them:

1. Unknown operation (or any other invalid envelope, including an expired one): deny.
2. Actor unknown, disabled, of a different type than claimed, or not resolvable: deny.
3. Agent or service actor: deny unless the catalog marks the operation
   `agent_requestable`; a protected (control-plane) operation is denied regardless.
4. Target not covered by the context's approved scope, or a channel not approved: deny.
5. An operation the catalog lists at L3: deny unless the context reports an approved,
   enabled, unexpired playbook for this operation and target scope (OD-15).
6. No rule matches: deny. L4 is never a plain allow; require_approval needs approver
   roles common to every deciding rule.

Stale supporting facts on a write turn allow or require_approval into hold. Every
evaluation attempts an audit record. If it cannot be written: a write is denied, a read
keeps its decision (logged), and if the evaluation had already failed internally,
`FailClosed` is raised. Any other exception inside the evaluation becomes a deny with
reason `internal_error`.
"""

from __future__ import annotations

import logging
from collections.abc import Callable, Mapping
from datetime import datetime, timedelta
from typing import Any

from ciso.common.clock import Clock
from ciso.common.enums import (
    AuthorityLevel,
    FreshnessState,
    PolicyOutcome,
    Role,
)
from ciso.common.errors import FailClosed
from ciso.common.principal import Principal
from ciso.common.protocols import AuditSink, PrincipalResolver
from ciso.common.schemas import Model
from ciso.policy.catalog import OperationCatalog
from ciso.policy.context import PlaybookStatus, PolicyContext
from ciso.policy.decision import DecisionReason, PolicyDecision, ReasonCode
from ciso.policy.envelope import (
    ActionEnvelope,
    CheckedEnvelope,
    EnvelopeRejected,
    EnvelopeValidator,
)
from ciso.policy.records import audit_event, internal_failure
from ciso.policy.rules import EFFECT_STRENGTH, MatchFacts, Rule, RuleEffect, RuleSet

logger = logging.getLogger(__name__)

_EFFECT_OUTCOME = {
    RuleEffect.ALLOW: (PolicyOutcome.ALLOW, ReasonCode.RULE_ALLOW),
    RuleEffect.DENY: (PolicyOutcome.DENY, ReasonCode.RULE_DENY),
    RuleEffect.HOLD: (PolicyOutcome.HOLD, ReasonCode.RULE_HOLD),
    RuleEffect.REQUIRE_APPROVAL: (
        PolicyOutcome.REQUIRE_APPROVAL,
        ReasonCode.RULE_REQUIRE_APPROVAL,
    ),
}


class _Verdict(Model):
    outcome: PolicyOutcome
    reasons: tuple[DecisionReason, ...]
    rule_ids: tuple[str, ...] = ()
    approver_roles: tuple[Role, ...] = ()
    level: AuthorityLevel | None = None
    writes: bool = True


class _ContextFailure(Exception):
    def __init__(self, method: str, cause: Exception) -> None:
        super().__init__(f"context.{method} could not be consulted: {type(cause).__name__}")


def _deny(code: ReasonCode, detail: str, **extra: Any) -> _Verdict:
    return _Verdict(
        outcome=PolicyOutcome.DENY, reasons=(DecisionReason(code=code, detail=detail),), **extra
    )


def _ask(method: str, call: Callable[[], Any]) -> Any:
    try:
        return call()
    except Exception as exc:
        raise _ContextFailure(method, exc) from exc


def _sorted_roles(roles: set[Role] | frozenset[Role]) -> tuple[Role, ...]:
    return tuple(sorted(roles, key=lambda role: role.value))


class PolicyEngine:
    """Evaluates action envelopes. Dependencies are injected; nothing is global.

    `principals` resolves the envelope's actor at every evaluation. `max_envelope_ttl`
    caps envelope expiry; `None` refuses every write (G14).
    """

    def __init__(
        self,
        *,
        catalog: OperationCatalog,
        ruleset: RuleSet,
        clock: Clock,
        audit: AuditSink,
        principals: PrincipalResolver,
        max_envelope_ttl: timedelta | None = None,
    ) -> None:
        self._catalog = catalog
        self._ruleset = ruleset
        self._clock = clock
        self._audit = audit
        self._principals = principals
        self._validator = EnvelopeValidator(
            catalog, clock, max_envelope_ttl, risk_classes=ruleset.risk_classes
        )

    @property
    def ruleset(self) -> RuleSet:
        return self._ruleset

    def evaluate(self, envelope: ActionEnvelope, context: PolicyContext) -> PolicyDecision:
        """Decide on `envelope`. Never raises except `FailClosed` (internal failure with the
        audit path also down) and non-`Exception` interrupts."""
        try:
            now = self._clock.now()
            verdict = self._decide(envelope, context, now)
            decision = self._record(envelope, verdict, now)
        except Exception as exc:
            logger.error("policy evaluation failed internally: %s", type(exc).__name__)
            failed = internal_failure(envelope, self._ruleset, exc)
            return self._audited(envelope, failed, writes=True, internal=True)
        return self._audited(envelope, decision, writes=verdict.writes, internal=False)

    # --- decision ---------------------------------------------------------------

    def _decide(self, envelope: ActionEnvelope, context: PolicyContext, now: datetime) -> _Verdict:
        spec = self._catalog.get(envelope.operation)
        writes = True if spec is None else spec.writes
        if self._ruleset.deny_all:
            return _deny(ReasonCode.RULESET_UNAVAILABLE, self._ruleset.deny_reason, writes=writes)
        try:
            checked = self._validator.validate(envelope)
        except EnvelopeRejected as exc:
            return _deny(exc.code, exc.detail, writes=writes)
        extra: dict[str, Any] = {"level": checked.authority_level, "writes": writes}
        resolved = self._resolve(envelope)
        if isinstance(resolved, _Verdict):
            return resolved.model_copy(update=extra)
        refused = _non_human_refusal(checked, resolved)
        if refused is not None:
            return refused.model_copy(update=extra)
        try:
            verdict = self._gates(checked, resolved, context, now) or self._rules(checked, resolved)
            if verdict.outcome in (PolicyOutcome.ALLOW, PolicyOutcome.REQUIRE_APPROVAL):
                verdict = _freshness(checked, context, verdict)
        except _ContextFailure as exc:
            return _deny(ReasonCode.CONTEXT_UNAVAILABLE, str(exc), **extra)
        return verdict.model_copy(update=extra)

    def _resolve(self, envelope: ActionEnvelope) -> Principal | _Verdict:
        """The actor as the identity store sees it now, or a deny."""
        try:
            principal = self._principals.resolve(envelope.actor_id)
        except Exception as exc:
            return _deny(
                ReasonCode.IDENTITY_UNAVAILABLE, f"identity store unavailable: {type(exc).__name__}"
            )
        if principal is None:
            return _deny(ReasonCode.ACTOR_INACTIVE, "actor is unknown or disabled")
        if not isinstance(principal, Principal) or principal.actor_id != envelope.actor_id:
            return _deny(ReasonCode.IDENTITY_UNAVAILABLE, "identity store returned another actor")
        if principal.actor_type is not envelope.actor_type:
            return _deny(
                ReasonCode.ACTOR_TYPE_MISMATCH,
                f"claimed {envelope.actor_type.value}, identity says {principal.actor_type.value}",
            )
        return principal

    def _gates(
        self,
        checked: CheckedEnvelope,
        principal: Principal,
        context: PolicyContext,
        now: datetime,
    ) -> _Verdict | None:
        """Context-backed invariants. Returns a deny, or None when all pass. Only an answer
        that `is True` counts as yes."""
        envelope = checked.envelope
        in_scope = _ask("is_within_scope", lambda: context.is_within_scope(principal, envelope))
        if in_scope is not True:
            return _deny(ReasonCode.OUT_OF_SCOPE, "no approved scope covers the target")
        channel = checked.channel
        if channel is not None:
            approved = _ask("is_channel_approved", lambda: context.is_channel_approved(channel))
            if approved is not True:
                return _deny(ReasonCode.CHANNEL_UNAPPROVED, f"channel {channel!r} is not approved")
        if checked.spec.authority_level is AuthorityLevel.L3_EXECUTE:
            status = _ask(
                "playbook_status",
                lambda: context.playbook_status(envelope.operation, envelope.scope),
            )
            if not _playbook_usable(status, now):
                return _deny(
                    ReasonCode.PLAYBOOK_NOT_ACTIVE,
                    "L3 needs an approved, enabled, unexpired playbook for this target",
                )
        return None

    def _rules(self, checked: CheckedEnvelope, principal: Principal) -> _Verdict:
        envelope = checked.envelope
        attributes = envelope.scope.attributes(envelope.target_resource)
        facts = MatchFacts(
            operation=checked.spec.name,
            authority_level=checked.authority_level,
            writes=checked.spec.writes,
            protected=checked.spec.protected,
            actor_type=principal.actor_type,
            covered_roles=principal.covering_roles(frozenset(Role), attributes),
            environment=envelope.scope.environment,
            risk_class=envelope.risk_class,
            channel=checked.channel,
        )
        matched = [rule for rule in self._ruleset.rules if rule.match.matches(facts)]
        if not matched:
            return self._no_match(facts, principal)
        effect = max((rule.effect for rule in matched), key=EFFECT_STRENGTH.__getitem__)
        rule_ids = tuple(rule.id for rule in matched)
        decisive = [rule for rule in matched if rule.effect is effect]
        if checked.authority_level is AuthorityLevel.L4_HIGH_IMPACT and effect is RuleEffect.ALLOW:
            return _deny(
                ReasonCode.L4_REQUIRES_APPROVAL,
                "L4 is never allowed without approval; no rule names approvers",
                rule_ids=rule_ids,
            )
        roles: tuple[Role, ...] = ()
        if effect is RuleEffect.REQUIRE_APPROVAL:
            roles = _common_approvers(decisive)
            if not roles:
                return _deny(
                    ReasonCode.NO_COMMON_APPROVER,
                    "the matching approval rules name no approver role in common",
                    rule_ids=rule_ids,
                )
        outcome, code = _EFFECT_OUTCOME[effect]
        return _Verdict(
            outcome=outcome,
            reasons=(
                DecisionReason(code=code, detail=f"decided by rules: {[r.id for r in decisive]}"),
            ),
            rule_ids=rule_ids,
            approver_roles=roles,
        )

    def _no_match(self, facts: MatchFacts, principal: Principal) -> _Verdict:
        """Explain a no-match: out of scope when a held role would have matched."""
        held = facts.model_copy(update={"covered_roles": principal.roles})
        if any(rule.match.matches(held) for rule in self._ruleset.rules):
            return _deny(
                ReasonCode.OUT_OF_SCOPE, "a role is held, but no grant of it reaches the target"
            )
        return _deny(ReasonCode.NO_MATCHING_RULE, "no rule allows this request")

    # --- record and audit -------------------------------------------------------

    def _record(self, envelope: ActionEnvelope, verdict: _Verdict, now: datetime) -> PolicyDecision:
        return PolicyDecision(
            outcome=verdict.outcome,
            reasons=verdict.reasons,
            matched_rule_ids=verdict.rule_ids,
            required_approver_roles=verdict.approver_roles,
            ruleset_version=self._ruleset.version,
            ruleset_hash=self._ruleset.content_hash,
            evaluated_at=now,
            envelope_hash=envelope.envelope_hash(),
            request_id=envelope.request_id,
            operation=envelope.operation,
            authority_level=verdict.level,
            requested_by=envelope.actor_id,
            requested_by_type=envelope.actor_type,
        )

    def _audited(
        self, envelope: ActionEnvelope, decision: PolicyDecision, *, writes: bool, internal: bool
    ) -> PolicyDecision:
        try:
            self._audit.append(audit_event(envelope, decision))
        except Exception as exc:
            logger.error("policy.evaluate audit write failed: %s", type(exc).__name__)
            if internal:
                raise FailClosed("policy evaluation failed and could not be audited") from exc
            if not writes:
                return decision
            return decision.model_copy(
                update={
                    "outcome": PolicyOutcome.DENY,
                    "required_approver_roles": (),
                    "reasons": (
                        *decision.reasons,
                        DecisionReason(
                            code=ReasonCode.AUDIT_UNAVAILABLE,
                            detail="the decision could not be audited; a write cannot proceed",
                        ),
                    ),
                }
            )
        return decision


def _non_human_refusal(checked: CheckedEnvelope, principal: Principal) -> _Verdict | None:
    """Agents and services may request only `agent_requestable` operations, and never a
    protected one (blueprint 9.2 last bullet)."""
    if principal.is_human:
        return None
    kind = principal.actor_type.value
    if checked.spec.protected:
        return _deny(
            ReasonCode.PROTECTED_OPERATION, f"{kind} actors may not request {checked.spec.name}"
        )
    if not checked.spec.agent_requestable:
        return _deny(
            ReasonCode.NOT_AGENT_REQUESTABLE,
            f"{checked.spec.name} is not registered as requestable by {kind} actors",
        )
    return None


def _playbook_usable(status: Any, now: datetime) -> bool:
    return (
        isinstance(status, PlaybookStatus)
        and status.approved is True
        and status.enabled is True
        and status.expires_at is not None
        and status.expires_at > now
    )


def _common_approvers(rules: list[Rule]) -> tuple[Role, ...]:
    common = set(rules[0].approver_roles)
    for rule in rules[1:]:
        common &= set(rule.approver_roles)
    return _sorted_roles(common)


def _freshness(checked: CheckedEnvelope, context: PolicyContext, verdict: _Verdict) -> _Verdict:
    """Hold a write whose supporting facts are not all exactly `current` (blueprint 9.5)."""
    if not checked.spec.writes:
        return verdict
    refs = checked.envelope.supporting_evidence

    def stale_refs() -> list[str]:
        answer = context.fact_freshness(refs)
        if not isinstance(answer, Mapping):
            raise TypeError("fact_freshness must return a mapping")
        return sorted(ref for ref in refs if answer.get(ref) is not FreshnessState.CURRENT)

    stale = _ask("fact_freshness", stale_refs)
    if not stale:
        return verdict
    return verdict.model_copy(
        update={
            "outcome": PolicyOutcome.HOLD,
            "approver_roles": (),
            "reasons": (
                *verdict.reasons,
                DecisionReason(code=ReasonCode.STALE_FACTS, detail=f"facts not current: {stale}"),
            ),
        }
    )
