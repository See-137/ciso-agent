"""T1.13: the engine under the default ruleset (blueprint 9.2), with allowed twins."""

from __future__ import annotations

import json
from collections.abc import Callable
from datetime import timedelta
from pathlib import Path
from typing import Any

import pytest
from tests.fakes.core import FakeAudit, FakePrincipals, make_principal
from tests.policy.conftest import L3_OP, EnvelopeBuilder, FakeContext, scope_for

from ciso.common.clock import FixedClock
from ciso.common.enums import (
    ActorType,
    AuditOutcome,
    AuthorityLevel,
    FreshnessState,
    PolicyOutcome,
    Role,
)
from ciso.common.errors import FailClosed
from ciso.common.principal import Principal
from ciso.policy import (
    PlaybookStatus,
    PolicyDecision,
    PolicyEngine,
    ReasonCode,
    RuleSet,
    load_ruleset,
)

pytestmark = pytest.mark.policy

L4_APPROVERS = (Role.EXECUTIVE_RISK_OWNER, Role.SYSTEM_OWNER)


def _codes(decision: PolicyDecision) -> set[ReasonCode]:
    return {reason.code for reason in decision.reasons}


# --- L0 / L1 -----------------------------------------------------------------------


@pytest.mark.parametrize("operation", ["asset.read", "finding.investigate"])
def test_l0_l1_reads_in_scope_are_allowed(
    engine_: PolicyEngine, build: EnvelopeBuilder, context: FakeContext, operation: str
) -> None:
    decision = engine_.evaluate(build(operation), context)
    assert decision.outcome is PolicyOutcome.ALLOW
    assert decision.matched_rule_ids == ("allow-read-l0-l1-nonhuman",)


def test_l0_out_of_scope_is_denied(
    engine_: PolicyEngine, build: EnvelopeBuilder, context: FakeContext
) -> None:
    context.in_scope = False
    decision = engine_.evaluate(build("asset.read"), context)
    assert decision.outcome is PolicyOutcome.DENY
    assert ReasonCode.OUT_OF_SCOPE in _codes(decision)


# --- L2 ----------------------------------------------------------------------------


def test_l2_to_approved_channel_is_allowed(
    engine_: PolicyEngine, build: EnvelopeBuilder, context: FakeContext
) -> None:
    decision = engine_.evaluate(build("ticket.create_draft"), context)
    assert decision.outcome is PolicyOutcome.ALLOW
    assert "is_channel_approved" in context.calls


def test_l2_to_unapproved_channel_is_denied(
    engine_: PolicyEngine, build: EnvelopeBuilder, context: FakeContext
) -> None:
    envelope = build("ticket.create_draft", arguments={"channel": "email:external", "title": "h"})
    decision = engine_.evaluate(envelope, context)
    assert decision.outcome is PolicyOutcome.DENY
    assert ReasonCode.CHANNEL_UNAPPROVED in _codes(decision)


def test_l2_out_of_scope_is_denied(
    engine_: PolicyEngine, build: EnvelopeBuilder, context: FakeContext
) -> None:
    context.in_scope = False
    decision = engine_.evaluate(build("ticket.create_draft"), context)
    assert decision.outcome is PolicyOutcome.DENY
    assert ReasonCode.OUT_OF_SCOPE in _codes(decision)


# --- L1: context answers must be exactly True --------------------------------------


@pytest.mark.parametrize("answer", ["disabled", "yes", 1, [False], object(), None])
def test_truthy_scope_answer_is_no(
    engine_: PolicyEngine, build: EnvelopeBuilder, context: FakeContext, answer: Any
) -> None:
    context.in_scope = answer
    decision = engine_.evaluate(build("asset.read"), context)
    assert decision.outcome is PolicyOutcome.DENY
    assert ReasonCode.OUT_OF_SCOPE in _codes(decision)


@pytest.mark.parametrize("answer", ["approved", 1, [True]])
def test_truthy_channel_answer_is_no(
    engine_: PolicyEngine, build: EnvelopeBuilder, context: FakeContext, answer: Any
) -> None:
    context.channel_answer = answer
    decision = engine_.evaluate(build("ticket.create_draft"), context)
    assert decision.outcome is PolicyOutcome.DENY
    assert ReasonCode.CHANNEL_UNAPPROVED in _codes(decision)


def test_playbook_answer_of_wrong_type_is_no(
    engine_: PolicyEngine, build: EnvelopeBuilder, context: FakeContext
) -> None:
    context.playbooks[(L3_OP, "app:billing")] = {"approved": True, "enabled": True}
    decision = engine_.evaluate(build(L3_OP), context)
    assert decision.outcome is PolicyOutcome.DENY
    assert ReasonCode.PLAYBOOK_NOT_ACTIVE in _codes(decision)


def test_playbook_status_is_strictly_typed() -> None:
    with pytest.raises(ValueError, match="bool"):
        PlaybookStatus(playbook_ref="playbook:p", approved="yes", enabled=True)  # type: ignore[arg-type]


# --- L3 (OD-15: ship zero playbooks) ----------------------------------------------


def test_l3_without_playbook_is_denied(
    engine_: PolicyEngine, build: EnvelopeBuilder, context: FakeContext
) -> None:
    decision = engine_.evaluate(build(L3_OP), context)
    assert decision.outcome is PolicyOutcome.DENY
    assert ReasonCode.PLAYBOOK_NOT_ACTIVE in _codes(decision)


@pytest.mark.parametrize(
    ("approved", "enabled", "expires_in"),
    [
        (False, True, timedelta(days=1)),
        (True, False, timedelta(days=1)),
        (True, True, timedelta(seconds=0)),
        (True, True, -timedelta(days=1)),
        (True, True, None),
    ],
)
def test_l3_with_unusable_playbook_is_denied(
    engine_: PolicyEngine,
    build: EnvelopeBuilder,
    context: FakeContext,
    clock: FixedClock,
    approved: bool,
    enabled: bool,
    expires_in: timedelta | None,
) -> None:
    context.playbooks[(L3_OP, "app:billing")] = PlaybookStatus(
        playbook_ref="playbook:pb1",
        approved=approved,
        enabled=enabled,
        expires_at=None if expires_in is None else clock.now() + expires_in,
    )
    decision = engine_.evaluate(build(L3_OP), context)
    assert decision.outcome is PolicyOutcome.DENY
    assert ReasonCode.PLAYBOOK_NOT_ACTIVE in _codes(decision)


def test_l3_with_valid_playbook_is_allowed(
    engine_: PolicyEngine, build: EnvelopeBuilder, context: FakeContext
) -> None:
    context.add_valid_playbook()
    decision = engine_.evaluate(build(L3_OP), context)
    assert decision.outcome is PolicyOutcome.ALLOW
    assert decision.matched_rule_ids == ("allow-l3-playbook-nonhuman",)


def test_playbook_for_one_target_does_not_cover_another(
    engine_: PolicyEngine, build: EnvelopeBuilder, context: FakeContext
) -> None:
    context.add_valid_playbook(resource="app:payroll")
    decision = engine_.evaluate(build(L3_OP), context)
    assert ReasonCode.PLAYBOOK_NOT_ACTIVE in _codes(decision)
    other = build(L3_OP, target_resource="app:payroll", scope=scope_for("app:payroll"))
    assert engine_.evaluate(other, context).is_allowed


def test_l3_claimed_as_l4_still_needs_its_playbook(
    engine_: PolicyEngine, build: EnvelopeBuilder, context: FakeContext
) -> None:
    envelope = build(L3_OP, authority_level=AuthorityLevel.L4_HIGH_IMPACT)
    decision = engine_.evaluate(envelope, context)
    assert decision.outcome is PolicyOutcome.DENY
    assert ReasonCode.PLAYBOOK_NOT_ACTIVE in _codes(decision)
    assert "playbook_status" in context.calls
    context.add_valid_playbook()
    approved = engine_.evaluate(envelope, context)
    assert approved.outcome is PolicyOutcome.REQUIRE_APPROVAL
    assert approved.required_approver_roles == L4_APPROVERS


# --- L4 ----------------------------------------------------------------------------


def test_l4_requires_approval_naming_roles(
    engine_: PolicyEngine, build: EnvelopeBuilder, context: FakeContext
) -> None:
    decision = engine_.evaluate(build("network.isolate_host"), context)
    assert decision.outcome is PolicyOutcome.REQUIRE_APPROVAL
    assert decision.required_approver_roles == L4_APPROVERS
    assert decision.requested_by == "agent_ciso"
    assert "playbook_status" not in context.calls


# --- actor resolution (C2) ---------------------------------------------------------


def test_actor_is_resolved_at_every_evaluation(
    engine_: PolicyEngine,
    build: EnvelopeBuilder,
    context: FakeContext,
    principals: FakePrincipals,
) -> None:
    envelope = build("asset.read")
    assert engine_.evaluate(envelope, context).is_allowed
    assert principals.lookups == ["agent_ciso"]
    principals.remove("agent_ciso")
    decision = engine_.evaluate(envelope, context)
    assert decision.outcome is PolicyOutcome.DENY
    assert _codes(decision) == {ReasonCode.ACTOR_INACTIVE}


def test_unknown_actor_is_denied(
    engine_: PolicyEngine, build: EnvelopeBuilder, context: FakeContext
) -> None:
    decision = engine_.evaluate(build("asset.read", "nobody_known"), context)
    assert _codes(decision) == {ReasonCode.ACTOR_INACTIVE}


def test_resolver_that_raises_gives_deny(
    engine_: PolicyEngine,
    build: EnvelopeBuilder,
    context: FakeContext,
    principals: FakePrincipals,
) -> None:
    principals.broken = True
    decision = engine_.evaluate(build("asset.read"), context)
    assert decision.outcome is PolicyOutcome.DENY
    assert _codes(decision) == {ReasonCode.IDENTITY_UNAVAILABLE}


def test_claimed_type_must_match_resolved_type(
    engine_: PolicyEngine, build: EnvelopeBuilder, context: FakeContext
) -> None:
    forged = build("asset.read", actor_id="agent_ciso", actor_type=ActorType.HUMAN)
    decision = engine_.evaluate(forged, context)
    assert decision.outcome is PolicyOutcome.DENY
    assert _codes(decision) == {ReasonCode.ACTOR_TYPE_MISMATCH}


def test_revoked_role_takes_effect_immediately(
    engine_: PolicyEngine,
    build: EnvelopeBuilder,
    context: FakeContext,
    principals: FakePrincipals,
) -> None:
    envelope = build("network.isolate_host", "human_owner")
    assert engine_.evaluate(envelope, context).outcome is PolicyOutcome.REQUIRE_APPROVAL
    principals.register(make_principal("human_owner", ActorType.HUMAN, Role.EMPLOYEE))
    assert engine_.evaluate(envelope, context).outcome is PolicyOutcome.DENY


# --- general deny paths ------------------------------------------------------------


def test_unknown_operation_is_denied(
    engine_: PolicyEngine, build: EnvelopeBuilder, context: FakeContext
) -> None:
    decision = engine_.evaluate(build("shell.exec", arguments={"cmd": "id"}), context)
    assert decision.outcome is PolicyOutcome.DENY
    assert _codes(decision) == {ReasonCode.UNKNOWN_OPERATION}
    assert decision.authority_level is None


def test_expired_envelope_is_denied(
    engine_: PolicyEngine, build: EnvelopeBuilder, context: FakeContext, clock: FixedClock
) -> None:
    envelope = build("asset.read")
    assert engine_.evaluate(envelope, context).outcome is PolicyOutcome.ALLOW
    clock.advance(minutes=10)
    decision = engine_.evaluate(envelope, context)
    assert decision.outcome is PolicyOutcome.DENY
    assert ReasonCode.ENVELOPE_EXPIRED in _codes(decision)


def test_unset_ttl_denies_every_write(
    make_engine: Callable[..., PolicyEngine], build: EnvelopeBuilder, context: FakeContext
) -> None:
    engine = make_engine(max_envelope_ttl=None)
    decision = engine.evaluate(build("ticket.create_draft"), context)
    assert decision.outcome is PolicyOutcome.DENY
    assert ReasonCode.ENVELOPE_TTL_UNSET in _codes(decision)
    assert engine.evaluate(build("asset.read"), context).outcome is PolicyOutcome.ALLOW


@pytest.mark.parametrize(
    ("operation", "method"),
    [
        ("asset.read", "is_within_scope"),
        ("ticket.create_draft", "is_channel_approved"),
        ("ticket.create_draft", "fact_freshness"),
        (L3_OP, "playbook_status"),
    ],
)
def test_context_that_raises_gives_deny(
    engine_: PolicyEngine,
    build: EnvelopeBuilder,
    context: FakeContext,
    operation: str,
    method: str,
) -> None:
    context.add_valid_playbook()
    assert engine_.evaluate(build(operation), context).outcome is PolicyOutcome.ALLOW
    context.raise_on.add(method)
    decision = engine_.evaluate(build(operation), context)
    assert decision.outcome is PolicyOutcome.DENY
    assert ReasonCode.CONTEXT_UNAVAILABLE in _codes(decision)
    assert method in context.calls


@pytest.mark.parametrize(
    "state",
    [FreshnessState.STALE, FreshnessState.EXPIRED, FreshnessState.MISSING, FreshnessState.UNKNOWN],
)
def test_stale_fact_on_write_gives_hold(
    engine_: PolicyEngine, build: EnvelopeBuilder, context: FakeContext, state: FreshnessState
) -> None:
    context.freshness["finding:f1"] = state
    decision = engine_.evaluate(build("ticket.create_draft"), context)
    assert decision.outcome is PolicyOutcome.HOLD
    assert ReasonCode.STALE_FACTS in _codes(decision)


def test_stale_fact_on_read_does_not_hold(
    engine_: PolicyEngine, build: EnvelopeBuilder, context: FakeContext
) -> None:
    context.freshness["finding:f1"] = FreshnessState.STALE
    assert engine_.evaluate(build("asset.read"), context).outcome is PolicyOutcome.ALLOW
    assert "fact_freshness" not in context.calls


@pytest.mark.parametrize("answer", [{}, ["finding:f1"], "current", {"finding:f1": "current"}])
def test_bad_freshness_answer_never_allows(
    engine_: PolicyEngine, build: EnvelopeBuilder, context: FakeContext, answer: Any
) -> None:
    context.freshness_answer = answer
    decision = engine_.evaluate(build("ticket.create_draft"), context)
    assert decision.outcome in (PolicyOutcome.HOLD, PolicyOutcome.DENY)
    assert _codes(decision) & {ReasonCode.STALE_FACTS, ReasonCode.CONTEXT_UNAVAILABLE}


def test_stale_fact_does_not_soften_a_deny(
    engine_: PolicyEngine, build: EnvelopeBuilder, context: FakeContext
) -> None:
    context.freshness["finding:f1"] = FreshnessState.STALE
    envelope = build("ticket.create_draft", arguments={"channel": "email:x", "title": "t"})
    assert engine_.evaluate(envelope, context).outcome is PolicyOutcome.DENY


def test_no_matching_rule_is_denied(
    make_engine: Callable[..., PolicyEngine],
    build: EnvelopeBuilder,
    context: FakeContext,
    tmp_path: Path,
) -> None:
    doc = {
        "schema_version": 1,
        "version": "only-l1",
        "risk_classes": ["low"],
        "rules": [
            {
                "id": "l1",
                "effect": "allow",
                "match": {"operations": ["finding.*"], "actor_types": ["agent"]},
            }
        ],
    }
    path = tmp_path / "r.json"
    path.write_text(json.dumps(doc), encoding="utf-8")
    engine = make_engine(load_ruleset(path))
    decision = engine.evaluate(build("asset.read"), context)
    assert decision.outcome is PolicyOutcome.DENY
    assert _codes(decision) == {ReasonCode.NO_MATCHING_RULE}
    assert decision.matched_rule_ids == ()
    assert engine.evaluate(build("finding.investigate"), context).outcome is PolicyOutcome.ALLOW


def test_deny_all_ruleset_denies_reads_and_writes(
    make_engine: Callable[..., PolicyEngine], build: EnvelopeBuilder, context: FakeContext
) -> None:
    engine = make_engine(RuleSet.deny_everything("file missing"))
    for op in ("asset.read", "ticket.create_draft", "network.isolate_host"):
        decision = engine.evaluate(build(op), context)
        assert decision.outcome is PolicyOutcome.DENY
        assert ReasonCode.RULESET_UNAVAILABLE in _codes(decision)


# --- L2: nothing escapes evaluate() -------------------------------------------------


class _BrokenClock:
    def now(self) -> Any:
        raise OSError("clock source gone")


def test_clock_failure_is_a_deny_with_audit(
    make_engine: Callable[..., PolicyEngine],
    build: EnvelopeBuilder,
    context: FakeContext,
    audit: FakeAudit,
) -> None:
    engine = make_engine(clock_=_BrokenClock())
    decision = engine.evaluate(build("asset.read"), context)
    assert decision.outcome is PolicyOutcome.DENY
    assert _codes(decision) == {ReasonCode.INTERNAL_ERROR}
    assert decision.evaluated_at is None
    assert len(audit.find("policy.evaluate")) == 1


def test_interrupts_are_not_swallowed(
    engine_: PolicyEngine, build: EnvelopeBuilder, context: FakeContext, audit: FakeAudit
) -> None:
    class Weird(FakeContext):
        def is_within_scope(self, principal: Principal, envelope: Any) -> Any:
            raise KeyboardInterrupt  # not an Exception: must still not be swallowed

    with pytest.raises(KeyboardInterrupt):
        engine_.evaluate(build("asset.read"), Weird(context.clock))


def test_internal_failure_with_audit_down_raises_fail_closed(
    make_engine: Callable[..., PolicyEngine],
    build: EnvelopeBuilder,
    context: FakeContext,
    audit: FakeAudit,
) -> None:
    engine = make_engine(clock_=_BrokenClock())
    audit.fail = True
    with pytest.raises(FailClosed):
        engine.evaluate(build("asset.read"), context)


def test_constructed_envelope_with_bad_text_is_a_deny(
    engine_: PolicyEngine, build: EnvelopeBuilder, context: FakeContext, audit: FakeAudit
) -> None:
    from ciso.policy import ActionEnvelope

    good = build("asset.read")
    bad = ActionEnvelope.model_construct(**{**dict(good), "purpose": "x\ud800"})
    decision = engine_.evaluate(bad, context)
    assert decision.outcome is PolicyOutcome.DENY
    assert audit.find("policy.evaluate")


# --- decision record and audit -----------------------------------------------------


def test_decision_carries_provenance(
    engine_: PolicyEngine,
    build: EnvelopeBuilder,
    context: FakeContext,
    clock: FixedClock,
    default_ruleset: RuleSet,
) -> None:
    envelope = build("ticket.create_draft")
    decision = engine_.evaluate(envelope, context)
    assert decision.matched_rule_ids == ("allow-l2-nonhuman",)
    assert decision.ruleset_version == default_ruleset.version
    assert decision.ruleset_hash == default_ruleset.content_hash
    assert decision.evaluated_at == clock.now()
    assert decision.envelope_hash == envelope.envelope_hash()
    assert decision.request_id == envelope.request_id
    assert decision.operation == "ticket.create_draft"
    assert decision.reasons
    assert all(r.detail for r in decision.reasons)


def test_every_evaluation_is_audited(
    engine_: PolicyEngine, build: EnvelopeBuilder, context: FakeContext, audit: FakeAudit
) -> None:
    allowed = build("ticket.create_draft")
    denied = build("shell.exec")
    engine_.evaluate(allowed, context)
    engine_.evaluate(denied, context)
    events = audit.find("policy.evaluate")
    assert len(events) == 2
    first, second = events
    assert first.outcome is AuditOutcome.SUCCESS
    assert first.details["decision"] == "allow"
    assert first.details["envelope_hash"] == allowed.envelope_hash()
    assert first.details["rule_ids"] == ["allow-l2-nonhuman"]
    assert first.correlation_id == allowed.request_id
    assert "arguments" not in first.details
    assert "Rotate key" not in json.dumps(first.details)
    assert second.outcome is AuditOutcome.DENIED
    assert second.details["reason_codes"] == ["unknown_operation"]


def test_audit_failure_on_write_gives_deny(
    engine_: PolicyEngine, build: EnvelopeBuilder, context: FakeContext, audit: FakeAudit
) -> None:
    assert engine_.evaluate(build("ticket.create_draft"), context).is_allowed
    audit.fail = True
    decision = engine_.evaluate(build("ticket.create_draft"), context)
    assert decision.outcome is PolicyOutcome.DENY
    assert ReasonCode.AUDIT_UNAVAILABLE in _codes(decision)


def test_audit_failure_on_read_keeps_the_decision(
    engine_: PolicyEngine, build: EnvelopeBuilder, context: FakeContext, audit: FakeAudit
) -> None:
    audit.fail = True
    assert engine_.evaluate(build("asset.read"), context).outcome is PolicyOutcome.ALLOW


def test_evaluation_is_deterministic(
    engine_: PolicyEngine, build: EnvelopeBuilder, context: FakeContext
) -> None:
    envelope = build("network.isolate_host")
    assert engine_.evaluate(envelope, context) == engine_.evaluate(envelope, context)


# --- requester gating under the default ruleset -------------------------------------

ACTORS = [
    ("employee", False),
    ("auditor", False),
    ("risk_owner", False),
    ("admin", True),
    ("system_owner", True),
    ("agent", True),
    ("service", True),
]


@pytest.mark.parametrize(("actor_fixture", "permitted"), ACTORS)
def test_l3_with_valid_playbook_gates_the_requester(
    engine_: PolicyEngine,
    build: EnvelopeBuilder,
    context: FakeContext,
    request: pytest.FixtureRequest,
    actor_fixture: str,
    permitted: bool,
) -> None:
    context.add_valid_playbook()
    actor: Principal = request.getfixturevalue(actor_fixture)
    decision = engine_.evaluate(build(L3_OP, actor), context)
    if permitted:
        assert decision.outcome is PolicyOutcome.ALLOW
    else:
        assert decision.outcome is PolicyOutcome.DENY
        assert _codes(decision) == {ReasonCode.NO_MATCHING_RULE}


@pytest.mark.parametrize(("actor_fixture", "permitted"), ACTORS)
def test_l4_request_gates_the_requester(
    engine_: PolicyEngine,
    build: EnvelopeBuilder,
    context: FakeContext,
    request: pytest.FixtureRequest,
    actor_fixture: str,
    permitted: bool,
) -> None:
    actor: Principal = request.getfixturevalue(actor_fixture)
    decision = engine_.evaluate(build("network.isolate_host", actor), context)
    if permitted:
        assert decision.outcome is PolicyOutcome.REQUIRE_APPROVAL
        assert decision.required_approver_roles == L4_APPROVERS
    else:
        assert decision.outcome is PolicyOutcome.DENY
        assert _codes(decision) == {ReasonCode.NO_MATCHING_RULE}
        assert decision.required_approver_roles == ()


def test_human_reader_with_role_allowed_employee_denied(
    engine_: PolicyEngine,
    build: EnvelopeBuilder,
    context: FakeContext,
    auditor: Principal,
    employee: Principal,
) -> None:
    assert engine_.evaluate(build("asset.read", auditor), context).is_allowed
    decision = engine_.evaluate(build("asset.read", employee), context)
    assert decision.outcome is PolicyOutcome.DENY
    assert ReasonCode.NO_MATCHING_RULE in _codes(decision)


def test_overstated_read_by_employee_is_denied(
    engine_: PolicyEngine, build: EnvelopeBuilder, context: FakeContext, employee: Principal
) -> None:
    envelope = build("asset.read", employee, authority_level=AuthorityLevel.L4_HIGH_IMPACT)
    assert engine_.evaluate(envelope, context).outcome is PolicyOutcome.DENY
