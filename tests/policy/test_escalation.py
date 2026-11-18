"""T1.13: built-in invariants hold against a ruleset that tries to allow everything.

Blueprint 9.2 last bullet, 19.3 policy/authorization (escalation, wrong role, wrong
scope, multi-role conflicts). Principals are built with `RoleGrant`s, the form identity
produces, and resolved through the `principals` fixture.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest
from tests.fakes.core import FakePrincipals
from tests.policy.conftest import (
    PROTECTED_OPS,
    EnvelopeBuilder,
    FakeContext,
    grant,
    human,
    scope_for,
)

from ciso.common.enums import AuthorityLevel, Environment, PolicyOutcome, Role
from ciso.common.principal import Principal
from ciso.policy import PolicyDecision, PolicyEngine, ReasonCode, load_ruleset

pytestmark = pytest.mark.policy

#: The most permissive ruleset the loader accepts: every actor type, every human role.
ALLOW_EVERYONE: list[dict[str, Any]] = [
    {"id": "allow-nonhuman", "effect": "allow", "match": {"actor_types": ["agent", "service"]}},
    {
        "id": "allow-any-human-role",
        "effect": "allow",
        "match": {"actor_types": ["human"], "required_roles": [r.value for r in Role]},
    },
]


def _ruleset_engine(
    make_engine: Callable[..., PolicyEngine], tmp_path: Path, rules: list[dict[str, Any]]
) -> PolicyEngine:
    doc = {
        "schema_version": 1,
        "version": "attack-1",
        "risk_classes": ["low", "high"],
        "rules": rules,
    }
    path = tmp_path / "rules.json"
    path.write_text(json.dumps(doc), encoding="utf-8")
    ruleset = load_ruleset(path)
    assert not ruleset.deny_all, ruleset.deny_reason
    return make_engine(ruleset)


@pytest.fixture
def permissive(make_engine: Callable[..., PolicyEngine], tmp_path: Path) -> PolicyEngine:
    return _ruleset_engine(make_engine, tmp_path, ALLOW_EVERYONE)


def _codes(decision: PolicyDecision) -> set[ReasonCode]:
    return {reason.code for reason in decision.reasons}


# --- protected operations and agent_requestable (H4) -------------------------------


@pytest.mark.parametrize("operation", PROTECTED_OPS)
@pytest.mark.parametrize("actor_fixture", ["agent", "service"])
def test_protected_operations_denied_for_non_humans_even_if_allowed(
    permissive: PolicyEngine,
    build: EnvelopeBuilder,
    context: FakeContext,
    request: pytest.FixtureRequest,
    operation: str,
    actor_fixture: str,
) -> None:
    actor: Principal = request.getfixturevalue(actor_fixture)
    decision = permissive.evaluate(build(operation, actor), context)
    assert decision.outcome is PolicyOutcome.DENY
    assert ReasonCode.PROTECTED_OPERATION in _codes(decision)


@pytest.mark.parametrize("actor_fixture", ["agent", "service"])
def test_non_human_may_only_request_agent_requestable_operations(
    permissive: PolicyEngine,
    build: EnvelopeBuilder,
    context: FakeContext,
    request: pytest.FixtureRequest,
    system_owner: Principal,
    actor_fixture: str,
) -> None:
    actor: Principal = request.getfixturevalue(actor_fixture)
    decision = permissive.evaluate(build("asset.annotate", actor), context)
    assert decision.outcome is PolicyOutcome.DENY
    assert _codes(decision) == {ReasonCode.NOT_AGENT_REQUESTABLE}
    assert permissive.evaluate(build("asset.annotate", system_owner), context).is_allowed
    assert permissive.evaluate(build("ticket.create_draft", actor), context).is_allowed


def test_protected_operation_twin_human_goes_to_rules(
    make_engine: Callable[..., PolicyEngine],
    tmp_path: Path,
    build: EnvelopeBuilder,
    context: FakeContext,
    admin: Principal,
) -> None:
    engine = _ruleset_engine(
        make_engine,
        tmp_path,
        [
            {
                "id": "admin-policy-change",
                "effect": "require_approval",
                "approver_roles": ["executive_risk_owner"],
                "match": {
                    "operations": ["policy.*"],
                    "actor_types": ["human"],
                    "required_roles": ["security_admin"],
                },
            }
        ],
    )
    decision = engine.evaluate(build("policy.update_rule", admin), context)
    assert decision.outcome is PolicyOutcome.REQUIRE_APPROVAL
    assert decision.required_approver_roles == (Role.EXECUTIVE_RISK_OWNER,)


def test_protected_operations_denied_by_default_ruleset_for_humans_too(
    engine_: PolicyEngine, build: EnvelopeBuilder, context: FakeContext, admin: Principal
) -> None:
    decision = engine_.evaluate(build("policy.update_rule", admin), context)
    assert decision.outcome is PolicyOutcome.DENY
    assert "deny-control-plane-changes" in decision.matched_rule_ids


def test_forged_human_type_does_not_unlock_protected_operations(
    make_engine: Callable[..., PolicyEngine],
    tmp_path: Path,
    build: EnvelopeBuilder,
    context: FakeContext,
) -> None:
    engine = _ruleset_engine(
        make_engine,
        tmp_path,
        [
            {
                "id": "admin-policy-change",
                "effect": "require_approval",
                "approver_roles": ["executive_risk_owner"],
                "match": {"actor_types": ["human"], "required_roles": ["security_admin"]},
            }
        ],
    )
    from ciso.common.enums import ActorType

    forged = build("policy.update_rule", actor_id="agent_ciso", actor_type=ActorType.HUMAN)
    decision = engine.evaluate(forged, context)
    assert decision.outcome is PolicyOutcome.DENY
    assert _codes(decision) == {ReasonCode.ACTOR_TYPE_MISMATCH}


# --- other invariants against a permissive ruleset ---------------------------------


def test_l4_is_never_plain_allow(
    permissive: PolicyEngine, build: EnvelopeBuilder, context: FakeContext, admin: Principal
) -> None:
    for actor in (None, admin):
        decision = permissive.evaluate(build("network.isolate_host", actor), context)
        assert decision.outcome is PolicyOutcome.DENY
        assert ReasonCode.L4_REQUIRES_APPROVAL in _codes(decision)


def test_l3_needs_playbook_even_if_allowed(
    permissive: PolicyEngine, build: EnvelopeBuilder, context: FakeContext
) -> None:
    decision = permissive.evaluate(build("credential.rotate_key"), context)
    assert decision.outcome is PolicyOutcome.DENY
    assert ReasonCode.PLAYBOOK_NOT_ACTIVE in _codes(decision)
    context.add_valid_playbook()
    assert permissive.evaluate(build("credential.rotate_key"), context).is_allowed


def test_unknown_operation_denied_even_if_allowed(
    permissive: PolicyEngine, build: EnvelopeBuilder, context: FakeContext
) -> None:
    decision = permissive.evaluate(build("anything.at_all"), context)
    assert _codes(decision) == {ReasonCode.UNKNOWN_OPERATION}


def test_understated_level_denied_even_if_allowed(
    permissive: PolicyEngine, build: EnvelopeBuilder, context: FakeContext
) -> None:
    envelope = build("network.isolate_host", authority_level=AuthorityLevel.L0_OBSERVE)
    decision = permissive.evaluate(envelope, context)
    assert decision.outcome is PolicyOutcome.DENY
    assert ReasonCode.AUTHORITY_UNDERSTATED in _codes(decision)


def test_deny_rule_beats_allow_rule(
    make_engine: Callable[..., PolicyEngine],
    tmp_path: Path,
    build: EnvelopeBuilder,
    context: FakeContext,
) -> None:
    engine = _ruleset_engine(
        make_engine,
        tmp_path,
        [
            *ALLOW_EVERYONE,
            {"id": "no-prod", "effect": "deny", "match": {"environments": ["production"]}},
        ],
    )
    prod = scope_for("app:billing", Environment.PRODUCTION)
    decision = engine.evaluate(build("asset.read", scope=prod), context)
    assert decision.outcome is PolicyOutcome.DENY
    assert ReasonCode.RULE_DENY in _codes(decision)
    assert set(decision.matched_rule_ids) == {"allow-nonhuman", "no-prod"}
    assert engine.evaluate(build("asset.read"), context).is_allowed


def test_hold_rule_and_risk_class_condition(
    make_engine: Callable[..., PolicyEngine],
    tmp_path: Path,
    build: EnvelopeBuilder,
    context: FakeContext,
) -> None:
    engine = _ruleset_engine(
        make_engine,
        tmp_path,
        [
            *ALLOW_EVERYONE,
            {"id": "hold-high", "effect": "hold", "match": {"risk_classes": ["high"]}},
        ],
    )
    assert engine.evaluate(build(risk_class="high"), context).outcome is PolicyOutcome.HOLD
    assert engine.evaluate(build(risk_class="low"), context).is_allowed


def test_channel_condition_matches_channel_name(
    make_engine: Callable[..., PolicyEngine],
    tmp_path: Path,
    build: EnvelopeBuilder,
    context: FakeContext,
) -> None:
    context.approved_channels.add("outbox:other")
    engine = _ruleset_engine(
        make_engine,
        tmp_path,
        [
            {
                "id": "sec-only",
                "effect": "allow",
                "match": {"channels": ["outbox:security"], "actor_types": ["agent"]},
            }
        ],
    )
    assert engine.evaluate(build("ticket.create_draft"), context).is_allowed
    other = build("ticket.create_draft", arguments={"channel": "outbox:other", "title": "t"})
    assert engine.evaluate(other, context).outcome is PolicyOutcome.DENY
    assert engine.evaluate(build("asset.read"), context).outcome is PolicyOutcome.DENY


# --- approver roles are an intersection (M5) ----------------------------------------


def _approval_rules(*approver_sets: list[str]) -> list[dict[str, Any]]:
    return [
        {
            "id": f"approve-{n}",
            "effect": "require_approval",
            "approver_roles": roles,
            "match": {"authority_levels": [4], "actor_types": ["agent"]},
        }
        for n, roles in enumerate(approver_sets)
    ]


def test_approver_roles_are_the_intersection(
    make_engine: Callable[..., PolicyEngine],
    tmp_path: Path,
    build: EnvelopeBuilder,
    context: FakeContext,
) -> None:
    engine = _ruleset_engine(
        make_engine,
        tmp_path,
        _approval_rules(["system_owner", "executive_risk_owner"], ["system_owner"]),
    )
    decision = engine.evaluate(build("network.isolate_host"), context)
    assert decision.outcome is PolicyOutcome.REQUIRE_APPROVAL
    assert decision.required_approver_roles == (Role.SYSTEM_OWNER,)


def test_empty_approver_intersection_is_deny(
    make_engine: Callable[..., PolicyEngine],
    tmp_path: Path,
    build: EnvelopeBuilder,
    context: FakeContext,
) -> None:
    engine = _ruleset_engine(
        make_engine, tmp_path, _approval_rules(["system_owner"], ["executive_risk_owner"])
    )
    decision = engine.evaluate(build("network.isolate_host"), context)
    assert decision.outcome is PolicyOutcome.DENY
    assert _codes(decision) == {ReasonCode.NO_COMMON_APPROVER}
    assert decision.required_approver_roles == ()


# --- wrong role --------------------------------------------------------------------


def test_wrong_role_is_denied_right_role_allowed(
    make_engine: Callable[..., PolicyEngine],
    tmp_path: Path,
    build: EnvelopeBuilder,
    context: FakeContext,
    employee: Principal,
    system_owner: Principal,
) -> None:
    engine = _ruleset_engine(
        make_engine,
        tmp_path,
        [
            {
                "id": "owners-coordinate",
                "effect": "allow",
                "match": {"required_roles": ["system_owner"], "actor_types": ["human"]},
            }
        ],
    )
    decision = engine.evaluate(build("ticket.create_draft", employee), context)
    assert decision.outcome is PolicyOutcome.DENY
    assert _codes(decision) == {ReasonCode.NO_MATCHING_RULE}
    assert engine.evaluate(build("ticket.create_draft", system_owner), context).is_allowed


def test_default_ruleset_denies_employee_coordinate(
    engine_: PolicyEngine,
    build: EnvelopeBuilder,
    context: FakeContext,
    employee: Principal,
    system_owner: Principal,
) -> None:
    denied = engine_.evaluate(build("ticket.create_draft", employee), context)
    assert denied.outcome is PolicyOutcome.DENY
    assert engine_.evaluate(build("ticket.create_draft", system_owner), context).is_allowed


# --- attribute scope through RoleGrant (C1) -----------------------------------------


def _eval(
    engine: PolicyEngine,
    build: EnvelopeBuilder,
    context: FakeContext,
    principals: FakePrincipals,
    actor: Principal,
    operation: str = "ticket.create_draft",
    resource: str = "app:billing",
    environment: Environment = Environment.STAGING,
    classification: str | None = "internal",
) -> PolicyDecision:
    principals.register(actor)
    scope = scope_for(resource, environment).model_copy(update={"classification": classification})
    return engine.evaluate(build(operation, actor, target_resource=resource, scope=scope), context)


def test_scoped_owner_on_another_system_is_denied(
    engine_: PolicyEngine, build: EnvelopeBuilder, context: FakeContext, principals: FakePrincipals
) -> None:
    owner = human("human_po", grant(Role.SYSTEM_OWNER, system="app:payroll"))
    outside = _eval(engine_, build, context, principals, owner, resource="app:billing")
    assert outside.outcome is PolicyOutcome.DENY
    assert ReasonCode.OUT_OF_SCOPE in _codes(outside)
    inside = _eval(engine_, build, context, principals, owner, resource="app:payroll")
    assert inside.is_allowed


@pytest.mark.parametrize(
    ("resource", "environment", "allowed"),
    [
        ("app:billing", Environment.PRODUCTION, True),
        ("app:payroll", Environment.STAGING, True),
        ("app:billing", Environment.STAGING, False),
        ("app:payroll", Environment.PRODUCTION, False),
    ],
)
def test_two_grants_do_not_mix_attributes(
    engine_: PolicyEngine,
    build: EnvelopeBuilder,
    context: FakeContext,
    principals: FakePrincipals,
    resource: str,
    environment: Environment,
    allowed: bool,
) -> None:
    owner = human(
        "human_two",
        grant(Role.SYSTEM_OWNER, system="app:billing", environment="production"),
        grant(Role.SYSTEM_OWNER, system="app:payroll", environment="staging"),
    )
    decision = _eval(
        engine_, build, context, principals, owner, resource=resource, environment=environment
    )
    assert decision.is_allowed is allowed
    if not allowed:
        assert ReasonCode.OUT_OF_SCOPE in _codes(decision)


def test_unscoped_admin_plus_scoped_owner_is_judged_per_rule(
    make_engine: Callable[..., PolicyEngine],
    tmp_path: Path,
    build: EnvelopeBuilder,
    context: FakeContext,
    principals: FakePrincipals,
) -> None:
    multi = human(
        "human_multi",
        grant(Role.SYSTEM_OWNER, system="app:payroll"),
        roles=(Role.SECURITY_ADMIN,),
    )
    owners_only = _ruleset_engine(
        make_engine,
        tmp_path,
        [
            {
                "id": "owners",
                "effect": "allow",
                "match": {"actor_types": ["human"], "required_roles": ["system_owner"]},
            }
        ],
    )
    assert _eval(owners_only, build, context, principals, multi).outcome is PolicyOutcome.DENY
    assert _eval(owners_only, build, context, principals, multi, resource="app:payroll").is_allowed
    admins_only = _ruleset_engine(
        make_engine,
        tmp_path,
        [
            {
                "id": "admins",
                "effect": "allow",
                "match": {"actor_types": ["human"], "required_roles": ["security_admin"]},
            }
        ],
    )
    assert _eval(admins_only, build, context, principals, multi).is_allowed


@pytest.mark.parametrize(
    ("classification", "allowed"), [("internal", True), ("restricted", False), (None, False)]
)
def test_classification_narrowing(
    engine_: PolicyEngine,
    build: EnvelopeBuilder,
    context: FakeContext,
    principals: FakePrincipals,
    classification: str | None,
    allowed: bool,
) -> None:
    owner = human("human_cls", grant(Role.SYSTEM_OWNER, classification="internal"))
    decision = _eval(engine_, build, context, principals, owner, classification=classification)
    assert decision.is_allowed is allowed


def test_grant_on_unknown_attribute_does_not_match(
    engine_: PolicyEngine, build: EnvelopeBuilder, context: FakeContext, principals: FakePrincipals
) -> None:
    owner = human("human_odd", grant(Role.SYSTEM_OWNER, time_window="office_hours"))
    assert _eval(engine_, build, context, principals, owner).outcome is PolicyOutcome.DENY
    plain = human("human_plain", grant(Role.SYSTEM_OWNER))
    assert _eval(engine_, build, context, principals, plain).is_allowed


def test_flat_scopes_field_cannot_widen_a_grant(
    engine_: PolicyEngine, build: EnvelopeBuilder, context: FakeContext, principals: FakePrincipals
) -> None:
    # The old flat `scopes` field is gone: a principal carrying it is refused outright, so
    # it can never widen a narrowed grant. The grant alone still decides (deny here).
    with pytest.raises(ValueError, match="scopes"):
        Principal(
            actor_id="human_flat",
            actor_type=human("x").actor_type,
            roles=frozenset({Role.SYSTEM_OWNER}),
            grants=(grant(Role.SYSTEM_OWNER, system="app:payroll"),),
            scopes={"system": frozenset({"app:billing"})},  # type: ignore[call-arg]
        )
    owner = Principal(
        actor_id="human_flat",
        actor_type=human("x").actor_type,
        roles=frozenset({Role.SYSTEM_OWNER}),
        grants=(grant(Role.SYSTEM_OWNER, system="app:payroll"),),
    )
    assert _eval(engine_, build, context, principals, owner).outcome is PolicyOutcome.DENY


def test_context_scope_answer_is_also_required(
    engine_: PolicyEngine, build: EnvelopeBuilder, context: FakeContext, admin: Principal
) -> None:
    context.in_scope = False
    decision = engine_.evaluate(build("asset.read", admin), context)
    assert ReasonCode.OUT_OF_SCOPE in _codes(decision)
    context.in_scope = True
    assert engine_.evaluate(build("asset.read", admin), context).is_allowed
