"""Requesting and deciding approvals. Blueprint 9.5, 19.3; FR-025; G14, G33; ADR-0016/0021."""

from __future__ import annotations

from datetime import timedelta
from typing import Any

import pytest
from sqlalchemy import Engine
from tests.approvals.conftest import (
    BINDING,
    HASH,
    KIND,
    TARGET,
    TTL,
    MakeService,
    ScriptedAudit,
    ask,
    reason_of,
    row_count,
    signed_in,
    tamper,
    use_args,
)
from tests.fakes.core import FakePrincipals, make_principal

from ciso.approvals import (
    APPROVE_ACTION,
    REJECT_ACTION,
    REQUEST_ACTION,
    ApprovalConflict,
    ApprovalForbidden,
    ApprovalInputInvalid,
    ApprovalInvalid,
    ApprovalReason,
    ApprovalService,
    ApprovalStatus,
    ApprovalUnavailable,
)
from ciso.common.clock import FixedClock
from ciso.common.enums import ActorType, AuditOutcome, Role
from ciso.common.errors import (
    ApprovalRequired,
    AuthorizationError,
    Conflict,
    FailClosed,
    ValidationFailed,
)
from ciso.common.principal import Principal, RoleGrant

pytestmark = pytest.mark.policy

R = ApprovalReason


# --- request -----------------------------------------------------------------------------


def test_request_records_everything_and_is_audited(
    svc: ApprovalService, audit: ScriptedAudit, clock: FixedClock
) -> None:
    made = ask(svc, correlation_id="corr-1")
    stored = svc.get(made.approval_id)
    assert stored == made
    assert stored.status is ApprovalStatus.PENDING
    assert (stored.subject_kind, stored.subject_hash) == (KIND, HASH)
    assert dict(stored.binding) == BINDING
    assert dict(stored.target) == TARGET
    assert (stored.requested_by, stored.requested_by_type) == ("agent_ciso", ActorType.AGENT)
    assert stored.required_roles == (Role.EXECUTIVE_RISK_OWNER, Role.SYSTEM_OWNER)
    assert stored.expires_at == clock.now() + TTL
    assert audit.outcomes(REQUEST_ACTION) == [AuditOutcome.ATTEMPT, AuditOutcome.SUCCESS]
    event = audit.find(REQUEST_ACTION)[-1]
    assert event.target == f"approval:{made.approval_id}"
    assert event.correlation_id == "corr-1"
    assert event.details["subject_hash"] == HASH
    assert event.details["binding"] == BINDING


def test_unset_ttl_refuses_requests(engine: Engine, make_service: MakeService) -> None:
    closed = make_service(engine, approval_ttl=None)
    with pytest.raises(ApprovalUnavailable) as excinfo:
        ask(closed)
    assert reason_of(excinfo) is R.TTL_UNSET
    assert isinstance(excinfo.value, FailClosed)
    assert row_count(engine) == 0


def test_default_constructor_has_no_ttl_and_no_self_approval(
    engine: Engine, audit: ScriptedAudit, clock: FixedClock, principals: FakePrincipals
) -> None:
    bare = ApprovalService(engine=engine, audit=audit, clock=clock, principals=principals)
    with pytest.raises(ApprovalUnavailable) as excinfo:
        ask(bare)
    assert reason_of(excinfo) is R.TTL_UNSET


@pytest.mark.parametrize("ttl", [timedelta(0), timedelta(seconds=-1), 3600])
def test_bad_ttl_is_refused_at_construction(
    engine: Engine, make_service: MakeService, ttl: Any
) -> None:
    with pytest.raises(ApprovalInputInvalid) as excinfo:
        make_service(engine, approval_ttl=ttl)
    assert reason_of(excinfo) is R.INVALID_SETTING


@pytest.mark.parametrize(
    ("override", "reason"),
    [
        ({"required_roles": []}, R.INVALID_ROLES),
        ({"required_roles": [Role.SECURITY_ADMIN]}, R.INVALID_ROLES),
        ({"required_roles": [Role.SYSTEM_OWNER, Role.AUDITOR]}, R.INVALID_ROLES),
        ({"required_roles": ["no_such_role"]}, R.INVALID_ROLES),
        ({"required_roles": "system_owner"}, R.INVALID_ROLES),
        ({"subject_hash": "abc"}, R.INVALID_SUBJECT),
        ({"subject_hash": HASH.upper()}, R.INVALID_SUBJECT),
        ({"subject_kind": "Bad Kind"}, R.INVALID_SUBJECT),
        ({"binding": {"model": 3}}, R.INVALID_BINDING),
        ({"binding": ["model"]}, R.INVALID_BINDING),
        ({"target": {"system": 7}}, R.INVALID_TARGET),
        ({"requested_by": ""}, R.INVALID_REQUESTER),
        ({"requested_by_type": ActorType.ANONYMOUS}, R.INVALID_REQUESTER),
    ],
)
def test_bad_request_input_is_refused_and_nothing_stored(
    svc: ApprovalService,
    engine: Engine,
    audit: ScriptedAudit,
    override: dict[str, Any],
    reason: ApprovalReason,
) -> None:
    with pytest.raises(ApprovalInputInvalid) as excinfo:
        ask(svc, **override)
    assert reason_of(excinfo) is reason
    assert isinstance(excinfo.value, ValidationFailed)
    assert row_count(engine) == 0
    assert audit.events == []


def test_unknown_target_attribute_is_dropped_not_stored_as_none(svc: ApprovalService) -> None:
    made = ask(svc, target={"system": "app:billing", "environment": None})
    assert dict(made.target) == {"system": "app:billing"}


def test_record_cannot_be_changed_in_place(svc: ApprovalService) -> None:
    made = ask(svc)
    with pytest.raises(TypeError):
        made.binding["model"] = "other"  # type: ignore[index]
    with pytest.raises(TypeError):
        made.target["system"] = "app:other"  # type: ignore[index]
    with pytest.raises(ValueError, match="frozen"):
        made.status = ApprovalStatus.APPROVED  # type: ignore[misc]


# --- approve: who ------------------------------------------------------------------------


def test_role_holder_approves(
    svc: ApprovalService, owner: Principal, audit: ScriptedAudit, clock: FixedClock
) -> None:
    made = ask(svc)
    clock.advance(minutes=5)
    done = svc.approve(made.approval_id, owner, note="looks right")
    assert done.status is ApprovalStatus.APPROVED
    assert done.decided_by == "human_owner"
    assert done.decided_at == clock.now()
    assert done.decided_roles == (Role.SYSTEM_OWNER,)
    assert done.decision_note == "looks right"
    assert done.self_approved is False
    assert done.approver_credential_issuer == "human_idp_admin"
    assert done.decision_audit_ref
    assert done.expires_at == made.expires_at
    assert audit.outcomes(APPROVE_ACTION) == [AuditOutcome.ATTEMPT, AuditOutcome.SUCCESS]
    event = audit.find(APPROVE_ACTION)[-1]
    assert (event.actor_id, event.actor_type) == ("human_owner", ActorType.HUMAN)
    assert event.details["self_approved"] is False
    assert event.details["decided_roles"] == ["system_owner"]
    assert svc.check(made.approval_id, **use_args()).approval_id == made.approval_id


@pytest.mark.parametrize(
    ("fixture", "reason"),
    [
        ("agent", R.APPROVER_NOT_HUMAN),
        ("service", R.APPROVER_NOT_HUMAN),
        ("employee", R.APPROVER_LACKS_ROLE),
        ("auditor", R.APPROVER_LACKS_ROLE),
        ("admin", R.APPROVER_LACKS_ROLE),
    ],
)
def test_non_holder_agent_or_service_cannot_approve(
    svc: ApprovalService,
    audit: ScriptedAudit,
    request: pytest.FixtureRequest,
    fixture: str,
    reason: ApprovalReason,
) -> None:
    actor = signed_in(request.getfixturevalue(fixture))
    made = ask(svc, requested_by="human_requester", requested_by_type=ActorType.HUMAN)
    with pytest.raises(ApprovalForbidden) as excinfo:
        svc.approve(made.approval_id, actor)
    assert reason_of(excinfo) is reason
    assert isinstance(excinfo.value, AuthorizationError)
    assert svc.get(made.approval_id).status is ApprovalStatus.PENDING
    denied = audit.find(APPROVE_ACTION)
    assert [e.outcome for e in denied] == [AuditOutcome.DENIED]
    assert denied[0].details["reason"] == reason.value
    assert denied[0].actor_id == actor.actor_id


def test_unknown_and_disabled_actors_cannot_approve(
    svc: ApprovalService, owner: Principal, principals: FakePrincipals
) -> None:
    made = ask(svc)
    ghost = signed_in(make_principal("human_ghost", ActorType.HUMAN, Role.SYSTEM_OWNER))
    with pytest.raises(ApprovalForbidden) as excinfo:
        svc.approve(made.approval_id, ghost)
    assert reason_of(excinfo) is R.APPROVER_UNKNOWN
    principals.remove("human_owner")  # disabled: the resolver no longer returns the actor
    with pytest.raises(ApprovalForbidden) as excinfo:
        svc.approve(made.approval_id, owner)
    assert reason_of(excinfo) is R.APPROVER_UNKNOWN
    assert svc.get(made.approval_id).status is ApprovalStatus.PENDING


def test_roles_come_from_the_resolver_not_from_the_object_handed_in(
    svc: ApprovalService, owner: Principal, principals: FakePrincipals
) -> None:
    made = ask(svc)
    principals.register(make_principal("human_owner", ActorType.HUMAN, Role.EMPLOYEE))
    assert owner.has_role(Role.SYSTEM_OWNER)  # the stale snapshot still claims the role
    with pytest.raises(ApprovalForbidden) as excinfo:
        svc.approve(made.approval_id, owner)
    assert reason_of(excinfo) is R.APPROVER_LACKS_ROLE
    assert principals.lookups[-1] == "human_owner"


def test_approver_must_hold_one_of_the_required_roles(
    svc: ApprovalService, owner: Principal, risk_owner: Principal
) -> None:
    made = ask(svc, required_roles=[Role.EXECUTIVE_RISK_OWNER])
    with pytest.raises(ApprovalForbidden) as excinfo:
        svc.approve(made.approval_id, owner)
    assert reason_of(excinfo) is R.APPROVER_LACKS_ROLE
    done = svc.approve(made.approval_id, signed_in(risk_owner))
    assert done.decided_roles == (Role.EXECUTIVE_RISK_OWNER,)


@pytest.mark.parametrize(
    ("target", "allowed"),
    [
        ({"system": "app:billing"}, True),
        ({"system": "app:other"}, False),
        ({"environment": "staging"}, False),
        ({}, False),
    ],
)
def test_scoped_grant_must_reach_the_target(
    svc: ApprovalService, principals: FakePrincipals, target: dict[str, str], allowed: bool
) -> None:
    grant = RoleGrant(role=Role.SYSTEM_OWNER, scope={"system": frozenset({"app:billing"})})
    scoped = principals.register(
        make_principal("human_scoped", ActorType.HUMAN, Role.SYSTEM_OWNER, grants=(grant,))
    )
    made = ask(svc, target=target)
    if allowed:
        assert svc.approve(made.approval_id, signed_in(scoped)).status is ApprovalStatus.APPROVED
        return
    with pytest.raises(ApprovalForbidden) as excinfo:
        svc.approve(made.approval_id, signed_in(scoped))
    assert reason_of(excinfo) is R.APPROVER_LACKS_ROLE


def test_stored_role_outside_the_approver_list_never_counts(
    svc: ApprovalService, engine: Engine, admin: Principal
) -> None:
    made = ask(svc)
    tamper(engine, made.approval_id, required_roles='["security_admin"]')
    with pytest.raises(ApprovalForbidden) as excinfo:
        svc.approve(made.approval_id, signed_in(admin))
    assert reason_of(excinfo) is R.APPROVER_LACKS_ROLE


def test_identity_failure_refuses_the_decision(
    svc: ApprovalService, owner: Principal, principals: FakePrincipals
) -> None:
    made = ask(svc)
    principals.broken = True
    with pytest.raises(ApprovalUnavailable) as excinfo:
        svc.approve(made.approval_id, owner)
    assert reason_of(excinfo) is R.IDENTITY_UNAVAILABLE
    assert isinstance(excinfo.value, FailClosed)
    principals.broken = False
    assert svc.get(made.approval_id).status is ApprovalStatus.PENDING


# --- approve: separation of duties -------------------------------------------------------


def test_requester_cannot_approve_own_request(
    svc: ApprovalService, owner: Principal, audit: ScriptedAudit
) -> None:
    made = ask(svc, requested_by="human_owner", requested_by_type=ActorType.HUMAN)
    with pytest.raises(ApprovalForbidden) as excinfo:
        svc.approve(made.approval_id, owner)
    assert reason_of(excinfo) is R.SELF_APPROVAL
    assert svc.get(made.approval_id).status is ApprovalStatus.PENDING
    assert audit.find(APPROVE_ACTION)[-1].details["reason"] == "self_approval"


def test_allowed_self_approval_is_flagged_on_record_and_audit(
    engine: Engine, make_service: MakeService, owner: Principal, audit: ScriptedAudit
) -> None:
    lax = make_service(engine, allow_self_approval=True)
    made = ask(lax, requested_by="human_owner", requested_by_type=ActorType.HUMAN)
    done = lax.approve(made.approval_id, signed_in(owner, issued_by="human_owner"))
    assert done.self_approved is True
    events = audit.find(APPROVE_ACTION)
    assert [e.details["self_approved"] for e in events] == [True, True]
    assert lax.check(made.approval_id, **use_args()).self_approved is True


@pytest.mark.parametrize("flag", [1, "yes", None])
def test_only_a_real_true_switches_self_approval_on(
    engine: Engine, make_service: MakeService, owner: Principal, flag: Any
) -> None:
    odd = make_service(engine, allow_self_approval=flag)
    made = ask(odd, requested_by="human_owner", requested_by_type=ActorType.HUMAN)
    with pytest.raises(ApprovalForbidden) as excinfo:
        odd.approve(made.approval_id, owner)
    assert reason_of(excinfo) is R.SELF_APPROVAL


def test_approver_whose_credential_the_requester_issued_is_refused(
    svc: ApprovalService, system_owner: Principal
) -> None:
    made = ask(svc, requested_by="human_admin", requested_by_type=ActorType.HUMAN)
    with pytest.raises(ApprovalForbidden) as excinfo:
        svc.approve(made.approval_id, signed_in(system_owner, issued_by="human_admin"))
    assert reason_of(excinfo) is R.CREDENTIAL_ISSUED_BY_REQUESTER
    done = svc.approve(made.approval_id, signed_in(system_owner, issued_by="human_other"))
    assert done.status is ApprovalStatus.APPROVED


def test_approver_with_no_known_credential_issuer_is_refused(
    svc: ApprovalService, system_owner: Principal
) -> None:
    made = ask(svc)
    assert system_owner.credential_issued_by == ""
    with pytest.raises(ApprovalForbidden) as excinfo:
        svc.approve(made.approval_id, system_owner)
    assert reason_of(excinfo) is R.CREDENTIAL_ISSUER_UNKNOWN
    assert svc.get(made.approval_id).status is ApprovalStatus.PENDING


# --- approve / reject: state -------------------------------------------------------------


def test_unset_ttl_refuses_grants_but_still_lets_a_request_be_rejected(
    svc: ApprovalService, engine: Engine, make_service: MakeService, owner: Principal
) -> None:
    made = ask(svc)
    closed = make_service(engine, approval_ttl=None)
    with pytest.raises(ApprovalUnavailable) as excinfo:
        closed.approve(made.approval_id, owner)
    assert reason_of(excinfo) is R.TTL_UNSET
    assert closed.get(made.approval_id).status is ApprovalStatus.PENDING
    assert closed.reject(made.approval_id, owner).status is ApprovalStatus.REJECTED


def test_a_decision_is_final(
    svc: ApprovalService, owner: Principal, risk_owner: Principal, audit: ScriptedAudit
) -> None:
    first = svc.approve(ask(svc).approval_id, owner)
    second = svc.reject(ask(svc).approval_id, owner)
    for record in (first, second):
        for decide in (svc.approve, svc.reject):
            with pytest.raises(ApprovalConflict) as excinfo:
                decide(record.approval_id, signed_in(risk_owner))
            assert reason_of(excinfo) is R.ALREADY_DECIDED
            assert isinstance(excinfo.value, Conflict)
    assert svc.get(first.approval_id).decided_by == "human_owner"
    assert svc.get(second.approval_id).status is ApprovalStatus.REJECTED
    # refused before any attempt was recorded: one attempt each, from the first decisions
    assert audit.outcomes(APPROVE_ACTION).count(AuditOutcome.ATTEMPT) == 1
    assert audit.outcomes(REJECT_ACTION).count(AuditOutcome.ATTEMPT) == 1


def test_expired_request_cannot_be_approved(
    svc: ApprovalService, owner: Principal, clock: FixedClock
) -> None:
    made = ask(svc)
    clock.advance(TTL)
    with pytest.raises(ApprovalInvalid) as excinfo:
        svc.approve(made.approval_id, owner)
    assert reason_of(excinfo) is R.EXPIRED
    assert isinstance(excinfo.value, ApprovalRequired)
    assert svc.get(made.approval_id).status is ApprovalStatus.PENDING


def test_reject_is_audited_and_the_approval_is_never_usable(
    svc: ApprovalService, owner: Principal, audit: ScriptedAudit
) -> None:
    made = ask(svc)
    done = svc.reject(made.approval_id, owner, note="not now")
    assert (done.status, done.decided_by, done.decision_note) == (
        ApprovalStatus.REJECTED,
        "human_owner",
        "not now",
    )
    assert audit.outcomes(REJECT_ACTION) == [AuditOutcome.ATTEMPT, AuditOutcome.SUCCESS]
    for use in (svc.check, svc.consume):
        with pytest.raises(ApprovalInvalid) as excinfo:
            use(made.approval_id, **use_args())
        assert reason_of(excinfo) is R.REJECTED


def test_reject_needs_the_role_too(svc: ApprovalService, employee: Principal) -> None:
    made = ask(svc)
    with pytest.raises(ApprovalForbidden) as excinfo:
        svc.reject(made.approval_id, signed_in(employee))
    assert reason_of(excinfo) is R.APPROVER_LACKS_ROLE
    assert svc.get(made.approval_id).status is ApprovalStatus.PENDING
