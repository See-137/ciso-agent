"""Using an approval: validity computed at the moment of use, and single use.

Blueprint 8.4 step 4, 9.5; gaps G2, G12; plan row T2.1.
"""

from __future__ import annotations

import threading
from pathlib import Path
from typing import Any

import pytest
from sqlalchemy import Engine
from tests.approvals.conftest import (
    BINDING,
    BROKER,
    HASH,
    KIND,
    OTHER_HASH,
    TTL,
    MakeService,
    ScriptedAudit,
    ask,
    reason_of,
    signed_in,
    tamper,
    use_args,
)
from tests.fakes.core import FakePrincipals, make_principal

from ciso.approvals import (
    CHECK_ACTION,
    CONSUME_ACTION,
    Approval,
    ApprovalInputInvalid,
    ApprovalInvalid,
    ApprovalReason,
    ApprovalService,
    ApprovalStatus,
    ApprovalUnavailable,
)
from ciso.approvals.store import ApprovalStore
from ciso.common.clock import FixedClock
from ciso.common.db import create_db_engine
from ciso.common.enums import ActorType, AuditOutcome, Role
from ciso.common.errors import ApprovalRequired, FailClosed
from ciso.common.principal import Principal
from ciso.common.protocols import AuditEvent
from ciso.common.schemas import canonical_json

pytestmark = pytest.mark.policy

R = ApprovalReason


def refused(svc: ApprovalService, approval_id: str, **overrides: Any) -> list[ApprovalReason]:
    """Reasons `check` and `consume` give; both must refuse with ApprovalInvalid."""
    reasons = []
    for use in (svc.check, svc.consume):
        with pytest.raises(ApprovalInvalid) as excinfo:
            use(approval_id, **use_args(**overrides))
        assert isinstance(excinfo.value, ApprovalRequired)
        reasons.append(reason_of(excinfo))
    return reasons


# --- binding -----------------------------------------------------------------------------


def test_pending_approval_is_not_usable(svc: ApprovalService) -> None:
    assert refused(svc, ask(svc).approval_id) == [R.NOT_APPROVED] * 2


def test_exact_subject_and_binding_pass(svc: ApprovalService, approved: Approval) -> None:
    assert svc.check(approved.approval_id, **use_args()).status is ApprovalStatus.APPROVED
    assert svc.check(approved.approval_id, **use_args(binding=dict(reversed(BINDING.items()))))


@pytest.mark.parametrize(
    ("override", "reason"),
    [
        ({"subject_hash": OTHER_HASH}, R.SUBJECT_MISMATCH),
        ({"subject_kind": "action_envelope"}, R.SUBJECT_MISMATCH),
        ({"binding": {**BINDING, "provider": "prov-b"}}, R.BINDING_MISMATCH),
        ({"binding": {**BINDING, "model": "model-2"}}, R.BINDING_MISMATCH),
        ({"binding": {**BINDING, "purpose": "summary"}}, R.BINDING_MISMATCH),
        ({"binding": {**BINDING, "request_id": "req-2"}}, R.BINDING_MISMATCH),
        ({"binding": {**BINDING, "extra": "x"}}, R.BINDING_MISMATCH),
        ({"binding": {k: v for k, v in BINDING.items() if k != "purpose"}}, R.BINDING_MISMATCH),
        ({"binding": {}}, R.BINDING_MISMATCH),
    ],
)
def test_any_difference_in_subject_or_binding_is_refused(
    svc: ApprovalService,
    approved: Approval,
    audit: ScriptedAudit,
    override: dict[str, Any],
    reason: ApprovalReason,
) -> None:
    assert refused(svc, approved.approval_id, **override) == [reason] * 2
    assert svc.get(approved.approval_id).status is ApprovalStatus.APPROVED
    assert audit.outcomes(CHECK_ACTION) == [AuditOutcome.DENIED]
    assert audit.outcomes(CONSUME_ACTION) == [AuditOutcome.DENIED]
    assert audit.find(CONSUME_ACTION)[0].details["reason"] == reason.value
    assert audit.find(CONSUME_ACTION)[0].actor_id == BROKER
    svc.consume(approved.approval_id, **use_args())  # the right subject still works


def test_malformed_use_arguments_are_bad_input(svc: ApprovalService, approved: Approval) -> None:
    for override in ({"subject_hash": "zz"}, {"binding": {"model": 1}}, {"actor_id": ""}):
        with pytest.raises(ApprovalInputInvalid):
            svc.consume(approved.approval_id, **use_args(**override))
    assert svc.get(approved.approval_id).status is ApprovalStatus.APPROVED


# --- expiry ------------------------------------------------------------------------------


def test_expired_approval_is_invalid(
    svc: ApprovalService, approved: Approval, clock: FixedClock
) -> None:
    clock.advance(TTL - (clock.now() - approved.requested_at) - TTL / 3600)
    assert svc.check(approved.approval_id, **use_args())
    clock.advance(TTL / 3600)  # exactly at expires_at
    assert clock.now() == approved.expires_at
    assert refused(svc, approved.approval_id) == [R.EXPIRED] * 2
    assert svc.get(approved.approval_id).status is ApprovalStatus.APPROVED  # never stored


def test_unset_ttl_refuses_use(
    engine: Engine, make_service: MakeService, approved: Approval
) -> None:
    closed = make_service(engine, approval_ttl=None)
    for use in (closed.check, closed.consume):
        with pytest.raises(ApprovalUnavailable) as excinfo:
            use(approved.approval_id, **use_args())
        assert reason_of(excinfo) is R.TTL_UNSET
    assert closed.get(approved.approval_id).status is ApprovalStatus.APPROVED


# --- approver re-checked at use (G12) ----------------------------------------------------


def test_role_revoked_after_approving_makes_the_approval_invalid(
    svc: ApprovalService, approved: Approval, principals: FakePrincipals, owner: Principal
) -> None:
    principals.register(make_principal("human_owner", ActorType.HUMAN, Role.EMPLOYEE))
    assert refused(svc, approved.approval_id) == [R.APPROVER_LACKS_ROLE] * 2
    assert svc.get(approved.approval_id).status is ApprovalStatus.APPROVED
    principals.register(owner)  # role restored: validity is recomputed, not remembered
    assert svc.consume(approved.approval_id, **use_args()).status is ApprovalStatus.CONSUMED


def test_approver_disabled_after_approving_makes_the_approval_invalid(
    svc: ApprovalService, approved: Approval, principals: FakePrincipals
) -> None:
    principals.remove("human_owner")
    assert refused(svc, approved.approval_id) == [R.APPROVER_UNKNOWN] * 2


def test_approver_no_longer_human_makes_the_approval_invalid(
    svc: ApprovalService, approved: Approval, principals: FakePrincipals
) -> None:
    principals.register(make_principal("human_owner", ActorType.SERVICE))
    assert refused(svc, approved.approval_id) == [R.APPROVER_NOT_HUMAN] * 2


def test_grant_narrowed_away_from_the_target_makes_the_approval_invalid(
    svc: ApprovalService, approved: Approval, principals: FakePrincipals
) -> None:
    from ciso.common.principal import RoleGrant

    elsewhere = RoleGrant(role=Role.SYSTEM_OWNER, scope={"system": frozenset({"app:other"})})
    principals.register(
        make_principal("human_owner", ActorType.HUMAN, Role.SYSTEM_OWNER, grants=(elsewhere,))
    )
    assert refused(svc, approved.approval_id) == [R.APPROVER_LACKS_ROLE] * 2


def test_identity_failure_at_use_is_fail_closed(
    svc: ApprovalService, approved: Approval, principals: FakePrincipals
) -> None:
    principals.broken = True
    for use in (svc.check, svc.consume):
        with pytest.raises(ApprovalUnavailable) as excinfo:
            use(approved.approval_id, **use_args())
        assert reason_of(excinfo) is R.IDENTITY_UNAVAILABLE
        assert isinstance(excinfo.value, FailClosed)
    principals.broken = False
    assert svc.get(approved.approval_id).status is ApprovalStatus.APPROVED


def test_self_approval_switched_off_later_invalidates_a_self_approved_grant(
    engine: Engine, make_service: MakeService, owner: Principal
) -> None:
    lax = make_service(engine, allow_self_approval=True)
    made = ask(lax, requested_by="human_owner", requested_by_type=ActorType.HUMAN)
    lax.approve(made.approval_id, owner)
    strict = make_service(engine)
    assert refused(strict, made.approval_id) == [R.SELF_APPROVAL] * 2
    assert lax.consume(made.approval_id, **use_args()).status is ApprovalStatus.CONSUMED


@pytest.mark.parametrize(
    ("issuer", "reason"),
    [("agent_ciso", R.CREDENTIAL_ISSUED_BY_REQUESTER), (None, R.CREDENTIAL_ISSUER_UNKNOWN)],
)
def test_issuer_rule_is_rechecked_from_the_stored_record(
    svc: ApprovalService,
    engine: Engine,
    approved: Approval,
    issuer: str | None,
    reason: ApprovalReason,
) -> None:
    tamper(engine, approved.approval_id, approver_credential_issuer=issuer)
    assert refused(svc, approved.approval_id) == [reason] * 2


def test_grant_without_its_audit_record_is_not_usable(
    svc: ApprovalService, engine: Engine, approved: Approval
) -> None:
    tamper(engine, approved.approval_id, decision_audit_ref=None)
    assert refused(svc, approved.approval_id) == [R.GRANT_NOT_AUDITED] * 2


# --- single use --------------------------------------------------------------------------


def test_consume_spends_the_approval_once(
    svc: ApprovalService, approved: Approval, audit: ScriptedAudit, clock: FixedClock
) -> None:
    clock.advance(minutes=1)
    spent = svc.consume(approved.approval_id, **use_args())
    assert spent.status is ApprovalStatus.CONSUMED
    assert (spent.consumed_by, spent.consumed_at) == (BROKER, clock.now())
    assert audit.outcomes(CONSUME_ACTION) == [AuditOutcome.ATTEMPT, AuditOutcome.SUCCESS]
    assert audit.find(CONSUME_ACTION)[-1].actor_type is ActorType.SERVICE
    assert refused(svc, approved.approval_id) == [R.ALREADY_CONSUMED] * 2
    assert audit.outcomes(CONSUME_ACTION)[-1] is AuditOutcome.DENIED


def test_check_does_not_spend(svc: ApprovalService, approved: Approval) -> None:
    for _ in range(3):
        svc.check(approved.approval_id, **use_args())
    assert svc.consume(approved.approval_id, **use_args()).status is ApprovalStatus.CONSUMED


def test_store_takes_an_approval_at_most_once(engine: Engine, approved: Approval) -> None:
    store = ApprovalStore(engine)
    now = approved.requested_at
    assert store.consume(approved, consumed_by="a", now=now) is True
    assert store.consume(approved, consumed_by="b", now=now) is False
    found = store.find(approved.approval_id)
    assert found is not None
    assert found.consumed_by == "a"


def test_store_decides_a_request_at_most_once(svc: ApprovalService, engine: Engine) -> None:
    made = ask(svc)
    store = ApprovalStore(engine)
    args: dict[str, Any] = {
        "decided_at": made.requested_at, "decided_roles": (Role.SYSTEM_OWNER,), "note": "",
        "self_approved": False, "credential_issuer": "x",
    }  # fmt: skip
    assert store.decide(made.approval_id, status=ApprovalStatus.REJECTED, decided_by="a", **args)
    assert not store.decide(
        made.approval_id, status=ApprovalStatus.APPROVED, decided_by="b", **args
    )
    assert svc.get(made.approval_id).status is ApprovalStatus.REJECTED
    late = ask(svc)
    args["decided_at"] = late.expires_at
    assert not store.decide(
        late.approval_id, status=ApprovalStatus.APPROVED, decided_by="a", **args
    )


def test_store_will_not_take_a_row_that_changed_since_it_was_read(
    engine: Engine, approved: Approval
) -> None:
    store = ApprovalStore(engine)
    now = approved.requested_at
    assert not store.consume(approved, consumed_by="a", now=approved.expires_at)
    canonical = canonical_json(dict(approved.binding))
    changes: tuple[tuple[dict[str, Any], dict[str, Any]], ...] = (
        ({"subject_hash": OTHER_HASH}, {"subject_hash": approved.subject_hash}),
        ({"subject_kind": "action_envelope"}, {"subject_kind": approved.subject_kind}),
        ({"binding": "{}"}, {"binding": canonical}),
        ({"decided_by": "human_other"}, {"decided_by": approved.decided_by}),
        ({"decision_audit_ref": None}, {"decision_audit_ref": approved.decision_audit_ref}),
        ({"status": "void"}, {"status": "approved"}),
        ({"consumed_at": now}, {"consumed_at": None}),
    )
    for change, restore in changes:
        tamper(engine, approved.approval_id, **change)
        assert not store.consume(approved, consumed_by="a", now=now), change
        tamper(engine, approved.approval_id, **restore)
    assert store.consume(approved, consumed_by="a", now=now)


def test_approved_row_that_carries_a_consumption_time_is_spent(
    svc: ApprovalService, engine: Engine, approved: Approval
) -> None:
    tamper(engine, approved.approval_id, consumed_at=approved.requested_at)
    assert refused(svc, approved.approval_id) == [R.ALREADY_CONSUMED] * 2


def test_store_confirms_a_grant_once_and_voids_only_from_the_named_state(
    svc: ApprovalService, engine: Engine, approved: Approval
) -> None:
    store = ApprovalStore(engine)
    pending = ask(svc)
    assert not store.confirm_grant(pending.approval_id, "aud_x")
    assert not store.confirm_grant(approved.approval_id, "aud_other")
    assert svc.get(approved.approval_id).decision_audit_ref == approved.decision_audit_ref
    assert not store.void(pending.approval_id, ApprovalStatus.APPROVED)
    assert svc.get(pending.approval_id).status is ApprovalStatus.PENDING
    assert store.void(pending.approval_id, ApprovalStatus.PENDING)
    assert svc.get(pending.approval_id).status is ApprovalStatus.VOID
    tamper(engine, approved.approval_id, decision_audit_ref=None)
    assert store.confirm_grant(approved.approval_id, "aud_new")


def test_two_concurrent_consumers_exactly_one_wins(
    file_db: tuple[Path, Engine],
    make_service: MakeService,
    audit: ScriptedAudit,
    owner: Principal,
) -> None:
    path, first_engine = file_db
    second_engine = create_db_engine(path)
    try:
        one, two = make_service(first_engine), make_service(second_engine)
        made = one.approve(ask(one).approval_id, owner)
        gate = threading.Barrier(2, timeout=20)

        def hold(event: AuditEvent) -> None:
            # Both callers have passed every validity check before either may write.
            if event.action == CONSUME_ACTION and event.outcome is AuditOutcome.ATTEMPT:
                gate.wait()

        audit.during = hold
        results: list[Approval | BaseException] = []

        def run(service: ApprovalService, name: str) -> None:
            try:
                results.append(service.consume(made.approval_id, **use_args(actor_id=name)))
            except BaseException as exc:
                results.append(exc)

        threads = [
            threading.Thread(target=run, args=(svc, name))
            for svc, name in ((one, "svc_a"), (two, "svc_b"))
        ]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=30)
        assert not any(thread.is_alive() for thread in threads)
        audit.during = None
        winners = [r for r in results if isinstance(r, Approval)]
        losers = [r for r in results if isinstance(r, BaseException)]
        assert len(winners) == 1, results
        assert len(losers) == 1, results
        assert isinstance(losers[0], ApprovalInvalid)
        assert losers[0].reason is R.ALREADY_CONSUMED
        final = one.get(made.approval_id)
        assert final.status is ApprovalStatus.CONSUMED
        assert final.consumed_by == winners[0].consumed_by
        outcomes = sorted(o.value for o in audit.outcomes(CONSUME_ACTION))
        assert outcomes == ["attempt", "attempt", "denied", "success"]
    finally:
        second_engine.dispose()


def test_subject_constants_are_what_the_tests_think(approved: Approval) -> None:
    assert (approved.subject_kind, approved.subject_hash) == (KIND, HASH)
    assert signed_in(make_principal()).credential_issued_by == "human_idp_admin"
