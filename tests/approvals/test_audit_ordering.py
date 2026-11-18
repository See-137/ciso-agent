"""Audit ordering: attempt, short transaction, result; never under the write lock.

Blueprint 9.5 (audit path unavailable means stop); plan row T2.1 "an audit failure leaves
nothing recorded".
"""

from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest
from sqlalchemy import Engine
from tests.approvals.conftest import (
    MakeService,
    ScriptedAudit,
    ask,
    reason_of,
    row_count,
    signed_in,
    use_args,
)
from tests.fakes.core import FakePrincipals

from ciso.approvals import (
    APPROVE_ACTION,
    CONSUME_ACTION,
    REJECT_ACTION,
    REQUEST_ACTION,
    Approval,
    ApprovalConflict,
    ApprovalForbidden,
    ApprovalInvalid,
    ApprovalReason,
    ApprovalService,
    ApprovalStatus,
    ApprovalUnavailable,
)
from ciso.approvals.store import ApprovalStore
from ciso.common.enums import AuditOutcome
from ciso.common.errors import FailClosed
from ciso.common.principal import Principal
from ciso.common.protocols import AuditEvent

pytestmark = pytest.mark.policy

R = ApprovalReason


def audit_down(excinfo: pytest.ExceptionInfo[ApprovalUnavailable]) -> None:
    assert reason_of(excinfo) is R.AUDIT_UNAVAILABLE
    assert isinstance(excinfo.value, FailClosed)


# --- the attempt cannot be audited: nothing is recorded ----------------------------------


def test_request_with_audit_down_stores_nothing(
    svc: ApprovalService, engine: Engine, audit: ScriptedAudit
) -> None:
    audit.fail = True
    with pytest.raises(ApprovalUnavailable) as excinfo:
        ask(svc)
    audit_down(excinfo)
    assert row_count(engine) == 0
    audit.fail = False
    ask(svc)
    assert row_count(engine) == 1


@pytest.mark.parametrize("decision", ["approve", "reject"])
def test_decision_with_audit_down_changes_nothing(
    svc: ApprovalService, owner: Principal, audit: ScriptedAudit, decision: str
) -> None:
    made = ask(svc)
    audit.fail = True
    with pytest.raises(ApprovalUnavailable) as excinfo:
        getattr(svc, decision)(made.approval_id, owner)
    audit_down(excinfo)
    audit.fail = False
    assert svc.get(made.approval_id) == made


def test_consume_with_audit_down_does_not_spend(
    svc: ApprovalService, approved: Approval, audit: ScriptedAudit
) -> None:
    audit.fail = True
    with pytest.raises(ApprovalUnavailable) as excinfo:
        svc.consume(approved.approval_id, **use_args())
    audit_down(excinfo)
    audit.fail = False
    assert svc.get(approved.approval_id) == approved
    assert svc.consume(approved.approval_id, **use_args()).status is ApprovalStatus.CONSUMED


def test_refusal_is_still_raised_when_it_cannot_be_audited(
    svc: ApprovalService, agent: Principal, approved: Approval, audit: ScriptedAudit
) -> None:
    made = ask(svc)
    audit.fail = True
    with pytest.raises(ApprovalForbidden) as forbidden:
        svc.approve(made.approval_id, signed_in(agent))
    assert reason_of(forbidden) is R.APPROVER_NOT_HUMAN
    with pytest.raises(ApprovalInvalid) as invalid:
        svc.consume(approved.approval_id, **use_args(binding={}))
    assert reason_of(invalid) is R.BINDING_MISMATCH
    audit.fail = False
    assert svc.get(made.approval_id).status is ApprovalStatus.PENDING
    assert svc.get(approved.approval_id).status is ApprovalStatus.APPROVED


# --- the result cannot be audited: the state ends on the unusable side -------------------


def test_request_whose_result_cannot_be_audited_is_voided(
    svc: ApprovalService, engine: Engine, audit: ScriptedAudit, owner: Principal
) -> None:
    audit.fail_on(REQUEST_ACTION, AuditOutcome.SUCCESS)
    with pytest.raises(ApprovalUnavailable) as excinfo:
        ask(svc)
    audit_down(excinfo)
    audit.fail_if = None
    assert svc.list_pending() == ()
    assert row_count(engine) == 1
    attempt = audit.find(REQUEST_ACTION)[0]
    approval_id = attempt.target.split(":")[1]
    assert svc.get(approval_id).status is ApprovalStatus.VOID
    with pytest.raises(ApprovalConflict) as conflict:
        svc.approve(approval_id, owner)
    assert reason_of(conflict) is R.ALREADY_DECIDED


def test_grant_whose_result_cannot_be_audited_is_voided(
    svc: ApprovalService, owner: Principal, audit: ScriptedAudit
) -> None:
    made = ask(svc)
    audit.fail_on(APPROVE_ACTION, AuditOutcome.SUCCESS)
    with pytest.raises(ApprovalUnavailable) as excinfo:
        svc.approve(made.approval_id, owner)
    audit_down(excinfo)
    audit.fail_if = None
    assert svc.get(made.approval_id).status is ApprovalStatus.VOID
    for use in (svc.check, svc.consume):
        with pytest.raises(ApprovalInvalid) as invalid:
            use(made.approval_id, **use_args())
        assert reason_of(invalid) is R.VOIDED


def test_unaudited_grant_is_unusable_even_when_it_cannot_be_voided(
    svc: ApprovalService,
    owner: Principal,
    audit: ScriptedAudit,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    made = ask(svc)
    audit.fail_on(APPROVE_ACTION, AuditOutcome.SUCCESS)

    def broken_void(self: ApprovalStore, approval_id: str, from_status: ApprovalStatus) -> bool:
        raise ApprovalUnavailable(R.STORE_UNAVAILABLE)

    monkeypatch.setattr(ApprovalStore, "void", broken_void)
    with pytest.raises(ApprovalUnavailable) as excinfo:
        svc.approve(made.approval_id, owner)
    audit_down(excinfo)
    audit.fail_if = None
    stuck = svc.get(made.approval_id)
    assert (stuck.status, stuck.decision_audit_ref) == (ApprovalStatus.APPROVED, None)
    for use in (svc.check, svc.consume):
        with pytest.raises(ApprovalInvalid) as invalid:
            use(made.approval_id, **use_args())
        assert reason_of(invalid) is R.GRANT_NOT_AUDITED
    assert svc.get(made.approval_id).status is ApprovalStatus.APPROVED


def test_grant_that_cannot_be_confirmed_is_reported_and_unusable(
    svc: ApprovalService, owner: Principal, monkeypatch: pytest.MonkeyPatch
) -> None:
    made = ask(svc)
    monkeypatch.setattr(ApprovalStore, "confirm_grant", lambda self, approval_id, ref: False)
    with pytest.raises(ApprovalUnavailable) as excinfo:
        svc.approve(made.approval_id, owner)
    assert reason_of(excinfo) is R.STORE_UNAVAILABLE
    with pytest.raises(ApprovalInvalid) as invalid:
        svc.consume(made.approval_id, **use_args())
    assert reason_of(invalid) is R.GRANT_NOT_AUDITED


def test_rejection_whose_result_cannot_be_audited_stays_rejected(
    svc: ApprovalService, owner: Principal, audit: ScriptedAudit
) -> None:
    made = ask(svc)
    audit.fail_on(REJECT_ACTION, AuditOutcome.SUCCESS)
    with pytest.raises(ApprovalUnavailable) as excinfo:
        svc.reject(made.approval_id, owner)
    audit_down(excinfo)
    audit.fail_if = None
    assert svc.get(made.approval_id).status is ApprovalStatus.REJECTED


def test_consumption_whose_result_cannot_be_audited_stays_spent(
    svc: ApprovalService, approved: Approval, audit: ScriptedAudit
) -> None:
    audit.fail_on(CONSUME_ACTION, AuditOutcome.SUCCESS)
    with pytest.raises(ApprovalUnavailable) as excinfo:
        svc.consume(approved.approval_id, **use_args())
    audit_down(excinfo)
    audit.fail_if = None
    assert svc.get(approved.approval_id).status is ApprovalStatus.CONSUMED
    with pytest.raises(ApprovalInvalid) as invalid:
        svc.consume(approved.approval_id, **use_args())
    assert reason_of(invalid) is R.ALREADY_CONSUMED


# --- races the conditional writes must settle --------------------------------------------


def test_decision_that_loses_a_race_is_a_conflict(
    svc: ApprovalService, owner: Principal, risk_owner: Principal, audit: ScriptedAudit
) -> None:
    made = ask(svc)
    state = {"done": False}

    def reject_first(event: AuditEvent) -> None:
        if event.action == APPROVE_ACTION and not state["done"]:
            state["done"] = True
            svc.reject(made.approval_id, signed_in(risk_owner))

    audit.during = reject_first
    with pytest.raises(ApprovalConflict) as excinfo:
        svc.approve(made.approval_id, owner)
    assert reason_of(excinfo) is R.ALREADY_DECIDED
    final = svc.get(made.approval_id)
    assert (final.status, final.decided_by) == (ApprovalStatus.REJECTED, "human_risk")
    assert audit.outcomes(APPROVE_ACTION) == [AuditOutcome.ATTEMPT, AuditOutcome.DENIED]


# --- the sink and the resolver are never called under the write lock ---------------------


def test_audit_and_identity_are_never_called_while_holding_the_write_lock(
    file_db: tuple[Path, Engine],
    make_service: MakeService,
    audit: ScriptedAudit,
    principals: FakePrincipals,
    owner: Principal,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path, engine = file_db
    probes: list[str] = []

    def probe(label: str) -> None:
        # A second connection can take the write lock only if nobody else holds it.
        other = sqlite3.connect(path, timeout=0, isolation_level=None)
        try:
            other.execute("BEGIN IMMEDIATE")
            other.execute("ROLLBACK")
        finally:
            other.close()
        probes.append(label)

    audit.during = lambda event: probe(f"{event.action}:{event.outcome.value}")
    real_resolve = principals.resolve

    def resolve(actor_id: str) -> Principal | None:
        probe("resolve")
        return real_resolve(actor_id)

    monkeypatch.setattr(principals, "resolve", resolve)
    service = make_service(engine)
    spent = service.approve(ask(service).approval_id, owner)
    service.consume(spent.approval_id, **use_args())
    service.reject(ask(service).approval_id, owner)
    with pytest.raises(ApprovalInvalid):
        service.consume(spent.approval_id, **use_args())
    assert probes.count("resolve") == 3
    assert [p for p in probes if p != "resolve"] == [
        "approval.request:attempt", "approval.request:success",
        "approval.approve:attempt", "approval.approve:success",
        "approval.consume:attempt", "approval.consume:success",
        "approval.request:attempt", "approval.request:success",
        "approval.reject:attempt", "approval.reject:success",
        "approval.consume:denied",
    ]  # fmt: skip
