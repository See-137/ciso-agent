"""Regression tests for the M2 review of approvals
(`docs/reviews/m2-approvals-external-inference.md`), named by finding id. Each test
replays the reviewer's concrete sequence and has an allowed path next to it.
"""

from __future__ import annotations

from collections.abc import Callable
from datetime import timedelta
from typing import Any

import pytest
from sqlalchemy import Engine, select
from tests.approvals.conftest import (
    BINDING,
    HASH,
    KIND,
    MakeService,
    ScriptedAudit,
    ask,
    reason_of,
    signed_in,
    tamper,
    use_args,
)
from tests.fakes.core import FakePrincipals, FakeRedactor, make_principal

from ciso.approvals import (
    APPROVE_ACTION,
    REQUEST_ACTION,
    WITHDRAW_ACTION,
    ApprovalConflict,
    ApprovalForbidden,
    ApprovalInputInvalid,
    ApprovalInvalid,
    ApprovalReason,
    ApprovalService,
    ApprovalStatus,
    ApprovalUnavailable,
    AuditRecordView,
    rules,
)
from ciso.approvals.store import ApprovalStore
from ciso.approvals.tables import approval
from ciso.common.clock import FixedClock
from ciso.common.enums import ActorType, AuditOutcome, Role
from ciso.common.errors import FailClosed
from ciso.common.principal import Principal
from ciso.common.protocols import AuditEvent, AuditReceipt

pytestmark = pytest.mark.policy

SECRET = "hunter2-correct-horse-battery"


class LookupAudit(ScriptedAudit):
    """An audit sink that can be read back by record id, as the real one can."""

    def __init__(self, clock: FixedClock) -> None:
        super().__init__(clock)
        self.by_id: dict[str, AuditEvent] = {}
        self.lookup_down = False
        self.override: Callable[[AuditRecordView], AuditRecordView] | None = None

    def append(self, event: AuditEvent) -> AuditReceipt:
        receipt = super().append(event)
        self.by_id[receipt.record_id] = event
        return receipt

    def read_back(self, record_id: str) -> AuditRecordView | None:
        if self.lookup_down:
            raise RuntimeError("audit store unreadable (scripted)")
        event = self.by_id.get(record_id)
        if event is None:
            return None
        view = AuditRecordView(
            action=event.action, target=event.target, outcome=event.outcome, actor_id=event.actor_id
        )
        return view if self.override is None else self.override(view)


class ReadBack:
    """The `AuditRecordLookup` adapter the composition root would wire."""

    def __init__(self, audit: LookupAudit) -> None:
        self._audit = audit

    def find(self, record_id: str) -> AuditRecordView | None:
        return self._audit.read_back(record_id)


@pytest.fixture
def lookup_audit(clock: FixedClock) -> LookupAudit:
    return LookupAudit(clock)


@pytest.fixture
def verified(
    engine: Engine, lookup_audit: LookupAudit, clock: FixedClock, principals: FakePrincipals
) -> ApprovalService:
    """A service wired with the audit read-back (finding M1)."""
    return ApprovalService(
        engine=engine,
        audit=lookup_audit,
        clock=clock,
        principals=principals,
        approval_ttl=timedelta(hours=1),
        audit_records=ReadBack(lookup_audit),
    )


# --- H1: a hand-built Principal ---------------------------------------------------------------


def test_h1_forged_principal_snapshot_is_refused(
    svc: ApprovalService, audit: ScriptedAudit, owner: Principal
) -> None:
    """P4: the object says agent, the id names the owner."""
    made = ask(svc)
    forged = Principal(
        actor_id="human_owner", actor_type=ActorType.AGENT, credential_issued_by="made-up"
    )
    with pytest.raises(ApprovalForbidden) as excinfo:
        svc.approve(made.approval_id, forged)
    assert reason_of(excinfo) is ApprovalReason.PRINCIPAL_MISMATCH
    assert svc.get(made.approval_id).status is ApprovalStatus.PENDING
    denied = audit.find(APPROVE_ACTION)[-1]
    assert (denied.outcome, denied.details["reason"]) == (
        AuditOutcome.DENIED,
        "principal_mismatch",
    )
    with pytest.raises(ApprovalInvalid):
        svc.consume(made.approval_id, **use_args())
    # The honest snapshot of the same actor decides it.
    assert svc.approve(made.approval_id, owner).status is ApprovalStatus.APPROVED


def test_h1_snapshot_claiming_a_role_the_actor_lacks_is_refused(
    svc: ApprovalService, owner: Principal
) -> None:
    made = ask(svc)
    inflated = signed_in(
        make_principal("human_owner", ActorType.HUMAN, Role.SYSTEM_OWNER, Role.EXECUTIVE_RISK_OWNER)
    )
    with pytest.raises(ApprovalForbidden) as excinfo:
        svc.reject(made.approval_id, inflated)
    assert reason_of(excinfo) is ApprovalReason.PRINCIPAL_MISMATCH
    assert svc.reject(made.approval_id, owner).status is ApprovalStatus.REJECTED


def test_h1_something_that_is_not_a_principal_is_refused(svc: ApprovalService) -> None:
    made = ask(svc)
    with pytest.raises(ApprovalInputInvalid) as excinfo:
        svc.approve(made.approval_id, "human_owner")  # type: ignore[arg-type]
    assert reason_of(excinfo) is ApprovalReason.INVALID_ACTOR


# --- H2: parties ------------------------------------------------------------------------------


def test_h2_a_named_party_cannot_decide(
    svc: ApprovalService, owner: Principal, risk_owner: Principal
) -> None:
    """The author of what is being approved is on the record and may not approve it,
    even though somebody else filed the request."""
    made = ask(svc, requested_by="human_emp", requested_by_type=ActorType.HUMAN,
               parties=["human_owner"])  # fmt: skip
    assert made.parties == ("human_owner",)
    with pytest.raises(ApprovalForbidden) as excinfo:
        svc.approve(made.approval_id, owner)
    assert reason_of(excinfo) is ApprovalReason.SELF_APPROVAL
    done = svc.approve(made.approval_id, signed_in(risk_owner))
    assert (done.status, done.self_approved) == (ApprovalStatus.APPROVED, False)


def test_h2_a_party_may_decide_only_with_the_self_approval_switch(
    engine: Engine, make_service: MakeService, owner: Principal
) -> None:
    svc = make_service(engine, allow_self_approval=True)
    made = ask(svc, parties=["human_owner"])
    done = svc.approve(made.approval_id, owner)
    assert (done.status, done.self_approved) == (ApprovalStatus.APPROVED, True)


def test_h2_credential_issued_by_a_party_is_refused(
    svc: ApprovalService, system_owner: Principal
) -> None:
    made = ask(svc, parties=["human_author"])
    with pytest.raises(ApprovalForbidden) as excinfo:
        svc.approve(made.approval_id, signed_in(system_owner, issued_by="human_author"))
    assert reason_of(excinfo) is ApprovalReason.CREDENTIAL_ISSUED_BY_REQUESTER
    assert svc.approve(made.approval_id, signed_in(system_owner)).status is (
        ApprovalStatus.APPROVED
    )


def test_h2_parties_are_checked_again_at_use(
    svc: ApprovalService, engine: Engine, owner: Principal
) -> None:
    made = ask(svc)
    svc.approve(made.approval_id, owner)
    svc.check(made.approval_id, **use_args())
    tamper(engine, made.approval_id, parties='["human_owner"]')
    with pytest.raises(ApprovalInvalid) as excinfo:
        svc.consume(made.approval_id, **use_args())
    assert reason_of(excinfo) is ApprovalReason.SELF_APPROVAL


@pytest.mark.parametrize("parties", [[" human_owner"], ["a\nb"], [""], "humanowner", [7]])
def test_h2_malformed_parties_are_refused(svc: ApprovalService, parties: Any) -> None:
    with pytest.raises(ApprovalInputInvalid) as excinfo:
        ask(svc, parties=parties)
    assert reason_of(excinfo) is ApprovalReason.INVALID_PARTIES


def test_h2_the_number_of_parties_is_bounded(svc: ApprovalService) -> None:
    names = [f"human_{i}" for i in range(rules.MAX_PARTIES + 1)]
    with pytest.raises(ApprovalInputInvalid) as excinfo:
        ask(svc, parties=names)
    assert reason_of(excinfo) is ApprovalReason.INVALID_PARTIES
    # The requester named among the parties does not count twice.
    kept = ask(svc, parties=[*names[:-1], "agent_ciso"])
    assert len(kept.parties) == rules.MAX_PARTIES
    assert "agent_ciso" not in kept.parties


# --- M1: the grant's audit record is read back ------------------------------------------------


def _forge_grant(engine: Engine, approval_id: str, clock: FixedClock, ref: str) -> None:
    tamper(
        engine, approval_id, status="approved", decided_by="human_owner",
        decided_at=clock.now(), approver_credential_issuer="x", decision_audit_ref=ref,
    )  # fmt: skip


def test_m1_forged_grant_is_refused_when_the_audit_log_can_be_read(
    verified: ApprovalService, engine: Engine, clock: FixedClock, lookup_audit: LookupAudit
) -> None:
    """P5: a database writer marks a pending row approved with a made-up audit ref."""
    made = ask(verified)
    _forge_grant(engine, made.approval_id, clock, "aud_does_not_exist")
    for call in (verified.check, verified.consume):
        with pytest.raises(ApprovalInvalid) as excinfo:
            call(made.approval_id, **use_args())
        assert reason_of(excinfo) is ApprovalReason.GRANT_NOT_AUDITED
    assert verified.get(made.approval_id).status is ApprovalStatus.APPROVED
    assert lookup_audit.find(APPROVE_ACTION) == []


def test_m1_a_real_grant_is_accepted_and_a_ref_to_another_record_is_not(
    verified: ApprovalService, engine: Engine, clock: FixedClock, owner: Principal,
    lookup_audit: LookupAudit,
) -> None:  # fmt: skip
    real = verified.approve(ask(verified).approval_id, owner)
    forged = ask(verified)
    # Point the forged row at the genuine grant record of a different approval.
    assert real.decision_audit_ref is not None
    _forge_grant(engine, forged.approval_id, clock, real.decision_audit_ref)
    with pytest.raises(ApprovalInvalid) as excinfo:
        verified.consume(forged.approval_id, **use_args())
    assert reason_of(excinfo) is ApprovalReason.GRANT_NOT_AUDITED
    assert verified.consume(real.approval_id, **use_args()).status is ApprovalStatus.CONSUMED


@pytest.mark.parametrize(
    "change",
    [
        {"action": "approval.reject"},
        {"outcome": AuditOutcome.ATTEMPT},
        {"actor_id": "human_risk"},
        {"target": "approval:apr_00000000000000000000000000"},
    ],
    ids=["action", "outcome", "actor", "target"],
)
def test_m1_each_field_of_the_grant_record_is_compared(
    verified: ApprovalService, owner: Principal, lookup_audit: LookupAudit, change: dict[str, Any]
) -> None:
    done = verified.approve(ask(verified).approval_id, owner)
    lookup_audit.override = lambda view: view.model_copy(update=change)
    with pytest.raises(ApprovalInvalid) as excinfo:
        verified.check(done.approval_id, **use_args())
    assert reason_of(excinfo) is ApprovalReason.GRANT_NOT_AUDITED
    lookup_audit.override = None
    assert verified.check(done.approval_id, **use_args()).approval_id == done.approval_id


def test_m1_a_lookup_that_returns_something_else_is_not_a_grant_record(
    verified: ApprovalService, owner: Principal, lookup_audit: LookupAudit
) -> None:
    done = verified.approve(ask(verified).approval_id, owner)
    lookup_audit.override = lambda view: view.model_dump()  # type: ignore[assignment, return-value]
    with pytest.raises(ApprovalInvalid) as excinfo:
        verified.consume(done.approval_id, **use_args())
    assert reason_of(excinfo) is ApprovalReason.GRANT_NOT_AUDITED
    lookup_audit.override = None
    assert verified.consume(done.approval_id, **use_args()).status is ApprovalStatus.CONSUMED


def test_m1_unreadable_audit_log_fails_closed(
    verified: ApprovalService, owner: Principal, lookup_audit: LookupAudit
) -> None:
    done = verified.approve(ask(verified).approval_id, owner)
    lookup_audit.lookup_down = True
    with pytest.raises(ApprovalUnavailable) as excinfo:
        verified.consume(done.approval_id, **use_args())
    assert reason_of(excinfo) is ApprovalReason.AUDIT_UNAVAILABLE
    assert isinstance(excinfo.value, FailClosed)
    assert verified.get(done.approval_id).status is ApprovalStatus.APPROVED
    lookup_audit.lookup_down = False
    assert verified.consume(done.approval_id, **use_args()).status is ApprovalStatus.CONSUMED


# --- M4: "voided" must be true ----------------------------------------------------------------


def test_m4_request_reported_voided_is_unusable_even_if_approved_meanwhile(
    svc: ApprovalService, audit: ScriptedAudit, owner: Principal
) -> None:
    """P9: the SUCCESS record of `request` fails after an approver already approved."""
    seen: dict[str, str] = {}

    def approve_then_fail(event: AuditEvent) -> bool:
        if event.action == REQUEST_ACTION and event.outcome is AuditOutcome.SUCCESS:
            seen["id"] = event.target.split(":")[1]
            audit.fail_if = None
            svc.approve(seen["id"], owner)
            return True
        return False

    audit.fail_if = approve_then_fail
    with pytest.raises(ApprovalUnavailable) as excinfo:
        ask(svc)
    assert reason_of(excinfo) is ApprovalReason.AUDIT_UNAVAILABLE
    assert "voided" in str(excinfo.value)
    assert svc.get(seen["id"]).status is ApprovalStatus.VOID
    with pytest.raises(ApprovalInvalid) as refused:
        svc.consume(seen["id"], **use_args())
    assert reason_of(refused) is ApprovalReason.VOIDED


def test_m4_a_request_that_could_not_be_voided_says_so(
    svc: ApprovalService, audit: ScriptedAudit, owner: Principal
) -> None:
    """Approved and already used inside the window: nothing is left to void."""
    seen: dict[str, str] = {}

    def use_then_fail(event: AuditEvent) -> bool:
        if event.action == REQUEST_ACTION and event.outcome is AuditOutcome.SUCCESS:
            seen["id"] = event.target.split(":")[1]
            audit.fail_if = None
            svc.approve(seen["id"], owner)
            svc.consume(seen["id"], **use_args())
            return True
        return False

    audit.fail_if = use_then_fail
    with pytest.raises(ApprovalUnavailable) as excinfo:
        ask(svc)
    assert reason_of(excinfo) is ApprovalReason.VOID_FAILED
    assert svc.get(seen["id"]).status is ApprovalStatus.CONSUMED


def test_m4_a_void_the_store_refuses_is_not_reported_as_done(
    svc: ApprovalService, audit: ScriptedAudit, monkeypatch: pytest.MonkeyPatch
) -> None:
    def down(self: ApprovalStore, approval_id: str, *statuses: ApprovalStatus) -> bool:
        raise ApprovalUnavailable(ApprovalReason.STORE_UNAVAILABLE, "store down (scripted)")

    monkeypatch.setattr(ApprovalStore, "void", down)
    audit.fail_on(REQUEST_ACTION, AuditOutcome.SUCCESS)
    with pytest.raises(ApprovalUnavailable) as excinfo:
        ask(svc)
    assert reason_of(excinfo) is ApprovalReason.VOID_FAILED


# --- M5: identifiers --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "requester",
    [
        "agent\nciso\x00\x1b[31m",
        " human_owner",
        "human_owner" + chr(0x200B),
        "human_owner ",
        "a b",
        "",
    ],
)
def test_m5_unclean_requester_ids_are_refused_at_request(
    svc: ApprovalService, engine: Engine, requester: str
) -> None:
    """P12: each of these used to be accepted and then approved by `human_owner`."""
    with pytest.raises(ApprovalInputInvalid) as excinfo:
        ask(svc, requested_by=requester, requested_by_type=ActorType.HUMAN)
    assert reason_of(excinfo) is ApprovalReason.INVALID_REQUESTER
    with engine.begin() as conn:
        assert conn.execute(select(approval.c.approval_id)).all() == []


@pytest.mark.parametrize(
    ("override", "reason"),
    [
        ({"binding": {"k\n": "v"}}, ApprovalReason.INVALID_BINDING),
        ({"binding": {"k": "v\r\n\x00"}}, ApprovalReason.INVALID_BINDING),
        ({"binding": {"k": " v"}}, ApprovalReason.INVALID_BINDING),
        ({"binding": {"k": "v" + chr(0x202E)}}, ApprovalReason.INVALID_BINDING),
        ({"target": {"system": "app\x1b[31m"}}, ApprovalReason.INVALID_TARGET),
        ({"target": {"sys tem": "app"}}, ApprovalReason.INVALID_TARGET),
        ({"correlation_id": "c\nid"}, ApprovalReason.INVALID_TEXT),
        ({"correlation_id": " c"}, ApprovalReason.INVALID_TEXT),
        ({"subject_kind": "kind\n"}, ApprovalReason.INVALID_SUBJECT),
    ],
)
def test_m5_control_characters_and_padding_are_refused(
    svc: ApprovalService, override: dict[str, Any], reason: ApprovalReason
) -> None:
    with pytest.raises(ApprovalInputInvalid) as excinfo:
        ask(svc, **override)
    assert reason_of(excinfo) is reason


def test_m5_clean_values_are_accepted_as_given(svc: ApprovalService) -> None:
    made = ask(svc, correlation_id="corr-1.a:b", binding={"purpose": "two words", "k.2": ""})
    assert made.correlation_id == "corr-1.a:b"
    assert dict(made.binding) == {"purpose": "two words", "k.2": ""}


def test_m5_unclean_actor_and_note_are_refused_when_deciding_and_using(
    svc: ApprovalService, owner: Principal
) -> None:
    made = ask(svc)
    with pytest.raises(ApprovalInputInvalid) as excinfo:
        svc.approve(made.approval_id, owner, note="fine\x00\x1b[2J")
    assert reason_of(excinfo) is ApprovalReason.INVALID_TEXT
    with pytest.raises(ApprovalInputInvalid) as excinfo:
        svc.approve(made.approval_id, owner, note=" padded")
    assert reason_of(excinfo) is ApprovalReason.INVALID_TEXT
    padded = owner.model_copy(update={"actor_id": " human_owner"})
    with pytest.raises(ApprovalInputInvalid) as excinfo:
        svc.approve(made.approval_id, padded)
    assert reason_of(excinfo) is ApprovalReason.INVALID_ACTOR
    odd_issuer = owner.model_copy(update={"credential_issued_by": "x\ny"})
    with pytest.raises(ApprovalInputInvalid) as excinfo:
        svc.approve(made.approval_id, odd_issuer)
    assert reason_of(excinfo) is ApprovalReason.INVALID_ACTOR
    svc.approve(made.approval_id, owner, note="looks right to me")
    with pytest.raises(ApprovalInputInvalid) as excinfo:
        svc.check(made.approval_id, **use_args(actor_id="svc\nbroker"))
    assert reason_of(excinfo) is ApprovalReason.INVALID_ACTOR
    assert svc.check(made.approval_id, **use_args()).decision_note == "looks right to me"


# --- L1: a clock that went backwards ----------------------------------------------------------


def test_l1_clock_behind_the_decision_time_fails_closed(
    svc: ApprovalService, clock: FixedClock, owner: Principal
) -> None:
    """P11: expired at +2h, clock set back, `consume` used to succeed."""
    made = ask(svc)
    clock.advance(minutes=1)
    svc.approve(made.approval_id, owner)
    clock.advance(hours=2)
    with pytest.raises(ApprovalInvalid) as expired:
        svc.check(made.approval_id, **use_args())
    assert reason_of(expired) is ApprovalReason.EXPIRED
    clock.advance(hours=-2, seconds=-1)
    for call in (svc.check, svc.consume):
        with pytest.raises(ApprovalUnavailable) as excinfo:
            call(made.approval_id, **use_args())
        assert reason_of(excinfo) is ApprovalReason.CLOCK_UNRELIABLE
        assert isinstance(excinfo.value, FailClosed)
    assert svc.get(made.approval_id).status is ApprovalStatus.APPROVED
    clock.advance(seconds=1)
    assert svc.consume(made.approval_id, **use_args()).status is ApprovalStatus.CONSUMED


def test_l1_clock_behind_the_request_time_refuses_a_decision(
    svc: ApprovalService, clock: FixedClock, owner: Principal
) -> None:
    made = ask(svc)
    clock.advance(seconds=-1)
    for call in (svc.approve, svc.reject):
        with pytest.raises(ApprovalUnavailable) as excinfo:
            call(made.approval_id, owner)
        assert reason_of(excinfo) is ApprovalReason.CLOCK_UNRELIABLE
    assert svc.get(made.approval_id).status is ApprovalStatus.PENDING
    clock.advance(seconds=1)
    assert svc.approve(made.approval_id, owner).status is ApprovalStatus.APPROVED


# --- L2: the note is redacted -----------------------------------------------------------------


def test_l2_decision_note_is_redacted_before_storage(
    engine: Engine, make_service: MakeService, owner: Principal, audit: ScriptedAudit
) -> None:
    """P16."""
    svc = make_service(engine, redactor=FakeRedactor(SECRET))
    made = ask(svc)
    done = svc.approve(made.approval_id, owner, note=f"ok, token is {SECRET}")
    assert done.decision_note == "ok, token is [REDACTED]"
    with engine.begin() as conn:
        stored = conn.execute(select(approval.c.decision_note)).scalar_one()
    assert SECRET not in stored
    assert SECRET not in repr([e.model_dump() for e in audit.events])


def test_l2_a_redactor_that_fails_stops_the_decision(
    engine: Engine, make_service: MakeService, owner: Principal
) -> None:
    class Broken(FakeRedactor):
        def redact(self, text: str) -> str:
            raise RuntimeError(f"redactor broke on {text}")

    svc = make_service(engine, redactor=Broken())
    made = ask(svc)
    with pytest.raises(ApprovalUnavailable) as excinfo:
        svc.approve(made.approval_id, owner, note=SECRET)
    assert reason_of(excinfo) is ApprovalReason.REDACTOR_UNAVAILABLE
    assert SECRET not in str(excinfo.value)
    assert svc.get(made.approval_id).status is ApprovalStatus.PENDING


# --- L3: guards that had no test --------------------------------------------------------------


def test_l3_binding_and_target_size_limits(svc: ApprovalService) -> None:
    many = {f"k{i}": "v" for i in range(rules.MAX_BINDING_FIELDS + 1)}
    with pytest.raises(ApprovalInputInvalid) as excinfo:
        ask(svc, binding=many)
    assert reason_of(excinfo) is ApprovalReason.INVALID_BINDING
    with pytest.raises(ApprovalInputInvalid) as excinfo:
        ask(svc, binding={"k": "v" * (rules.MAX_FIELD + 1)})
    assert reason_of(excinfo) is ApprovalReason.INVALID_BINDING
    with pytest.raises(ApprovalInputInvalid) as excinfo:
        ask(svc, binding={"k" * (rules.MAX_KEY + 1): "v"})
    assert reason_of(excinfo) is ApprovalReason.INVALID_BINDING
    at_limit = {f"k{i}": "v" * rules.MAX_FIELD for i in range(rules.MAX_BINDING_FIELDS)}
    assert len(ask(svc, binding=at_limit).binding) == rules.MAX_BINDING_FIELDS


def test_l3_note_length_limit(svc: ApprovalService, owner: Principal) -> None:
    made = ask(svc)
    with pytest.raises(ApprovalInputInvalid) as excinfo:
        svc.approve(made.approval_id, owner, note="n" * (rules.MAX_NOTE + 1))
    assert reason_of(excinfo) is ApprovalReason.INVALID_TEXT
    done = svc.approve(made.approval_id, owner, note="n" * rules.MAX_NOTE)
    assert len(done.decision_note) == rules.MAX_NOTE


def test_l3_actor_id_length_limit(svc: ApprovalService) -> None:
    with pytest.raises(ApprovalInputInvalid) as excinfo:
        ask(svc, requested_by="a" * (rules.MAX_ACTOR + 1))
    assert reason_of(excinfo) is ApprovalReason.INVALID_REQUESTER
    assert ask(svc, requested_by="a" * rules.MAX_ACTOR).requested_by == "a" * rules.MAX_ACTOR


def test_l3_an_over_long_correlation_id_is_refused_not_cut(svc: ApprovalService) -> None:
    with pytest.raises(ApprovalInputInvalid) as excinfo:
        ask(svc, correlation_id="c" * (rules.MAX_CORRELATION + 1))
    assert reason_of(excinfo) is ApprovalReason.INVALID_TEXT
    kept = ask(svc, correlation_id="c" * rules.MAX_CORRELATION)
    assert kept.correlation_id == "c" * rules.MAX_CORRELATION


# --- L4: list_pending by role -----------------------------------------------------------------


def test_l4_list_pending_by_role_skips_rows_nobody_with_that_role_can_decide(
    svc: ApprovalService, engine: Engine
) -> None:
    """P13: a stored role outside the approver list was listed for that role."""
    made = ask(svc)
    assert [r.approval_id for r in svc.list_pending(role=Role.SYSTEM_OWNER)] == [made.approval_id]
    tamper(engine, made.approval_id, required_roles='["security_admin"]')
    assert svc.list_pending(role=Role.SECURITY_ADMIN) == ()
    assert svc.list_pending(role=Role.SYSTEM_OWNER) == ()
    assert len(svc.list_pending()) == 1


# --- L5 (approvals side): withdrawing an orphan request ---------------------------------------


@pytest.mark.parametrize("approve_first", [False, True], ids=["pending", "approved"])
def test_l5_withdraw_makes_a_request_unusable_and_is_audited(
    svc: ApprovalService, audit: ScriptedAudit, owner: Principal, approve_first: bool
) -> None:
    made = ask(svc)
    if approve_first:
        svc.approve(made.approval_id, owner)
    gone = svc.withdraw(made.approval_id, actor_id="human_emp", actor_type=ActorType.HUMAN)
    assert gone.status is ApprovalStatus.VOID
    assert audit.outcomes(WITHDRAW_ACTION) == [AuditOutcome.ATTEMPT, AuditOutcome.SUCCESS]
    with pytest.raises(ApprovalInvalid) as excinfo:
        svc.consume(made.approval_id, **use_args())
    assert reason_of(excinfo) is ApprovalReason.VOIDED
    with pytest.raises(ApprovalConflict) as again:
        svc.approve(made.approval_id, owner)
    assert reason_of(again) is ApprovalReason.ALREADY_DECIDED


def test_l5_withdraw_voids_even_when_the_audit_path_is_down(
    svc: ApprovalService, audit: ScriptedAudit
) -> None:
    made = ask(svc)
    audit.fail = True
    with pytest.raises(ApprovalUnavailable) as excinfo:
        svc.withdraw(made.approval_id, actor_id="human_emp", actor_type=ActorType.HUMAN)
    assert reason_of(excinfo) is ApprovalReason.AUDIT_UNAVAILABLE
    audit.fail = False
    assert svc.get(made.approval_id).status is ApprovalStatus.VOID


def test_l5_withdraw_cannot_undo_a_consumed_approval(
    svc: ApprovalService, owner: Principal
) -> None:
    made = ask(svc)
    svc.approve(made.approval_id, owner)
    svc.consume(made.approval_id, **use_args())
    with pytest.raises(ApprovalUnavailable) as excinfo:
        svc.withdraw(made.approval_id, actor_id="human_emp", actor_type=ActorType.HUMAN)
    assert reason_of(excinfo) is ApprovalReason.VOID_FAILED
    assert svc.get(made.approval_id).status is ApprovalStatus.CONSUMED


def test_binding_constants_used_by_the_conftest_are_still_valid() -> None:
    assert rules.check_binding(BINDING) == BINDING
    assert rules.check_subject(KIND, HASH) == (KIND, HASH)
