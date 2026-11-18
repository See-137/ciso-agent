"""Status lifecycle, who may move a finding, audit attempt -> transaction -> result."""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

import pytest
from sqlalchemy import Engine, select
from tests.fakes.core import FakePrincipals, make_principal
from tests.findings.conftest import (
    FakePeople,
    MakeService,
    ScriptedAudit,
    action,
    decision,
    lock_probe,
)

from ciso.common.activity import Verdict
from ciso.common.enums import ActorType, Role
from ciso.common.errors import AuthorizationError, Conflict, FailClosed, NotFound, ValidationFailed
from ciso.common.principal import Principal, RoleGrant
from ciso.common.protocols import AuditEvent
from ciso.findings import (
    ACCEPT_RISK_ACTION,
    ACKNOWLEDGE_ACTION,
    FALSE_POSITIVE_ACTION,
    RESOLVE_ACTION,
    Finding,
    FindingsService,
    FindingStatus,
)
from ciso.findings.tables import finding_transition

pytestmark = pytest.mark.unit

S = FindingStatus


def new_finding(svc: FindingsService, person_ref: str | None = "person:p_emp") -> Finding:
    out = svc.record(
        decision(Verdict.DENY, person_ref=person_ref), action(), None, decision_id="dec_1"
    )
    return out.findings[0]


# --- the lifecycle --------------------------------------------------------------------


def test_open_acknowledged_resolved(svc: FindingsService, engine: Engine) -> None:
    f = new_finding(svc)
    acked = svc.acknowledge("human_admin", f.finding_id)
    assert acked.status is S.ACKNOWLEDGED
    assert acked.status_changed_by == "human_admin"
    done = svc.resolve("human_admin", f.finding_id)
    assert done.status is S.RESOLVED
    assert done.version == 3
    with engine.connect() as conn:
        history = [
            (r.from_status, r.to_status, r.actor_id)
            for r in conn.execute(select(finding_transition).order_by(finding_transition.c.at))
        ]
    assert history == [
        ("open", "acknowledged", "human_admin"),
        ("acknowledged", "resolved", "human_admin"),
    ]


def test_open_cannot_jump_to_resolved(svc: FindingsService) -> None:
    f = new_finding(svc)
    with pytest.raises(Conflict):
        svc.resolve("human_admin", f.finding_id)


@pytest.mark.parametrize("first", ["open", "acknowledged"])
def test_risk_accepted_from_open_or_acknowledged_records_the_approval(
    svc: FindingsService, audit: ScriptedAudit, first: str
) -> None:
    f = new_finding(svc)
    if first == "acknowledged":
        svc.acknowledge("human_admin", f.finding_id)
    out = svc.accept_risk("human_admin", f.finding_id, "approval:apr_1")
    assert out.status is S.RISK_ACCEPTED
    assert out.approval_ref == "approval:apr_1"
    assert audit.find(ACCEPT_RISK_ACTION)[-1].details["approval_ref"] == "approval:apr_1"


@pytest.mark.parametrize("ref", ["", "approval apr_1", "x\n", "a" * 200])
def test_risk_accepted_requires_a_valid_approval_reference(svc: FindingsService, ref: str) -> None:
    f = new_finding(svc)
    with pytest.raises(ValidationFailed):
        svc.accept_risk("human_admin", f.finding_id, ref)
    assert svc.get("human_admin", f.finding_id).status is S.OPEN


def test_false_positive_requires_a_reason_and_records_it(svc: FindingsService) -> None:
    f = new_finding(svc)
    with pytest.raises(ValidationFailed):
        svc.mark_false_positive("human_admin", f.finding_id, "")
    with pytest.raises(ValidationFailed):
        svc.mark_false_positive("human_admin", f.finding_id, "bad\nreason")
    out = svc.mark_false_positive("human_admin", f.finding_id, "test repository fixture")
    assert out.status is S.FALSE_POSITIVE
    assert out.status_reason == "test repository fixture"


@pytest.mark.parametrize("terminal", ["resolved", "risk_accepted", "false_positive"])
def test_terminal_statuses_cannot_move(svc: FindingsService, terminal: str) -> None:
    f = new_finding(svc)
    if terminal == "resolved":
        svc.acknowledge("human_admin", f.finding_id)
        svc.resolve("human_admin", f.finding_id)
    elif terminal == "risk_accepted":
        svc.accept_risk("human_admin", f.finding_id, "approval:apr_1")
    else:
        svc.mark_false_positive("human_admin", f.finding_id, "noise")
    attempts: list[Callable[[], Finding]] = [
        lambda: svc.acknowledge("human_admin", f.finding_id),
        lambda: svc.resolve("human_admin", f.finding_id),
        lambda: svc.accept_risk("human_admin", f.finding_id, "approval:apr_2"),
        lambda: svc.mark_false_positive("human_admin", f.finding_id, "again"),
    ]
    for attempt in attempts:
        with pytest.raises(Conflict):
            attempt()


def test_unknown_finding_is_not_found(svc: FindingsService) -> None:
    with pytest.raises(NotFound):
        svc.acknowledge("human_admin", "fnd_01KAAAAAAAAAAAAAAAAAAAAAAA")


def test_findings_are_never_deleted(svc: FindingsService) -> None:
    assert not any(name.startswith(("delete", "remove", "purge")) for name in dir(svc))


# --- who may do what -----------------------------------------------------------------


def test_subject_person_may_acknowledge_their_own(svc: FindingsService) -> None:
    f = new_finding(svc, person_ref="person:p_emp")
    assert svc.acknowledge("human_emp", f.finding_id).status is S.ACKNOWLEDGED


def test_employee_may_not_acknowledge_someone_elses(
    svc: FindingsService, audit: ScriptedAudit
) -> None:
    f = new_finding(svc, person_ref="person:p_other")
    with pytest.raises(AuthorizationError):
        svc.acknowledge("human_emp", f.finding_id)
    assert audit.trail()[-1] == (ACKNOWLEDGE_ACTION, "denied")


def test_unattributed_finding_cannot_be_acknowledged_by_a_person_without_a_link(
    svc: FindingsService, people: FakePeople
) -> None:
    f = new_finding(svc, person_ref=None)
    people.links.pop("human_emp")
    with pytest.raises(AuthorizationError):
        svc.acknowledge("human_emp", f.finding_id)


@pytest.mark.parametrize(
    ("verb", "args", "action"),
    [
        ("resolve", (), RESOLVE_ACTION),
        ("accept_risk", ("approval:apr_1",), ACCEPT_RISK_ACTION),
        ("mark_false_positive", ("mine",), FALSE_POSITIVE_ACTION),
    ],
)
def test_subject_person_may_do_nothing_but_acknowledge(
    svc: FindingsService, audit: ScriptedAudit, verb: str, args: tuple[str, ...], action: str
) -> None:
    f = new_finding(svc)
    svc.acknowledge("human_emp", f.finding_id)
    with pytest.raises(AuthorizationError):
        getattr(svc, verb)("human_emp", f.finding_id, *args)
    assert audit.trail()[-1] == (action, "denied")


@pytest.mark.parametrize("actor", ["human_aud", "human_owner", "human_risk", "agent_ciso"])
def test_auditor_owners_and_agents_cannot_transition(svc: FindingsService, actor: str) -> None:
    f = new_finding(svc)
    with pytest.raises(AuthorizationError):
        svc.acknowledge(actor, f.finding_id)
    with pytest.raises(AuthorizationError):
        svc.mark_false_positive(actor, f.finding_id, "no")


def test_privilege_is_decided_on_the_resolver_now(
    svc: FindingsService, principals: FakePrincipals
) -> None:
    f = new_finding(svc, person_ref="person:p_other")
    principals.register(make_principal("human_admin", ActorType.HUMAN, Role.EMPLOYEE))
    with pytest.raises(AuthorizationError):
        svc.mark_false_positive("human_admin", f.finding_id, "revoked admin")
    assert "human_admin" in principals.lookups


def test_disabled_actor_is_refused(svc: FindingsService, principals: FakePrincipals) -> None:
    f = new_finding(svc)
    principals.remove("human_admin")
    with pytest.raises(AuthorizationError):
        svc.acknowledge("human_admin", f.finding_id)


def test_scoped_admin_grant_does_not_reach_findings(
    svc: FindingsService, principals: FakePrincipals
) -> None:
    f = new_finding(svc, person_ref="person:p_other")
    principals.register(
        make_principal(
            "human_admin",
            ActorType.HUMAN,
            Role.SECURITY_ADMIN,
            grants=(RoleGrant(role=Role.SECURITY_ADMIN, scope={"system": frozenset({"x"})}),),
        )
    )
    with pytest.raises(AuthorizationError):
        svc.acknowledge("human_admin", f.finding_id)


def test_identity_store_down_fails_closed(svc: FindingsService, principals: FakePrincipals) -> None:
    f = new_finding(svc)
    principals.broken = True
    with pytest.raises(FailClosed):
        svc.acknowledge("human_admin", f.finding_id)


def test_person_store_down_fails_closed_for_a_non_admin(
    svc: FindingsService, people: FakePeople
) -> None:
    f = new_finding(svc)
    people.broken = True
    with pytest.raises(FailClosed):
        svc.acknowledge("human_emp", f.finding_id)


# --- audit ordering ------------------------------------------------------------------


def test_transition_is_audited_attempt_then_success(
    svc: FindingsService, audit: ScriptedAudit
) -> None:
    f = new_finding(svc)
    svc.acknowledge("human_admin", f.finding_id)
    assert audit.trail()[-2:] == [(ACKNOWLEDGE_ACTION, "attempt"), (ACKNOWLEDGE_ACTION, "success")]
    assert audit.events[-1].target == f.ref
    assert audit.events[-1].details["from"] == "open"


def test_false_positive_reason_stays_out_of_audit(
    svc: FindingsService, audit: ScriptedAudit
) -> None:
    f = new_finding(svc)
    svc.mark_false_positive("human_admin", f.finding_id, "contains-private-words")
    assert "contains-private-words" not in repr(audit.events)


def test_transition_with_audit_down_changes_nothing(
    svc: FindingsService, audit: ScriptedAudit
) -> None:
    f = new_finding(svc)
    audit.fail = True
    with pytest.raises(FailClosed):
        svc.acknowledge("human_admin", f.finding_id)
    audit.fail = False
    assert svc.get("human_admin", f.finding_id).status is S.OPEN


def test_transition_result_audit_failure_raises_after_change(
    svc: FindingsService, audit: ScriptedAudit
) -> None:
    f = new_finding(svc)
    audit.fail_if = lambda e: e.action == ACKNOWLEDGE_ACTION and e.outcome.value == "success"
    with pytest.raises(FailClosed, match="not audited"):
        svc.acknowledge("human_admin", f.finding_id)
    audit.fail_if = None
    assert svc.get("human_admin", f.finding_id).status is S.ACKNOWLEDGED


def test_concurrent_change_between_check_and_write_is_a_conflict(
    svc: FindingsService, audit: ScriptedAudit
) -> None:
    f = new_finding(svc)
    fired: list[bool] = []

    def race(event: AuditEvent) -> None:
        if event.outcome.value == "attempt" and not fired:
            fired.append(True)
            audit.during = None
            svc.mark_false_positive("human_admin", f.finding_id, "someone else won")

    audit.during = race
    with pytest.raises(Conflict):
        svc.acknowledge("human_admin", f.finding_id)
    assert audit.trail()[-1] == (ACKNOWLEDGE_ACTION, "failed")


def test_transition_never_audits_or_resolves_under_the_write_lock(
    file_db: tuple[Path, Engine],
    make_service: MakeService,
    audit: ScriptedAudit,
    principals: FakePrincipals,
    people: FakePeople,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path, engine = file_db
    svc = make_service(engine=engine)
    f = new_finding(svc)
    probes: list[str] = []

    def probe(label: str) -> None:
        lock_probe(path)
        probes.append(label)

    real_resolve, real_person = principals.resolve, people.person_ref_of

    def resolve(actor_id: str) -> Principal | None:
        probe("resolve")
        return real_resolve(actor_id)

    def person_ref_of(actor_id: str) -> str | None:
        probe("person")
        return real_person(actor_id)

    monkeypatch.setattr(principals, "resolve", resolve)
    monkeypatch.setattr(people, "person_ref_of", person_ref_of)
    audit.during = lambda e: probe(f"{e.action}:{e.outcome.value}")
    svc.acknowledge("human_emp", f.finding_id)
    assert probes == [
        "resolve",
        "person",
        f"{ACKNOWLEDGE_ACTION}:attempt",
        f"{ACKNOWLEDGE_ACTION}:success",
    ]
