"""Which decisions create findings, dedupe, recommendations, evidence, audit order."""

from __future__ import annotations

from pathlib import Path

import pytest
from sqlalchemy import Engine, func, select
from tests.findings.conftest import (
    AGENT_REF,
    EMP_PERSON,
    SERVICE_ACTOR,
    MakeService,
    ScriptedAudit,
    action,
    decision,
    inspection,
    lock_probe,
)

from ciso.common.activity import Severity, Verdict
from ciso.common.errors import FailClosed, ValidationFailed
from ciso.findings import (
    GENERIC_RECOMMENDATION,
    RECORD_ACTION,
    FindingOrigin,
    FindingsService,
    FindingStatus,
    RecommendationCatalog,
)
from ciso.findings.tables import alert, finding

pytestmark = pytest.mark.unit


def rows(engine: Engine, table: object) -> int:
    with engine.connect() as conn:
        return int(conn.execute(select(func.count()).select_from(table)).scalar_one())  # type: ignore[arg-type]


# --- which decisions create findings --------------------------------------------------


def test_allowed_action_without_findings_creates_nothing(
    svc: FindingsService, engine: Engine
) -> None:
    out = svc.record(decision(Verdict.ALLOW), action(), inspection(), decision_id="dec_1")
    assert out.findings == ()
    assert out.alerts == ()
    assert rows(engine, finding) == 0


def test_allowed_action_with_only_low_findings_creates_nothing(svc: FindingsService) -> None:
    result = inspection(("style.lint", Severity.LOW), ("info.note", Severity.INFO))
    out = svc.record(decision(Verdict.ALLOW), action(), result, decision_id="dec_1")
    assert out.findings == ()


def test_allowed_action_with_medium_inspection_finding_creates_one(
    svc: FindingsService,
) -> None:
    result = inspection(("deps.vulnerable", Severity.MEDIUM), ("style.lint", Severity.LOW))
    out = svc.record(decision(Verdict.ALLOW), action(), result, decision_id="dec_1")
    assert [f.check_key for f in out.findings] == ["deps.vulnerable"]
    assert out.findings[0].origin is FindingOrigin.INSPECTION
    assert out.findings[0].verdict is Verdict.ALLOW


def test_deny_creates_a_decision_finding(svc: FindingsService) -> None:
    out = svc.record(decision(Verdict.DENY), action(), None, decision_id="dec_1")
    (f,) = out.findings
    assert f.origin is FindingOrigin.DECISION
    assert f.check_key == "decision.deny.push_protected_branch"
    assert f.category == "policy"
    assert f.status is FindingStatus.OPEN
    assert f.severity is Severity.MEDIUM
    assert out.created == (f.finding_id,)


def test_ask_creates_a_decision_finding(svc: FindingsService) -> None:
    out = svc.record(decision(Verdict.ASK), action(), None, decision_id="dec_1")
    (f,) = out.findings
    assert f.check_key == "decision.ask.push_protected_branch"
    assert f.severity is Severity.LOW


def test_deny_with_critical_inspection_creates_both(svc: FindingsService) -> None:
    result = inspection(("secrets.token", Severity.CRITICAL, "src/app.py:3"))
    out = svc.record(decision(Verdict.DENY), action(), result, decision_id="dec_1")
    assert sorted(f.origin.value for f in out.findings) == ["decision", "inspection"]


def test_finding_carries_attribution_target_and_decision(svc: FindingsService) -> None:
    act = action(repository="repo-x", branch="dev", path="src/a.py")
    out = svc.record(decision(Verdict.DENY), act, None, decision_id="dec_9")
    f = out.findings[0]
    assert (f.person_ref, f.agent_ref, f.session_id) == (EMP_PERSON, AGENT_REF, "ses_1")
    assert (f.repository, f.branch, f.path) == ("repo-x", "dev", "src/a.py")
    assert (f.decision_id, f.last_decision_id, f.verdict) == ("dec_9", "dec_9", Verdict.DENY)
    assert f.action_kind.value == "git_push"
    assert f.agent_class.value == "employee_operated"


# --- recommendation -------------------------------------------------------------------


def test_recommendation_comes_from_the_catalog(svc: FindingsService) -> None:
    result = inspection(("secrets.token", Severity.HIGH))
    out = svc.record(decision(Verdict.DENY), action(), result, decision_id="dec_1")
    texts = {f.origin: f.recommendation for f in out.findings}
    assert texts[FindingOrigin.DECISION] == "Open a pull request instead of pushing."
    assert texts[FindingOrigin.INSPECTION] == "Remove the credential and rotate it."


def test_missing_recommendation_gets_the_generic_text(svc: FindingsService) -> None:
    out = svc.record(
        decision(Verdict.DENY, code="unlisted_reason"), action(), None, decision_id="dec_1"
    )
    assert out.findings[0].recommendation == GENERIC_RECOMMENDATION


@pytest.mark.parametrize(
    "texts",
    [{"secrets.token": "line one\nline two"}, {"secrets.token": ""}, {"Bad Key": "fine"}],
)
def test_catalog_refuses_unsafe_text_or_keys(texts: dict[str, str]) -> None:
    with pytest.raises(ValueError, match="validation error for RecommendationCatalog"):
        RecommendationCatalog(by_check=texts)


# --- evidence and content ------------------------------------------------------------


def test_evidence_is_references_only_and_command_is_never_stored(
    svc: FindingsService, engine: Engine
) -> None:
    act = action(evidence_ref="evidence:ev_1")
    dec = decision(Verdict.DENY, finding_refs=("inspection:if_1",))
    out = svc.record(dec, act, None, decision_id="dec_1")
    assert out.findings[0].evidence_refs == (
        "decision:dec_1",
        "action:act_1",
        "evidence:ev_1",
        "inspection:if_1",
    )
    with engine.connect() as conn:
        dumped = repr([tuple(r) for r in conn.execute(select(finding))])
    assert "SUPERSECRET" not in dumped
    assert "git push" not in dumped
    assert "evidence:ev_1" not in repr(out.findings[0])


# --- dedupe ---------------------------------------------------------------------------


def test_repeat_folds_into_one_open_finding(
    svc: FindingsService, engine: Engine, clock: object
) -> None:
    first = svc.record(decision(Verdict.DENY), action(), None, decision_id="dec_1")
    clock.advance(minutes=5)  # type: ignore[attr-defined]
    second = svc.record(
        decision(Verdict.DENY, action_id="act_2"),
        action("act_2"),
        None,
        decision_id="dec_2",
    )
    assert rows(engine, finding) == 1
    f = second.findings[0]
    assert f.finding_id == first.findings[0].finding_id
    assert second.created == ()
    assert f.occurrences == 2
    assert f.last_seen > f.first_seen
    assert (f.decision_id, f.last_decision_id) == ("dec_1", "dec_2")


@pytest.mark.parametrize(
    ("dec_kw", "act_kw"),
    [
        ({"person_ref": "person:p_other"}, {}),
        ({"agent_ref": "agent:a_2"}, {}),
        ({}, {"repository": "repo-b"}),
        ({}, {"path": "other.py"}),
        ({"code": "another_rule"}, {}),
        ({"verdict": Verdict.ASK}, {}),
    ],
)
def test_different_person_agent_repo_location_or_check_is_a_new_finding(
    svc: FindingsService, engine: Engine, dec_kw: dict[str, object], act_kw: dict[str, str]
) -> None:
    svc.record(decision(Verdict.DENY), action(), None, decision_id="dec_1")
    verdict = dec_kw.pop("verdict", Verdict.DENY)
    out = svc.record(
        decision(verdict, action_id="act_2", **dec_kw),  # type: ignore[arg-type]
        action("act_2", **act_kw),  # type: ignore[arg-type]
        None,
        decision_id="dec_2",
    )
    assert len(out.created) == 1
    assert rows(engine, finding) == 2


def test_two_unknown_people_in_different_sessions_are_not_merged(
    svc: FindingsService, engine: Engine
) -> None:
    svc.record(decision(Verdict.DENY, person_ref=None), action(), None, decision_id="dec_1")
    svc.record(
        decision(Verdict.DENY, person_ref=None, action_id="act_2", session_id="ses_2"),
        action("act_2", session_id="ses_2"),
        None,
        decision_id="dec_2",
    )
    assert rows(engine, finding) == 2


def test_closed_finding_does_not_absorb_new_activity(svc: FindingsService, engine: Engine) -> None:
    first = svc.record(decision(Verdict.DENY), action(), None, decision_id="dec_1")
    svc.mark_false_positive("human_admin", first.findings[0].finding_id, "test fixture")
    out = svc.record(
        decision(Verdict.DENY, action_id="act_2"), action("act_2"), None, decision_id="dec_2"
    )
    assert len(out.created) == 1
    assert rows(engine, finding) == 2


def test_repeat_with_higher_severity_raises_the_finding(svc: FindingsService) -> None:
    svc.record(
        decision(Verdict.ALLOW),
        action(),
        inspection(("deps.vulnerable", Severity.MEDIUM)),
        decision_id="dec_1",
    )
    out = svc.record(
        decision(Verdict.ALLOW, action_id="act_2"),
        action("act_2"),
        inspection(("deps.vulnerable", Severity.HIGH), action_id="act_2"),
        decision_id="dec_2",
    )
    assert out.findings[0].severity is Severity.HIGH


# --- input consistency ---------------------------------------------------------------


@pytest.mark.parametrize("which", ["decision_action", "session", "inspection"])
def test_mismatched_records_are_refused(
    svc: FindingsService, engine: Engine, audit: ScriptedAudit, which: str
) -> None:
    dec, act, ins = decision(Verdict.DENY), action(), inspection()
    if which == "decision_action":
        # Inspection agrees with the action, so only the decision/action check can refuse.
        act, ins = action("act_other"), inspection(action_id="act_other")
    elif which == "session":
        act = action(session_id="ses_other")
    else:
        ins = inspection(action_id="act_other")
    with pytest.raises(ValidationFailed):
        svc.record(dec, act, ins, decision_id="dec_1")
    assert rows(engine, finding) == 0
    assert audit.events == []


@pytest.mark.parametrize("bad", ["", "dec 1", "dec/../x", "d" * 200])
def test_bad_decision_id_is_refused(svc: FindingsService, bad: str) -> None:
    with pytest.raises(ValidationFailed):
        svc.record(decision(Verdict.DENY), action(), None, decision_id=bad)


def test_service_actor_id_is_required(make_service: MakeService) -> None:
    with pytest.raises(ValidationFailed):
        make_service(service_actor_id="")


# --- audit ordering ------------------------------------------------------------------


def test_record_is_audited_attempt_then_success(svc: FindingsService, audit: ScriptedAudit) -> None:
    out = svc.record(decision(Verdict.DENY), action(), None, decision_id="dec_1")
    assert audit.trail() == [(RECORD_ACTION, "attempt"), (RECORD_ACTION, "success")]
    done = audit.events[-1]
    assert done.actor_id == SERVICE_ACTOR
    assert done.details["created"] == [out.findings[0].finding_id]
    assert "SUPERSECRET" not in repr(audit.events)


def test_allowed_clean_action_is_not_audited_here(
    svc: FindingsService, audit: ScriptedAudit
) -> None:
    svc.record(decision(Verdict.ALLOW), action(), None, decision_id="dec_1")
    assert audit.events == []


def test_record_with_audit_down_stores_nothing(
    svc: FindingsService, engine: Engine, audit: ScriptedAudit
) -> None:
    audit.fail = True
    with pytest.raises(FailClosed):
        svc.record(decision(Verdict.DENY), action(), None, decision_id="dec_1")
    assert rows(engine, finding) == 0
    assert rows(engine, alert) == 0


def test_record_result_audit_failure_raises_after_storing(
    svc: FindingsService, engine: Engine, audit: ScriptedAudit
) -> None:
    audit.fail_if = lambda e: e.outcome.value == "success"
    with pytest.raises(FailClosed, match="not audited"):
        svc.record(decision(Verdict.DENY), action(), None, decision_id="dec_1")
    assert rows(engine, finding) == 1


def test_record_never_audits_or_delivers_under_the_write_lock(
    file_db: tuple[Path, Engine], make_service: MakeService, audit: ScriptedAudit
) -> None:
    path, engine = file_db
    probes: list[str] = []

    def probe(label: str) -> None:
        lock_probe(path)
        probes.append(label)

    class ProbeSink:
        def deliver(self, alert: object) -> None:
            probe("deliver")

    audit.during = lambda e: probe(f"{e.action}:{e.outcome.value}")
    svc = make_service(engine=engine, alert_sink=ProbeSink())
    svc.record(decision(Verdict.DENY), action(), None, decision_id="dec_1")
    assert probes == [f"{RECORD_ACTION}:attempt", f"{RECORD_ACTION}:success", "deliver"]
