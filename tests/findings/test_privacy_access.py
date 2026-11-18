"""Access segregation: a person sees only findings about themselves; minimised content."""

from __future__ import annotations

import pytest
from tests.findings.conftest import (
    OTHER_PERSON,
    FakePeople,
    ScriptedAudit,
    action,
    decision,
)

from ciso.common.activity import Verdict
from ciso.common.errors import AuthorizationError, FailClosed, ValidationFailed
from ciso.findings import READ_ACTION, FindingFilter, FindingsService, InMemoryAlertSink

pytestmark = pytest.mark.privacy


@pytest.fixture
def two_people(svc: FindingsService) -> FindingsService:
    svc.record(decision(Verdict.DENY), action(), None, decision_id="dec_1")
    svc.record(
        decision(Verdict.DENY, action_id="act_2", person_ref=OTHER_PERSON),
        action("act_2"),
        None,
        decision_id="dec_2",
    )
    return svc


def test_own_read_returns_only_my_findings(two_people: FindingsService) -> None:
    mine = two_people.list_own("human_emp")
    assert [f.person_ref for f in mine] == ["person:p_emp"]


def test_own_read_cannot_name_someone_else(two_people: FindingsService) -> None:
    with pytest.raises(ValidationFailed):
        two_people.list_own("human_emp", FindingFilter(person_ref=OTHER_PERSON))


def test_own_read_ignores_nothing_else_and_filters_still_apply(
    two_people: FindingsService,
) -> None:
    assert two_people.list_own("human_emp", FindingFilter(repository="repo-none")) == ()


def test_actor_without_a_person_link_is_refused(
    two_people: FindingsService, people: FakePeople
) -> None:
    people.links.pop("human_emp")
    with pytest.raises(AuthorizationError):
        two_people.list_own("human_emp")


def test_own_read_uses_the_link_resolved_now(
    two_people: FindingsService, people: FakePeople
) -> None:
    people.links["human_emp"] = OTHER_PERSON
    assert [f.person_ref for f in two_people.list_own("human_emp")] == [OTHER_PERSON]


def test_own_read_refuses_unknown_or_non_human_actors(two_people: FindingsService) -> None:
    for actor in ("nobody", "agent_ciso", "svc_connector"):
        with pytest.raises(AuthorizationError):
            two_people.list_own(actor)


def test_own_read_with_person_store_down_fails_closed(
    two_people: FindingsService, people: FakePeople
) -> None:
    people.broken = True
    with pytest.raises(FailClosed):
        two_people.list_own("human_emp")


def test_own_read_is_audited(two_people: FindingsService, audit: ScriptedAudit) -> None:
    two_people.list_own("human_emp")
    assert audit.trail()[-1] == (READ_ACTION, "success")
    assert audit.events[-1].details["scope"] == "own"


def test_employee_cannot_get_one_finding_by_id(two_people: FindingsService) -> None:
    other = two_people.list("human_admin", FindingFilter(person_ref=OTHER_PERSON))[0]
    with pytest.raises(AuthorizationError):
        two_people.get("human_emp", other.finding_id)


def test_alert_content_is_minimised(svc: FindingsService, sink: InMemoryAlertSink) -> None:
    act = action(evidence_ref="evidence:ev_1", path="src/secret_config.py")
    svc.record(decision(Verdict.DENY), act, None, decision_id="dec_1")
    (alert,) = sink.delivered
    payload = alert.payload()
    assert set(payload) == {
        "alert_id",
        "trigger",
        "finding_id",
        "decision_id",
        "severity",
        "title",
        "person_ref",
        "agent_ref",
        "repository",
        "branch",
        "recommendation",
        "created_at",
    }
    text = repr(payload) + repr(alert)
    for leak in ("SUPERSECRET", "git push", "evidence:ev_1", "rule matched"):
        assert leak not in text


def test_subject_person_may_get_their_own_finding(two_people: FindingsService) -> None:
    mine = two_people.list_own("human_emp")[0]
    assert two_people.get("human_emp", mine.finding_id) == mine
