"""List with filters, get one, summary counts."""

from __future__ import annotations

from datetime import timedelta

import pytest
from tests.fakes.core import FakePrincipals
from tests.findings.conftest import ScriptedAudit, action, decision, inspection

from ciso.common.activity import Severity, Verdict
from ciso.common.clock import FixedClock
from ciso.common.errors import AuthorizationError, FailClosed, NotFound
from ciso.findings import READ_ACTION, FindingFilter, FindingsService, FindingStatus

pytestmark = pytest.mark.unit


@pytest.fixture
def seeded(svc: FindingsService, clock: FixedClock) -> FindingsService:
    """Three findings: deny/emp/repo-a (medium), critical secret/emp/repo-a, deny/other/repo-b."""
    svc.record(
        decision(Verdict.DENY),
        action(),
        inspection(("secrets.token", Severity.CRITICAL, "a.py:1")),
        decision_id="dec_1",
    )
    clock.advance(hours=2)
    svc.record(
        decision(Verdict.DENY, action_id="act_2", person_ref="person:p_other", agent_ref="agent:b"),
        action("act_2", repository="repo-b"),
        None,
        decision_id="dec_2",
    )
    return svc


def test_list_all_newest_first(seeded: FindingsService) -> None:
    found = seeded.list("human_admin")
    assert len(found) == 3
    assert found[0].repository == "repo-b"


@pytest.mark.parametrize(
    ("filters", "expected"),
    [
        (FindingFilter(severity=Severity.CRITICAL), 1),
        (FindingFilter(person_ref="person:p_other"), 1),
        (FindingFilter(agent_ref="agent:b"), 1),
        (FindingFilter(repository="repo-a"), 2),
        (FindingFilter(status=FindingStatus.OPEN), 3),
        (FindingFilter(status=FindingStatus.RESOLVED), 0),
        (FindingFilter(limit=2), 2),
    ],
)
def test_list_filters(seeded: FindingsService, filters: FindingFilter, expected: int) -> None:
    assert len(seeded.list("human_admin", filters)) == expected


def test_list_since(seeded: FindingsService, clock: FixedClock) -> None:
    since = clock.now() - timedelta(hours=1)
    found = seeded.list("human_admin", FindingFilter(since=since))
    assert [f.repository for f in found] == ["repo-b"]


def test_get_one(seeded: FindingsService) -> None:
    first = seeded.list("human_aud")[0]
    assert seeded.get("human_aud", first.finding_id) == first


def test_get_missing_is_not_found(seeded: FindingsService) -> None:
    with pytest.raises(NotFound):
        seeded.get("human_admin", "fnd_01KAAAAAAAAAAAAAAAAAAAAAAA")


def test_summary_counts(seeded: FindingsService) -> None:
    f = seeded.list("human_admin", FindingFilter(severity=Severity.CRITICAL))[0]
    seeded.acknowledge("human_admin", f.finding_id)
    summary = seeded.summary("human_aud")
    assert summary.total == 3
    assert dict(summary.by_severity) == {"critical": 1, "medium": 2}
    assert dict(summary.by_status) == {"acknowledged": 1, "open": 2}
    narrowed = seeded.summary("human_aud", FindingFilter(repository="repo-b"))
    assert narrowed.total == 1


def test_reads_are_audited(seeded: FindingsService, audit: ScriptedAudit) -> None:
    seeded.list("human_aud")
    assert audit.trail()[-1] == (READ_ACTION, "success")
    assert audit.events[-1].actor_id == "human_aud"


def test_read_with_audit_down_returns_nothing(
    seeded: FindingsService, audit: ScriptedAudit
) -> None:
    audit.fail = True
    with pytest.raises(FailClosed):
        seeded.list("human_admin")


@pytest.mark.parametrize("actor", ["human_emp", "human_owner", "agent_ciso", "nobody"])
def test_only_admin_and_auditor_read_everything(seeded: FindingsService, actor: str) -> None:
    with pytest.raises(AuthorizationError):
        seeded.list(actor)
    with pytest.raises(AuthorizationError):
        seeded.summary(actor)


def test_read_decided_on_resolver_now(seeded: FindingsService, principals: FakePrincipals) -> None:
    principals.remove("human_aud")
    with pytest.raises(AuthorizationError):
        seeded.list("human_aud")
