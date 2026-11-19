"""Review L1: the subject of a finding cannot quiet its future alerts, and a repeat that
raises a finding into high or critical always alerts."""

from __future__ import annotations

import pytest
from sqlalchemy import Engine, select
from tests.findings.conftest import SERVICE_ACTOR, action, decision, inspection

from ciso.common.activity import Severity, Verdict
from ciso.findings import AlertTrigger, FindingsService, FindingStatus
from ciso.findings.tables import finding_transition

pytestmark = pytest.mark.unit

CHECK = "secrets.token"


def _record(svc: FindingsService, n: int, level: Severity) -> object:
    return svc.record(
        decision(Verdict.ALLOW, action_id=f"act_{n}"),
        action(f"act_{n}"),
        inspection((CHECK, level), action_id=f"act_{n}"),
        decision_id=f"dec_{n}",
    )


def _severe(outcome: object) -> list[str]:
    return [
        a.decision_id
        for a in outcome.alerts  # type: ignore[attr-defined]
        if a.trigger is AlertTrigger.SEVERE_FINDING
    ]


def test_a_repeat_raising_high_to_critical_alerts(svc: FindingsService) -> None:
    assert _severe(_record(svc, 1, Severity.HIGH)) == ["dec_1"]
    raised = _record(svc, 2, Severity.CRITICAL)
    assert raised.created == ()  # type: ignore[attr-defined]
    assert _severe(raised) == ["dec_2"]


@pytest.mark.parametrize("by", ["human_emp", "human_admin"])
def test_an_acknowledged_finding_alerts_again_on_a_severe_repeat_and_reopens(
    svc: FindingsService, engine: Engine, by: str
) -> None:
    first = _record(svc, 1, Severity.HIGH)
    finding_id = first.findings[0].finding_id  # type: ignore[attr-defined]
    acked = svc.acknowledge(by, finding_id)
    assert acked.status is FindingStatus.ACKNOWLEDGED
    again = _record(svc, 2, Severity.HIGH)
    assert again.created == ()  # type: ignore[attr-defined]
    assert _severe(again) == ["dec_2"]
    (reopened,) = again.findings  # type: ignore[attr-defined]
    assert reopened.finding_id == finding_id
    assert reopened.status is FindingStatus.OPEN
    assert reopened.status_changed_by == SERVICE_ACTOR
    with engine.connect() as conn:
        moves = conn.execute(
            select(
                finding_transition.c.from_status,
                finding_transition.c.to_status,
                finding_transition.c.actor_id,
            ).order_by(finding_transition.c.at, finding_transition.c.transition_id)
        ).all()
    assert [tuple(m) for m in moves][-1] == ("acknowledged", "open", SERVICE_ACTOR)


def test_an_open_finding_repeating_at_the_same_level_does_not_alert_again(
    svc: FindingsService,
) -> None:
    _record(svc, 1, Severity.HIGH)
    assert _severe(_record(svc, 2, Severity.HIGH)) == []


def test_an_acknowledged_finding_repeating_below_high_stays_quiet(
    svc: FindingsService,
) -> None:
    first = _record(svc, 1, Severity.MEDIUM)
    svc.acknowledge("human_emp", first.findings[0].finding_id)  # type: ignore[attr-defined]
    again = _record(svc, 2, Severity.MEDIUM)
    assert _severe(again) == []
    assert again.findings[0].status is FindingStatus.ACKNOWLEDGED  # type: ignore[attr-defined]
