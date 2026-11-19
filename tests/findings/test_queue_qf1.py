"""Fix round QF1: pre-push protocol steps make no findings and no alerts.

The pre-push flow (docs/skill/decision-api.md, "Pre-push change upload") answers a push or
commit asked without its change with a deny whose only reason is `inspection_incomplete`
(the client then uploads the change), and a push whose sandbox report is not back with
`checks_pending`. Both are steps of the protocol, not problems: they must not create a
finding or an alert. The final verdict on the scanned change does.
"""

from __future__ import annotations

import pytest
from sqlalchemy import Engine, func, select
from tests.findings.conftest import action, decision, inspection

from ciso.common.activity import (
    ActionKind,
    InspectionFinding,
    InspectionResult,
    Phase,
    Severity,
    Verdict,
)
from ciso.findings import FindingsService, InMemoryAlertSink
from ciso.findings.rules import is_protocol_step
from ciso.findings.tables import alert, finding

pytestmark = pytest.mark.unit


def rows(engine: Engine, table: object) -> int:
    with engine.connect() as conn:
        return int(conn.execute(select(func.count()).select_from(table)).scalar_one())  # type: ignore[arg-type]


def _finding(check_id: str, category: str, severity: Severity) -> InspectionFinding:
    return InspectionFinding(
        check_id=check_id, category=category, severity=severity, detail="a problem was found"
    )


#: What the inspector says about a push or commit whose change is not attached yet.
CONTENT_MISSING = _finding("inspection.content_missing", "coverage", Severity.MEDIUM)


def incomplete(*findings: InspectionFinding) -> InspectionResult:
    return InspectionResult(
        action_id="act_1", checks_run=("inspection.size",), findings=findings, complete=False
    )


FIRST_ASKS = [
    (ActionKind.GIT_PUSH, incomplete(CONTENT_MISSING)),
    (ActionKind.GIT_COMMIT, incomplete(CONTENT_MISSING)),
    (ActionKind.SHELL_COMMAND, incomplete()),
]


@pytest.mark.parametrize(("kind", "result"), FIRST_ASKS)
def test_the_first_ask_of_a_push_or_commit_makes_no_finding_and_no_alert(
    svc: FindingsService,
    engine: Engine,
    sink: InMemoryAlertSink,
    kind: ActionKind,
    result: InspectionResult,
) -> None:
    held = decision(Verdict.DENY, code="inspection_incomplete")
    act = action(kind=kind)
    assert is_protocol_step(held, act, result) is True
    out = svc.record(held, act, result, decision_id="dec_1")
    assert out.findings == ()
    assert out.alerts == ()
    assert rows(engine, finding) == 0
    assert rows(engine, alert) == 0
    assert sink.delivered == []


def test_checks_pending_makes_no_finding(svc: FindingsService, engine: Engine) -> None:
    pending = decision(Verdict.DENY, code="checks_pending")
    out = svc.record(pending, action(), None, decision_id="dec_1")
    assert out.findings == ()
    assert rows(engine, finding) == 0


def test_a_problem_in_the_command_text_is_still_recorded_on_the_first_ask(
    svc: FindingsService, engine: Engine
) -> None:
    secret = _finding("secret.assignment", "secret", Severity.HIGH)
    held = decision(Verdict.DENY, code="inspection_incomplete")
    out = svc.record(held, action(), incomplete(CONTENT_MISSING, secret), decision_id="dec_1")
    assert [f.check_key for f in out.findings] == ["secret.assignment"]
    assert rows(engine, finding) == 1


def test_the_final_verdict_on_the_scanned_change_makes_findings_and_alerts(
    svc: FindingsService, engine: Engine
) -> None:
    final = decision(Verdict.DENY, code="rule_deny")
    failed = inspection(("test_failure.sandbox", Severity.HIGH))
    out = svc.record(final, action(), failed, decision_id="dec_2")
    keys = {f.check_key for f in out.findings}
    assert keys == {"decision.deny.rule_deny", "test_failure.sandbox"}
    assert len(out.alerts) >= 2  # the severe finding and the BEFORE deny
    assert rows(engine, finding) == 2


@pytest.mark.parametrize(
    ("kind", "phase", "codes", "result"),
    [
        # The sandbox could not check the change: a real gap, not a protocol step.
        (
            ActionKind.GIT_PUSH,
            Phase.BEFORE,
            "inspection_incomplete",
            incomplete(_finding("sandbox.unavailable", "coverage", Severity.HIGH)),
        ),
        # A line too long to inspect.
        (
            ActionKind.SHELL_COMMAND,
            Phase.BEFORE,
            "inspection_incomplete",
            incomplete(_finding("inspection.line_too_long", "coverage", Severity.MEDIUM)),
        ),
        # Not a push or commit.
        (ActionKind.FILE_WRITE, Phase.BEFORE, "inspection_incomplete", incomplete()),
        # Reported after the fact.
        (ActionKind.GIT_PUSH, Phase.AFTER, "inspection_incomplete", incomplete()),
        # Another reason as well.
        (ActionKind.GIT_PUSH, Phase.BEFORE, "rule_deny", incomplete()),
        # A complete inspection cannot be "not attached yet".
        (ActionKind.GIT_PUSH, Phase.BEFORE, "inspection_incomplete", inspection()),
        # No inspection at all.
        (ActionKind.GIT_PUSH, Phase.BEFORE, "inspection_incomplete", None),
    ],
)
def test_other_incomplete_inspections_still_make_a_decision_finding(
    svc: FindingsService,
    kind: ActionKind,
    phase: Phase,
    codes: str,
    result: InspectionResult | None,
) -> None:
    held = decision(Verdict.DENY, code=codes)
    act = action(kind=kind, phase=phase)
    assert is_protocol_step(held, act, result) is False
    out = svc.record(held, act, result, decision_id="dec_1")
    assert f"decision.deny.{codes}" in {f.check_key for f in out.findings}


def test_two_reasons_are_not_a_protocol_step(svc: FindingsService) -> None:
    held = decision(Verdict.DENY, code="inspection_incomplete")
    held = held.model_copy(update={"reasons": (*held.reasons, *decision(code="rule_deny").reasons)})
    assert is_protocol_step(held, action(), incomplete(CONTENT_MISSING)) is False


def test_an_ask_or_allow_is_never_a_protocol_step() -> None:
    for verdict in (Verdict.ASK, Verdict.ALLOW):
        held = decision(verdict, code="checks_pending")
        assert is_protocol_step(held, action(), incomplete()) is False
