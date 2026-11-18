"""Contract additions for the integration lane: decision id, turn end, remediation, the
content bound and the person-reference kind."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from ciso.common.activity import (
    MAX_INSPECTION_CHARS,
    PERSON_REF_KIND,
    ActionKind,
    Attribution,
    DecisionReason,
    GovernanceDecision,
    InspectionFinding,
    InspectionInput,
    Severity,
    Verdict,
)
from ciso.common.ids import new_id

pytestmark = pytest.mark.unit

NOW = datetime(2026, 11, 19, tzinfo=UTC)


def _decision(**overrides: object) -> GovernanceDecision:
    fields: dict[str, object] = {
        "decision_id": new_id("dec"),
        "action_id": "act_1",
        "session_id": "s1",
        "verdict": Verdict.DENY,
        "reasons": (DecisionReason(code="rule_deny", detail="rule deny"),),
        "ruleset_version": "v1",
        "ruleset_hash": "0" * 64,
        "decided_at": NOW,
        "attribution": Attribution(session_id="s1"),
    }
    fields.update(overrides)
    return GovernanceDecision.model_validate(fields)


def test_a_decision_carries_a_platform_decision_id() -> None:
    assert _decision().decision_id.startswith("dec_")


@pytest.mark.parametrize("bad", ["", "dec_1", "fnd_01J0000000000000000000000Z", "dec_x;rm"])
def test_a_decision_id_must_be_a_platform_dec_id(bad: str) -> None:
    with pytest.raises(ValidationError):
        _decision(decision_id=bad)


def test_a_decision_without_an_id_is_refused() -> None:
    fields = _decision().model_dump()
    del fields["decision_id"]
    with pytest.raises(ValidationError):
        GovernanceDecision.model_validate(fields)


def test_turn_end_is_an_action_kind() -> None:
    assert ActionKind("turn_end") is ActionKind.TURN_END


def test_a_finding_carries_clean_remediation() -> None:
    finding = InspectionFinding(
        check_id="secret.x", category="secret", severity=Severity.HIGH, detail="d",
        remediation="Rotate the key",
    )  # fmt: skip
    assert finding.remediation == "Rotate the key"
    with pytest.raises(ValidationError):
        InspectionFinding(
            check_id="secret.x", category="secret", severity=Severity.HIGH, detail="d",
            remediation="line\nforged",
        )  # fmt: skip


def test_inspection_content_at_the_bound_is_accepted_and_above_it_refused() -> None:
    at = InspectionInput(
        action_id="a", kind=ActionKind.FILE_WRITE, content="x" * MAX_INSPECTION_CHARS
    )
    assert at.content is not None
    with pytest.raises(ValidationError) as caught:
        InspectionInput(
            action_id="a", kind=ActionKind.FILE_WRITE, content="y" * (MAX_INSPECTION_CHARS + 1)
        )
    assert "yyyy" not in str(caught.value)


def test_the_person_reference_kind_is_actor() -> None:
    assert PERSON_REF_KIND == "actor"
