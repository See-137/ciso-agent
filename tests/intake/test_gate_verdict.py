"""The verdict body returned to the central gate, in the documented shape:
https://platform.claude.com/docs/en/manage-claude/inference-hooks-endpoint.md
("Return a verdict": `action` allow|deny; `deny_reason` at most 500 characters;
`reference_id` at most 50 characters from `[A-Za-z0-9._:/-]`)."""

from __future__ import annotations

import re
from datetime import UTC, datetime

import pytest

from ciso.common.activity import (
    Attribution,
    DecisionReason,
    GovernanceDecision,
    Verdict,
)
from ciso.common.ids import new_id
from ciso.intake import (
    MAX_DENY_REASON_CHARS,
    IntakeRefused,
    RefusalCode,
    render_frame_verdict,
    render_refusal,
    render_verdict,
)

pytestmark = pytest.mark.unit

REFERENCE_RE = re.compile(r"[A-Za-z0-9._:/-]{1,50}")


def decision(
    verdict: Verdict, *, explanation: str = "", action_id: str = "cg_" + "a" * 40
) -> GovernanceDecision:
    return GovernanceDecision(
        decision_id=new_id("dec"),
        action_id=action_id,
        session_id="s1",
        verdict=verdict,
        reasons=(DecisionReason(code="secret_in_prompt", detail="A secret was found"),),
        ruleset_version="v1",
        ruleset_hash="0" * 64,
        decided_at=datetime(2026, 11, 18, tzinfo=UTC),
        attribution=Attribution(session_id="s1"),
        explanation=explanation,
    )


def test_allow_is_exactly_the_documented_body() -> None:
    assert render_verdict(decision(Verdict.ALLOW)) == {"action": "allow"}


def test_deny_carries_reason_and_reference() -> None:
    made = decision(Verdict.DENY, explanation="Remove the API key and retry.")
    body = render_verdict(made)
    assert body == {
        "action": "deny",
        "deny_reason": "Remove the API key and retry.",
        "reference_id": made.decision_id,
    }
    assert REFERENCE_RE.fullmatch(body["reference_id"])


def test_ask_becomes_deny_because_the_gate_cannot_ask() -> None:
    body = render_verdict(decision(Verdict.ASK, explanation="Needs approval."))
    assert body["action"] == "deny"
    assert body["deny_reason"] == "Needs approval."


def test_deny_without_explanation_names_the_reason_code() -> None:
    body = render_verdict(decision(Verdict.DENY))
    assert "secret_in_prompt" in body["deny_reason"]


def test_deny_reason_is_cut_to_the_documented_limit() -> None:
    long = "x" * 510  # the contract bounds explanation at 512
    body = render_verdict(decision(Verdict.DENY, explanation=long))
    assert MAX_DENY_REASON_CHARS == 500
    assert len(body["deny_reason"]) == 500


def test_reference_id_does_not_depend_on_the_action_id_shape() -> None:
    for action_id in ("hk_" + "b" * 60, "has space"):
        made = decision(Verdict.DENY, action_id=action_id)
        assert render_verdict(made)["reference_id"] == made.decision_id


def test_frame_verdict_allows_only_when_every_decision_allows() -> None:
    allow = decision(Verdict.ALLOW)
    deny = decision(Verdict.DENY, explanation="No.", action_id="cg_" + "c" * 40)
    assert render_frame_verdict([allow, allow]) == {"action": "allow"}
    body = render_frame_verdict([allow, deny])
    assert body["action"] == "deny"
    assert body["reference_id"] == deny.decision_id


def test_frame_verdict_without_decisions_denies() -> None:
    assert render_frame_verdict([])["action"] == "deny"


def test_refusal_renders_a_deny_with_its_code() -> None:
    body = render_refusal(IntakeRefused(RefusalCode.MALFORMED_FRAME))
    assert body["action"] == "deny"
    assert body["reference_id"] == "malformed_frame"
    assert REFERENCE_RE.fullmatch(body["reference_id"])
    assert len(body["deny_reason"]) <= MAX_DENY_REASON_CHARS
