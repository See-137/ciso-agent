"""Review-round fixes in the intake: reserved claim kinds (review M5), distinct SessionStart
ids (queue Q2) and the decision id as the central gate's reference (queue Q9)."""

from __future__ import annotations

from datetime import timedelta
from typing import Any

import pytest
from tests.fakes.core import FakeRedactor
from tests.intake.conftest import (
    DEVICE_ACTOR,
    DEVICE_NAME,
    RECEIVED_AT,
    envelope,
    hook_payload_pre_bash,
    hook_payload_session_start,
)
from tests.intake.test_gate_verdict import decision

from ciso.common.activity import Verdict
from ciso.intake import IntakeRefused, RefusalCode, normalize_hook_report, render_verdict

pytestmark = pytest.mark.unit


def normalize(request: Any, *, at: Any = RECEIVED_AT) -> Any:
    return normalize_hook_report(
        request, device_actor_id=DEVICE_ACTOR, device_name=DEVICE_NAME, received_at=at, redactor=FakeRedactor()
    )


# -- M5: a client cannot speak for the token or for the signed gate --------------------


@pytest.mark.parametrize(
    "kind", ["device_actor", "device_name", "assistant_account", "assistant_email"]
)
def test_a_client_claim_of_a_reserved_kind_is_refused(kind: str) -> None:
    claims = [{"kind": kind, "subject": "svc_someone_else", "verified": False}]
    with pytest.raises(IntakeRefused) as info:
        normalize(envelope(hook_payload_pre_bash(), claims=claims))
    assert info.value.code is RefusalCode.CLAIM_KIND_RESERVED


def test_only_the_token_device_actor_is_verified() -> None:
    claims = normalize(envelope(hook_payload_pre_bash())).action.identity_claims
    assert [(c.kind, c.subject) for c in claims if c.verified] == [("device_actor", DEVICE_ACTOR)]


# -- Q2: two session starts are two actions; a retry is the same one --------------------


def _start(**overrides: Any) -> dict[str, Any]:
    return envelope(hook_payload_session_start(), **overrides)


def test_two_reports_of_one_session_start_with_report_ids_differ() -> None:
    first = normalize(_start(report_id="r-0001")).action.action_id
    second = normalize(_start(report_id="r-0002")).action.action_id
    assert first != second


def test_a_retry_with_the_same_report_id_is_the_same_action() -> None:
    first = normalize(_start(report_id="r-0001")).action.action_id
    later = RECEIVED_AT + timedelta(seconds=3)
    retry = normalize(_start(report_id="r-0001"), at=later).action.action_id
    assert first == retry


def test_without_a_report_id_the_receive_time_separates_two_starts() -> None:
    first = normalize(_start()).action.action_id
    second = normalize(_start(), at=RECEIVED_AT + timedelta(minutes=5)).action.action_id
    assert first != second


def test_report_id_does_not_change_tool_event_ids() -> None:
    plain = normalize(envelope(hook_payload_pre_bash())).action.action_id
    tagged = normalize(envelope(hook_payload_pre_bash(), report_id="r-9")).action.action_id
    assert plain == tagged


@pytest.mark.parametrize("value", ["", "has space", 7, None, "x" * 129])
def test_a_bad_report_id_is_refused(value: Any) -> None:
    with pytest.raises(IntakeRefused) as info:
        normalize(_start(report_id=value))
    assert info.value.code is RefusalCode.INVALID_FIELD


# -- Q9: the gate's reference is the decision id ---------------------------------------


def test_gate_reference_is_the_decision_id() -> None:
    made = decision(Verdict.DENY, explanation="No.")
    body = render_verdict(made)
    assert body["reference_id"] == made.decision_id
    assert body["reference_id"] != made.action_id
