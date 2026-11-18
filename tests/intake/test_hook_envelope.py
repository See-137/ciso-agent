"""The decision-API envelope (docs/skill/decision-api.md) is checked strictly: every
refusal path has a named reason code, and the allowed path produces a record."""

from __future__ import annotations

import copy
from typing import Any

import pytest
from tests.fakes.core import FakeRedactor
from tests.intake.conftest import (
    DEVICE_ACTOR,
    RECEIVED_AT,
    envelope,
    hook_payload_pre_bash,
    hook_payload_prompt,
    hook_payload_session_end,
    pre_tool,
)

from ciso.common.activity import ActionKind, ActivitySource, Phase
from ciso.intake import (
    MAX_REQUEST_BYTES,
    IntakeRefused,
    RefusalCode,
    normalize_hook_report,
)

pytestmark = pytest.mark.unit


def normalize(request: Any) -> Any:
    return normalize_hook_report(
        request, device_actor_id=DEVICE_ACTOR, received_at=RECEIVED_AT, redactor=FakeRedactor()
    )


def refused(request: Any) -> RefusalCode:
    with pytest.raises(IntakeRefused) as info:
        normalize(request)
    return info.value.code


def test_documented_pre_tool_use_example_is_accepted() -> None:
    report = normalize(envelope(hook_payload_pre_bash()))
    action = report.action
    assert action.kind is ActionKind.SHELL_COMMAND
    assert action.phase is Phase.BEFORE
    assert action.source is ActivitySource.HOOK
    assert action.session_id == "abc123"
    assert action.tool_name == "Bash"
    assert action.surface == "cli"
    assert action.received_at == RECEIVED_AT
    assert action.command == "npm test"
    assert action.command_truncated is False
    assert action.target["repository"] == "my-project"


def test_request_must_be_an_object() -> None:
    assert refused(["not", "an", "object"]) is RefusalCode.INVALID_FIELD


def test_unknown_envelope_field_is_refused() -> None:
    assert refused(envelope(hook_payload_pre_bash(), extra="x")) is RefusalCode.UNKNOWN_FIELD


@pytest.mark.parametrize("missing", ["format", "event", "surface", "claims", "payload"])
def test_missing_envelope_field_is_refused(missing: str) -> None:
    request = envelope(hook_payload_pre_bash())
    del request[missing]
    assert refused(request) is RefusalCode.MISSING_FIELD


def test_other_format_is_refused() -> None:
    request = envelope(hook_payload_pre_bash(), format="central_gate_v1")
    assert refused(request) is RefusalCode.UNSUPPORTED_FORMAT


def test_unknown_event_is_refused() -> None:
    payload = hook_payload_pre_bash()
    payload["hook_event_name"] = "PermissionRequest"
    assert refused(envelope(payload)) is RefusalCode.UNKNOWN_EVENT


def test_event_must_match_the_payload() -> None:
    request = envelope(hook_payload_pre_bash(), event="PostToolUse")
    assert refused(request) is RefusalCode.EVENT_MISMATCH


def test_oversized_request_is_refused() -> None:
    request = pre_tool("Bash", {"command": "x" * (MAX_REQUEST_BYTES + 1)})
    assert refused(request) is RefusalCode.REQUEST_TOO_LARGE


def test_a_request_just_under_the_bound_is_accepted() -> None:
    request = pre_tool("Bash", {"command": "x" * (MAX_REQUEST_BYTES - 2000)})
    assert normalize(request).action.command_truncated is True


def test_non_json_values_are_refused() -> None:
    request = envelope(hook_payload_pre_bash())
    request["payload"]["tool_input"]["timeout"] = float("nan")
    assert refused(request) is RefusalCode.NOT_JSON
    request = envelope(hook_payload_pre_bash())
    request["payload"]["tool_input"]["obj"] = object()
    assert refused(request) is RefusalCode.NOT_JSON


def test_excessive_nesting_is_refused() -> None:
    deep: dict[str, Any] = {}
    cursor = deep
    for _ in range(100):
        cursor["a"] = {}
        cursor = cursor["a"]
    request = pre_tool("Bash", {"command": "ls", "deep": deep})
    assert refused(request) is RefusalCode.NOT_JSON


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("surface", "CLI with spaces"),
        ("surface", ""),
        ("device", "WS\n0142"),
        ("device", 42),
        ("claims", "CORP\\jdoe"),
        ("payload", []),
    ],
)
def test_bad_envelope_values_are_refused(field: str, value: Any) -> None:
    request = envelope(hook_payload_pre_bash())
    request[field] = value
    assert refused(request) is RefusalCode.INVALID_FIELD


def test_claim_marked_verified_by_the_client_is_refused() -> None:
    claims = [{"kind": "os_account", "subject": "CORP\\jdoe", "verified": True}]
    request = envelope(hook_payload_pre_bash(), claims=claims)
    assert refused(request) is RefusalCode.CLAIM_MARKED_VERIFIED


@pytest.mark.parametrize(
    "claim",
    [
        {"kind": "os_account", "subject": "CORP\\jdoe"},
        {"kind": "os_account", "subject": "CORP\\jdoe", "verified": False, "x": 1},
        {"kind": "OS Account", "subject": "CORP\\jdoe", "verified": False},
        {"kind": "os_account", "subject": "line\nbreak", "verified": False},
        {"kind": "os_account", "subject": "", "verified": False},
    ],
)
def test_malformed_claims_are_refused(claim: dict[str, Any]) -> None:
    assert refused(envelope(hook_payload_pre_bash(), claims=[claim])) is RefusalCode.INVALID_FIELD


def test_too_many_claims_are_refused() -> None:
    claim = {"kind": "os_account", "subject": "CORP\\jdoe", "verified": False}
    request = envelope(hook_payload_pre_bash(), claims=[claim] * 17)
    assert refused(request) is RefusalCode.INVALID_FIELD


def test_claims_are_kept_unverified_and_the_device_actor_is_verified() -> None:
    claims = normalize(envelope(hook_payload_pre_bash())).action.identity_claims
    by_kind = {claim.kind: claim for claim in claims}
    assert by_kind["os_account"].subject == "CORP\\jdoe"
    assert by_kind["os_account"].verified is False
    assert by_kind["device_name"].subject == "WS-0142"
    assert by_kind["device_name"].verified is False
    assert by_kind["device_actor"].subject == DEVICE_ACTOR
    assert by_kind["device_actor"].verified is True


@pytest.mark.parametrize("field", ["session_id", "hook_event_name"])
def test_payload_without_required_common_field_is_refused(field: str) -> None:
    payload = hook_payload_pre_bash()
    del payload[field]
    request = envelope(hook_payload_pre_bash())
    request["payload"] = payload
    assert refused(request) is RefusalCode.MISSING_FIELD


@pytest.mark.parametrize("field", ["tool_name", "tool_input", "tool_use_id"])
def test_tool_event_without_tool_fields_is_refused(field: str) -> None:
    payload = hook_payload_pre_bash()
    del payload[field]
    code = refused(envelope(payload))
    expected = (
        RefusalCode.MISSING_CORRELATION_ID if field == "tool_use_id" else RefusalCode.MISSING_FIELD
    )
    assert code is expected


def test_prompt_without_prompt_id_is_refused() -> None:
    payload = hook_payload_prompt()
    del payload["prompt_id"]
    assert refused(envelope(payload)) is RefusalCode.MISSING_CORRELATION_ID


def test_prompt_without_text_is_refused() -> None:
    payload = hook_payload_prompt()
    payload["prompt"] = 7
    assert refused(envelope(payload)) is RefusalCode.INVALID_FIELD


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("session_id", ""),
        ("session_id", "abc 123"),
        ("session_id", "x" * 200),
        ("tool_use_id", "toolu\n1"),
        ("tool_name", ""),
        ("tool_name", "Ba sh"),
        ("tool_input", "npm test"),
        ("cwd", 5),
        ("cwd", "/home/user/‮project"),
    ],
)
def test_bad_payload_values_are_refused(field: str, value: Any) -> None:
    payload = hook_payload_pre_bash()
    payload[field] = value
    assert refused(envelope(payload)) is RefusalCode.INVALID_FIELD


def test_unknown_payload_fields_are_tolerated_but_not_kept() -> None:
    payload = hook_payload_pre_bash()
    payload["effort"] = {"level": "high"}
    payload["future_field"] = "anything"
    action = normalize(envelope(payload)).action
    assert "future_field" not in action.model_dump_json()


def test_the_request_is_not_mutated() -> None:
    request = envelope(hook_payload_pre_bash())
    before = copy.deepcopy(request)
    normalize(request)
    assert request == before


def test_after_events_are_recorded_after() -> None:
    report = normalize(envelope(hook_payload_session_end()))
    assert report.action.phase is Phase.AFTER
    assert report.action.kind is ActionKind.SESSION_END


def test_device_actor_id_must_be_clean() -> None:
    with pytest.raises(IntakeRefused) as info:
        normalize_hook_report(
            envelope(hook_payload_pre_bash()),
            device_actor_id="svc\nforged",
            received_at=RECEIVED_AT,
            redactor=FakeRedactor(),
        )
    assert info.value.code is RefusalCode.INVALID_FIELD


def test_refusal_message_names_the_code_only() -> None:
    request = envelope(hook_payload_pre_bash(), surface="bad surface value")
    with pytest.raises(IntakeRefused) as info:
        normalize(request)
    assert "bad surface value" not in str(info.value)
    assert info.value.__cause__ is None
    assert info.value.__context__ is None or info.value.__suppress_context__


def test_device_is_a_target_attribute_matching_the_agents_registry_key() -> None:
    from ciso.agents.models import DEVICE_TARGET_KEY
    from ciso.intake import DEVICE_TARGET_KEY as INTAKE_KEY

    assert INTAKE_KEY == DEVICE_TARGET_KEY
    action = normalize(envelope(hook_payload_pre_bash())).action
    assert action.target[DEVICE_TARGET_KEY] == "WS-0142"


@pytest.mark.parametrize("absent", ["missing", "null"])
def test_no_device_gives_no_device_target_or_claim(absent: str) -> None:
    request = envelope(hook_payload_pre_bash())
    if absent == "missing":
        del request["device"]
    else:
        request["device"] = None
    action = normalize(request).action
    assert "device" not in action.target
    assert "device_name" not in {claim.kind for claim in action.identity_claims}
    assert "device_actor" in {claim.kind for claim in action.identity_claims}
