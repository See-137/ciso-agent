"""A planted secret in a command, a prompt or a remote URL appears nowhere in what the
intake returns, nor in any repr or refusal. File content reaches only
`InspectionInput.content`, which inspection needs and which no repr shows."""

from __future__ import annotations

from typing import Any

import pytest
from tests.intake.conftest import (
    DEVICE_ACTOR,
    PLANTED,
    RECEIVED_AT,
    envelope,
    gate_prompt_frame,
    gate_tool_call_frame,
    hook_payload_prompt,
    pre_tool,
    signed,
)

from ciso.intake import CentralGate, IntakeRefused, NormalizedReport, normalize_hook_report
from ciso.vault import SecretRedactor

pytestmark = pytest.mark.privacy


def everything(report: NormalizedReport) -> str:
    """Every rendering of a report a log, an audit row or an error could carry."""
    parts = [repr(report), str(report), report.model_dump_json(), repr(report.action)]
    if report.inspection is not None:
        parts += [repr(report.inspection), str(report.inspection)]
        parts.append(report.inspection.command or "")
        parts.append(report.inspection.content or "")
    return "\n".join(parts)


def hook(request: dict[str, Any], redactor: SecretRedactor) -> NormalizedReport:
    return normalize_hook_report(
        request, device_actor_id=DEVICE_ACTOR, received_at=RECEIVED_AT, redactor=redactor
    )


@pytest.mark.parametrize(
    "command",
    [
        f"curl -H 'X-Key: {PLANTED}' https://api.example.com",
        f"export SERVICE_PASSWORD={PLANTED} && ./run.sh",
        f"git push https://bot:{PLANTED}@git.example.com/r.git main",
        f"git push {PLANTED} main",
    ],
)
def test_secret_in_a_command_appears_nowhere(
    planted_redactor: SecretRedactor, command: str
) -> None:
    report = hook(pre_tool("Bash", {"command": command}), planted_redactor)
    assert report.action.command is not None
    assert "[REDACTED]" in report.action.command
    assert PLANTED not in everything(report)


def test_token_shaped_secret_is_removed_by_pattern(planted_redactor: SecretRedactor) -> None:
    command = "deploy --token=Zq81x9VvTT0pLmN3 now"
    report = hook(pre_tool("Bash", {"command": command}), planted_redactor)
    assert "Zq81x9VvTT0pLmN3" not in everything(report)


def test_secret_in_a_prompt_appears_nowhere(planted_redactor: SecretRedactor) -> None:
    payload = hook_payload_prompt()
    payload["prompt"] = f"use this key {PLANTED} to call the service"
    report = hook(envelope(payload), planted_redactor)
    assert report.inspection is not None
    assert report.inspection.content == "use this key [REDACTED] to call the service"
    assert PLANTED not in everything(report)


def test_secret_in_a_subagent_prompt_appears_nowhere(planted_redactor: SecretRedactor) -> None:
    report = hook(pre_tool("Agent", {"prompt": f"login with {PLANTED}"}), planted_redactor)
    assert PLANTED not in everything(report)


def test_secret_in_a_fetched_url_appears_nowhere(planted_redactor: SecretRedactor) -> None:
    request = pre_tool("WebFetch", {"url": f"https://h.example.com/?k={PLANTED}", "prompt": "x"})
    assert PLANTED not in everything(hook(request, planted_redactor))


def test_file_content_is_only_in_inspection_content(planted_redactor: SecretRedactor) -> None:
    content = f"API_KEY = '{PLANTED}'\n"
    report = hook(
        pre_tool("Write", {"file_path": "/repo/cfg.py", "content": content}), planted_redactor
    )
    assert report.inspection is not None
    assert report.inspection.content == content  # inspection must see the real content
    shown = [repr(report), str(report), report.action.model_dump_json(), repr(report.inspection)]
    assert all(PLANTED not in text for text in shown)


def test_refusals_do_not_carry_the_secret(planted_redactor: SecretRedactor) -> None:
    request = pre_tool("Write", {"file_path": f"/repo/{PLANTED}\n", "content": PLANTED})
    with pytest.raises(IntakeRefused) as info:
        hook(request, planted_redactor)
    assert PLANTED not in str(info.value)
    assert PLANTED not in repr(info.value)
    assert info.value.__cause__ is None
    assert info.value.__context__ is None or info.value.__suppress_context__


def test_secret_in_a_gate_prompt_appears_nowhere(gate: CentralGate) -> None:
    frame_body = gate_prompt_frame()
    frame_body["messages"][0]["content"][0]["text"] = f"here is {PLANTED}"
    frame = gate.receive(*signed(frame_body))
    rendered = [repr(frame), str(frame), frame.model_dump_json()]
    rendered += [inspection.content or "" for inspection in frame.inspections]
    assert all(PLANTED not in text for text in rendered)
    assert "here is [REDACTED]" in frame.inspections[0].content  # type: ignore[operator]


def test_secret_in_a_gate_command_appears_nowhere(gate: CentralGate) -> None:
    block = {
        "type": "tool_use",
        "id": "toolu_x",
        "tool_name": "bash",
        "input": {"command": f"echo {PLANTED}"},
        "tool_info": {"type": "client"},
    }
    frame = gate.receive(*signed(gate_tool_call_frame(block)))
    rendered = [repr(frame), frame.model_dump_json()]
    rendered += [inspection.command or "" for inspection in frame.inspections]
    assert all(PLANTED not in text for text in rendered)
    assert frame.actions[0].command == "echo [REDACTED]"


def test_signing_secret_is_never_in_a_refusal(gate: CentralGate) -> None:
    from tests.intake.conftest import GATE_SECRET

    headers, body = signed(gate_prompt_frame())
    headers["webhook-signature"] = "v1,AAAA"
    with pytest.raises(IntakeRefused) as info:
        gate.receive(headers, body)
    key_text = GATE_SECRET.removeprefix("whsec_")
    assert key_text not in str(info.value)
    assert key_text not in repr(gate)


def test_secret_in_a_target_path_is_redacted(planted_redactor: SecretRedactor) -> None:
    request = pre_tool("Read", {"file_path": f"/home/user/my-project/{PLANTED}.txt"})
    report = hook(request, planted_redactor)
    assert report.action.target["path"] == "[REDACTED].txt"
    assert PLANTED not in everything(report)
