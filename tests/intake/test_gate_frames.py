"""Parsing signed central-gate frames into `ObservedAction`s.

Example frames and tool_use blocks are the documented ones:
https://platform.claude.com/docs/en/manage-claude/inference-hooks-endpoint.md"""

from __future__ import annotations

import copy
import json
from typing import Any

import pytest
from tests.intake.conftest import (
    GATE_BASH_BLOCK,
    GATE_CONNECTOR_BLOCK,
    GATE_MCP_BLOCK,
    GATE_NOW,
    gate_prompt_frame,
    gate_tool_call_frame,
    signed,
)

from ciso.common.activity import ActionKind, ActivitySource, Phase
from ciso.intake import (
    MAX_TOOL_CALLS_PER_FRAME,
    CentralGate,
    GateFrame,
    IntakeRefused,
    RefusalCode,
)

pytestmark = pytest.mark.unit


def receive(gate: CentralGate, frame: dict[str, Any] | bytes) -> GateFrame:
    return gate.receive(*signed(frame))


def refused(gate: CentralGate, frame: dict[str, Any] | bytes) -> RefusalCode:
    with pytest.raises(IntakeRefused) as info:
        receive(gate, frame)
    return info.value.code


def test_documented_prompt_frame(gate: CentralGate) -> None:
    frame = receive(gate, gate_prompt_frame())
    assert frame.frame_type == "prompt"
    (action,) = frame.actions
    assert action.kind is ActionKind.PROMPT
    assert action.phase is Phase.BEFORE
    assert action.source is ActivitySource.CENTRAL_GATE
    assert action.session_id == "22222222-2222-2222-2222-222222222222"
    assert action.surface == "claude-ai"
    assert action.received_at == GATE_NOW
    claims = {claim.kind: claim for claim in action.identity_claims}
    assert claims["assistant_account"].subject == "user_01AbCdEfGhIjKlMnOpQrStUv"
    assert claims["assistant_account"].verified is True
    assert claims["assistant_email"].subject == "alice@example.com"
    assert claims["assistant_email"].verified is True
    (inspection,) = frame.inspections
    assert inspection.kind is ActionKind.PROMPT
    assert inspection.action_id == action.action_id
    assert inspection.content == (
        "Summarize the attached report.\nQ2 revenue grew 14% quarter over quarter..."
    )
    assert "Summarize" not in action.model_dump_json()


def test_prompt_inspection_takes_only_the_last_message(gate: CentralGate) -> None:
    body = gate_prompt_frame()
    body["messages"] = [
        {"role": "user", "content": [{"type": "text", "text": "earlier turn"}]},
        {"role": "assistant", "content": [{"type": "text", "text": "answer"}]},
        {
            "role": "user",
            "content": [
                {
                    "type": "tool_result",
                    "content": "result text",
                    "is_error": False,
                    "tool_name": "bash",
                    "tool_use_id": "toolu_1",
                },
                {"type": "future_block", "x": 1},
                {
                    "type": "attachment",
                    "file_name": None,
                    "media_type": "image/png",
                    "size_bytes": 10,
                    "text": None,
                },
            ],
        },
    ]
    (inspection,) = receive(gate, body).inspections
    assert inspection.content == "result text"


def test_documented_tool_call_frame_gives_one_action_per_tool_use(gate: CentralGate) -> None:
    frame = receive(
        gate, gate_tool_call_frame(GATE_BASH_BLOCK, GATE_MCP_BLOCK, GATE_CONNECTOR_BLOCK)
    )
    assert frame.frame_type == "tool_call"
    bash, mcp, connector = frame.actions
    assert bash.kind is ActionKind.SHELL_COMMAND
    assert bash.command == "ls -la reports/"
    assert bash.target["provider"] == "client"
    assert mcp.kind is ActionKind.CONNECTOR_CALL
    assert mcp.target["server"] == "crm"
    assert mcp.target["origin"] == "https://mcp.crm.example.com"
    assert mcp.target["origin_verified"] == "true"
    assert connector.kind is ActionKind.CONNECTOR_CALL
    assert connector.target["server"] == "Gmail"
    assert connector.target["origin_verified"] == "false"
    assert {a.phase for a in frame.actions} == {Phase.BEFORE}
    assert len({a.action_id for a in frame.actions}) == 3
    assert all(a.session_id == bash.session_id for a in frame.actions)
    assert [i.kind for i in frame.inspections] == [ActionKind.SHELL_COMMAND]


def test_documented_application_and_client_tools(gate: CentralGate) -> None:
    web = {
        "type": "tool_use",
        "id": "toolu_01LmNoPqRsTuVwXyZaBcDeFg",
        "tool_name": "web_search",
        "input": {"query": "comparable deals for unannounced 4.2B USD Acme Corp acquisition"},
        "tool_info": {"type": "application"},
    }
    read = {
        "type": "tool_use",
        "id": "toolu_01AbCdEfGhIjKlMnOpQrStUv",
        "tool_name": "read_file",
        "input": {"path": "reports/q3.txt"},
        "tool_info": {"type": "client"},
    }
    web_action, read_action = receive(gate, gate_tool_call_frame(web, read)).actions
    assert web_action.kind is ActionKind.WEB_FETCH
    assert web_action.target["provider"] == "application"
    assert "Acme" not in web_action.model_dump_json()
    assert read_action.kind is ActionKind.OTHER_TOOL
    assert read_action.tool_name == "read_file"


def test_code_tool_write_through_the_gate_hashes_content(gate: CentralGate) -> None:
    block = {
        "type": "tool_use",
        "id": "toolu_w1",
        "tool_name": "Write",
        "input": {"file_path": "/repo/a.py", "content": "print(1)\n"},
        "tool_info": {"type": "client"},
    }
    frame = receive(gate, gate_tool_call_frame(block))
    (action,) = frame.actions
    assert action.kind is ActionKind.FILE_WRITE
    assert action.target["path"] == "/repo/a.py"
    assert action.content_bytes == 9
    assert frame.inspections[0].content == "print(1)\n"


def test_unknown_tool_info_kind_is_accepted(gate: CentralGate) -> None:
    block = dict(GATE_BASH_BLOCK, tool_info={"type": "future_kind", "x": 1})
    (action,) = receive(gate, gate_tool_call_frame(block)).actions
    assert action.target["provider"] == "future_kind"


def test_null_tool_use_fields_still_give_an_action(gate: CentralGate) -> None:
    block = {
        "type": "tool_use",
        "id": None,
        "tool_name": None,
        "input": None,
        "tool_info": {"type": "client"},
    }
    (action,) = receive(gate, gate_tool_call_frame(block)).actions
    assert action.kind is ActionKind.OTHER_TOOL
    assert action.tool_name == ""


def test_action_ids_are_deterministic_for_a_redelivered_frame(gate: CentralGate) -> None:
    first = receive(gate, gate_tool_call_frame(GATE_BASH_BLOCK)).actions[0].action_id
    again = gate_tool_call_frame(GATE_BASH_BLOCK)
    again["request_id"] = "req_retry"  # a new delivery id, the same tool_use id
    assert receive(gate, again).actions[0].action_id == first
    assert first.startswith("cg_")
    assert len(first) <= 50


def test_missing_session_id_is_marked_not_merged(gate: CentralGate) -> None:
    frame = gate_prompt_frame()
    frame["session_id"] = None
    (action,) = receive(gate, frame).actions
    assert action.session_id == "unsessioned:req_abc123"


def test_actor_without_id_gives_no_account_claim(gate: CentralGate) -> None:
    frame = gate_prompt_frame()
    frame["actor"] = {"type": "user", "id": None, "email_address": None}
    (action,) = receive(gate, frame).actions
    assert action.identity_claims == ()


def test_future_actor_kind_gives_no_claim(gate: CentralGate) -> None:
    frame = gate_prompt_frame()
    frame["actor"] = {"type": "service_account", "name": "x"}
    (action,) = receive(gate, frame).actions
    assert action.identity_claims == ()


def test_unknown_top_level_fields_are_ignored(gate: CentralGate) -> None:
    frame = gate_prompt_frame()
    frame["future_field"] = {"anything": True}
    frame["metadata"] = {"k": "v"}
    assert receive(gate, frame).frame_type == "prompt"


def test_unknown_frame_type_is_refused_not_allowed(gate: CentralGate) -> None:
    frame = gate_prompt_frame()
    frame["type"] = "response"
    assert refused(gate, frame) is RefusalCode.UNKNOWN_FRAME_TYPE


def test_too_many_tool_calls_are_refused(gate: CentralGate) -> None:
    blocks = []
    for index in range(MAX_TOOL_CALLS_PER_FRAME + 1):
        block = copy.deepcopy(GATE_BASH_BLOCK)
        block["id"] = f"toolu_{index}"
        blocks.append(block)
    assert refused(gate, gate_tool_call_frame(*blocks)) is RefusalCode.TOO_MANY_TOOL_CALLS


def test_tool_call_frame_without_tool_use_is_refused(gate: CentralGate) -> None:
    frame = gate_tool_call_frame()
    frame["messages"][0]["content"] = [{"type": "text", "text": "no tools"}]
    assert refused(gate, frame) is RefusalCode.MALFORMED_FRAME


def test_tool_call_frame_must_end_with_the_assistant_message(gate: CentralGate) -> None:
    frame = gate_tool_call_frame()
    frame["messages"][0]["role"] = "user"
    assert refused(gate, frame) is RefusalCode.MALFORMED_FRAME


@pytest.mark.parametrize(
    "mutate",
    [
        lambda f: f.update(messages=[]),
        lambda f: f.update(messages="x"),
        lambda f: f.update(messages=[{"role": "user", "content": "x"}]),
        lambda f: f.update(messages=[{"role": "user", "content": [{"text": "no type"}]}]),
        lambda f: f.update(messages=[{"role": "user", "content": [{"type": "text", "text": 5}]}]),
        lambda f: f.update(actor="alice"),
        lambda f: f.update(actor={"type": "user", "id": "user\nforged"}),
        lambda f: f.update(source={"application": 5}),
        lambda f: f.update(session_id=7),
        lambda f: f.update(request_id=None),
        lambda f: f.pop("type"),
    ],
)
def test_malformed_frames_are_refused(gate: CentralGate, mutate: Any) -> None:
    frame = gate_prompt_frame()
    mutate(frame)
    assert refused(gate, frame) in {
        RefusalCode.MALFORMED_FRAME,
        RefusalCode.REQUEST_ID_MISMATCH,
    }


@pytest.mark.parametrize(
    "body",
    [
        b"not json",
        b"\xff\xfe",
        b"[1, 2]",
        b'{"type": "prompt", "type": "tool_call", "request_id": "req_abc123"}',
        b'{"type": "prompt", "request_id": "req_abc123", "x": NaN}',
        b"[" * 5000 + b"]" * 5000,
    ],
)
def test_unparseable_bodies_are_refused(gate: CentralGate, body: bytes) -> None:
    headers, raw = signed(body, msg_id="req_abc123")
    with pytest.raises(IntakeRefused) as info:
        gate.receive(headers, raw)
    assert info.value.code is RefusalCode.MALFORMED_FRAME


def test_a_bad_bash_input_refuses_the_whole_frame(gate: CentralGate) -> None:
    block = dict(GATE_BASH_BLOCK, input={"command": 5})
    assert refused(gate, gate_tool_call_frame(block)) is RefusalCode.MALFORMED_TOOL_INPUT


def test_config_test_frames_parse_normally(gate: CentralGate) -> None:
    frame = gate_prompt_frame()
    frame["source"] = {"application": "config-test"}
    assert receive(gate, frame).actions[0].surface == "config-test"


def test_body_is_verified_as_raw_bytes(gate: CentralGate) -> None:
    raw = json.dumps(gate_prompt_frame(), indent=2).encode()
    assert receive(gate, raw.replace(b"req_abc123", b"msg_bytes")).request_id == "msg_bytes"


def test_duplicate_keys_in_an_otherwise_valid_frame_are_refused(gate: CentralGate) -> None:
    body = json.dumps(gate_prompt_frame()).encode()
    body = b'{"session_id": "forged-session", ' + body[1:]
    headers, raw = signed(body, msg_id="req_abc123")
    with pytest.raises(IntakeRefused) as info:
        gate.receive(headers, raw)
    assert info.value.code is RefusalCode.MALFORMED_FRAME
