"""Fixtures for the intake lane: documented example payloads and signing helpers.

Example payloads are copied from the vendor documentation (URLs in each docstring); only
the values the tests need are changed, and each change is commented.
"""

from __future__ import annotations

import base64
import copy
import hashlib
import hmac
import json
from datetime import UTC, datetime
from typing import Any

import pytest
from tests.fakes.core import FakeSecrets

from ciso.common.clock import FixedClock
from ciso.intake import BoundedSeenMessages, CentralGate
from ciso.vault import SecretRedactor

#: A secret planted in commands, prompts and content. It must never leave the intake
#: except inside an `InspectionInput.content` for file content, which inspection needs.
PLANTED = "plantedSecretValue-7f3a9c1e5b"

RECEIVED_AT = datetime(2026, 11, 18, 9, 0, 0, tzinfo=UTC)
DEVICE_ACTOR = "svc_device_ws0142"
#: The registered name of DEVICE_ACTOR (the API layer reads it from the device directory).
DEVICE_NAME = "WS-0142"

#: Standard Webhooks reference library test vector (libraries/python/tests/test_webhooks.py,
#: https://github.com/standard-webhooks/standard-webhooks): test_sign_function.
SW_SECRET = "whsec_MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw"
SW_MSG_ID = "msg_p5jXN8AQM9LWM0D4loKWxJek"
SW_TIMESTAMP = 1614265330
SW_PAYLOAD = b'{"test": 2432232314}'
SW_SIGNATURE = "v1,g0hM9SsE+OTPJTGt/tmIKtSyZlE3uFJELVlNIOLJ1OE="
#: Same file: BINARY_PAYLOAD = bytes(range(256)) signed with the same secret, id, time.
SW_BINARY_SIGNATURE = "v1,sEcZ042G8Crqgxbybb3y0eDxQR3TcfYsk11I1XULhSI="

SECRET_REF = "secret://central_gate_signing"
OLD_SECRET_REF = "secret://central_gate_signing_previous"
GATE_SECRET = "whsec_" + base64.b64encode(b"k" * 32).decode()
OLD_GATE_SECRET = "whsec_" + base64.b64encode(b"o" * 32).decode()
GATE_NOW = datetime(2026, 11, 18, 9, 0, 0, tzinfo=UTC)
TOLERANCE = 300


def hook_payload_pre_bash() -> dict[str, Any]:
    """PreToolUse example, https://code.claude.com/docs/en/hooks.md (Common input fields)."""
    return {
        "session_id": "abc123",
        "prompt_id": "550e8400-e29b-41d4-a716-446655440000",
        "transcript_path": "/home/user/.claude/projects/.../transcript.jsonl",
        "cwd": "/home/user/my-project",
        "scratchpad_dir": "/tmp/claude-1000/-home-user-my-project/abc123/scratchpad",  # noqa: S108
        "permission_mode": "default",
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": {
            "command": "npm test",
            "description": "Run test suite",
            "timeout": 120000,
            "run_in_background": False,
        },
        # Documented as "toolu_01ABC123..."; the ellipsis is replaced by a concrete id.
        "tool_use_id": "toolu_01ABC123",
    }


def hook_payload_post_write() -> dict[str, Any]:
    """PostToolUse example (a Write call), https://code.claude.com/docs/en/hooks.md."""
    return {
        "session_id": "abc123",
        "transcript_path": "/Users/.../.claude/projects/.../00893aaf.jsonl",
        "cwd": "/Users/...",
        "permission_mode": "default",
        "hook_event_name": "PostToolUse",
        "tool_name": "Write",
        "tool_input": {"file_path": "/path/to/file.txt", "content": "file content"},
        "tool_response": {"filePath": "/path/to/file.txt", "type": "create"},
        "tool_use_id": "toolu_01ABC123",
        "duration_ms": 12,
    }


def hook_payload_prompt() -> dict[str, Any]:
    """UserPromptSubmit example, https://code.claude.com/docs/en/hooks.md. `prompt_id`
    added: verified present on 2026-11-18 (spec-draft section 9, item 2)."""
    return {
        "session_id": "abc123",
        "prompt_id": "550e8400-e29b-41d4-a716-446655440000",
        "transcript_path": "/Users/.../.claude/projects/.../00893aaf.jsonl",
        "cwd": "/Users/...",
        "permission_mode": "default",
        "hook_event_name": "UserPromptSubmit",
        "prompt": "Write a function to calculate the factorial of a number",
    }


def hook_payload_session_start() -> dict[str, Any]:
    """SessionStart example, https://code.claude.com/docs/en/hooks.md."""
    return {
        "session_id": "abc123",
        "transcript_path": "/Users/.../.claude/projects/.../00893aaf.jsonl",
        "cwd": "/Users/...",
        "hook_event_name": "SessionStart",
        "source": "resume",
        "model": "claude-opus-5",
    }


def hook_payload_session_end() -> dict[str, Any]:
    """SessionEnd example, https://code.claude.com/docs/en/hooks.md."""
    return {
        "session_id": "abc123",
        "transcript_path": "/Users/.../.claude/projects/.../00893aaf.jsonl",
        "cwd": "/Users/...",
        "hook_event_name": "SessionEnd",
        "reason": "other",
    }


def hook_payload_subagent_start() -> dict[str, Any]:
    """SubagentStart example, https://code.claude.com/docs/en/hooks.md."""
    return {
        "session_id": "abc123",
        "transcript_path": "/Users/.../.claude/projects/.../00893aaf.jsonl",
        "cwd": "/Users/...",
        "hook_event_name": "SubagentStart",
        "agent_id": "agent-abc123",
        "agent_type": "Explore",
    }


def envelope(payload: dict[str, Any], **overrides: Any) -> dict[str, Any]:
    """The decision-API request (docs/skill/decision-api.md) around a hook payload."""
    request: dict[str, Any] = {
        "format": "assistant_hook_v1",
        "event": payload["hook_event_name"],
        "surface": "cli",
        "device": "WS-0142",
        "claims": [{"kind": "os_account", "subject": "CORP\\jdoe", "verified": False}],
        "payload": payload,
    }
    request.update(overrides)
    return request


def pre_tool(tool_name: str, tool_input: dict[str, Any], **extra: Any) -> dict[str, Any]:
    payload = hook_payload_pre_bash()
    payload["tool_name"] = tool_name
    payload["tool_input"] = tool_input
    payload.update(extra)
    return envelope(payload)


def gate_prompt_frame() -> dict[str, Any]:
    """Prompt frame example, https://platform.claude.com/docs/en/manage-claude/inference-hooks-endpoint.md"""
    return {
        "type": "prompt",
        "request_id": "req_abc123",
        "tenant_id": "11111111-1111-1111-1111-111111111111",
        "actor": {
            "type": "user",
            "id": "user_01AbCdEfGhIjKlMnOpQrStUv",
            "email_address": "alice@example.com",
        },
        "source": {"application": "claude-ai"},
        "session_id": "22222222-2222-2222-2222-222222222222",
        "model": "claude-sonnet-4-5",
        "messages": [
            {
                "role": "user",
                "content": [
                    {"type": "text", "text": "Summarize the attached report."},
                    {
                        "type": "attachment",
                        "file_name": "q2-report.pdf",
                        "media_type": "application/pdf",
                        "size_bytes": 48213,
                        "text": "Q2 revenue grew 14% quarter over quarter...",
                    },
                ],
            }
        ],
        "metadata": {},
    }


#: tool_use blocks from the same page (bash client tool; MCP third-party tool; connector).
GATE_BASH_BLOCK: dict[str, Any] = {
    "type": "tool_use",
    "id": "toolu_01HiJkLmNoPqRsTuVwXyZaBc",
    "tool_name": "bash",
    "input": {"command": "ls -la reports/"},
    "tool_info": {"type": "client", "tool_type": "bash_20250124"},
}
GATE_MCP_BLOCK: dict[str, Any] = {
    "type": "tool_use",
    "id": "toolu_01GhIjKlMnOpQrStUvWxYzAb",
    "tool_name": "crm_search",
    "input": {"query": "accounts renewing in Q4"},
    "tool_info": {
        "type": "third_party",
        "toolset_name": "crm",
        "origin": "https://mcp.crm.example.com",
        "verified_origin": True,
    },
}
GATE_CONNECTOR_BLOCK: dict[str, Any] = {
    "type": "tool_use",
    "id": "toolu_01DeFgHiJkLmNoPqRsTuVwXy",
    "tool_name": "mcp__Gmail__search_threads",
    "input": {"query": "from:cfo@example.com newer_than:30d"},
    "tool_info": {
        "type": "third_party",
        "toolset_name": "Gmail",
        "origin": "https://gmail.mcp.example.com",
        "verified_origin": False,
    },
}


def gate_tool_call_frame(*blocks: dict[str, Any]) -> dict[str, Any]:
    """A tool call frame: the prompt frame's top-level fields, `type` = `tool_call`, and
    `messages` holding only the latest assistant message (same page)."""
    frame = gate_prompt_frame()
    frame["type"] = "tool_call"
    frame["request_id"] = "req_tool456"
    chosen = blocks or (GATE_BASH_BLOCK,)
    frame["messages"] = [
        {
            "role": "assistant",
            "content": [{"type": "text", "text": "Let me look."}, *map(copy.deepcopy, chosen)],
        }
    ]
    return frame


def sign(secret: str, msg_id: str, timestamp: int, body: bytes) -> str:
    """Standard Webhooks v1: base64(HMAC-SHA256(key, "id.timestamp.body"))."""
    key = base64.b64decode(secret.removeprefix("whsec_"), validate=True)
    mac = hmac.new(key, f"{msg_id}.{timestamp}.".encode() + body, hashlib.sha256).digest()
    return "v1," + base64.b64encode(mac).decode()


def signed(
    frame: dict[str, Any] | bytes,
    *,
    secret: str = GATE_SECRET,
    msg_id: str | None = None,
    timestamp: int | None = None,
) -> tuple[dict[str, str], bytes]:
    body = frame if isinstance(frame, bytes) else json.dumps(frame).encode()
    ident = msg_id if msg_id is not None else _request_id(frame)
    stamp = timestamp if timestamp is not None else int(GATE_NOW.timestamp())
    headers = {
        "webhook-id": ident,
        "webhook-timestamp": str(stamp),
        "webhook-signature": sign(secret, ident, stamp, body),
    }
    return headers, body


def _request_id(frame: dict[str, Any] | bytes) -> str:
    if isinstance(frame, bytes):
        return "msg_bytes"
    return str(frame.get("request_id", "msg_missing"))


@pytest.fixture
def planted_redactor() -> SecretRedactor:
    redactor = SecretRedactor()
    assert redactor.register(PLANTED)
    return redactor


@pytest.fixture
def gate_clock() -> FixedClock:
    return FixedClock(GATE_NOW)


@pytest.fixture
def gate_secrets() -> FakeSecrets:
    return FakeSecrets({SECRET_REF: GATE_SECRET, OLD_SECRET_REF: OLD_GATE_SECRET})


@pytest.fixture
def seen() -> BoundedSeenMessages:
    return BoundedSeenMessages(capacity=64)


@pytest.fixture
def gate(
    gate_secrets: FakeSecrets,
    gate_clock: FixedClock,
    planted_redactor: SecretRedactor,
    seen: BoundedSeenMessages,
) -> CentralGate:
    return CentralGate(
        secrets=gate_secrets,
        secret_ref=SECRET_REF,
        clock=gate_clock,
        redactor=planted_redactor,
        seen=seen,
        tolerance_seconds=TOLERANCE,
    )
