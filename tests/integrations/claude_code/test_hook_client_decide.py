"""Decide mode: the verdict maps to the documented hook output; every failure blocks."""

from __future__ import annotations

import json
import ssl
import urllib.error
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest
from tests.integrations.claude_code.conftest import (
    PRE_TOOL_USE,
    SERVICE_URL,
    SESSION_START,
    TOKEN_VALUE,
    USER_PROMPT,
    FakeTransport,
    Runner,
)

pytestmark = pytest.mark.unit


def answer(verdict: str, message: str = "Pushing to main is not allowed.") -> bytes:
    return json.dumps(
        {
            "verdict": verdict,
            "decision_id": "dec_123",
            "reason": "branch_protected",
            "message": message,
        }
    ).encode()


def assert_blocked(result: tuple[int, str, str], hc: ModuleType) -> None:
    code, _out, err = result
    assert code == 2
    assert err.strip() == hc.BLOCK_MESSAGE


# --- request shape -------------------------------------------------------------------


def test_request_follows_the_contract(run: Runner, transport: FakeTransport) -> None:
    transport.results.append((200, answer("allow")))
    code, _out, _err = run("decide", PRE_TOOL_USE)
    assert code == 0
    assert len(transport.calls) == 1
    call = transport.calls[0]
    assert call.url == SERVICE_URL + "/v1/governance/decide"
    assert call.headers["Authorization"] == "Bearer " + TOKEN_VALUE
    assert call.headers["Content-Type"] == "application/json"
    assert call.timeout == 8.0
    body = json.loads(call.body)
    assert body == {
        "format": "assistant_hook_v1",
        "event": "PreToolUse",
        "surface": "cli",
        "device": "WS-0142",
        "claims": [{"kind": "os_account", "subject": "CORP\\jdoe", "verified": False}],
        "payload": PRE_TOOL_USE,
    }


def test_tls_context_verifies_certificates(run: Runner, transport: FakeTransport) -> None:
    transport.results.append((200, answer("allow")))
    run("decide", PRE_TOOL_USE)
    context = transport.calls[0].context
    assert isinstance(context, ssl.SSLContext)
    assert context.verify_mode == ssl.CERT_REQUIRED
    assert context.check_hostname is True


def test_token_is_not_written_to_output_or_log(
    run: Runner, transport: FakeTransport, environ: dict[str, str]
) -> None:
    transport.results.append(ConnectionRefusedError("refused"))
    code, out, err = run("decide", PRE_TOOL_USE)
    assert code == 2
    log = Path(environ["AIGOV_LOG_FILE"]).read_text(encoding="utf-8")
    assert "decide" in log
    for text in (out, err, log):
        assert TOKEN_VALUE not in text


# --- verdict mapping per event -------------------------------------------------------


def test_pretooluse_deny_maps_to_permission_decision(run: Runner, transport: FakeTransport) -> None:
    transport.results.append((200, answer("deny")))
    code, out, _err = run("decide", PRE_TOOL_USE)
    assert code == 0
    output = json.loads(out)
    specific = output["hookSpecificOutput"]
    assert specific["hookEventName"] == "PreToolUse"
    assert specific["permissionDecision"] == "deny"
    assert "Pushing to main is not allowed." in specific["permissionDecisionReason"]
    assert "dec_123" in specific["permissionDecisionReason"]


def test_pretooluse_ask_maps_to_ask(run: Runner, transport: FakeTransport) -> None:
    transport.results.append((200, answer("ask", "Needs a second person.")))
    code, out, _err = run("decide", PRE_TOOL_USE)
    assert code == 0
    specific = json.loads(out)["hookSpecificOutput"]
    assert specific["permissionDecision"] == "ask"
    assert "Needs a second person." in specific["permissionDecisionReason"]


def test_pretooluse_allow_leaves_the_normal_permission_flow(
    run: Runner, transport: FakeTransport
) -> None:
    transport.results.append((200, answer("allow", "")))
    code, out, err = run("decide", PRE_TOOL_USE)
    assert (code, out, err) == (0, "", "")


def test_prompt_deny_blocks_and_hides_the_prompt(run: Runner, transport: FakeTransport) -> None:
    transport.results.append((200, answer("deny", "Do not paste customer data.")))
    code, out, _err = run("decide", USER_PROMPT)
    assert code == 0
    output = json.loads(out)
    assert output["decision"] == "block"
    assert "Do not paste customer data." in output["reason"]
    assert output["hookSpecificOutput"] == {
        "hookEventName": "UserPromptSubmit",
        "suppressOriginalPrompt": True,
    }


def test_prompt_ask_blocks_because_a_prompt_cannot_be_held(
    run: Runner, transport: FakeTransport
) -> None:
    transport.results.append((200, answer("ask", "Needs approval.")))
    code, out, _err = run("decide", USER_PROMPT)
    assert code == 0
    assert json.loads(out)["decision"] == "block"


def test_prompt_allow_passes(run: Runner, transport: FakeTransport) -> None:
    transport.results.append((200, answer("allow", "")))
    assert run("decide", USER_PROMPT) == (0, "", "")


@pytest.mark.parametrize("verdict", ["deny", "ask"])
def test_session_start_refusal_stops_the_session(
    run: Runner, transport: FakeTransport, verdict: str
) -> None:
    transport.results.append((200, answer(verdict, "Unknown device.")))
    code, out, _err = run("decide", SESSION_START)
    assert code == 0
    output = json.loads(out)
    assert output["continue"] is False
    assert "Unknown device." in output["stopReason"]


def test_session_start_allow_passes(run: Runner, transport: FakeTransport) -> None:
    transport.results.append((200, answer("allow", "")))
    assert run("decide", SESSION_START) == (0, "", "")


def test_service_message_is_cleaned_before_display(run: Runner, transport: FakeTransport) -> None:
    transport.results.append((200, answer("deny", "bad\x1b[31m red\x07 " + "x" * 5000)))
    _code, out, _err = run("decide", PRE_TOOL_USE)
    reason = json.loads(out)["hookSpecificOutput"]["permissionDecisionReason"]
    assert "\x1b" not in reason
    assert "\x07" not in reason
    assert len(reason) <= 1200


# --- every failure blocks ------------------------------------------------------------


@pytest.mark.parametrize(
    "error",
    [
        ConnectionRefusedError("refused"),
        TimeoutError("timed out"),
        ssl.SSLCertVerificationError("bad cert"),
        urllib.error.URLError("no route"),
        OSError("network down"),
        RuntimeError("anything else"),
    ],
    ids=["refused", "timeout", "tls", "urlerror", "oserror", "other"],
)
def test_transport_failure_blocks(
    run: Runner, transport: FakeTransport, hc: ModuleType, error: BaseException
) -> None:
    transport.results.append(error)
    assert_blocked(run("decide", PRE_TOOL_USE), hc)


@pytest.mark.parametrize("status", [201, 202, 204, 301, 400, 401, 403, 404, 500, 503])
def test_non_200_blocks(run: Runner, transport: FakeTransport, hc: ModuleType, status: int) -> None:
    transport.results.append((status, answer("allow")))
    assert_blocked(run("decide", PRE_TOOL_USE), hc)


@pytest.mark.parametrize(
    "body",
    [
        b"",
        b"not json",
        b"[]",
        b'"allow"',
        b'{"verdict": "allow"}',
        b'{"verdict": "permit", "decision_id": "dec_1"}',
        b'{"verdict": "ALLOW", "decision_id": "dec_1"}',
        b'{"verdict": "allow", "decision_id": "dec 1; drop"}',
        b'{"verdict": "allow", "decision_id": 5}',
        b'{"verdict": "deny", "decision_id": "dec_1", "message": 7}',
        b"\xff\xfe",
    ],
    ids=[
        "empty",
        "not_json",
        "array",
        "string",
        "no_id",
        "unknown_verdict",
        "verdict_case",
        "bad_id",
        "id_not_str",
        "message_not_str",
        "not_utf8",
    ],
)
def test_malformed_answer_blocks(
    run: Runner, transport: FakeTransport, hc: ModuleType, body: bytes
) -> None:
    transport.results.append((200, body))
    assert_blocked(run("decide", PRE_TOOL_USE), hc)


def test_oversized_answer_blocks(run: Runner, transport: FakeTransport, hc: ModuleType) -> None:
    padding = "x" * (hc.MAX_RESPONSE_BYTES + 10)
    body = json.dumps({"verdict": "allow", "decision_id": "dec_1", "message": padding}).encode()
    transport.results.append((200, body))
    assert_blocked(run("decide", PRE_TOOL_USE), hc)


@pytest.mark.parametrize(
    "missing",
    [
        "AIGOV_SERVICE_URL",
        "AIGOV_DEVICE_TOKEN_FILE",
        "AIGOV_DECIDE_TIMEOUT_SECONDS",
    ],
)
def test_missing_configuration_blocks_without_calling(
    run: Runner,
    transport: FakeTransport,
    hc: ModuleType,
    environ: dict[str, str],
    missing: str,
) -> None:
    env = {k: v for k, v in environ.items() if k != missing}
    assert_blocked(run("decide", PRE_TOOL_USE, env=env), hc)
    assert transport.calls == []


@pytest.mark.parametrize("value", ["0", "-1", "abc", "nan", "inf", "", "601"])
def test_invalid_timeout_blocks(
    run: Runner,
    transport: FakeTransport,
    hc: ModuleType,
    environ: dict[str, str],
    value: str,
) -> None:
    env = {**environ, "AIGOV_DECIDE_TIMEOUT_SECONDS": value}
    assert_blocked(run("decide", PRE_TOOL_USE, env=env), hc)
    assert transport.calls == []


def test_missing_token_file_blocks(
    run: Runner, transport: FakeTransport, hc: ModuleType, environ: dict[str, str], tmp_path: Any
) -> None:
    env = {**environ, "AIGOV_DEVICE_TOKEN_FILE": str(tmp_path / "absent")}
    assert_blocked(run("decide", PRE_TOOL_USE, env=env), hc)
    assert transport.calls == []


@pytest.mark.parametrize("token", ["", "   \n", "abc\r\nX-Evil: 1", "tok en"])
def test_empty_or_unsafe_token_blocks(
    run: Runner,
    transport: FakeTransport,
    hc: ModuleType,
    environ: dict[str, str],
    token_file: Any,
    token: str,
) -> None:
    token_file.write_text(token, encoding="utf-8")
    assert_blocked(run("decide", PRE_TOOL_USE, env=environ), hc)
    assert transport.calls == []


@pytest.mark.parametrize(
    "url",
    [
        "http://governance.example.test",
        "http://10.0.0.5:8080",
        "ftp://governance.example.test",
        "https://user:pw@governance.example.test",
        "https://governance.example.test/?x=1",
        "https://governance.example.test/#frag",
        "https://",
        "governance.example.test",
    ],
)
def test_unsafe_service_url_blocks(
    run: Runner,
    transport: FakeTransport,
    hc: ModuleType,
    environ: dict[str, str],
    url: str,
) -> None:
    env = {**environ, "AIGOV_SERVICE_URL": url}
    assert_blocked(run("decide", PRE_TOOL_USE, env=env), hc)
    assert transport.calls == []


@pytest.mark.parametrize("url", ["http://localhost:8765", "http://127.0.0.1:8765/base"])
def test_plain_http_is_allowed_only_to_loopback(
    run: Runner, transport: FakeTransport, environ: dict[str, str], url: str
) -> None:
    transport.results.append((200, answer("allow")))
    env = {**environ, "AIGOV_SERVICE_URL": url}
    assert run("decide", PRE_TOOL_USE, env=env)[0] == 0
    assert transport.calls[0].url == url.rstrip("/") + "/v1/governance/decide"
    assert transport.calls[0].context is None


def test_missing_ca_bundle_blocks(
    run: Runner, transport: FakeTransport, hc: ModuleType, environ: dict[str, str], tmp_path: Any
) -> None:
    env = {**environ, "AIGOV_CA_BUNDLE": str(tmp_path / "missing-ca.pem")}
    assert_blocked(run("decide", PRE_TOOL_USE, env=env), hc)
    assert transport.calls == []
    log = Path(environ["AIGOV_LOG_FILE"]).read_text(encoding="utf-8")
    assert "outcome=ca_bundle_missing" in log


def test_oversized_request_blocks(run: Runner, transport: FakeTransport, hc: ModuleType) -> None:
    big = dict(PRE_TOOL_USE, tool_input={"content": "x" * hc.MAX_REQUEST_BYTES})
    assert_blocked(run("decide", big), hc)
    assert transport.calls == []


def test_request_just_under_the_cap_is_sent(
    run: Runner, transport: FakeTransport, hc: ModuleType
) -> None:
    transport.results.append((200, answer("allow")))
    big = dict(PRE_TOOL_USE, tool_input={"content": "x" * (hc.MAX_REQUEST_BYTES - 2048)})
    assert run("decide", big)[0] == 0
    assert len(transport.calls[0].body) <= hc.MAX_REQUEST_BYTES


@pytest.mark.parametrize(
    "raw",
    [
        b"",
        b"not json",
        b"[1,2]",
        b'{"session_id": "s"}',
        b'{"hook_event_name": "Pre Tool"}',
        b"\xff",
    ],
    ids=["empty", "not_json", "array", "no_event", "bad_event", "not_utf8"],
)
def test_malformed_hook_input_blocks(
    run: Runner, transport: FakeTransport, hc: ModuleType, raw: bytes
) -> None:
    assert_blocked(run("decide", None, raw=raw), hc)
    assert transport.calls == []


def test_decide_on_an_event_it_cannot_render_blocks(
    run: Runner, transport: FakeTransport, hc: ModuleType
) -> None:
    transport.results.append((200, answer("allow")))
    payload = dict(PRE_TOOL_USE, hook_event_name="PostToolUse")
    assert_blocked(run("decide", payload), hc)


def test_session_start_failure_also_asks_to_stop(
    run: Runner, transport: FakeTransport, hc: ModuleType
) -> None:
    transport.results.append(ConnectionRefusedError("refused"))
    code, out, err = run("decide", SESSION_START)
    assert code == 2
    assert err.strip() == hc.BLOCK_MESSAGE
    assert json.loads(out) == {"continue": False, "stopReason": hc.BLOCK_MESSAGE}


def test_unknown_mode_exits_2(run: Runner, hc: ModuleType) -> None:
    assert_blocked(run("judge", PRE_TOOL_USE), hc)


def test_prompt_failure_blocks_and_hides_the_prompt(
    run: Runner, transport: FakeTransport, hc: ModuleType
) -> None:
    transport.results.append(ConnectionRefusedError("refused"))
    code, out, err = run("decide", USER_PROMPT)
    assert code == 2
    assert err.strip() == hc.BLOCK_MESSAGE
    assert json.loads(out) == {
        "hookSpecificOutput": {
            "hookEventName": "UserPromptSubmit",
            "suppressOriginalPrompt": True,
        }
    }
