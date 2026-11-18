"""Report mode never blocks: one retry, then a local log line and exit 0."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from tests.integrations.claude_code.conftest import (
    POST_TOOL_USE,
    SERVICE_URL,
    TOKEN_VALUE,
    FakeTransport,
    Runner,
)

pytestmark = pytest.mark.unit

RECORDED = json.dumps({"recorded": True, "action_id": "act_1"}).encode()


def log_lines(environ: dict[str, str]) -> list[str]:
    path = Path(environ["AIGOV_LOG_FILE"])
    if not path.exists():
        return []
    return path.read_text(encoding="utf-8").splitlines()


def test_report_posts_to_activity_once(
    run: Runner, transport: FakeTransport, environ: dict[str, str]
) -> None:
    transport.results.append((202, RECORDED))
    assert run("report", POST_TOOL_USE) == (0, "", "")
    assert len(transport.calls) == 1
    call = transport.calls[0]
    assert call.url == SERVICE_URL + "/v1/activity"
    assert call.headers["Authorization"] == "Bearer " + TOKEN_VALUE
    assert call.timeout == 2.0
    body = json.loads(call.body)
    assert body["event"] == "PostToolUse"
    assert body["payload"] == POST_TOOL_USE
    assert log_lines(environ) == []


def test_report_retries_once_then_succeeds(
    run: Runner, transport: FakeTransport, environ: dict[str, str]
) -> None:
    transport.results.extend([ConnectionRefusedError("refused"), (202, RECORDED)])
    assert run("report", POST_TOOL_USE) == (0, "", "")
    assert len(transport.calls) == 2
    assert log_lines(environ) == []


@pytest.mark.parametrize(
    ("first", "second"),
    [
        (ConnectionRefusedError("x"), ConnectionRefusedError("x")),
        ((500, b""), (503, b"")),
        ((200, RECORDED), TimeoutError("x")),
    ],
    ids=["refused", "server_error", "wrong_status_then_timeout"],
)
def test_report_gives_up_after_one_retry_with_a_log_line(
    run: Runner, transport: FakeTransport, environ: dict[str, str], first: object, second: object
) -> None:
    transport.results.extend([first, second])
    assert run("report", POST_TOOL_USE) == (0, "", "")
    assert len(transport.calls) == 2
    lines = log_lines(environ)
    assert len(lines) == 1
    assert "report" in lines[0]
    assert "PostToolUse" in lines[0]
    assert "dropped" in lines[0]
    assert TOKEN_VALUE not in lines[0]


def test_report_without_configuration_exits_0_and_logs(
    run: Runner, transport: FakeTransport, environ: dict[str, str]
) -> None:
    env = {k: v for k, v in environ.items() if k != "AIGOV_SERVICE_URL"}
    assert run("report", POST_TOOL_USE, env=env) == (0, "", "")
    assert transport.calls == []
    assert len(log_lines(env)) == 1


def test_report_oversized_is_dropped_not_blocked(
    run: Runner, transport: FakeTransport, environ: dict[str, str], hc: object
) -> None:
    big = dict(POST_TOOL_USE, tool_response={"stdout": "x" * hc.MAX_REQUEST_BYTES})  # type: ignore[attr-defined]
    assert run("report", big) == (0, "", "")
    assert transport.calls == []
    assert "too_large" in log_lines(environ)[0]


def test_report_malformed_input_exits_0(
    run: Runner, transport: FakeTransport, environ: dict[str, str]
) -> None:
    assert run("report", None, raw=b"garbage") == (0, "", "")
    assert transport.calls == []
    assert len(log_lines(environ)) == 1


def test_report_with_unwritable_log_still_exits_0(
    run: Runner, transport: FakeTransport, environ: dict[str, str], tmp_path: Path
) -> None:
    env = {**environ, "AIGOV_LOG_FILE": str(tmp_path)}  # a directory: cannot be opened
    transport.results.extend([ConnectionRefusedError("x"), ConnectionRefusedError("x")])
    assert run("report", POST_TOOL_USE, env=env) == (0, "", "")
