"""Report mode never blocks: one retry, then a local log line and exit 0."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

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


def log_lines(config: dict[str, Any]) -> list[str]:
    path = Path(config["log_file"])
    if not path.exists():
        return []
    return path.read_text(encoding="utf-8").splitlines()


def test_report_posts_to_activity_once(
    run: Runner, transport: FakeTransport, config: dict[str, Any]
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
    assert log_lines(config) == []


def test_report_retries_once_then_succeeds(
    run: Runner, transport: FakeTransport, config: dict[str, Any]
) -> None:
    transport.results.extend([ConnectionRefusedError("refused"), (202, RECORDED)])
    assert run("report", POST_TOOL_USE) == (0, "", "")
    assert len(transport.calls) == 2
    assert log_lines(config) == []


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
    run: Runner, transport: FakeTransport, config: dict[str, Any], first: object, second: object
) -> None:
    transport.results.extend([first, second])
    assert run("report", POST_TOOL_USE) == (0, "", "")
    assert len(transport.calls) == 2
    lines = log_lines(config)
    assert len(lines) == 1
    assert "report" in lines[0]
    assert "PostToolUse" in lines[0]
    assert "dropped" in lines[0]
    assert TOKEN_VALUE not in lines[0]


def test_report_without_configuration_exits_0_and_sends_nothing(
    run: Runner, transport: FakeTransport, config: dict[str, Any]
) -> None:
    conf = {k: v for k, v in config.items() if k != "service_url"}
    assert run("report", POST_TOOL_USE, conf=conf) == (0, "", "")
    assert transport.calls == []
    # An unusable configuration file names no trusted log path, so nothing is logged.
    assert log_lines(config) == []


def test_report_oversized_is_dropped_not_blocked(
    run: Runner, transport: FakeTransport, config: dict[str, Any], hc: object
) -> None:
    big = dict(POST_TOOL_USE, tool_response={"stdout": "x" * hc.MAX_REQUEST_BYTES})  # type: ignore[attr-defined]
    assert run("report", big) == (0, "", "")
    assert transport.calls == []
    assert "too_large" in log_lines(config)[0]


def test_report_malformed_input_exits_0(
    run: Runner, transport: FakeTransport, config: dict[str, Any]
) -> None:
    assert run("report", None, raw=b"garbage") == (0, "", "")
    assert transport.calls == []
    assert len(log_lines(config)) == 1


def test_report_with_unwritable_log_still_exits_0(
    run: Runner, transport: FakeTransport, config: dict[str, Any], tmp_path: Path
) -> None:
    conf = {**config, "log_file": str(tmp_path)}  # a directory: cannot be opened
    transport.results.extend([ConnectionRefusedError("x"), ConnectionRefusedError("x")])
    assert run("report", POST_TOOL_USE, conf=conf) == (0, "", "")
