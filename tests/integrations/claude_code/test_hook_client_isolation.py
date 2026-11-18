"""The client refuses to answer anything but "block" unless Python runs isolated (`-I`):
otherwise a user's PYTHONPATH, PYTHONSTARTUP or user site directory could replace it."""

from __future__ import annotations

import pytest
from tests.integrations.claude_code.conftest import (
    POST_TOOL_USE,
    PRE_TOOL_USE,
    USER_PROMPT,
    FakeTransport,
    Runner,
)

pytestmark = pytest.mark.unit

ALLOW = (200, b'{"verdict": "allow", "decision_id": "dec_1", "reason": "r", "message": "m"}')


@pytest.mark.parametrize("payload", [PRE_TOOL_USE, USER_PROMPT])
def test_decide_without_isolation_blocks_and_sends_nothing(
    run: Runner, transport: FakeTransport, payload: dict[str, object]
) -> None:
    transport.results.append(ALLOW)
    code, _, stderr = run("decide", payload, isolated=False)
    assert code == 2
    assert stderr
    assert transport.calls == []


def test_report_without_isolation_sends_nothing(run: Runner, transport: FakeTransport) -> None:
    transport.results.append((202, b"{}"))
    code, stdout, _ = run("report", POST_TOOL_USE, isolated=False)
    assert (code, stdout) == (0, "")
    assert transport.calls == []


def test_decide_in_isolation_asks_the_service(run: Runner, transport: FakeTransport) -> None:
    transport.results.append(ALLOW)
    code, _, _ = run("decide", PRE_TOOL_USE, isolated=True)
    assert code == 0
    assert len(transport.calls) == 1
