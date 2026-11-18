"""Fixtures for the assistant-hook integration (C1, C2).

The hook client is a standalone script outside `src`, so it is loaded by path. Every
test talks to a fake transport; the repository egress guard blocks real connections.
"""

from __future__ import annotations

import importlib.util
import sys
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

REPO_ROOT = Path(__file__).resolve().parents[3]
INTEGRATION = REPO_ROOT / "integrations" / "claude_code"
CLIENT_PATH = INTEGRATION / "client" / "hook_client.py"
PLUGIN_ROOT = INTEGRATION / "plugin"
MANAGED_ROOT = INTEGRATION / "managed"

TOKEN_VALUE = "dev-token-abc123"
SERVICE_URL = "https://governance.example.test"


def load_script(path: Path, name: str) -> ModuleType:
    """Import a standalone script by file path, registered under a private name."""
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="session")
def hc() -> ModuleType:
    return load_script(CLIENT_PATH, "_aigov_hook_client")


@dataclass
class Call:
    url: str
    body: bytes
    headers: dict[str, str]
    timeout: float
    context: Any


@dataclass
class FakeTransport:
    """Answers each POST from a queue of results: an (status, body) pair or an exception."""

    results: list[Any] = field(default_factory=list)
    calls: list[Call] = field(default_factory=list)

    def post(
        self,
        url: str,
        body: bytes,
        headers: Mapping[str, str],
        timeout: float,
        context: Any,
    ) -> Any:
        self.calls.append(Call(url, body, dict(headers), timeout, context))
        if not self.results:
            raise AssertionError("fake transport called more often than scripted")
        result = self.results.pop(0)
        if isinstance(result, BaseException):
            raise result
        status, payload = result
        from_module = sys.modules["_aigov_hook_client"]
        return from_module.HttpResponse(status=status, body=payload)


@pytest.fixture
def transport(hc: ModuleType) -> FakeTransport:
    return FakeTransport()


@pytest.fixture
def token_file(tmp_path: Path) -> Path:
    path = tmp_path / "device-token"
    path.write_text(TOKEN_VALUE + "\n", encoding="utf-8")
    return path


@pytest.fixture
def environ(token_file: Path, tmp_path: Path) -> dict[str, str]:
    """A complete managed environment, as the policy pack would set it."""
    return {
        "AIGOV_SERVICE_URL": SERVICE_URL,
        "AIGOV_DEVICE_TOKEN_FILE": str(token_file),
        "AIGOV_DECIDE_TIMEOUT_SECONDS": "8",
        "AIGOV_REPORT_TIMEOUT_SECONDS": "2",
        "AIGOV_LOG_FILE": str(tmp_path / "hook-client.log"),
        "USERDOMAIN": "CORP",
        "USERNAME": "jdoe",
    }


PRE_TOOL_USE: dict[str, Any] = {
    "session_id": "sess-1",
    "prompt_id": "prompt-1",
    "transcript_path": "/home/u/.claude/projects/x/t.jsonl",
    "cwd": "/home/u/project",
    "permission_mode": "default",
    "hook_event_name": "PreToolUse",
    "tool_name": "Bash",
    "tool_input": {"command": "git push origin main", "description": "push"},
    "tool_use_id": "toolu_01",
}

USER_PROMPT: dict[str, Any] = {
    "session_id": "sess-1",
    "transcript_path": "/home/u/.claude/projects/x/t.jsonl",
    "cwd": "/home/u/project",
    "permission_mode": "default",
    "hook_event_name": "UserPromptSubmit",
    "prompt": "write a function",
}

SESSION_START: dict[str, Any] = {
    "session_id": "sess-1",
    "transcript_path": "/home/u/.claude/projects/x/t.jsonl",
    "cwd": "/home/u/project",
    "hook_event_name": "SessionStart",
    "source": "startup",
}

POST_TOOL_USE: dict[str, Any] = {
    "session_id": "sess-1",
    "cwd": "/home/u/project",
    "hook_event_name": "PostToolUse",
    "tool_name": "Bash",
    "tool_input": {"command": "ls"},
    "tool_response": {"stdout": "a\nb"},
    "tool_use_id": "toolu_02",
}


Runner = Callable[..., Any]


@pytest.fixture
def run(hc: ModuleType, environ: dict[str, str], transport: FakeTransport) -> Runner:
    """Run the client's `main` with in-memory streams; returns (exit, stdout, stderr)."""
    import io
    import json

    def _run(
        mode: str,
        payload: Any,
        env: dict[str, str] | None = None,
        raw: bytes | None = None,
        isolated: bool = True,
    ) -> tuple[int, str, str]:
        data = raw if raw is not None else json.dumps(payload).encode("utf-8")
        stdin = io.BytesIO(data)
        stdout = io.StringIO()
        stderr = io.StringIO()
        code = hc.main(
            ["hook_client.py", mode],
            stdin=stdin,
            stdout=stdout,
            stderr=stderr,
            environ=environ if env is None else env,
            transport=transport,
            hostname=lambda: "WS-0142",
            is_windows=True,
            isolated=isolated,
        )
        return code, stdout.getvalue(), stderr.getvalue()

    return _run
