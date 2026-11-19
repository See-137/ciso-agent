"""Fixtures for the assistant-hook integration (C1, C2).

The hook client is a standalone script outside `src`, so it is loaded by path. Every
test talks to a fake transport; the repository egress guard blocks real connections.
"""

from __future__ import annotations

import importlib.util
import json
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
#: The empty hooks directory the managed env names (an absolute path on any OS).
HOOKS_DIR = Path(__file__).resolve().parent / "no-hooks-for-tests"


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


def make_ca_pem() -> bytes:
    """A self-signed CA certificate in PEM, so the client's TLS context can load it."""
    import datetime

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "aigov test ca")])
    now = datetime.datetime(2026, 1, 1, tzinfo=datetime.UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.PEM)


@pytest.fixture(scope="session")
def ca_pem() -> bytes:
    return make_ca_pem()


@pytest.fixture
def ca_bundle(tmp_path: Path, ca_pem: bytes) -> Path:
    path = tmp_path / "ca.pem"
    path.write_bytes(ca_pem)
    return path


@pytest.fixture
def git_exe(tmp_path: Path) -> Path:
    exe = tmp_path / "git.exe"
    exe.write_bytes(b"")
    return exe


@pytest.fixture
def config(token_file: Path, ca_bundle: Path, git_exe: Path, tmp_path: Path) -> dict[str, Any]:
    """A complete client configuration file, as the managed pack installs it."""
    return {
        "service_url": SERVICE_URL,
        "ca_bundle": str(ca_bundle),
        "token_file": str(token_file),
        "decide_timeout_seconds": 8,
        "report_timeout_seconds": 2,
        "hook_deadline_seconds": 14,
        "git_path": str(git_exe),
        "surface": "cli",
        "log_file": str(tmp_path / "hook-client.log"),
        "git_hooks_dir": str(HOOKS_DIR),
    }


@pytest.fixture
def environ() -> dict[str, str]:
    """The hook's environment: only what the client may read from it (the OS account)."""
    return {"USERDOMAIN": "CORP", "USERNAME": "jdoe", "PATH": "/usr/bin"}


def write_config(tmp_path: Path, config: dict[str, Any]) -> Path:
    path = tmp_path / "aigov-client.json"
    path.write_text(json.dumps(config), encoding="utf-8")
    return path


def never_writable(path: Path) -> bool:
    return False


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
def run(
    hc: ModuleType,
    environ: dict[str, str],
    transport: FakeTransport,
    config: dict[str, Any],
    tmp_path: Path,
) -> Runner:
    """Run the client's `main` with in-memory streams; returns (exit, stdout, stderr).
    `conf` replaces the configuration file's content (None: the `config` fixture)."""
    import io

    def _run(
        mode: str,
        payload: Any,
        env: dict[str, str] | None = None,
        raw: bytes | None = None,
        isolated: bool = True,
        conf: dict[str, Any] | None = None,
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
            config_path=write_config(tmp_path, config if conf is None else conf),
            writable=never_writable,
        )
        return code, stdout.getvalue(), stderr.getvalue()

    return _run
