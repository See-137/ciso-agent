"""Claims, device and surface: what the client reads on the machine."""

from __future__ import annotations

import ast
import json
from types import ModuleType
from typing import Any

import pytest
from tests.integrations.claude_code.conftest import (
    CLIENT_PATH,
    PRE_TOOL_USE,
    FakeTransport,
    Runner,
)

pytestmark = pytest.mark.unit

ALLOW = json.dumps({"verdict": "allow", "decision_id": "dec_1"}).encode()


def test_windows_claim_is_domain_backslash_user(hc: ModuleType) -> None:
    claim = hc.os_account_claim({"USERDOMAIN": "CORP", "USERNAME": "jdoe"}, True, lambda: "x")
    assert claim == {"kind": "os_account", "subject": "CORP\\jdoe", "verified": False}


def test_windows_claim_without_domain_is_user_only(hc: ModuleType) -> None:
    claim = hc.os_account_claim({"USERNAME": "jdoe"}, True, lambda: "x")
    assert claim["subject"] == "jdoe"


def test_windows_claim_without_environment_uses_getuser(hc: ModuleType) -> None:
    claim = hc.os_account_claim({}, True, lambda: "fallback")
    assert claim["subject"] == "fallback"


def test_posix_claim_uses_account_lookup(hc: ModuleType) -> None:
    claim = hc.os_account_claim({"USERDOMAIN": "IGNORED", "USER": "spoof"}, False, lambda: "alice")
    assert claim["subject"] == "alice"


def test_claim_is_never_marked_verified(run: Runner, transport: FakeTransport) -> None:
    transport.results.append((200, ALLOW))
    run("decide", PRE_TOOL_USE)
    claims = json.loads(transport.calls[0].body)["claims"]
    assert all(c["verified"] is False for c in claims)


def test_unreadable_account_gives_no_claim(hc: ModuleType) -> None:
    def broken() -> str:
        raise OSError("no account")

    claim = hc.os_account_claim({}, True, broken)
    assert claim is None


def test_surface_comes_from_the_configuration_file(
    run: Runner, transport: FakeTransport, config: dict[str, Any], environ: dict[str, str]
) -> None:
    transport.results.append((200, ALLOW))
    env = {**environ, "AIGOV_SURFACE": "web"}  # the environment plays no part
    run("decide", PRE_TOOL_USE, env=env, conf={**config, "surface": "ide"})
    assert json.loads(transport.calls[0].body)["surface"] == "ide"


def test_invalid_surface_blocks(
    run: Runner, transport: FakeTransport, config: dict[str, Any]
) -> None:
    code, _out, _err = run("decide", PRE_TOOL_USE, conf={**config, "surface": "bad surface!"})
    assert code == 2
    assert transport.calls == []


def test_client_uses_only_the_standard_library() -> None:
    tree = ast.parse(CLIENT_PATH.read_text(encoding="utf-8"))
    allowed = {
        "__future__",
        "base64",
        "collections",
        "contextlib",
        "dataclasses",
        "getpass",
        "json",
        "math",
        "os",
        "pathlib",
        "re",
        "socket",
        "ssl",
        "stat",
        "subprocess",
        "sys",
        "tempfile",
        "time",
        "typing",
        "urllib",
        "uuid",
        "pwd",
    }
    imported: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported |= {alias.name.split(".")[0] for alias in node.names}
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.add(node.module.split(".")[0])
    assert imported, "no imports parsed"
    assert imported <= allowed, imported - allowed
    assert "ciso" not in imported
