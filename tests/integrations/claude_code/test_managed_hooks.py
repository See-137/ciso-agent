"""The enforcing hooks in the managed settings: every decide hook blocks on failure and has
a timeout, every hook runs an admin-installed interpreter on an admin-owned client."""

from __future__ import annotations

import copy
import json
from types import ModuleType
from typing import Any

import pytest
from tests.integrations.claude_code.conftest import MANAGED_ROOT, load_script

pytestmark = pytest.mark.unit

DECIDE_EVENTS = ("PreToolUse", "UserPromptSubmit", "SessionStart")
REPORT_EVENTS = ("PostToolUse", "SubagentStart", "SubagentStop", "Stop", "SessionEnd")
PLATFORMS = ("windows", "macos", "linux")


@pytest.fixture(scope="module")
def checker() -> ModuleType:
    return load_script(MANAGED_ROOT / "check_pack.py", "_aigov_check_pack_hooks")


@pytest.fixture(scope="module")
def source() -> dict[str, Any]:
    data = json.loads((MANAGED_ROOT / "pack_source.json").read_text(encoding="utf-8"))
    assert isinstance(data, dict)
    return data


def shipped(platform: str) -> dict[str, Any]:
    data = json.loads((MANAGED_ROOT / platform / "managed-settings.json").read_text("utf-8"))
    assert isinstance(data, dict)
    return data


def handlers(config: dict[str, Any], event: str) -> list[dict[str, Any]]:
    return [h for group in config["hooks"][event] for h in group["hooks"]]


@pytest.mark.parametrize("platform", PLATFORMS)
def test_every_platform_ships_the_hooks_in_managed_settings(platform: str) -> None:
    policy = shipped(platform)
    assert set(policy["hooks"]) == set(DECIDE_EVENTS) | set(REPORT_EVENTS)
    assert policy["allowManagedHooksOnly"] is True


@pytest.mark.parametrize("platform", PLATFORMS)
@pytest.mark.parametrize("event", DECIDE_EVENTS)
def test_decide_hooks_block_on_failure(platform: str, event: str, source: dict[str, Any]) -> None:
    (hook,) = handlers(shipped(platform), event)
    expected = source["platform_hook"][platform]
    assert hook["type"] == "command"
    assert hook["command"] == expected["command"]
    assert hook["args"] == ["-I", expected["client"], "decide"]
    assert hook["onFailure"] == "block"
    assert isinstance(hook["timeout"], int)
    assert hook["timeout"] > 0
    assert "async" not in hook


@pytest.mark.parametrize("event", REPORT_EVENTS)
def test_report_hooks_never_block(event: str) -> None:
    (hook,) = handlers(shipped("linux"), event)
    assert hook["args"][0] == "-I"
    assert hook["args"][2] == "report"
    assert hook.get("onFailure", "continue") == "continue"
    assert isinstance(hook["timeout"], int)


def test_pretooluse_matches_every_tool() -> None:
    assert [g["matcher"] for g in shipped("windows")["hooks"]["PreToolUse"]] == ["*"]


@pytest.mark.parametrize("platform", PLATFORMS)
def test_the_shipped_hooks_pass_the_checker(checker: ModuleType, platform: str) -> None:
    policy = shipped(platform)
    assert checker.hook_errors(policy) == []
    assert checker.hook_path_errors(policy, platform) == []


@pytest.mark.parametrize("event", DECIDE_EVENTS)
@pytest.mark.parametrize("field", ["onFailure", "timeout"])
def test_checker_rejects_a_decide_hook_missing_a_guard(
    checker: ModuleType, event: str, field: str
) -> None:
    policy = copy.deepcopy(shipped("linux"))
    del policy["hooks"][event][0]["hooks"][0][field]
    errors = checker.hook_errors(policy)
    assert any(event in e and field in e for e in errors), errors


@pytest.mark.parametrize(
    "change", [("onFailure", "continue"), ("async", True), ("timeout", 0), ("timeout", "15")]
)
def test_checker_rejects_a_weakened_decide_hook(
    checker: ModuleType, change: tuple[str, Any]
) -> None:
    policy = copy.deepcopy(shipped("linux"))
    key, value = change
    policy["hooks"]["PreToolUse"][0]["hooks"][0][key] = value
    assert checker.hook_errors(policy) != []


def test_checker_rejects_a_narrowed_pretooluse_matcher(checker: ModuleType) -> None:
    policy = copy.deepcopy(shipped("linux"))
    policy["hooks"]["PreToolUse"][0]["matcher"] = "Bash"
    assert any("matcher" in e for e in checker.hook_errors(policy))


@pytest.mark.parametrize(
    ("platform", "command", "client"),
    [
        ("linux", "python3", "/usr/local/lib/ai-governance/hook_client.py"),
        ("linux", "/usr/bin/python3", "${CLAUDE_PLUGIN_ROOT}/scripts/hook_client.py"),
        ("linux", "/usr/bin/python3", "/home/jo/hook_client.py"),
        ("linux", "/usr/bin/python3", "/tmp/hook_client.py"),  # noqa: S108
        ("macos", "/usr/bin/python3", "/Users/jo/hook_client.py"),
        ("windows", "python.exe", r"C:\Program Files\AIGovernance\hook_client.py"),
        ("windows", r"C:\Program Files\AIGovernance\python\python.exe",
         r"C:\Users\jo\AppData\Local\hook_client.py"),
        ("windows", r"C:\Program Files\AIGovernance\python\python.exe",
         r"%USERPROFILE%\hook_client.py"),
    ],
)  # fmt: skip
def test_checker_rejects_a_hook_a_user_could_replace(
    checker: ModuleType, source: dict[str, Any], platform: str, command: str, client: str
) -> None:
    hooks = checker.managed_hooks(source["hook_timeouts"], {"command": command, "client": client})
    assert checker.hook_path_errors({"hooks": hooks}, platform) != []


def test_the_client_timeouts_are_shorter_than_the_hook_timeouts(source: dict[str, Any]) -> None:
    env = source["policy"]["env"]
    timeouts = source["hook_timeouts"]
    assert float(env["AIGOV_DECIDE_TIMEOUT_SECONDS"]) < timeouts["decide"]
    assert float(env["AIGOV_REPORT_TIMEOUT_SECONDS"]) < min(timeouts.values())


@pytest.mark.parametrize("platform", PLATFORMS)
@pytest.mark.parametrize("args", [["CLIENT", "decide"], ["-E", "CLIENT", "decide"], []])
def test_checker_refuses_a_hook_without_isolated_python(
    checker: ModuleType, platform: str, args: list[str]
) -> None:
    policy = copy.deepcopy(shipped(platform))
    hook = policy["hooks"]["PreToolUse"][0]["hooks"][0]
    client = hook["args"][1]
    hook["args"] = [client if a == "CLIENT" else a for a in args]
    assert any("-I" in e or "absolute" in e for e in checker.hook_path_errors(policy, platform))
