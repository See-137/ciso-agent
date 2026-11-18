"""The plugin: manifest, hooks configuration, skill, and the bundled client copy."""

from __future__ import annotations

import copy
import json
from types import ModuleType
from typing import Any

import pytest
from tests.integrations.claude_code.conftest import (
    CLIENT_PATH,
    INTEGRATION,
    MANAGED_ROOT,
    PLUGIN_ROOT,
    load_script,
)

pytestmark = pytest.mark.unit

DECIDE_EVENTS = ("PreToolUse", "UserPromptSubmit", "SessionStart")
REPORT_EVENTS = ("PostToolUse", "SubagentStart", "SubagentStop", "Stop", "SessionEnd")


@pytest.fixture(scope="module")
def checker() -> ModuleType:
    return load_script(MANAGED_ROOT / "check_pack.py", "_aigov_check_pack")


@pytest.fixture
def hooks_config() -> dict[str, Any]:
    data = json.loads((PLUGIN_ROOT / "hooks" / "hooks.json").read_text(encoding="utf-8"))
    assert isinstance(data, dict)
    return data


def handlers(config: dict[str, Any], event: str) -> list[dict[str, Any]]:
    return [h for group in config["hooks"][event] for h in group["hooks"]]


def test_manifest_names_the_plugin() -> None:
    manifest = json.loads((PLUGIN_ROOT / ".claude-plugin" / "plugin.json").read_text("utf-8"))
    assert manifest["name"] == "ai-governance"
    assert manifest["version"]
    assert manifest["description"]
    assert manifest["author"]["name"]


def test_marketplace_lists_the_plugin() -> None:
    market = json.loads((INTEGRATION / ".claude-plugin" / "marketplace.json").read_text("utf-8"))
    assert market["name"] == "corp-ai-governance"
    assert market["owner"]["name"]
    assert [(p["name"], p["source"]) for p in market["plugins"]] == [("ai-governance", "./plugin")]


def test_hooks_file_has_the_documented_wrapper(hooks_config: dict[str, Any]) -> None:
    assert set(hooks_config) == {"description", "hooks"}
    assert set(hooks_config["hooks"]) == set(DECIDE_EVENTS) | set(REPORT_EVENTS)


@pytest.mark.parametrize("event", DECIDE_EVENTS)
def test_decide_hooks_block_on_failure(hooks_config: dict[str, Any], event: str) -> None:
    found = handlers(hooks_config, event)
    assert len(found) == 1
    hook = found[0]
    assert hook["type"] == "command"
    assert hook["command"] == "python3"
    assert hook["args"] == ["${CLAUDE_PLUGIN_ROOT}/scripts/hook_client.py", "decide"]
    assert hook["onFailure"] == "block"
    assert isinstance(hook["timeout"], int)
    assert hook["timeout"] > 0
    assert "async" not in hook
    assert "asyncRewake" not in hook


def test_pretooluse_matches_every_tool(hooks_config: dict[str, Any]) -> None:
    groups = hooks_config["hooks"]["PreToolUse"]
    assert [g["matcher"] for g in groups] == ["*"]


@pytest.mark.parametrize("event", REPORT_EVENTS)
def test_report_hooks_never_block(hooks_config: dict[str, Any], event: str) -> None:
    found = handlers(hooks_config, event)
    assert len(found) == 1
    hook = found[0]
    assert hook["args"] == ["${CLAUDE_PLUGIN_ROOT}/scripts/hook_client.py", "report"]
    assert hook.get("onFailure", "continue") == "continue"
    assert isinstance(hook["timeout"], int)


def test_checker_accepts_the_shipped_hooks(
    checker: ModuleType, hooks_config: dict[str, Any]
) -> None:
    assert checker.plugin_hook_errors(hooks_config) == []


@pytest.mark.parametrize("event", DECIDE_EVENTS)
@pytest.mark.parametrize("field", ["onFailure", "timeout"])
def test_checker_rejects_a_decide_hook_missing_a_guard(
    checker: ModuleType, hooks_config: dict[str, Any], event: str, field: str
) -> None:
    mutated = copy.deepcopy(hooks_config)
    del mutated["hooks"][event][0]["hooks"][0][field]
    errors = checker.plugin_hook_errors(mutated)
    assert any(event in e and field in e for e in errors), errors


@pytest.mark.parametrize(
    "change",
    [
        ("onFailure", "continue"),
        ("async", True),
        ("timeout", 0),
        ("timeout", "15"),
    ],
)
def test_checker_rejects_weakened_decide_hook(
    checker: ModuleType, hooks_config: dict[str, Any], change: tuple[str, Any]
) -> None:
    mutated = copy.deepcopy(hooks_config)
    key, value = change
    mutated["hooks"]["PreToolUse"][0]["hooks"][0][key] = value
    assert checker.plugin_hook_errors(mutated) != []


def test_checker_rejects_missing_decide_event(
    checker: ModuleType, hooks_config: dict[str, Any]
) -> None:
    mutated = copy.deepcopy(hooks_config)
    del mutated["hooks"]["UserPromptSubmit"]
    assert any("UserPromptSubmit" in e for e in checker.plugin_hook_errors(mutated))


def test_checker_rejects_narrowed_pretooluse_matcher(
    checker: ModuleType, hooks_config: dict[str, Any]
) -> None:
    mutated = copy.deepcopy(hooks_config)
    mutated["hooks"]["PreToolUse"][0]["matcher"] = "Bash"
    assert any("matcher" in e for e in checker.plugin_hook_errors(mutated))


def test_bundled_client_is_identical_to_the_source() -> None:
    bundled = PLUGIN_ROOT / "scripts" / "hook_client.py"
    assert bundled.read_bytes() == CLIENT_PATH.read_bytes()


def test_skill_advises_and_names_the_hooks_as_enforcement() -> None:
    text = (PLUGIN_ROOT / "skills" / "ai-governance" / "SKILL.md").read_text("utf-8")
    assert text.startswith("---\n")
    front, body = text[4:].split("\n---\n", 1)
    fields = dict(line.split(": ", 1) for line in front.splitlines() if ": " in line)
    assert fields["name"] == "ai-governance"
    assert len(fields["description"]) > 40
    lowered = body.lower()
    for phrase in ("advis", "hooks", "enforce", "decision", "ticket", "ask the person"):
        assert phrase in lowered, phrase
