"""The plugin: manifest, hooks configuration, skill, and the bundled client copy."""

from __future__ import annotations

import copy
import json
from pathlib import Path
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


@pytest.fixture(scope="module")
def checker() -> ModuleType:
    return load_script(MANAGED_ROOT / "check_pack.py", "_aigov_check_pack")


@pytest.fixture
def hooks_config() -> dict[str, Any]:
    data = json.loads((PLUGIN_ROOT / "hooks" / "hooks.json").read_text(encoding="utf-8"))
    assert isinstance(data, dict)
    return data


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
    # The CISO agent plugin (the deliverable) and the advisory plugin the optional service
    # add-on's managed pack force-enables.
    assert [(p["name"], p["source"]) for p in market["plugins"]] == [
        ("ciso-agent", "./ciso-plugin"),
        ("ai-governance", "./plugin"),
    ]


def test_the_plugin_declares_no_hooks(hooks_config: dict[str, Any], checker: ModuleType) -> None:
    """Enforcement lives in the managed settings; plugin files are user-writable."""
    assert set(hooks_config) == {"description", "hooks"}
    assert hooks_config["hooks"] == {}
    assert checker.plugin_declares_hooks(PLUGIN_ROOT) is False


def test_the_checker_refuses_a_plugin_that_declares_hooks(
    checker: ModuleType, hooks_config: dict[str, Any], tmp_path: Path
) -> None:
    plugin = tmp_path / "plugin"
    (plugin / "hooks").mkdir(parents=True)
    mutated = copy.deepcopy(hooks_config)
    mutated["hooks"] = {"PreToolUse": [{"matcher": "*", "hooks": [{"type": "command"}]}]}
    (plugin / "hooks" / "hooks.json").write_text(json.dumps(mutated), encoding="utf-8")
    assert checker.plugin_declares_hooks(plugin) is True
    report = checker.check_pack(MANAGED_ROOT, plugin)
    assert any("declares hooks" in e for e in report.errors)


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
