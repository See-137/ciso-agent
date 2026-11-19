"""Managed settings templates for the plugin and their checker."""

from __future__ import annotations

import copy
import importlib.util
import json
import shutil
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest
from tests.plugin.conftest import MANAGED_ROOT, PLUGIN_ROOT

pytestmark = pytest.mark.unit


@pytest.fixture(scope="module")
def checker() -> ModuleType:
    spec = importlib.util.spec_from_file_location("_ciso_check", MANAGED_ROOT / "check_managed.py")
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _filled(tmp_path: Path) -> Path:
    target = tmp_path / "managed"
    for name in ("windows", "macos", "linux"):
        text = (MANAGED_ROOT / name / "managed-settings.json").read_text(encoding="utf-8")
        text = text.replace("REPLACE_ME_ORG_UUID", "00000000-0000-4000-8000-000000000001")
        text = text.replace(
            "https://REPLACE_ME_MARKETPLACE_GIT_URL", "https://git.example.invalid/m.git"
        )
        (target / name).mkdir(parents=True)
        (target / name / "managed-settings.json").write_text(text, encoding="utf-8")
    return target


def _edit(folder: Path, change: Any) -> None:
    for name in ("windows", "macos", "linux"):
        path = folder / name / "managed-settings.json"
        data = json.loads(path.read_text(encoding="utf-8"))
        change(data)
        path.write_text(json.dumps(data), encoding="utf-8")


def test_committed_templates_are_not_ready_until_placeholders_are_filled(
    checker: ModuleType,
) -> None:
    code, lines = checker.check(MANAGED_ROOT, PLUGIN_ROOT)
    assert code == 1
    assert lines == ["placeholders (REPLACE_ME) remain"]


def test_filled_templates_are_ready(checker: ModuleType, tmp_path: Path) -> None:
    assert checker.check(_filled(tmp_path), PLUGIN_ROOT) == (0, [])


def test_templates_carry_every_control(tmp_path: Path) -> None:
    data = json.loads(
        (MANAGED_ROOT / "linux" / "managed-settings.json").read_text(encoding="utf-8")
    )
    assert data["allowManagedHooksOnly"] is True
    assert data["enabledPlugins"] == {"ciso-agent@corp-ai-governance": True}
    env = data["env"]
    pairs = {
        env[f"GIT_CONFIG_KEY_{i}"]: env[f"GIT_CONFIG_VALUE_{i}"]
        for i in range(int(env["GIT_CONFIG_COUNT"]))
    }
    assert pairs == {
        "safe.bareRepository": "explicit",
        "push.recurseSubmodules": "no",
        "protocol.ext.allow": "never",
        "core.hooksPath": "/usr/local/share/ciso-agent/empty-hooks",
    }
    assert (env["CISO_STOP"], env["CISO_ROLE"], env["CISO_AGENT_CLASS"]) == (
        "0",
        "employee",
        "employee_operated",
    )


@pytest.mark.parametrize(
    ("change", "expected"),
    [
        (lambda d: d.pop("allowManagedHooksOnly"), "allowManagedHooksOnly"),
        (lambda d: d.__setitem__("disableAllHooks", True), "disableAllHooks"),
        (lambda d: d.pop("disableSideloadFlags"), "disableSideloadFlags"),
        (lambda d: d["enabledPlugins"].clear(), "enabledPlugins"),
        (lambda d: d.__setitem__("strictKnownMarketplaces", []), "strictKnownMarketplaces"),
        (lambda d: d["env"].__setitem__("CISO_STOP", "maybe"), "CISO_STOP"),
        (lambda d: d["env"].__setitem__("CISO_ROLE", "root"), "CISO_ROLE"),
        (lambda d: d["env"].__setitem__("CISO_AGENT_CLASS", "bot"), "CISO_AGENT_CLASS"),
        (lambda d: d["env"].__setitem__("GIT_CONFIG_VALUE_0", "all"), "safe.bareRepository"),
        (lambda d: d["env"].__setitem__("GIT_CONFIG_COUNT", "2"), "GIT_CONFIG_KEY_n beyond"),
        (
            lambda d: d["permissions"].pop("disableBypassPermissionsMode"),
            "disableBypassPermissionsMode",
        ),
    ],
)
def test_a_weakened_control_is_invalid(
    checker: ModuleType, tmp_path: Path, change: Any, expected: str
) -> None:
    folder = _filled(tmp_path)
    _edit(folder, change)
    code, lines = checker.check(folder, PLUGIN_ROOT)
    assert code == 2
    assert any(expected in line for line in lines), lines


def test_platform_files_must_agree(checker: ModuleType, tmp_path: Path) -> None:
    folder = _filled(tmp_path)
    path = folder / "macos" / "managed-settings.json"
    data = json.loads(path.read_text(encoding="utf-8"))
    data["env"]["CISO_ROLE"] = "auditor"
    path.write_text(json.dumps(data), encoding="utf-8")
    code, lines = checker.check(folder, PLUGIN_ROOT)
    assert code == 2
    assert "disagree" in " ".join(lines)


@pytest.mark.parametrize("field", ["onFailure", "timeout", "args"])
def test_plugin_hooks_must_be_fail_closed_exec_form(
    checker: ModuleType, tmp_path: Path, field: str
) -> None:
    plugin = tmp_path / "plugin"
    shutil.copytree(PLUGIN_ROOT / "hooks", plugin / "hooks")
    path = plugin / "hooks" / "hooks.json"
    data = json.loads(path.read_text(encoding="utf-8"))
    mutated = copy.deepcopy(data)
    mutated["hooks"]["PreToolUse"][0]["hooks"][0].pop(field)
    path.write_text(json.dumps(mutated), encoding="utf-8")
    code, lines = checker.check(_filled(tmp_path), plugin)
    assert code == 2
    assert any("PreToolUse" in line for line in lines)


def test_plugin_hooks_cover_every_tool_and_the_prompt() -> None:
    data = json.loads((PLUGIN_ROOT / "hooks" / "hooks.json").read_text(encoding="utf-8"))
    assert data["hooks"]["PreToolUse"][0]["matcher"] == "*"
    for event in ("PreToolUse", "UserPromptSubmit"):
        handler = data["hooks"][event][0]["hooks"][0]
        assert handler["onFailure"] == "block"
        assert handler["args"][-4:-1] == ["python", "-I", "-B"]
        assert "--no-config" in handler["args"]
        assert "--directory" in handler["args"]
