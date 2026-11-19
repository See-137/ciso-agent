"""The managed policy pack: generated artifacts match the source; the checker refuses a
pack with placeholders or a missing control."""

from __future__ import annotations

import copy
import json
import plistlib
import sys
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest
from tests.integrations.claude_code.conftest import MANAGED_ROOT, PLUGIN_ROOT, load_script

pytestmark = pytest.mark.unit

FILLED = {
    "REPLACE_ME_ORG_UUID": "123e4567-e89b-12d3-a456-426614174000",
    "https://REPLACE_ME_SERVICE_HOST": "https://governance.corp.example",
    "https://REPLACE_ME_MARKETPLACE_GIT_URL": "https://git.corp.example/ai/plugins.git",
}


@pytest.fixture(scope="module")
def builder() -> ModuleType:
    return load_script(MANAGED_ROOT / "build_pack.py", "_aigov_build_pack")


@pytest.fixture(scope="module")
def checker() -> ModuleType:
    return load_script(MANAGED_ROOT / "check_pack.py", "_aigov_check_pack")


@pytest.fixture
def source() -> dict[str, Any]:
    data = json.loads((MANAGED_ROOT / "pack_source.json").read_text(encoding="utf-8"))
    assert isinstance(data, dict)
    return data


def fill(value: Any) -> Any:
    if isinstance(value, str):
        for placeholder, real in FILLED.items():
            value = value.replace(placeholder, real)
        return value
    if isinstance(value, list):
        return [fill(v) for v in value]
    if isinstance(value, dict):
        return {k: fill(v) for k, v in value.items()}
    return value


def write_pack(builder: ModuleType, src: dict[str, Any], out: Path) -> Path:
    for relative, data in builder.build(src).items():
        target = out / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
    return out


def test_committed_artifacts_match_the_source(builder: ModuleType, source: dict[str, Any]) -> None:
    built = builder.build(source)
    assert set(built) == set(builder.ARTIFACTS)
    for relative, data in built.items():
        assert (MANAGED_ROOT / relative).read_bytes() == data, relative


def test_artifacts_are_in_the_documented_formats(
    builder: ModuleType, source: dict[str, Any]
) -> None:
    built = builder.build(source)
    linux = json.loads(built["linux/managed-settings.json"])
    windows = json.loads(built["windows/managed-settings.json"])
    reg = built["windows/ClaudeCode-policy.reg"].decode("utf-16")
    assert reg.startswith("\ufeffWindows Registry Editor Version 5.00") or reg.startswith(
        "Windows Registry Editor Version 5.00"
    )
    assert "[HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\ClaudeCode]" in reg
    assert '"Settings"="' in reg
    profile = plistlib.loads(built["macos/com.anthropic.claudecode.mobileconfig"])
    payload = profile["PayloadContent"][0]
    assert payload["PayloadType"] == "com.anthropic.claudecode"
    assert payload["allowManagedHooksOnly"] is True
    assert not [k for k in (*linux["env"], *windows["env"]) if k.startswith("AIGOV_")]
    linux_client = json.loads(built["linux/aigov-client.json"])
    windows_client = json.loads(built["windows/aigov-client.json"])
    assert linux_client["token_file"].startswith("/etc/")
    assert windows_client["token_file"].startswith("C:\\ProgramData\\")
    assert windows_client["ca_bundle"].startswith("C:\\Program Files\\AIGovernance\\")
    admx = (MANAGED_ROOT / "windows" / "admx" / "ClaudeCodeGovernance.admx").read_text("utf-8")
    assert 'key="Software\\Policies\\ClaudeCode"' in admx
    assert 'valueName="Settings"' in admx


def test_committed_pack_is_not_ready_because_of_placeholders(checker: ModuleType) -> None:
    report = checker.check_pack(MANAGED_ROOT, PLUGIN_ROOT)
    assert report.errors == []
    assert report.placeholders, "placeholders expected in the committed template"
    assert checker.main(["check_pack.py", str(MANAGED_ROOT)]) == 1


def test_filled_pack_is_ready(
    builder: ModuleType, checker: ModuleType, source: dict[str, Any], tmp_path: Path
) -> None:
    pack = write_pack(builder, fill(source), tmp_path / "pack")
    _copy_admx(pack)
    report = checker.check_pack(pack, PLUGIN_ROOT)
    assert report.errors == []
    assert report.placeholders == []
    assert checker.main(["check_pack.py", str(pack), "--plugin", str(PLUGIN_ROOT)]) == 0


def _copy_admx(pack: Path) -> None:
    for path in (MANAGED_ROOT / "windows" / "admx").rglob("*"):
        if path.is_file():
            target = pack / path.relative_to(MANAGED_ROOT)
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(path.read_bytes())


MUTATIONS: list[tuple[str, Any]] = [
    ("allowManagedHooksOnly", None),
    ("allowManagedHooksOnly", False),
    ("forceLoginMethod", "console"),
    ("forceLoginOrgUUID", None),
    ("forceLoginOrgUUID", ["not-a-uuid"]),
    ("disableSideloadFlags", None),
    ("allowManagedPermissionRulesOnly", None),
    ("strictKnownMarketplaces", []),
    ("enabledPlugins", {}),
    ("requiredMinimumVersion", "2.1.200"),
    ("permissions.disableBypassPermissionsMode", None),
    ("permissions.deny", []),
    ("env.AIGOV_SERVICE_URL", "https://governance.corp.example"),
    ("env.AIGOV_CA_BUNDLE", "/etc/ai-governance/x.pem"),
    ("env.GIT_CONFIG_COUNT", None),
    ("env.GIT_CONFIG_COUNT", "3"),
    ("env.GIT_CONFIG_COUNT", "5"),
    ("env.GIT_CONFIG_VALUE_0", None),
    ("env.GIT_CONFIG_VALUE_0", "/home/jo/hooks"),
    ("env.GIT_CONFIG_VALUE_0", "hooks"),
    ("env.GIT_CONFIG_VALUE_1", "all"),
    ("env.GIT_CONFIG_VALUE_2", "on-demand"),
    ("env.GIT_CONFIG_VALUE_3", "always"),
    ("env.GIT_CONFIG_KEY_3", "protocol.allow"),
    ("env.GIT_CONFIG_KEY_4", "remote.origin.pushurl"),
    ("hooks", None),
    ("hooks.PreToolUse", None),
    ("hooks.UserPromptSubmit", None),
    ("hooks.Stop", None),
]


def linux_policy(checker: ModuleType, source: dict[str, Any]) -> dict[str, Any]:
    hooks = checker.managed_hooks(source["hook_timeouts"], source["platform_hook"]["linux"])
    merged: dict[str, Any] = checker.merge_platform(
        fill(source["policy"]),
        fill(source["platform_env"]["linux"]),
        source["platform_deny"]["linux"],
        hooks,
    )
    return merged


def _mutate(policy: dict[str, Any], dotted: str, value: Any) -> dict[str, Any]:
    result = copy.deepcopy(policy)
    *parents, leaf = dotted.split(".")
    node = result
    for part in parents:
        node = node[part]
    if value is None:
        node.pop(leaf, None)
    else:
        node[leaf] = value
    return result


@pytest.mark.parametrize(("dotted", "value"), MUTATIONS, ids=[f"{d}={v}" for d, v in MUTATIONS])
def test_checker_refuses_a_weakened_policy(
    checker: ModuleType, source: dict[str, Any], dotted: str, value: Any
) -> None:
    merged = linux_policy(checker, source)
    assert checker.policy_errors(merged, "linux") == []
    weakened = _mutate(merged, dotted, value)
    assert checker.policy_errors(weakened, "linux") != []


def test_checker_detects_artifacts_that_disagree(
    builder: ModuleType, checker: ModuleType, source: dict[str, Any], tmp_path: Path
) -> None:
    pack = write_pack(builder, fill(source), tmp_path / "pack")
    _copy_admx(pack)
    path = pack / "windows" / "managed-settings.json"
    data = json.loads(path.read_text("utf-8"))
    data["companyAnnouncements"] = ["changed by hand"]
    path.write_text(json.dumps(data), encoding="utf-8")
    report = checker.check_pack(pack, PLUGIN_ROOT)
    assert any("registry" in e for e in report.errors), report.errors
    assert checker.main(["check_pack.py", str(pack), "--plugin", str(PLUGIN_ROOT)]) == 2


def test_checker_reports_a_missing_artifact(
    builder: ModuleType, checker: ModuleType, source: dict[str, Any], tmp_path: Path
) -> None:
    pack = write_pack(builder, fill(source), tmp_path / "pack")
    _copy_admx(pack)
    (pack / "macos" / "com.anthropic.claudecode.mobileconfig").unlink()
    report = checker.check_pack(pack, PLUGIN_ROOT)
    assert any("mobileconfig" in e for e in report.errors)


CLIENT_MUTATIONS: list[tuple[str, Any]] = [
    ("service_url", "http://governance.corp.example"),
    ("service_url", None),
    ("ca_bundle", None),
    ("ca_bundle", "ca.pem"),
    ("ca_bundle", "/home/jo/ca.pem"),
    ("git_path", "git"),
    ("git_path", "/Users/jo/bin/git"),
    ("token_file", "device-token"),
    ("log_file", None),
    ("decide_timeout_seconds", 15),
    ("decide_timeout_seconds", "8"),
    ("decide_timeout_seconds", True),
    ("report_timeout_seconds", 5),
    ("hook_deadline_seconds", 15),
    ("hook_deadline_seconds", 7),  # below the decide timeout
    ("surface", "Bad Surface"),
    ("proxy", "http://proxy.corp.example"),
]


@pytest.mark.parametrize(
    ("key", "value"), CLIENT_MUTATIONS, ids=[f"{k}={v}" for k, v in CLIENT_MUTATIONS]
)
def test_checker_refuses_a_weakened_client_configuration(
    checker: ModuleType, source: dict[str, Any], key: str, value: Any
) -> None:
    filled = fill(source)
    client = checker.client_config(filled, "linux")
    policy = linux_policy(checker, source)
    assert checker.client_config_errors(client, policy, "linux") == []
    weakened = dict(client)
    if value is None:
        weakened.pop(key)
    else:
        weakened[key] = value
    assert checker.client_config_errors(weakened, policy, "linux") != []


def test_checker_reports_a_missing_client_configuration(
    builder: ModuleType, checker: ModuleType, source: dict[str, Any], tmp_path: Path
) -> None:
    pack = write_pack(builder, fill(source), tmp_path / "pack")
    _copy_admx(pack)
    (pack / "windows" / "aigov-client.json").unlink()
    report = checker.check_pack(pack, PLUGIN_ROOT)
    assert any("aigov-client.json" in e for e in report.errors)


def test_the_checker_and_the_client_agree_on_the_configuration_keys(
    checker: ModuleType, hc: ModuleType
) -> None:
    assert checker.CLIENT_CONFIG_KEYS == hc.CONFIG_KEYS
    assert checker.CLIENT_CONFIG_NAME == hc.CONFIG_FILE_NAME


@pytest.mark.parametrize("platform", ["windows", "macos", "linux"])
def test_the_client_reads_the_built_configuration(
    builder: ModuleType, hc: ModuleType, source: dict[str, Any], tmp_path: Path, platform: str
) -> None:
    if (platform == "windows") != (sys.platform == "win32"):
        pytest.skip("paths are absolute only on their own platform")
    path = tmp_path / "aigov-client.json"
    path.write_bytes(builder.build(fill(source))[f"{platform}/aigov-client.json"])
    parsed = hc.read_file_config(path, lambda p: False)
    assert parsed.service_url == "https://governance.corp.example"
    assert parsed.hook_deadline < source["hook_timeouts"]["decide"]


def test_checker_validates_the_client_configuration_artifact(
    builder: ModuleType, checker: ModuleType, source: dict[str, Any], tmp_path: Path
) -> None:
    pack = write_pack(builder, fill(source), tmp_path / "pack")
    _copy_admx(pack)
    assert checker.check_pack(pack, PLUGIN_ROOT).errors == []
    path = pack / "linux" / "aigov-client.json"
    data = json.loads(path.read_text("utf-8"))
    data["ca_bundle"] = "/home/jo/ca.pem"
    path.write_text(json.dumps(data), encoding="utf-8")
    report = checker.check_pack(pack, PLUGIN_ROOT)
    assert any("linux/aigov-client.json" in e and "ca_bundle" in e for e in report.errors)
