#!/usr/bin/env python3
"""Check that a managed policy pack (component C1) is complete, consistent and ready.

Usage: ``python3 check_pack.py <pack_dir> [--plugin <plugin_dir>]``

Exit codes: 0 ready to deploy; 1 well formed but placeholders remain (NOT READY);
2 errors (a control is missing or weakened, an artifact is missing or the artifacts
disagree with each other). The plugin directory defaults to ``<pack_dir>/../plugin``; its
hooks are checked too, because a decide hook without ``onFailure: "block"`` and a timeout
fails open (spec section 9, item 1).

What each key does is documented at https://code.claude.com/docs/en/settings-reference.md
and https://code.claude.com/docs/en/managed-settings.md. Standard library only.
"""

from __future__ import annotations

import copy
import json
import math
import plistlib
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

PLACEHOLDER = "REPLACE_ME"
MARKETPLACE_NAME = "corp-ai-governance"
PLUGIN_ID = "ai-governance@" + MARKETPLACE_NAME
#: onFailure on command hooks requires this Claude Code version (hooks reference).
MIN_VERSION = (2, 1, 295)
PLATFORMS = ("windows", "macos", "linux")
DECIDE_EVENTS = ("PreToolUse", "UserPromptSubmit", "SessionStart")
REPORT_EVENTS = ("PostToolUse", "SubagentStart", "SubagentStop", "Stop", "SessionEnd")
REQUIRED_DENY = ("Read(~/.ssh/**)", "Read(//**/.env)", "Read(~/.aws/credentials)")
REGISTRY_KEY = "HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\ClaudeCode"
PROFILE_DOMAIN = "com.anthropic.claudecode"

JSON_ARTIFACTS = {
    "windows": "windows/managed-settings.json",
    "macos": "macos/managed-settings.json",
    "linux": "linux/managed-settings.json",
}
REG_ARTIFACT = "windows/ClaudeCode-policy.reg"
PROFILE_ARTIFACT = "macos/com.anthropic.claudecode.mobileconfig"
ADMX_ARTIFACT = "windows/admx/ClaudeCodeGovernance.admx"
ADML_ARTIFACT = "windows/admx/en-US/ClaudeCodeGovernance.adml"

_UUID_RE = re.compile(
    r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"
)
_VERSION_RE = re.compile(r"(\d+)\.(\d+)\.(\d+)")
_HTTPS_RE = re.compile(r"https://[A-Za-z0-9.-]+(:\d{1,5})?(/[A-Za-z0-9._~/-]*)?")
_WINDOWS_ABS_RE = re.compile(r"[A-Za-z]:\\.+")


@dataclass
class Report:
    errors: list[str] = field(default_factory=list)
    placeholders: list[str] = field(default_factory=list)


def merge_platform(policy: dict[str, Any], env: dict[str, str], deny: list[str]) -> dict[str, Any]:
    """The policy for one platform: shared keys plus that platform's env and deny rules."""
    merged = copy.deepcopy(policy)
    merged["env"] = {**merged.get("env", {}), **env}
    permissions = merged.setdefault("permissions", {})
    permissions["deny"] = [*permissions.get("deny", []), *deny]
    return merged


def has_placeholder(value: Any) -> bool:
    return isinstance(value, str) and PLACEHOLDER in value


def find_placeholders(value: Any, where: str) -> list[str]:
    if has_placeholder(value):
        return [where]
    if isinstance(value, dict):
        return [p for k, v in value.items() for p in find_placeholders(v, f"{where}.{k}")]
    if isinstance(value, list):
        return [p for i, v in enumerate(value) for p in find_placeholders(v, f"{where}[{i}]")]
    return []


# --- plugin hooks ----------------------------------------------------------------------


def _handlers(config: dict[str, Any], event: str) -> list[dict[str, Any]]:
    groups = config.get("hooks", {}).get(event)
    if not isinstance(groups, list):
        return []
    return [
        h for g in groups if isinstance(g, dict) for h in g.get("hooks", []) if isinstance(h, dict)
    ]


def _timeout_ok(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value > 0


def plugin_hook_errors(config: dict[str, Any]) -> list[str]:
    """Every decide hook: command type, explicit timeout, onFailure "block", synchronous.

    PreToolUse must match every tool. Report hooks must exist and carry a timeout.
    """
    errors: list[str] = []
    for event in DECIDE_EVENTS:
        found = _handlers(config, event)
        if not found:
            errors.append(f"{event}: no decide hook")
        for hook in found:
            if hook.get("type") != "command":
                errors.append(f"{event}: hook type must be command")
            if not _timeout_ok(hook.get("timeout")):
                errors.append(f"{event}: decide hook needs an explicit timeout")
            if hook.get("onFailure") != "block":
                errors.append(f'{event}: decide hook needs onFailure "block"')
            if hook.get("async") or hook.get("asyncRewake"):
                errors.append(f"{event}: decide hook must not be async")
            if "decide" not in hook.get("args", []):
                errors.append(f"{event}: hook must run the client in decide mode")
    matchers = [g.get("matcher") for g in config.get("hooks", {}).get("PreToolUse", []) or []]
    if matchers and any(m not in ("*", "", None) for m in matchers):
        errors.append("PreToolUse: matcher must match every tool ('*')")
    for event in REPORT_EVENTS:
        found = _handlers(config, event)
        if not found:
            errors.append(f"{event}: no report hook")
        for hook in found:
            if not _timeout_ok(hook.get("timeout")):
                errors.append(f"{event}: report hook needs an explicit timeout")
    return errors


def hook_timeouts(plugin_dir: Path, events: tuple[str, ...]) -> list[int]:
    config = json.loads((plugin_dir / "hooks" / "hooks.json").read_text(encoding="utf-8"))
    return [
        h["timeout"] for e in events for h in _handlers(config, e) if _timeout_ok(h.get("timeout"))
    ]


# --- policy ----------------------------------------------------------------------------


def _version_ok(value: Any) -> bool:
    match = _VERSION_RE.fullmatch(value) if isinstance(value, str) else None
    return match is not None and tuple(int(g) for g in match.groups()) >= MIN_VERSION


def _seconds(value: Any) -> float | None:
    try:
        number = float(value)
    except (TypeError, ValueError):
        return None
    return number if math.isfinite(number) and number > 0 else None


def _login_errors(policy: dict[str, Any]) -> list[str]:
    errors = []
    if policy.get("forceLoginMethod") != "claudeai":
        errors.append('forceLoginMethod must be "claudeai"')
    orgs = policy.get("forceLoginOrgUUID")
    orgs = [orgs] if isinstance(orgs, str) else orgs
    if not isinstance(orgs, list) or not orgs:
        errors.append("forceLoginOrgUUID must name the company organization")
    else:
        for org in orgs:
            if not has_placeholder(org) and not (isinstance(org, str) and _UUID_RE.fullmatch(org)):
                errors.append("forceLoginOrgUUID entries must be UUIDs")
    providers = policy.get("allowedProviders")
    if not isinstance(providers, list) or not providers:
        errors.append("allowedProviders must list the permitted providers")
    return errors


def _lock_errors(policy: dict[str, Any]) -> list[str]:
    errors = [
        f"{key} must be true"
        for key in (
            "allowManagedHooksOnly",
            "disableSideloadFlags",
            "allowManagedPermissionRulesOnly",
            "disableCommandPluginSources",
        )
        if policy.get(key) is not True
    ]
    if not _version_ok(policy.get("requiredMinimumVersion")):
        errors.append("requiredMinimumVersion must be at least 2.1.295 (onFailure support)")
    permissions = policy.get("permissions", {})
    if permissions.get("disableBypassPermissionsMode") != "disable":
        errors.append('permissions.disableBypassPermissionsMode must be "disable"')
    deny = permissions.get("deny", [])
    missing = [rule for rule in REQUIRED_DENY if rule not in deny]
    if missing:
        errors.append(f"permissions.deny is missing {missing}")
    return errors


def _plugin_errors(policy: dict[str, Any]) -> list[str]:
    errors = []
    if policy.get("enabledPlugins", {}).get(PLUGIN_ID) is not True:
        errors.append(f"enabledPlugins must force-enable {PLUGIN_ID}")
    market = policy.get("extraKnownMarketplaces", {}).get(MARKETPLACE_NAME)
    allowed = policy.get("strictKnownMarketplaces")
    if not isinstance(market, dict):
        errors.append(f"extraKnownMarketplaces must register {MARKETPLACE_NAME}")
    if not isinstance(allowed, list) or not allowed:
        errors.append("strictKnownMarketplaces must be a non-empty allowlist")
    elif isinstance(market, dict) and market.get("source") not in allowed:
        errors.append("strictKnownMarketplaces must admit the governance marketplace source")
    return errors


def _env_errors(policy: dict[str, Any], plugin_dir: Path, platform: str) -> list[str]:
    errors = []
    env = policy.get("env", {})
    url = env.get("AIGOV_SERVICE_URL")
    if not has_placeholder(url) and not (isinstance(url, str) and _HTTPS_RE.fullmatch(url)):
        errors.append("env.AIGOV_SERVICE_URL must be an https URL")
    token = env.get("AIGOV_DEVICE_TOKEN_FILE", "")
    absolute = _WINDOWS_ABS_RE.fullmatch(token) if platform == "windows" else token.startswith("/")
    if not absolute:
        errors.append("env.AIGOV_DEVICE_TOKEN_FILE must be an absolute path")
    if env.get("CLAUDE_CODE_SYNC_PLUGIN_INSTALL") != "1":
        errors.append(
            "env.CLAUDE_CODE_SYNC_PLUGIN_INSTALL must be 1 (plugin hooks before the first turn)"
        )
    for variable, events in (
        ("AIGOV_DECIDE_TIMEOUT_SECONDS", DECIDE_EVENTS),
        ("AIGOV_REPORT_TIMEOUT_SECONDS", REPORT_EVENTS),
    ):
        seconds = _seconds(env.get(variable))
        limits = hook_timeouts(plugin_dir, events)
        if seconds is None:
            errors.append(f"env.{variable} must be a positive number of seconds")
        elif not limits or seconds >= min(limits):
            errors.append(f"env.{variable} must be shorter than the plugin hook timeout")
    return errors


def policy_errors(policy: dict[str, Any], plugin_dir: Path, platform: str) -> list[str]:
    """Every control the pack must carry, for one platform. Placeholders are not errors."""
    return (
        _login_errors(policy)
        + _lock_errors(policy)
        + _plugin_errors(policy)
        + _env_errors(policy, plugin_dir, platform)
    )


# --- artifacts -------------------------------------------------------------------------


def read_registry_settings(data: bytes) -> dict[str, Any]:
    """The JSON stored in the ``Settings`` value of a .reg file (UTF-16, version 5)."""
    text = data.decode("utf-16")
    if REGISTRY_KEY not in text:
        raise ValueError("registry key missing")
    prefix = '"Settings"="'
    for line in text.splitlines():
        if line.startswith(prefix) and line.endswith('"'):
            raw = line[len(prefix) : -1]
            value = re.sub(r"\\(.)", r"\1", raw)
            loaded = json.loads(value)
            if isinstance(loaded, dict):
                return loaded
    raise ValueError("Settings value missing")


def read_profile_settings(data: bytes) -> dict[str, Any]:
    profile = plistlib.loads(data)
    payloads = [
        p for p in profile.get("PayloadContent", []) if p.get("PayloadType") == PROFILE_DOMAIN
    ]
    if len(payloads) != 1:
        raise ValueError("expected one com.anthropic.claudecode payload")
    return {k: v for k, v in payloads[0].items() if not k.startswith("Payload")}


def _load_json(pack: Path, relative: str, report: Report) -> dict[str, Any] | None:
    try:
        loaded = json.loads((pack / relative).read_text(encoding="utf-8"))
    except (OSError, ValueError) as error:
        report.errors.append(f"{relative}: unreadable ({error.__class__.__name__})")
        return None
    if not isinstance(loaded, dict):
        report.errors.append(f"{relative}: not a JSON object")
        return None
    return loaded


def _compare(
    pack: Path, relative: str, reader: Any, expected: Any, label: str, report: Report
) -> None:
    try:
        found = reader((pack / relative).read_bytes())
    except (OSError, ValueError) as error:
        report.errors.append(f"{relative}: unreadable {label} ({error.__class__.__name__})")
        return
    if expected is not None and found != expected:
        report.errors.append(f"{relative}: {label} settings differ from the JSON file")


def _check_admx(pack: Path, report: Report) -> None:
    try:
        admx = (pack / ADMX_ARTIFACT).read_text(encoding="utf-8")
        (pack / ADML_ARTIFACT).read_text(encoding="utf-8")
    except OSError:
        report.errors.append(f"{ADMX_ARTIFACT}: missing group-policy template")
        return
    if 'key="Software\\Policies\\ClaudeCode"' not in admx or 'valueName="Settings"' not in admx:
        report.errors.append(
            f"{ADMX_ARTIFACT}: must write Settings under Software\\Policies\\ClaudeCode"
        )


def check_pack(pack: Path, plugin_dir: Path) -> Report:
    report = Report()
    try:
        hooks = json.loads((plugin_dir / "hooks" / "hooks.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        report.errors.append("plugin hooks/hooks.json: unreadable")
        return report
    report.errors.extend("plugin " + e for e in plugin_hook_errors(hooks))
    policies: dict[str, dict[str, Any] | None] = {}
    for platform, relative in JSON_ARTIFACTS.items():
        policy = _load_json(pack, relative, report)
        policies[platform] = policy
        if policy is not None:
            report.errors.extend(
                f"{relative}: {e}" for e in policy_errors(policy, plugin_dir, platform)
            )
            report.placeholders.extend(find_placeholders(policy, relative))
    _compare(pack, REG_ARTIFACT, read_registry_settings, policies["windows"], "registry", report)
    _compare(
        pack, PROFILE_ARTIFACT, read_profile_settings, policies["macos"], "mobileconfig", report
    )
    _check_admx(pack, report)
    return report


def main(argv: list[str]) -> int:
    args = argv[1:]
    if not args or args[0].startswith("-"):
        sys.stderr.write("usage: check_pack.py <pack_dir> [--plugin <plugin_dir>]\n")
        return 2
    pack = Path(args[0])
    plugin = pack.parent / "plugin"
    if len(args) == 3 and args[1] == "--plugin":
        plugin = Path(args[2])
    elif len(args) != 1:
        sys.stderr.write("usage: check_pack.py <pack_dir> [--plugin <plugin_dir>]\n")
        return 2
    report = check_pack(pack, plugin)
    for error in report.errors:
        sys.stdout.write(f"ERROR {error}\n")
    for where in report.placeholders:
        sys.stdout.write(f"PLACEHOLDER {where}\n")
    if report.errors:
        sys.stdout.write("RESULT: INVALID - do not deploy\n")
        return 2
    if report.placeholders:
        sys.stdout.write("RESULT: NOT READY - placeholders remain\n")
        return 1
    sys.stdout.write("RESULT: READY\n")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
