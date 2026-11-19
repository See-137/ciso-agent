"""Check the CISO agent plugin's managed settings templates before IT deploys them.

    python check_managed.py <managed-plugin folder> [<plugin folder>]

Exit 0 / `RESULT: READY`: deployable. Exit 1 / `RESULT: NOT READY`: placeholders
(`REPLACE_ME`) remain. Exit 2 / `RESULT: INVALID`: a control is missing or weakened, the
platform files disagree, or the plugin's enforcing hooks are not fail-closed.
Standard library only; runs on any Python 3.10+.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import Any

PLUGIN_ID = "ciso-agent@corp-ai-governance"
MARKETPLACE = "corp-ai-governance"
PLATFORMS = ("windows", "macos", "linux")
PLACEHOLDER = "REPLACE_ME"
ROLES = {"security_admin", "system_owner", "executive_risk_owner", "employee", "auditor"}
AGENT_CLASSES = {"employee_operated", "organizational"}
STOP_VALUES = {"0", "1"}
REQUIRED_GIT = {
    "safe.bareRepository": "explicit",
    "push.recurseSubmodules": "no",
    "protocol.ext.allow": "never",
}
ENFORCED_EVENTS = ("PreToolUse", "UserPromptSubmit")
#: Keys allowed to differ between platforms (inside `env`).
PLATFORM_ENV = {"CISO_GIT_PATH"}


def _absolute(text: str) -> bool:
    return PurePosixPath(text).is_absolute() or PureWindowsPath(text).is_absolute()


def _placeholders(value: Any) -> bool:
    return PLACEHOLDER in json.dumps(value)


def git_pairs(env: dict[str, Any], errors: list[str]) -> dict[str, str]:
    try:
        count = int(env.get("GIT_CONFIG_COUNT", ""))
    except ValueError:
        errors.append("env.GIT_CONFIG_COUNT is missing or not a number")
        return {}
    pairs: dict[str, str] = {}
    for index in range(count):
        key, value = env.get(f"GIT_CONFIG_KEY_{index}"), env.get(f"GIT_CONFIG_VALUE_{index}")
        if not isinstance(key, str) or not isinstance(value, str):
            errors.append(f"env.GIT_CONFIG_KEY_{index} / VALUE_{index} missing")
            continue
        pairs[key] = value
    extra = [
        k for k in env if k.startswith("GIT_CONFIG_KEY_") and int(k.rsplit("_", 1)[1]) >= count
    ]
    if extra:
        errors.append("env has GIT_CONFIG_KEY_n beyond GIT_CONFIG_COUNT")
    return pairs


def check_settings(settings: Any) -> list[str]:
    """Every way one platform's managed settings weaken or miss a control."""
    errors: list[str] = []
    if not isinstance(settings, dict):
        return ["settings are not a JSON object"]
    if settings.get("allowManagedHooksOnly") is not True:
        errors.append("allowManagedHooksOnly must be true")
    if settings.get("disableAllHooks"):
        errors.append("disableAllHooks must not be set")
    if settings.get("disableSideloadFlags") is not True:
        errors.append("disableSideloadFlags must be true")
    if settings.get("enabledPlugins", {}).get(PLUGIN_ID) is not True:
        errors.append(f"enabledPlugins must force-enable {PLUGIN_ID}")
    market = settings.get("extraKnownMarketplaces", {}).get(MARKETPLACE)
    if not isinstance(market, dict) or not isinstance(market.get("source"), dict):
        errors.append(f"extraKnownMarketplaces must register {MARKETPLACE}")
    elif market["source"] not in settings.get("strictKnownMarketplaces", []):
        errors.append("strictKnownMarketplaces must list exactly the marketplace's source")
    perms = settings.get("permissions", {})
    if not isinstance(perms, dict) or perms.get("disableBypassPermissionsMode") != "disable":
        errors.append('permissions.disableBypassPermissionsMode must be "disable"')
    env = settings.get("env")
    if not isinstance(env, dict):
        return [*errors, "env block missing"]
    if env.get("CISO_STOP") not in STOP_VALUES:
        errors.append('env.CISO_STOP must be "0" or "1"')
    if env.get("CISO_ROLE") not in ROLES:
        errors.append("env.CISO_ROLE must be a known role")
    if env.get("CISO_AGENT_CLASS") not in AGENT_CLASSES:
        errors.append("env.CISO_AGENT_CLASS must be employee_operated or organizational")
    git_path = env.get("CISO_GIT_PATH")
    if git_path is not None and not (isinstance(git_path, str) and _absolute(git_path)):
        errors.append("env.CISO_GIT_PATH must be an absolute path")
    pairs = git_pairs(env, errors)
    for key, value in REQUIRED_GIT.items():
        if pairs.get(key) != value:
            errors.append(f"git hardening must set {key}={value}")
    hooks_path = pairs.get("core.hooksPath", "")
    if not _absolute(hooks_path):
        errors.append("git hardening must set core.hooksPath to an absolute, admin-owned folder")
    return errors


def check_plugin_hooks(plugin: Path) -> list[str]:
    """The plugin's enforcing hooks must be exec form, time-limited and fail-closed."""
    try:
        data = json.loads((plugin / "hooks" / "hooks.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return ["plugin hooks/hooks.json is missing or not JSON"]
    errors: list[str] = []
    hooks = data.get("hooks", {}) if isinstance(data, dict) else {}
    for event in ENFORCED_EVENTS:
        entries = hooks.get(event) or []
        handlers = [h for e in entries if isinstance(e, dict) for h in e.get("hooks", [])]
        if not handlers:
            errors.append(f"plugin declares no {event} hook")
        for handler in handlers:
            if handler.get("onFailure") != "block":
                errors.append(f"{event} hook lacks onFailure: block")
            if not isinstance(handler.get("timeout"), int) or handler["timeout"] <= 0:
                errors.append(f"{event} hook lacks a timeout")
            if not isinstance(handler.get("args"), list):
                errors.append(f"{event} hook is not exec form (args)")
        if event == "PreToolUse" and not any(e.get("matcher") == "*" for e in entries):
            errors.append("PreToolUse hook must match every tool (*)")
    return errors


def check(managed: Path, plugin: Path | None = None) -> tuple[int, list[str]]:
    errors: list[str] = []
    placeholders = False
    loaded: dict[str, Any] = {}
    for name in PLATFORMS:
        path = managed / name / "managed-settings.json"
        try:
            loaded[name] = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            errors.append(f"{name}: managed-settings.json missing or not JSON")
            continue
        placeholders = placeholders or _placeholders(loaded[name])
        errors += [f"{name}: {e}" for e in check_settings(loaded[name])]
    shared = []
    for settings in loaded.values():
        if isinstance(settings, dict):
            env = {k: v for k, v in settings.get("env", {}).items() if k not in PLATFORM_ENV}
            env = {
                k: v
                for k, v in env.items()
                if not k.startswith("GIT_CONFIG_VALUE_")
                or env.get("GIT_CONFIG_KEY_" + k.rsplit("_", 1)[1]) != "core.hooksPath"
            }
            shared.append(json.dumps({**settings, "env": env}, sort_keys=True))
    if len(set(shared)) > 1:
        errors.append("platform files disagree outside their platform paths")
    if plugin is not None:
        errors += check_plugin_hooks(plugin)
    if errors:
        return 2, errors
    return (1, ["placeholders (REPLACE_ME) remain"]) if placeholders else (0, [])


def main(argv: list[str]) -> int:
    if len(argv) not in (2, 3):
        sys.stderr.write("usage: check_managed.py <managed-plugin folder> [<plugin folder>]\n")
        return 2
    code, lines = check(Path(argv[1]), Path(argv[2]) if len(argv) == 3 else None)
    for line in lines:
        sys.stdout.write(line + "\n")
    sys.stdout.write("RESULT: " + {0: "READY", 1: "NOT READY", 2: "INVALID"}[code] + "\n")
    return code


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
