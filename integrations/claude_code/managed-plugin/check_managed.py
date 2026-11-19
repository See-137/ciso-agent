"""Check the CISO agent plugin's managed settings templates before IT deploys them.

    python check_managed.py <managed-plugin folder> [<plugin folder>]

Exit 0 / `RESULT: READY`: deployable. Exit 1 / `RESULT: NOT READY`: placeholders
(`REPLACE_ME`) remain. Exit 2 / `RESULT: INVALID`: a control is missing or weakened, the
platform files disagree, or the plugin's enforcing hooks are not the CISO hook.

The check is POSITIVE (review M4): every security key must have exactly the expected
value, not merely be present.

- `allowManagedHooksOnly`, `disableSideloadFlags`, `disableCommandPluginSources` true;
  `disableAllHooks` absent; no managed `hooks` (the only hooks are the plugin's);
- `forceLoginMethod` `claudeai` and a non-empty `forceLoginOrgUUID`;
- `requiredMinimumVersion` at least `MIN_VERSION`;
- exactly one marketplace (`extraKnownMarketplaces` and `strictKnownMarketplaces` both
  name only ours, with the same source), and the plugin force-enabled;
- `permissions`: `disableBypassPermissionsMode` `disable`, `deny` holding at least every
  rule of `REQUIRED_DENY`, no `defaultMode` of `dontAsk` / `bypassPermissions`, no broad
  `allow` rule (a bare tool name or a pattern of only wildcards);
- `env`: the CISO values valid, `UV_NO_CONFIG` `1`, no two keys equal ignoring case, and
  the git hardening exactly `REQUIRED_GIT` plus an absolute `core.hooksPath`, each key
  once compared case-insensitively (git takes the last of case variants), with no other
  `GIT_CONFIG*` variable;
- the plugin's two enforcing hooks run exactly `uv` with `HOOK_ARGS`, exec form,
  time-limited, `onFailure: block`.

Standard library only; runs on any Python 3.10+.
"""

from __future__ import annotations

import json
import re
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
MIN_VERSION = (2, 1, 316)
#: Display name -> value. Compared case-insensitively, as git does.
REQUIRED_GIT = {
    "safe.bareRepository": "explicit",
    "push.recurseSubmodules": "no",
    "protocol.ext.allow": "never",
    "core.fsmonitor": "false",
}
HOOKS_PATH_KEY = "core.hookspath"
REQUIRED_DENY = (
    "Edit(~/.claude/plugins/**)",
    "Write(~/.claude/plugins/**)",
    "Edit(~/.claude/settings.json)",
    "Write(~/.claude/settings.json)",
    "Edit(//**/.claude/settings*.json)",
    "Write(//**/.claude/settings*.json)",
    "Edit(//**/.mcp.json)",
    "Write(//**/.mcp.json)",
    "Read(~/.ssh/**)",
    "Read(~/.aws/credentials)",
    "Read(~/.git-credentials)",
    "Read(//**/.env)",
    "Read(//**/.env.*)",
    "Read(~/.claude/.credentials.json)",
    "Read(~/.claude.json)",
    "Read(//**/.credentials.json)",
    "Read(~/.config/anthropic/**)",
    "Read(~/AppData/Roaming/Anthropic/**)",
    "Edit(~/AppData/Local/uv/**)",
    "Write(~/AppData/Local/uv/**)",
    "Edit(~/AppData/Roaming/uv/**)",
    "Write(~/AppData/Roaming/uv/**)",
    "Edit(~/.cache/uv/**)",
    "Write(~/.cache/uv/**)",
    "Edit(~/.local/share/uv/**)",
    "Write(~/.local/share/uv/**)",
)
_ROOT = "${CLAUDE_PLUGIN_ROOT}"
_INDEX = "https://pypi.org/simple"
#: The plugin's hook argv (hooks/hooks.json), exactly.
HOOK_ARGS = (
    "run", "--quiet", "--isolated", "--no-config", "--no-project", "--no-env-file",
    "--python", ">=3.13", "--default-index", _INDEX, "--index", _INDEX,
    "--find-links", _ROOT + "/scripts/no-local-packages", "--index-strategy", "first-index",
    "--keyring-provider", "disabled", "--no-build", "--directory", _ROOT,
    "--with-requirements", _ROOT + "/scripts/runtime-requirements.txt",
    "--", "python", "-I", "-B", _ROOT + "/scripts/ciso_hook.py",
)  # fmt: skip
ENFORCED_EVENTS = ("PreToolUse", "UserPromptSubmit")
UNSAFE_MODES = {"dontask", "bypasspermissions"}
#: Keys allowed to differ between platforms (inside `env`).
PLATFORM_ENV = {"CISO_GIT_PATH"}
_WILDCARD_ONLY = re.compile(r"[\s*:/~.]*")
_GIT_ENV = re.compile(r"GIT_CONFIG_(KEY|VALUE)_(\d+)")


def _absolute(text: str) -> bool:
    return PurePosixPath(text).is_absolute() or PureWindowsPath(text).is_absolute()


def _placeholders(value: Any) -> bool:
    return PLACEHOLDER in json.dumps(value)


def _version(text: Any) -> tuple[int, ...] | None:
    if not isinstance(text, str) or not re.fullmatch(r"\d+(\.\d+){1,3}", text):
        return None
    return tuple(int(part) for part in text.split("."))


def git_pairs(env: dict[str, Any], errors: list[str]) -> dict[str, str]:
    """The git hardening pairs, keys lower-cased. Every refusal is appended to errors."""
    upper = {k.upper(): k for k in env}
    if any(k.upper().startswith("GIT_CONFIG") and k != k.upper() for k in env):
        errors.append("env has a GIT_CONFIG variable that is not upper case")
    try:
        count = int(env.get("GIT_CONFIG_COUNT", ""))
    except ValueError:
        errors.append("env.GIT_CONFIG_COUNT is missing or not a number")
        return {}
    for name in upper:
        match = _GIT_ENV.fullmatch(name)
        if (
            name.startswith("GIT_CONFIG")
            and name != "GIT_CONFIG_COUNT"
            and (match is None or int(match.group(2)) >= count)
        ):
            errors.append(
                f"env has GIT_CONFIG_KEY_n beyond GIT_CONFIG_COUNT or another GIT_CONFIG "
                f"variable: {name}"
            )
    pairs: dict[str, str] = {}
    for index in range(count):
        key, value = env.get(f"GIT_CONFIG_KEY_{index}"), env.get(f"GIT_CONFIG_VALUE_{index}")
        if not isinstance(key, str) or not isinstance(value, str):
            errors.append(f"env.GIT_CONFIG_KEY_{index} / VALUE_{index} missing")
            continue
        low = key.casefold()
        if low in pairs:
            errors.append(f"git hardening sets {low} more than once (case-insensitive)")
        pairs[low] = value
    return pairs


def _check_git(env: dict[str, Any], errors: list[str]) -> None:
    pairs = git_pairs(env, errors)
    for key, value in REQUIRED_GIT.items():
        if pairs.get(key.casefold()) != value:
            errors.append(f"git hardening must set {key}={value}")
    if not _absolute(pairs.get(HOOKS_PATH_KEY, "")):
        errors.append("git hardening must set core.hooksPath to an absolute, admin-owned folder")
    extra = set(pairs) - {k.casefold() for k in REQUIRED_GIT} - {HOOKS_PATH_KEY}
    if extra:
        errors.append(f"git hardening sets keys outside the hardening: {sorted(extra)}")


def _check_env(env: Any, errors: list[str]) -> None:
    if not isinstance(env, dict):
        errors.append("env block missing")
        return
    folded = [k.upper() for k in env]
    if len(set(folded)) != len(folded):
        errors.append("env has two keys that differ only in case")
    if env.get("CISO_STOP") not in STOP_VALUES:
        errors.append('env.CISO_STOP must be "0" or "1"')
    if env.get("CISO_ROLE") not in ROLES:
        errors.append("env.CISO_ROLE must be a known role")
    if env.get("CISO_AGENT_CLASS") not in AGENT_CLASSES:
        errors.append("env.CISO_AGENT_CLASS must be employee_operated or organizational")
    if env.get("UV_NO_CONFIG") != "1":
        errors.append('env.UV_NO_CONFIG must be "1"')
    git_path = env.get("CISO_GIT_PATH")
    if git_path is not None and not (isinstance(git_path, str) and _absolute(git_path)):
        errors.append("env.CISO_GIT_PATH must be an absolute path")
    _check_git(env, errors)


def _broad(rule: Any) -> bool:
    if not isinstance(rule, str):
        return True
    _tool, paren, rest = rule.partition("(")
    if not paren:
        return True  # a bare tool name allows every use of it
    return bool(_WILDCARD_ONLY.fullmatch(rest.rstrip(")")))


def _check_permissions(perms: Any, errors: list[str]) -> None:
    if not isinstance(perms, dict):
        errors.append("permissions block missing")
        return
    if perms.get("disableBypassPermissionsMode") != "disable":
        errors.append('permissions.disableBypassPermissionsMode must be "disable"')
    deny = perms.get("deny")
    missing = [r for r in REQUIRED_DENY if not isinstance(deny, list) or r not in deny]
    if missing:
        errors.append(f"permissions.deny lacks {len(missing)} required rule(s): {missing[:3]}")
    mode = perms.get("defaultMode")
    if (isinstance(mode, str) and mode.casefold() in UNSAFE_MODES) or (
        mode is not None and not isinstance(mode, str)
    ):
        errors.append("permissions.defaultMode must not be dontAsk or bypassPermissions")
    allow = perms.get("allow", [])
    if not isinstance(allow, list) or any(_broad(rule) for rule in allow):
        errors.append("permissions.allow has a broad rule (bare tool name or wildcard only)")


def _check_marketplaces(settings: dict[str, Any], errors: list[str]) -> None:
    extra = settings.get("extraKnownMarketplaces")
    if not isinstance(extra, dict) or list(extra) != [MARKETPLACE]:
        errors.append(f"extraKnownMarketplaces must register exactly {MARKETPLACE}")
        return
    market = extra[MARKETPLACE]
    if not isinstance(market, dict) or not isinstance(market.get("source"), dict):
        errors.append(f"extraKnownMarketplaces must register {MARKETPLACE} with a source")
        return
    if settings.get("strictKnownMarketplaces") != [market["source"]]:
        errors.append("strictKnownMarketplaces must list exactly the marketplace's source")


def check_settings(settings: Any) -> list[str]:
    """Every way one platform's managed settings weaken or miss a control."""
    errors: list[str] = []
    if not isinstance(settings, dict):
        return ["settings are not a JSON object"]
    for key in ("allowManagedHooksOnly", "disableSideloadFlags", "disableCommandPluginSources"):
        if settings.get(key) is not True:
            errors.append(f"{key} must be true")
    if "disableAllHooks" in settings:
        errors.append("disableAllHooks must not be set")
    if settings.get("hooks"):
        errors.append("managed hooks must be empty: the plugin's hooks are the only hooks")
    if settings.get("forceLoginMethod") != "claudeai":
        errors.append('forceLoginMethod must be "claudeai"')
    org = settings.get("forceLoginOrgUUID")
    if not (isinstance(org, str) and org) and not (isinstance(org, list) and org):
        errors.append("forceLoginOrgUUID must name the organization")
    version = _version(settings.get("requiredMinimumVersion"))
    if version is None or version < MIN_VERSION:
        errors.append("requiredMinimumVersion must be at least 2.1.316")
    plugins = settings.get("enabledPlugins")
    if not isinstance(plugins, dict) or plugins.get(PLUGIN_ID) is not True:
        errors.append(f"enabledPlugins must force-enable {PLUGIN_ID}")
    _check_marketplaces(settings, errors)
    _check_permissions(settings.get("permissions"), errors)
    _check_env(settings.get("env"), errors)
    return errors


def check_plugin_hooks(plugin: Path) -> list[str]:
    """The plugin's enforcing hooks must be exactly the CISO hook: `uv` with `HOOK_ARGS`,
    exec form, time-limited and fail-closed, one handler per event."""
    try:
        data = json.loads((plugin / "hooks" / "hooks.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return ["plugin hooks/hooks.json is missing or not JSON"]
    errors: list[str] = []
    hooks = data.get("hooks", {}) if isinstance(data, dict) else {}
    if set(hooks) != set(ENFORCED_EVENTS):
        errors.append(f"plugin hooks must be exactly {list(ENFORCED_EVENTS)}")
    for event in ENFORCED_EVENTS:
        entries = hooks.get(event) or []
        handlers = [h for e in entries if isinstance(e, dict) for h in e.get("hooks", [])]
        if len(handlers) != 1:
            errors.append(f"plugin must declare exactly one {event} hook")
        for handler in handlers:
            if handler.get("onFailure") != "block":
                errors.append(f"{event} hook lacks onFailure: block")
            if not isinstance(handler.get("timeout"), int) or handler["timeout"] <= 0:
                errors.append(f"{event} hook lacks a timeout")
            if not isinstance(handler.get("args"), list):
                errors.append(f"{event} hook is not exec form (args)")
            elif handler.get("command") != "uv" or tuple(handler["args"]) != HOOK_ARGS:
                errors.append(f"{event} hook does not run scripts/ciso_hook.py as declared")
        if event == "PreToolUse" and not any(e.get("matcher") == "*" for e in entries):
            errors.append("PreToolUse hook must match every tool (*)")
    return errors


def _shared(settings: dict[str, Any]) -> str:
    env = {k: v for k, v in settings.get("env", {}).items() if k not in PLATFORM_ENV}
    env = {
        k: v
        for k, v in env.items()
        if not k.startswith("GIT_CONFIG_VALUE_")
        or str(env.get("GIT_CONFIG_KEY_" + k.rsplit("_", 1)[1], "")).casefold() != HOOKS_PATH_KEY
    }
    return json.dumps({**settings, "env": env}, sort_keys=True)


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
    shared = {_shared(s) for s in loaded.values() if isinstance(s, dict)}
    if len(shared) > 1:
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
