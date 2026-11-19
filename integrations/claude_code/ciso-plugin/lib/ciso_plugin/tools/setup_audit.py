"""Audit the agent setup of a repository and of the user's machine for risky configuration.

Looks at MCP server definitions, assistant settings (permission rules, modes, hooks,
helpers, `env`), and instruction files (CLAUDE.md, AGENTS.md and other assistants'
equivalents). Findings name the file, the setting and why it is risky. Values are never
printed: environment values, headers and arguments are only scanned for secret shapes by
the bundled inspector, which reports the rule, not the value.
"""

from __future__ import annotations

import json
import re
from collections.abc import Iterator, Mapping
from pathlib import Path
from typing import Any, Final

from ciso.common.activity import ActionKind, InspectionFinding, InspectionInput, Severity
from ciso.inspection import Inspector

MAX_CONFIG_BYTES: Final = 4 * 1024 * 1024
INSTRUCTION_FILES: Final = (
    "CLAUDE.md",
    "CLAUDE.local.md",
    ".claude/CLAUDE.md",
    "AGENTS.md",
    ".github/copilot-instructions.md",
    ".cursorrules",
    ".windsurfrules",
)
SETTINGS_FILES: Final = (".claude/settings.json", ".claude/settings.local.json")
_LOOPBACK: Final = re.compile(r"https?://(localhost|127\.0\.0\.1|\[::1\])([:/]|$)", re.I)
_RUNNERS: Final = frozenset({"npx", "uvx", "pipx", "bunx", "pnpm", "yarn"})
_SUBCOMMANDS: Final = frozenset({"dlx", "run", "exec", "x"})
_PINNED: Final = re.compile(r".+@\d[\w.\-]*$|.+==\d[\w.\-]*$")
_BROAD: Final = frozenset({"Bash", "Bash(*)", "Bash(*:*)", "*", "PowerShell", "PowerShell(*)"})
_SUSPICIOUS: Final = (
    (
        re.compile(r"ignore (all |any )?(previous|prior|above) instructions", re.I),
        "instruction override",
    ),
    (
        re.compile(r"(curl|wget|iwr|invoke-webrequest)[^\n|]{0,200}\|\s*(ba|z)?sh", re.I),
        "download piped to a shell",
    ),
    (
        re.compile(r"--no-verify|dangerously-skip-permissions|bypassPermissions", re.I),
        "instruction to bypass checks",
    ),
    (re.compile(r"disable(AllHooks| the hooks| hooks)", re.I), "instruction to disable hooks"),
)


def _finding(
    check: str, severity: Severity, detail: str, location: str, fix: str
) -> InspectionFinding:
    return InspectionFinding(
        check_id=f"setup.{check}",
        category="agent_setup",
        severity=severity,
        detail=f"{detail}. Remediation: {fix}"[:500],
        location=location[:500],
        remediation=fix,
    )


def _load_json(path: Path) -> tuple[Any, str | None]:
    raw = path.read_bytes()
    if len(raw) > MAX_CONFIG_BYTES:
        return None, "too large to read"
    try:
        return json.loads(raw.decode("utf-8-sig")), None
    except (UnicodeDecodeError, ValueError):
        return None, "not valid JSON"


def _secrets(text: str, label: str) -> list[InspectionFinding]:
    item = InspectionInput(action_id="setup", kind=ActionKind.PROMPT, content=text)
    found = Inspector().inspect(item).findings
    return [f.model_copy(update={"location": f"{label} {f.location}".strip()[:500]}) for f in found]


def _servers(servers: Any, label: str) -> Iterator[InspectionFinding]:
    if not isinstance(servers, Mapping):
        return
    for name, spec in servers.items():
        where = f"{label} mcpServers.{name}"
        if not isinstance(spec, Mapping):
            continue
        url = spec.get("url")
        if isinstance(url, str) and url.lower().startswith("http://") and not _LOOPBACK.match(url):
            yield _finding(
                "mcp_plain_http",
                Severity.HIGH,
                "MCP server reached over plain http",
                where,
                "Use https, or remove the server",
            )
        command = spec.get("command")
        args = [a for a in spec.get("args", []) if isinstance(a, str)]
        if isinstance(command, str) and Path(command).name.split(".")[0] in _RUNNERS:
            packages = [a for a in args if not a.startswith("-") and a not in _SUBCOMMANDS]
            if packages and not _PINNED.match(packages[0]):
                yield _finding(
                    "mcp_unpinned_package",
                    Severity.MEDIUM,
                    "MCP server runs a package without a pinned version",
                    where,
                    "Pin the package version so an update cannot change the code",
                )
        for key in ("env", "headers"):
            if isinstance(spec.get(key), Mapping) and spec[key]:
                yield from _secrets(json.dumps(spec[key]), f"{where}.{key}")


def _settings(data: Any, label: str) -> Iterator[InspectionFinding]:
    if not isinstance(data, Mapping):
        return
    perms = data.get("permissions") if isinstance(data.get("permissions"), Mapping) else {}
    allow = perms.get("allow", []) if isinstance(perms, Mapping) else []
    for rule in allow if isinstance(allow, list) else []:
        if rule in _BROAD:
            yield _finding(
                "broad_allow_rule",
                Severity.HIGH,
                "Permission rule allows any shell command",
                f"{label} permissions.allow",
                "Allow named commands only",
            )
    mode = perms.get("defaultMode") if isinstance(perms, Mapping) else None
    if mode in ("bypassPermissions", "dontAsk"):
        yield _finding(
            "permission_mode",
            Severity.HIGH,
            f"Default permission mode {mode}",
            f"{label} permissions.defaultMode",
            "Remove the mode; keep prompts on",
        )
    checks = (
        ("disableAllHooks", Severity.HIGH, "Setting turns hooks off", "Remove disableAllHooks"),
        (
            "enableAllProjectMcpServers",
            Severity.MEDIUM,
            "Every MCP server a repository defines is trusted",
            "Approve MCP servers one by one",
        ),
        (
            "hooks",
            Severity.MEDIUM,
            "Hooks defined here run commands on this machine",
            "Review each hook command; organization hooks come from the plugin",
        ),
        (
            "apiKeyHelper",
            Severity.MEDIUM,
            "A helper program supplies credentials",
            "Confirm the helper is approved by IT",
        ),
        (
            "statusLine",
            Severity.LOW,
            "A status line command runs on every refresh",
            "Review the status line command",
        ),
    )
    for key, severity, detail, fix in checks:
        if data.get(key):
            yield _finding(key.lower(), severity, detail, f"{label} {key}", fix)
    if isinstance(data.get("env"), Mapping) and data["env"]:
        yield from _secrets(json.dumps(data["env"]), f"{label} env")
    yield from _servers(data.get("mcpServers"), label)


def _instructions(path: Path, label: str) -> Iterator[InspectionFinding]:
    raw = path.read_bytes()[:MAX_CONFIG_BYTES]
    text = raw.decode("utf-8", errors="replace")
    for pattern, what in _SUSPICIOUS:
        if pattern.search(text):
            yield _finding(
                "instruction_risk",
                Severity.MEDIUM,
                f"Instruction file contains an {what}"
                if what[0] in "aeiou"
                else f"Instruction file contains a {what}",
                label,
                "Read the file and remove instructions that weaken controls",
            )
    yield from _secrets(text, label)


def _json_file(path: Path, label: str, kind: str) -> Iterator[InspectionFinding]:
    data, problem = _load_json(path)
    if problem:
        yield _finding(
            "unreadable_config",
            Severity.LOW,
            f"Configuration {problem}",
            label,
            "Fix the file so it can be reviewed",
        )
        return
    if kind == "mcp":
        yield from _servers(data.get("mcpServers") if isinstance(data, Mapping) else None, label)
    elif kind == "user_state":
        if isinstance(data, Mapping):
            yield from _servers(data.get("mcpServers"), label)
            projects = data.get("projects")
            for project, state in projects.items() if isinstance(projects, Mapping) else []:
                if isinstance(state, Mapping):
                    yield from _servers(state.get("mcpServers"), f"{label} projects[{project}]")
    else:
        yield from _settings(data, label)


def audit_repo(repo: Path) -> list[InspectionFinding]:
    found: list[InspectionFinding] = []
    if (repo / ".mcp.json").is_file():
        found += _json_file(repo / ".mcp.json", ".mcp.json", "mcp")
    for name in SETTINGS_FILES:
        if (repo / name).is_file():
            found += _json_file(repo / name, name, "settings")
    for name in INSTRUCTION_FILES:
        if (repo / name).is_file():
            found += _instructions(repo / name, name)
    rules = repo / ".cursor" / "rules"
    if rules.is_dir():
        for path in sorted(rules.glob("*"))[:200]:
            if path.is_file():
                found += _instructions(path, path.relative_to(repo).as_posix())
    return found


def audit_home(home: Path) -> list[InspectionFinding]:
    found: list[InspectionFinding] = []
    settings = home / ".claude" / "settings.json"
    if settings.is_file():
        found += _json_file(settings, "~/.claude/settings.json", "settings")
    state = home / ".claude.json"
    if state.is_file():
        found += _json_file(state, "~/.claude.json", "user_state")
    memory = home / ".claude" / "CLAUDE.md"
    if memory.is_file():
        found += _instructions(memory, "~/.claude/CLAUDE.md")
    return found
