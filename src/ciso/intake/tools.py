"""What a tool call is: kind, target, command and content, from its name and input.

Shared by both formats. Tool names and input fields follow the assistant's hook
documentation (tool_input tables for Bash, PowerShell, Write, Edit, Read, Glob, Grep, WebFetch,
WebSearch, Agent; connector tools named `mcp__<server>__<tool>`). `MultiEdit` and `Task`
are older names kept for compatibility: `MultiEdit` is read as `file_path` plus `edits`,
a list of objects each with a `new_string`. A tool not named here is `other_tool`, never
dropped.

Nothing here decides anything. A path, host or server name is a claim made by the agent's
own tool input.
"""

from __future__ import annotations

import hashlib
import re
from collections.abc import Callable, Mapping
from typing import Any, NamedTuple

from ciso.common.activity import MAX_COMMAND_CHARS, ActionKind
from ciso.common.protocols import Redactor
from ciso.intake.errors import RefusalCode, refuse
from ciso.intake.gitcommand import classify_git

#: `PowerShell` is the assistant's native PowerShell tool (on by default on Windows); its
#: hook input carries `command` like `Bash` (tools reference, "PowerShell tool"). The
#: governance classifier reads commands with a POSIX shell grammar, so PowerShell syntax
#: it cannot read lands in `unparseable` (ask at most), never in an allow by default.
SHELL_TOOLS = frozenset({"Bash", "bash", "PowerShell"})
WRITE_TOOLS = frozenset({"Write"})
EDIT_TOOLS = frozenset({"Edit", "MultiEdit"})
READ_TOOLS = frozenset({"Read", "Grep", "Glob"})
WEB_TOOLS = frozenset({"WebFetch", "WebSearch", "web_search", "web_fetch"})
SUBAGENT_TOOLS = frozenset({"Agent", "Task"})
#: Most edits accepted in one multi-edit call.
MAX_EDITS = 1000

_CONNECTOR = re.compile(r"mcp__(?P<server>.+?)__(?P<tool>.+)")
_URL_HOST = re.compile(r"[A-Za-z][A-Za-z0-9+.-]*://(?:[^/?#@]*@)?(?P<host>\[[^\]/]*\]|[^/?#:]+)")


class ToolView(NamedTuple):
    """What the intake keeps from one tool call. `content` and `prompt` are for inspection
    only and never land on the `ObservedAction`."""

    kind: ActionKind
    target: dict[str, str]
    command: str | None = None
    truncated: bool = False
    content: str | None = None
    path: str = ""
    prompt: str | None = None


def bound_command(redactor: Redactor, raw: str) -> tuple[str, bool]:
    """Redact first, then cut to `MAX_COMMAND_CHARS`; cutting first could split a secret
    so that the redactor no longer recognises the half that stays."""
    redacted = redactor.redact(raw)
    if len(redacted) > MAX_COMMAND_CHARS:
        return redacted[:MAX_COMMAND_CHARS], True
    return redacted, False


def content_digest(content: str) -> tuple[str, int]:
    raw = content.encode("utf-8", errors="surrogatepass")
    return hashlib.sha256(raw).hexdigest(), len(raw)


def _string(tool_input: Mapping[str, Any], key: str, *, required: bool) -> str | None:
    value = tool_input.get(key)
    if value is None and not required:
        return None
    if not isinstance(value, str):
        raise refuse(RefusalCode.MALFORMED_TOOL_INPUT)
    return value


def relative_path(path: str, cwd: str | None) -> str:
    """`path` relative to `cwd` when it lies inside it (either separator), else as given."""
    if cwd:
        base = cwd.rstrip("/\\")
        for sep in ("/", "\\"):
            if base and path.startswith(base + sep) and len(path) > len(base) + 1:
                return path[len(base) + 1 :]
    return path


def url_host(url: str) -> str | None:
    match = _URL_HOST.match(url)
    return match.group("host").lower() if match else None


def connector_server(tool_name: str) -> str | None:
    match = _CONNECTOR.fullmatch(tool_name)
    return match.group("server") if match else None


def _shell(tool_input: Mapping[str, Any], redactor: Redactor) -> ToolView:
    raw = _string(tool_input, "command", required=True) or ""
    command, truncated = bound_command(redactor, raw)
    kind, target = classify_git(command)
    return ToolView(kind, target, command=command, truncated=truncated)


def _write(tool_input: Mapping[str, Any], cwd: str | None) -> ToolView:
    path = _string(tool_input, "file_path", required=True) or ""
    content = _string(tool_input, "content", required=True)
    shown = relative_path(path, cwd)
    return ToolView(ActionKind.FILE_WRITE, {"path": shown}, content=content, path=shown)


def _edit(tool_name: str, tool_input: Mapping[str, Any], cwd: str | None) -> ToolView:
    path = _string(tool_input, "file_path", required=True) or ""
    if tool_name == "MultiEdit":
        edits = tool_input.get("edits")
        if not isinstance(edits, list) or not edits or len(edits) > MAX_EDITS:
            raise refuse(RefusalCode.MALFORMED_TOOL_INPUT)
        parts = []
        for edit in edits:
            if not isinstance(edit, dict):
                raise refuse(RefusalCode.MALFORMED_TOOL_INPUT)
            parts.append(_string(edit, "new_string", required=True) or "")
        content = "\n".join(parts)
    else:
        content = _string(tool_input, "new_string", required=True) or ""
    shown = relative_path(path, cwd)
    return ToolView(ActionKind.FILE_EDIT, {"path": shown}, content=content, path=shown)


def _read(tool_name: str, tool_input: Mapping[str, Any], cwd: str | None) -> ToolView:
    key = "file_path" if tool_name == "Read" else "path"
    path = _string(tool_input, key, required=tool_name == "Read")
    target = {"path": relative_path(path, cwd)} if path else {}
    return ToolView(ActionKind.FILE_READ, target)


def _web(tool_name: str, tool_input: Mapping[str, Any]) -> ToolView:
    if tool_name in {"WebFetch", "web_fetch"}:
        url = _string(tool_input, "url", required=True) or ""
        host = url_host(url)
        return ToolView(ActionKind.WEB_FETCH, {"host": host} if host else {})
    return ToolView(ActionKind.WEB_FETCH, {})


def _subagent(tool_input: Mapping[str, Any]) -> ToolView:
    prompt = _string(tool_input, "prompt", required=False)
    agent_type = _string(tool_input, "subagent_type", required=False)
    target = {"agent_type": agent_type} if agent_type else {}
    return ToolView(ActionKind.SUBAGENT, target, prompt=prompt)


def classify_tool(
    tool_name: str, tool_input: Mapping[str, Any], *, cwd: str | None, redactor: Redactor
) -> ToolView:
    """Map one tool call. Raises `IntakeRefused(MALFORMED_TOOL_INPUT)` when a known tool's
    required input is missing or of the wrong type."""
    handlers: dict[frozenset[str], Callable[[], ToolView]] = {
        SHELL_TOOLS: lambda: _shell(tool_input, redactor),
        WRITE_TOOLS: lambda: _write(tool_input, cwd),
        EDIT_TOOLS: lambda: _edit(tool_name, tool_input, cwd),
        READ_TOOLS: lambda: _read(tool_name, tool_input, cwd),
        WEB_TOOLS: lambda: _web(tool_name, tool_input),
        SUBAGENT_TOOLS: lambda: _subagent(tool_input),
    }
    for names, handler in handlers.items():
        if tool_name in names:
            return handler()
    server = connector_server(tool_name)
    if server is not None:
        return ToolView(ActionKind.CONNECTOR_CALL, {"server": server})
    return ToolView(ActionKind.OTHER_TOOL, {})
