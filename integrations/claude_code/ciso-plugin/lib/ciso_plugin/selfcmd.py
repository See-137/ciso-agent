"""The plugin's own skill and its read-only tool, recognised exactly.

The CISO skill must work under the plugin's own hooks: loading it (the `Skill` tool) and
running its tool script would otherwise be asked or refused like any unknown program.
Two fixed, tested shapes are allowed here, before the engine:

1. the `Skill` tool naming this plugin's skill (`ciso` or `ciso-agent:ciso`);
2. a `Bash` command that is EXACTLY `uv run <fixed flags> --directory <this plugin's root>
   --with-requirements <this tool> -- python -I -B <this tool> <subcommand> <options>`,
   where the paths resolve to this plugin's own files, the subcommand and every option are
   on a fixed list, `--data-dir` (when given) is this plugin's data directory, and the
   raw text holds no character a shell would expand or use to join commands.
   `--directory` keeps uv from reading a `.venv`, `uv.toml` or `.python-version`
   planted in the repository being reviewed.

The tool only reads and writes reports under the plugin's data directory; it prints
findings (rule, severity, location), never file content. Anything that does not match
exactly goes to the governance engine like every other command.
"""

from __future__ import annotations

import os
import shlex
from collections.abc import Mapping
from pathlib import Path
from typing import Any, Final

SKILL_NAMES: Final = frozenset({"ciso", "ciso-agent:ciso"})
TOOL_RELATIVE: Final = Path("skills") / "ciso" / "scripts" / "ciso_tool.py"
_FORBIDDEN: Final = frozenset("$`;&|<>(){}[]*?!~#\n\r")
_UV_FLAGS: Final = ("--quiet", "--no-config", "--no-project")
_PYTHON_VERSIONS: Final = frozenset({"3.13"})
#: Subcommand -> option -> takes a value.
_OPTIONS: Final[dict[str, dict[str, bool]]] = {
    "review": {"--repo": True, "--staged": False, "--range": True, "--data-dir": True},
    "check": {"--command": True, "--tool": True, "--path": True, "--data-dir": True},
    "audit-setup": {"--repo": True, "--home": False, "--data-dir": True},
    "summary": {"--days": True, "--data-dir": True},
}


def _same_file(text: str, expected: Path) -> bool:
    try:
        candidate = Path(text)
        if not candidate.is_absolute():
            return False
        a = os.path.normcase(str(candidate.resolve()))
        b = os.path.normcase(str(expected.resolve()))
    except (OSError, ValueError):
        return False
    return a == b


def _options_ok(subcommand: str, args: list[str], data_dir: Path) -> bool:
    allowed = _OPTIONS.get(subcommand)
    if allowed is None:
        return False
    index = 0
    while index < len(args):
        name = args[index]
        if name not in allowed:
            return False
        if name == "--data-dir" and (
            index + 1 >= len(args) or not _same_file(args[index + 1], data_dir)
        ):
            return False
        index += 2 if allowed[name] else 1
        if index > len(args):
            return False
    return True


def own_tool_command(command: str, plugin_root: Path, data_dir: Path) -> bool:
    """True only for the exact tool invocation described in the module docstring."""
    if any(ch in _FORBIDDEN for ch in command) or "\\\\" in command:
        return False
    try:
        lexer = shlex.shlex(command, posix=True, punctuation_chars=True)
        lexer.whitespace_split = True
        words = list(lexer)
    except ValueError:
        return False
    tool = plugin_root / TOOL_RELATIVE
    head = words[:12]
    if len(words) < 17 or head[:2] != ["uv", "run"] or tuple(head[2:5]) != _UV_FLAGS:
        return False
    if head[5] != "--python" or head[6] not in _PYTHON_VERSIONS or head[7] != "--directory":
        return False
    if not _same_file(head[8], plugin_root) or head[9] != "--with-requirements":
        return False
    if not _same_file(head[10], tool) or head[11] != "--":
        return False
    if words[12:15] != ["python", "-I", "-B"] or not _same_file(words[15], tool):
        return False
    return _options_ok(words[16], words[17:], data_dir)


def own_invocation(
    tool_name: str, tool_input: Mapping[str, Any], plugin_root: Path, data_dir: Path
) -> bool:
    """The `Skill` tool loading this plugin's skill, or the exact tool command via Bash."""
    if tool_name == "Skill":
        return tool_input.get("skill") in SKILL_NAMES
    if tool_name == "Bash":
        command = tool_input.get("command")
        return isinstance(command, str) and own_tool_command(command, plugin_root, data_dir)
    return False
