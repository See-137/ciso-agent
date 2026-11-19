"""The plugin's own skill and its read-only tool, recognised exactly.

The CISO skill must work under the plugin's own hooks: loading it (the `Skill` tool) and
running its tool script would otherwise be asked or refused like any unknown program.
Two fixed, tested shapes are recognised here:

1. the `Skill` tool naming this plugin's skill by its namespaced name `ciso-agent:ciso`
   (plugin skills are always namespaced; a bare `ciso` is a project or user skill, review
   M2);
2. a `Bash` command that is EXACTLY the command in `skills/ciso/SKILL.md`: `uv run` with
   the fixed flags of `TOOL_ARGV` (isolated, every package source on the command line,
   review H1), this plugin's root, its runtime requirements and its empty find-links
   folder, `-- python -I -B <this tool> <subcommand> <options>`, where the paths resolve
   to this plugin's own files, the subcommand and every option are on a fixed list,
   `--data-dir` (when given) is this plugin's data directory, and the raw text holds no
   character a shell would expand or use to join commands.

Recognising a shape is not an allow: `decide.py` still applies the stop flag and the
identity checks (review M3). The tool only reads, and writes reports under the plugin's
data directory (`review` and `audit-setup` with `--data-dir`); it prints findings (rule,
severity, location), never file content. Anything that does not match exactly goes to the
governance engine like every other command.
"""

from __future__ import annotations

import os
import shlex
from collections.abc import Mapping
from pathlib import Path
from typing import Any, Final

SKILL_NAMES: Final = frozenset({"ciso-agent:ciso"})
TOOL_RELATIVE: Final = Path("skills") / "ciso" / "scripts" / "ciso_tool.py"
REQUIREMENTS_RELATIVE: Final = Path("scripts") / "runtime-requirements.txt"
NO_LOCAL_PACKAGES_RELATIVE: Final = Path("scripts") / "no-local-packages"
INDEX: Final = "https://pypi.org/simple"
_FORBIDDEN: Final = frozenset("$`;&|<>(){}[]*?!~#\n\r")
#: Placeholders in `TOOL_ARGV` for paths compared by identity.
ROOT, REQUIREMENTS, NO_LOCAL, TOOL = "<root>", "<requirements>", "<no-local>", "<tool>"
#: The skill's tool command up to the subcommand (SKILL.md, "The tool").
TOOL_ARGV: Final = (
    "uv", "run", "--quiet", "--isolated", "--no-config", "--no-project", "--no-env-file",
    "--python", "3.13", "--default-index", INDEX, "--index", INDEX,
    "--find-links", NO_LOCAL, "--index-strategy", "first-index",
    "--keyring-provider", "disabled", "--no-build", "--directory", ROOT,
    "--with-requirements", REQUIREMENTS, "--", "python", "-I", "-B", TOOL,
)  # fmt: skip
#: Subcommands that write nothing (allowed while the stop flag is engaged).
READ_ONLY_SUBCOMMANDS: Final = frozenset({"summary"})
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


def tool_subcommand(command: str, plugin_root: Path, data_dir: Path) -> str | None:
    """The subcommand of the exact tool invocation described in the module docstring,
    or None when the command is anything else."""
    if any(ch in _FORBIDDEN for ch in command) or "\\\\" in command:
        return None
    try:
        lexer = shlex.shlex(command, posix=True, punctuation_chars=True)
        lexer.whitespace_split = True
        words = list(lexer)
    except ValueError:
        return None
    paths = {
        ROOT: plugin_root,
        REQUIREMENTS: plugin_root / REQUIREMENTS_RELATIVE,
        NO_LOCAL: plugin_root / NO_LOCAL_PACKAGES_RELATIVE,
        TOOL: plugin_root / TOOL_RELATIVE,
    }
    head = len(TOOL_ARGV)
    if len(words) <= head:
        return None
    for expected, word in zip(TOOL_ARGV, words[:head], strict=True):
        if expected in paths:
            if not _same_file(word, paths[expected]):
                return None
        elif word != expected:
            return None
    subcommand = words[head]
    return subcommand if _options_ok(subcommand, words[head + 1 :], data_dir) else None


def own_tool_command(command: str, plugin_root: Path, data_dir: Path) -> bool:
    """True only for the exact tool invocation described in the module docstring."""
    return tool_subcommand(command, plugin_root, data_dir) is not None


def own_invocation(
    tool_name: str, tool_input: Mapping[str, Any], plugin_root: Path, data_dir: Path
) -> str | None:
    """What own part this is: "skill" (loading this plugin's skill), the tool's
    subcommand for the exact tool command via Bash, or None."""
    if tool_name == "Skill":
        return "skill" if tool_input.get("skill") in SKILL_NAMES else None
    if tool_name == "Bash":
        command = tool_input.get("command")
        if isinstance(command, str):
            return tool_subcommand(command, plugin_root, data_dir)
    return None


def writes_nothing(part: str) -> bool:
    """True for the parts that only read: loading the skill and `summary`."""
    return part == "skill" or part in READ_ONLY_SUBCOMMANDS
