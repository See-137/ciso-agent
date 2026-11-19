"""Environment variables set in front of a command (`NAME=value cmd`, `env NAME=value`,
`export`, `set`, `setx`, `$env:NAME = ...`).

Any such assignment makes the command not read-only. Variables that choose what code
runs (preloaded libraries, interpreter options, pagers and editors, the search path, the
shell's startup file, git's command hooks) add `environment_hijack`.
"""

from __future__ import annotations

import re

from ciso.governance.classes import CommandClass as C

_HIJACK_NAMES = frozenset(
    {
        "LD_PRELOAD",
        "LD_LIBRARY_PATH",
        "LD_AUDIT",
        "BASH_ENV",
        "ENV",
        "NODE_OPTIONS",
        "NODE_PATH",
        "PAGER",
        "EDITOR",
        "VISUAL",
        "LESSOPEN",
        "LESSCLOSE",
        "PATH",
        "IFS",
        "GCONV_PATH",
        "PERL5OPT",
        "PERL5LIB",
        "PERLLIB",
        "RUBYOPT",
        "RUBYLIB",
        "PROMPT_COMMAND",
        "SHELLOPTS",
        "BASHOPTS",
        "PS4",
        "ZDOTDIR",
        "JAVA_TOOL_OPTIONS",
        "_JAVA_OPTIONS",
        "MANPAGER",
        "SYSTEMD_PAGER",
        "PATHEXT",
        "PSMODULEPATH",
        "COMSPEC",
    }
)
_HIJACK_PREFIXES = ("DYLD_", "GIT_", "PYTHON", "LD_")
_HISTORY_RE = re.compile(r"HIST(FILE|SIZE|FILESIZE)")


def assignment_classes(assignment: str) -> set[C]:
    """Classes shown by one `NAME=value` text (any case; `env:` prefix allowed)."""
    name, _, value = assignment.partition("=")
    name = name.strip().removeprefix("$").removesuffix("+")
    if name.casefold().startswith("env:"):
        name = name[4:]
    upper = name.upper()
    found: set[C] = set()
    if upper in _HIJACK_NAMES or upper.startswith(_HIJACK_PREFIXES):
        found.add(C.ENVIRONMENT_HIJACK)
    if _HISTORY_RE.fullmatch(upper) and (value.strip() in ("0", "") or "/dev/null" in value):
        found.add(C.SECURITY_TOOL_TAMPER)
    return found


def variable_classes(name: str) -> set[C]:
    """Classes for a variable set without `=` in the same word (`setx PATH value`)."""
    return assignment_classes(f"{name}=x") - {C.SECURITY_TOOL_TAMPER}
