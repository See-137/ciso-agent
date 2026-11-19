"""Word-level conditions for `read_only_command`, and bash arithmetic hazards.

Read-only is earned, never defaulted (review C1, Q1). A word keeps a command read-only
only when its text as written holds none of the characters a shell gives meaning to
beyond plain text: expansions (`$`, a backtick, `%`, `!`, `~`), globs and braces (`*`,
`?`, `[`, `]`, `{`, `}`) and line breaks. (A command with any character outside ASCII is
never read-only; `ciso.governance.commands` decides that for the whole text.) A
backslash is an escape in the POSIX reading and only allowed inside a Windows path in
the PowerShell/cmd reading; a word starting with `@` (PowerShell splatting) and the cmd
escape `^` are refused in that reading.

Bash evaluates some operands arithmetically, and arithmetic evaluation expands array
subscripts and the values of variables recursively, running any command substitution it
finds, even one written inside single quotes. `arithmetic_hazard` names those operands.
"""

from __future__ import annotations

import re

from ciso.governance.lexer_types import Dialect, Word

#: Characters that make a word more than plain text in some shell.
_FORBIDDEN = frozenset("$`[]*?{}~%!\n\r")
_WINDOWS_PATH_RE = re.compile(r"[\"']?[A-Za-z0-9_.:\\/ -]+[\"']?")
#: Markers of a command hidden in text bash may evaluate.
_HIDDEN_MARKERS = ("$(", "`", "<(", ">(")
#: Programs whose operands bash may evaluate as arithmetic or as array subscripts.
_SUBSCRIPT_PROGRAMS = frozenset(
    {
        "[[",
        "[",
        "test",
        "let",
        "printf",
        "read",
        "declare",
        "typeset",
        "local",
        "export",
        "readonly",
        "unset",
        "mapfile",
        "readarray",
        "wait",
    }
)
_ARITHMETIC_OPERATORS = frozenset({"-eq", "-ne", "-lt", "-le", "-gt", "-ge"})
_SUBSCRIPT_RE = re.compile(r"\[([^\]]*)\]")
_NUMBER_RE = re.compile(r"[0-9]+")


def word_earns_read_only(word: Word, dialect: Dialect) -> bool:
    """True when `word`, as written, is plain text in `dialect` (see module doc)."""
    raw = word.raw
    if any(ch in _FORBIDDEN for ch in raw):
        return False
    if dialect is Dialect.WINDOWS:
        if raw.startswith("@") or "^" in raw:
            return False
        return "\\" not in raw or bool(_WINDOWS_PATH_RE.fullmatch(raw))
    return "\\" not in raw


def arithmetic_unsafe(body: str) -> bool:
    """True when arithmetic text could run a command: a hidden command, a variable name
    (its value is evaluated again), a subscript, or a quote."""
    if any(marker in body for marker in _HIDDEN_MARKERS):
        return True
    return bool(re.search(r"[A-Za-z_$\[\]'\"\\]", body))


def _bad_subscript(text: str) -> bool:
    return any(not _NUMBER_RE.fullmatch(m.group(1)) for m in _SUBSCRIPT_RE.finditer(text))


def arithmetic_hazard(name: str, raws: list[str]) -> bool:
    """True when bash could run a command while evaluating the operands of `name`.

    Any operand with a hidden-command marker or a non-numeric array subscript counts; for
    `let` and the arithmetic comparisons of `[[`, any operand that is not a plain number
    counts (a variable's value is itself evaluated as arithmetic).
    """
    if name not in _SUBSCRIPT_PROGRAMS:
        return False
    if any(m in raw for raw in raws for m in _HIDDEN_MARKERS) or any(map(_bad_subscript, raws)):
        return True
    if name == "let":
        return any(arithmetic_unsafe(raw) for raw in raws)
    if name == "[[":
        for index, raw in enumerate(raws):
            if raw in _ARITHMETIC_OPERATORS:
                operands = raws[index - 1 : index] + raws[index + 1 : index + 2]
                if any(arithmetic_unsafe(op) for op in operands):
                    return True
    return False
