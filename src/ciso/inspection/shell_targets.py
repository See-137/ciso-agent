"""Files a shell command writes, read from its text (queue Q3, review M1 inspection side).

A redirect (`>`, `>>`, `2>`, `&>`, `*>`, `>|`), `tee`, a copy or move destination, the
PowerShell content cmdlets (`Out-File`, `Set-Content`, `Add-Content`, `New-Item`) and
`dd of=` name a file the command writes. Each is checked against the sensitive-path
rules, and a relative one also under every directory an earlier `cd`, `pushd` or
`Set-Location` in the same command moved to.

This is a reading of the text, not a shell: it splits on whitespace and the usual
separators, removes quotes, and keeps backslashes (they are Windows separators). It never
clears a command; the governance classifier judges the command itself. A target it cannot
see (computed, inside a script) is simply not reported.
"""

from __future__ import annotations

import re
from collections.abc import Iterator
from typing import Final, NamedTuple

#: Most write targets taken from one command.
MAX_TARGETS: Final = 64

_TOKEN = re.compile(
    r"""(?P<space>\s+)
    |(?P<dup>[0-9]*>&[0-9-]*)
    |(?P<redir>(?:[0-9]+|&|\*)?>>?\|?)
    |(?P<sep>&&|\|\||[;&|()\n<])
    |(?P<word>(?:'[^']*'|"[^"]*"|[^\s;&|()<>'"])+)
    |(?P<other>.)""",
    re.VERBOSE,
)
_QUOTED = re.compile(r"'([^']*)'|\"([^\"]*)\"")
_ASSIGNMENT = re.compile(r"[A-Za-z_][A-Za-z0-9_]*=.*")
_PREFIXES: Final = frozenset({"sudo", "doas", "env", "command", "nohup", "time", "exec"})
_COPIES: Final = frozenset(
    {"cp", "mv", "install", "ln", "copy", "move", "copy-item", "move-item", "cpi", "mi"}
)
_CONTENT: Final = frozenset(
    {"out-file", "set-content", "add-content", "sc", "ac", "new-item", "ni", "tee-object"}
)
_DIRECTORY: Final = frozenset({"cd", "pushd", "chdir", "set-location", "sl"})
_PATH_PARAMS: Final = frozenset({"-filepath", "-path", "-literalpath", "-lp", "-pspath"})
_DEST_PARAMS: Final = frozenset({"-destination", "-dest", "--target-directory", "-t"})
_SWITCHES: Final = frozenset(
    {"-append", "-force", "-noclobber", "-nonewline", "-passthru", "-whatif", "-confirm",
     "-recurse", "-a", "-f", "-i", "-n", "-r", "-v", "-p"}
)  # fmt: skip
_ABSOLUTE = re.compile(r"[/\\~$%]|[A-Za-z]:")


class _Command(NamedTuple):
    words: list[str]
    redirects: list[str]


def _unquote(word: str) -> str:
    return _QUOTED.sub(lambda m: m.group(1) if m.group(1) is not None else m.group(2), word)


def _commands(text: str) -> Iterator[_Command]:
    words: list[str] = []
    redirects: list[str] = []
    expect_target = False
    for match in _TOKEN.finditer(text):
        kind = match.lastgroup
        if kind == "space" or kind == "dup":
            continue
        if kind == "redir":
            expect_target = True
            continue
        if kind == "word":
            word = _unquote(match.group())
            (redirects if expect_target else words).append(word)
            expect_target = False
            continue
        expect_target = False
        if kind == "sep":
            yield _Command(words, redirects)
            words, redirects = [], []
    yield _Command(words, redirects)


def _program(words: list[str]) -> tuple[str, list[str]]:
    index = 0
    while index < len(words) and (
        _ASSIGNMENT.fullmatch(words[index]) or words[index].lower() in _PREFIXES
    ):
        index += 1
    if index >= len(words):
        return "", []
    name = re.split(r"[/\\]", words[index])[-1].lower().removesuffix(".exe")
    return name, words[index + 1 :]


def _positional(args: list[str]) -> list[str]:
    """Arguments that are not options or option values (options with a value are
    assumed to take the next word unless they are known switches)."""
    out: list[str] = []
    skip = False
    for arg in args:
        if skip:
            skip = False
            continue
        if arg.startswith("-") and len(arg) > 1:
            skip = "=" not in arg and arg.lower() not in _SWITCHES
            continue
        out.append(arg)
    return out


def _named(args: list[str], names: frozenset[str]) -> list[str]:
    found = []
    for index, arg in enumerate(args[:-1]):
        if arg.lower() in names:
            found.append(args[index + 1])
    return found


def _written(name: str, args: list[str]) -> list[str]:
    if name == "tee":
        return [a for a in args if not a.startswith("-")]
    if name == "dd":
        return [a[3:] for a in args if a.startswith("of=")]
    if name in _COPIES:
        named = _named(args, _DEST_PARAMS)
        if named:
            return named
        plain = [a for a in args if not a.startswith("-")]
        return plain[-1:] if len(plain) > 1 else []
    if name in _CONTENT:
        named = _named(args, _PATH_PARAMS)
        return named or _positional(args)[:1]
    return []


def write_targets(text: str) -> tuple[str, ...]:
    """The files `text` writes, as written, plus relative ones joined to earlier `cd`
    directories. At most `MAX_TARGETS`."""
    found: list[str] = []
    directories: list[str] = []
    for command in _commands(text):
        name, args = _program(command.words)
        if name in _DIRECTORY:
            directories.extend(_positional(args)[:1])
            continue
        for target in (*command.redirects, *_written(name, args)):
            if not target:
                continue
            found.append(target)
            if not _ABSOLUTE.match(target):
                found.extend(f"{directory}/{target}" for directory in directories)
    return tuple(dict.fromkeys(found))[:MAX_TARGETS]
