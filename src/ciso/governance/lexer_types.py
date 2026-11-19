"""Types and constants shared by the shell command reader (`ciso.governance.shell_lexer`)."""

from __future__ import annotations

from enum import StrEnum
from typing import NamedTuple

#: Stands for text whose value is only known when the command runs.
DYN = "\x00"
#: Deepest nesting of substitutions, groups and command strings read.
MAX_DEPTH = 8
#: Most words in one command line, all nesting included.
MAX_WORDS = 2000

#: Characters the PowerShell tokenizer treats as an ASCII quote, dash or space.
#: (PowerShell's tokenizer: left, right, base and reversed single quotes; left,
#: right and low double quotes; en dash, em dash, horizontal bar; Unicode spaces.)
POWERSHELL_QUOTES_SINGLE = "\u2018\u2019\u201a\u201b"
POWERSHELL_QUOTES_DOUBLE = "\u201c\u201d\u201e"
POWERSHELL_DASHES = "\u2013\u2014\u2015"
POWERSHELL_SPACES = (
    "\u00a0\u0085\u1680\u2000\u2001\u2002\u2003\u2004\u2005\u2006"
    "\u2007\u2008\u2009\u200a\u2028\u2029\u202f\u205f\u3000"
)
POWERSHELL_SPECIAL = (
    POWERSHELL_QUOTES_SINGLE + POWERSHELL_QUOTES_DOUBLE + POWERSHELL_DASHES + POWERSHELL_SPACES
)
POWERSHELL_EQUIVALENTS = str.maketrans(
    {
        **dict.fromkeys(POWERSHELL_QUOTES_SINGLE, "'"),
        **dict.fromkeys(POWERSHELL_QUOTES_DOUBLE, '"'),
        **dict.fromkeys(POWERSHELL_DASHES, "-"),
        **dict.fromkeys(POWERSHELL_SPACES, " "),
    }
)


class ParseError(ValueError):
    """The text cannot be read with confidence."""


class HiddenCommand(ParseError):
    """A construct whose body is not read (arithmetic, a parameter default, an unquoted
    here-document) contains a command. The whole command is unparseable, whatever any
    other reading of it says."""


class Dialect(StrEnum):
    POSIX = "posix"
    WINDOWS = "windows"


class Word(NamedTuple):
    text: str
    raw: str
    subs: tuple[Script, ...] = ()
    variables: tuple[str, ...] = ()
    ansi_c: bool = False

    @property
    def dynamic(self) -> bool:
        return DYN in self.text


class Redirect(NamedTuple):
    op: str
    target: Word | None
    body: str | None = None


class Stage(NamedTuple):
    words: tuple[Word, ...]
    redirects: tuple[Redirect, ...]
    groups: tuple[Script, ...]
    #: A group came before the first word: the command name is computed, e.g. `(x) y`.
    lead_group: bool = False


class Script(NamedTuple):
    pipelines: tuple[tuple[Stage, ...], ...]
    dialect: Dialect
    #: Evasion signals seen while reading, for example `ifs` (`${IFS}` used as a space).
    flags: frozenset[str]


#: Redirection operators, longest first so that `>>&` is not read as `>>` then `&`.
REDIRECT_OPERATORS = (
    "<<<",
    "<<-",
    ">>&",
    "&>>",
    "<<",
    ">>",
    ">&",
    "<&",
    ">|",
    "<>",
    "&>",
    "<",
    ">",
)
POSIX_STOP = frozenset(" \t\r\n;&|<>()")
WINDOWS_STOP = frozenset(" \t\r\n;&|<>(){}")
ANSI_SIMPLE = {
    "n": "\n",
    "t": "\t",
    "r": "\r",
    "a": "\a",
    "b": "\b",
    "e": "\x1b",
    "E": "\x1b",
    "f": "\f",
    "v": "\v",
    "\\": "\\",
    "'": "'",
    '"': '"',
    "?": "?",
}
VAR_FIRST = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_"
VAR_CHARS = VAR_FIRST + "0123456789"


class WordBuilder:
    """Mutable accumulator for one word while it is being read."""

    def __init__(self) -> None:
        self.parts: list[str] = []
        self.subs: list[Script] = []
        self.variables: list[str] = []
        self.ansi_c = False
        self.started = False

    def add(self, text: str) -> None:
        self.parts.append(text)
        self.started = True

    def dynamic(self, name: str = "") -> None:
        self.parts.append(DYN)
        if name:
            self.variables.append(name)
        self.started = True


def hides_command(body: str) -> bool:
    """True when skipped text could start a command: `$(`, a backtick, `<(` or `>(`."""
    return any(marker in body for marker in ("$(", "`", "<(", ">("))
