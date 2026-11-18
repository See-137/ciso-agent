"""A deterministic reader of shell command text, for classification only.

It never runs anything and never expands anything it cannot know. Two dialects:

- `POSIX`: sh/bash quoting (`'..'`, `".."`, `$'..'`, backslash), `$(..)`, backticks,
  `${..}`, `<(..)`, here-documents, comments.
- `WINDOWS`: PowerShell and cmd together (`'..'` with `''`, `".."`, the backtick and the
  caret as escape characters, `$(..)`, `(..)`, `{..}` script blocks, `%VAR%`, `$env:X`,
  here-strings, `&` as a separator).

Anything the reader cannot read with confidence raises `ParseError`; the classifier then
reports the command as unparseable. Expansions whose value is unknown are kept as the
`DYN` marker, so a command name built from a variable is visible as such.
"""

from __future__ import annotations

from enum import StrEnum
from typing import NamedTuple

#: Stands for text whose value is only known when the command runs.
DYN = "\x00"
#: Deepest nesting of substitutions, groups and command strings read.
MAX_DEPTH = 8
#: Most words in one command line, all nesting included.
MAX_WORDS = 2000


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
_REDIRECT_OPERATORS = (
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
_POSIX_STOP = frozenset(" \t\r\n;&|<>()")
_WINDOWS_STOP = frozenset(" \t\r\n;&|<>(){}")
_ANSI_SIMPLE = {
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
_VAR_FIRST = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_"
_VAR_CHARS = _VAR_FIRST + "0123456789"


class _Builder:
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


class _Reader:
    def __init__(self, text: str, dialect: Dialect, depth: int, budget: list[int]) -> None:
        if depth > MAX_DEPTH:
            raise ParseError("nesting too deep")
        self.s = text
        self.i = 0
        self.dialect = dialect
        self.depth = depth
        self.budget = budget
        self.flags: set[str] = set()
        self.heredoc_skip: dict[int, int] = {}
        self.heredoc_line_end = -1
        self.heredoc_cursor = -1

    # --- helpers ---------------------------------------------------------------

    def peek(self, offset: int = 0) -> str:
        j = self.i + offset
        return self.s[j] if j < len(self.s) else ""

    def at(self, chars: str, offset: int = 0) -> bool:
        ch = self.peek(offset)
        return ch != "" and ch in chars

    def nested(self, text: str, dialect: Dialect | None = None) -> Script:
        return parse_script(text, dialect or self.dialect, self.depth + 1, self.budget)

    def read_balanced(self, open_ch: str, close_ch: str) -> str:
        """From just after `open_ch`, the text up to the matching `close_ch`, quote-aware."""
        start = self.i
        level = 1
        while self.i < len(self.s):
            ch = self.s[self.i]
            if ch in "'\"":
                self.skip_quoted(ch)
                continue
            if (ch == "\\" and self.dialect is Dialect.POSIX) or (
                ch == "`" and (self.dialect is Dialect.WINDOWS)
            ):
                self.i += 2
                continue
            if ch == open_ch:
                level += 1
            elif ch == close_ch:
                level -= 1
                if level == 0:
                    body = self.s[start : self.i]
                    self.i += 1
                    return body
            self.i += 1
        raise ParseError(f"unbalanced {open_ch!r}")

    def skip_quoted(self, quote: str) -> None:
        self.i += 1
        while self.i < len(self.s):
            ch = self.s[self.i]
            if ch == quote:
                self.i += 1
                return
            if quote == '"' and ch in ("\\" if self.dialect is Dialect.POSIX else "`"):
                self.i += 1
            self.i += 1
        raise ParseError("unterminated quote")

    # --- script level ----------------------------------------------------------

    def script(self, closer: str = "") -> Script:
        pipelines: list[tuple[Stage, ...]] = []
        stages: list[Stage] = []
        words: list[Word] = []
        redirects: list[Redirect] = []
        groups: list[Script] = []
        lead = [False]

        def end_stage() -> None:
            if words or redirects or groups:
                stages.append(Stage(tuple(words), tuple(redirects), tuple(groups), lead[0]))
            words.clear()
            redirects.clear()
            groups.clear()
            lead[0] = False

        def end_pipeline() -> None:
            end_stage()
            if stages:
                pipelines.append(tuple(stages))
            stages.clear()

        posix = self.dialect is Dialect.POSIX
        while True:
            ch = self.peek()
            if ch == "":
                if closer:
                    raise ParseError(f"missing {closer!r}")
                break
            if closer and ch == closer:
                self.i += 1
                break
            if ch in " \t\r":
                self.i += 1
            elif ch == "\n":
                end_pipeline()
                self.i = self.heredoc_skip.get(self.i, self.i + 1)
            elif (
                ch in "\\`^"
                and self.peek(1) == "\n"
                and ((ch == "\\") == posix or (ch in "`^" and not posix))
            ):
                self.i += 2
            elif ch == ";":
                end_pipeline()
                self.i += 1
            elif ch == "&":
                if self.peek(1) == ">" and posix:
                    self.redirect(redirects, "&>")
                    continue
                end_pipeline()
                self.i += 2 if self.peek(1) == "&" else 1
            elif ch == "|":
                if self.peek(1) == "|":
                    end_pipeline()
                    self.i += 2
                else:
                    end_stage()
                    self.i += 2 if self.peek(1) == "&" else 1
            elif posix and ch == "#":
                while self.i < len(self.s) and self.s[self.i] != "\n":
                    self.i += 1
            elif ch == "(":
                self.i += 1
                lead[0] = lead[0] or not words
                groups.append(self.nested(self.read_balanced("(", ")")))
            elif ch == ")" or (ch == "}" and not posix):
                raise ParseError(f"unexpected {ch!r}")
            elif ch == "{" and not posix:
                self.i += 1
                lead[0] = lead[0] or not words
                groups.append(self.nested(self.read_balanced("{", "}")))
            elif (
                ch in "<>"
                or (ch.isdigit() and self.is_fd_redirect())
                or (ch == "*" and (not posix and self.peek(1) == ">"))
            ):
                if ch in "<>" and self.peek(1) == "(" and posix:
                    substituted = self.word()
                    if substituted is not None:
                        words.append(substituted)
                else:
                    self.redirect(redirects, "")
            else:
                word = self.word()
                if word is not None:
                    words.append(word)
            if len(words) > MAX_WORDS:
                raise ParseError("too many words")
        end_pipeline()
        self.budget[0] -= sum(len(st.words) for pl in pipelines for st in pl)
        if self.budget[0] < 0:
            raise ParseError("too many words")
        return Script(tuple(pipelines), self.dialect, frozenset(self.flags))

    def at_word_start(self) -> bool:
        return self.i == 0 or self.s[self.i - 1] in " \t\r\n;&|("

    def is_fd_redirect(self) -> bool:
        j = self.i
        while j < len(self.s) and self.s[j].isdigit():
            j += 1
        return j < len(self.s) and self.s[j] in "<>" and self.at_word_start()

    def redirect(self, redirects: list[Redirect], forced: str) -> None:
        start = self.i
        if forced:
            self.i += len(forced)
        else:
            while self.at("0123456789*"):
                self.i += 1
            for operator in _REDIRECT_OPERATORS:
                if self.s.startswith(operator, self.i):
                    self.i += len(operator)
                    break
        op = self.s[start : self.i].lstrip("0123456789*") or ">"
        while self.at(" \t"):
            self.i += 1
        if op.endswith("&") and (self.peek().isdigit() or self.peek() == "-"):
            target_start = self.i
            while self.peek().isdigit() or self.peek() == "-":
                self.i += 1
            text = self.s[target_start : self.i]
            redirects.append(Redirect(op, Word(text, text)))
            return
        target = self.word()
        if target is None:
            raise ParseError("redirection without a target")
        if op.startswith("<<") and not op.startswith("<<<"):
            if self.dialect is not Dialect.POSIX:
                raise ParseError("here-document outside a POSIX shell")
            body = self.heredoc(target, strip_tabs=op.endswith("-"))
            redirects.append(Redirect("<<", target, body))
            return
        redirects.append(Redirect(op, target))

    def heredoc(self, delimiter: Word, *, strip_tabs: bool) -> str:
        if delimiter.dynamic or not delimiter.text:
            raise ParseError("here-document delimiter is not literal")
        line_end = self.s.find("\n", self.i)
        if line_end < 0:
            raise ParseError("here-document without a body")
        start = self.heredoc_cursor if self.heredoc_line_end == line_end else line_end + 1
        pos = start
        lines: list[str] = []
        while pos <= len(self.s):
            nl = self.s.find("\n", pos)
            end = len(self.s) if nl < 0 else nl
            line = self.s[pos:end]
            if (line.lstrip("\t") if strip_tabs else line) == delimiter.text:
                resume = end + 1 if nl >= 0 else len(self.s)
                self.heredoc_line_end = line_end
                self.heredoc_cursor = resume
                self.heredoc_skip[line_end] = resume
                body = "\n".join(lines)
                quoted = any(q in delimiter.raw for q in "'\"\\")
                if not quoted and _hides_command(body):
                    # An unquoted here-document expands substitutions even when it only
                    # feeds data to a reader such as `cat`.
                    raise HiddenCommand("command substitution inside a here-document")
                return body
            lines.append(line)
            if nl < 0:
                break
            pos = nl + 1
        raise ParseError("here-document is not terminated")

    # --- word level ------------------------------------------------------------

    def word(self) -> Word | None:
        start = self.i
        b = _Builder()
        stop = _POSIX_STOP if self.dialect is Dialect.POSIX else _WINDOWS_STOP
        if self.dialect is Dialect.POSIX and self.at("<>") and self.peek(1) == "(":
            self.i += 2
            b.subs.append(self.nested(self.read_balanced("(", ")")))
            b.dynamic()
        if self.dialect is Dialect.WINDOWS and self.peek() == "@" and self.at("'\"", 1):
            self.here_string(b)
        while self.i < len(self.s) and self.s[self.i] not in stop:
            if self.dialect is Dialect.POSIX:
                if self.posix_char(b):
                    break
            else:
                self.windows_char(b)
        if not b.started and self.i == start:
            raise ParseError(f"unexpected character {self.peek()!r}")
        if not b.started:
            return None
        return Word(
            "".join(b.parts),
            self.s[start : self.i],
            tuple(b.subs),
            tuple(b.variables),
            b.ansi_c,
        )

    def posix_char(self, b: _Builder) -> bool:
        """Read one unit of a POSIX word. True when `${IFS}` ended the word."""
        ch = self.s[self.i]
        if ch == "\\":
            nxt = self.peek(1)
            self.i += 2
            if nxt == "":
                raise ParseError("trailing backslash")
            if nxt != "\n":
                b.add(nxt)
        elif ch == "'":
            end = self.s.find("'", self.i + 1)
            if end < 0:
                raise ParseError("unterminated single quote")
            b.add(self.s[self.i + 1 : end])
            self.i = end + 1
        elif ch == '"':
            self.i += 1
            self.posix_double(b)
        elif ch == "`":
            self.i += 1
            b.subs.append(self.nested(self.backtick_body()))
            b.dynamic()
        elif ch == "$":
            return self.posix_dollar(b, quoted=False)
        else:
            b.add(ch)
            self.i += 1
        return False

    def posix_double(self, b: _Builder) -> None:
        b.started = True
        while True:
            ch = self.peek()
            if ch == "":
                raise ParseError("unterminated double quote")
            if ch == '"':
                self.i += 1
                return
            if ch == "\\" and self.at('$`"\\\n', 1):
                if self.peek(1) != "\n":
                    b.add(self.peek(1))
                self.i += 2
            elif ch == "`":
                self.i += 1
                b.subs.append(self.nested(self.backtick_body()))
                b.dynamic()
            elif ch == "$":
                self.posix_dollar(b, quoted=True)
            else:
                b.add(ch)
                self.i += 1

    def backtick_body(self) -> str:
        out: list[str] = []
        while True:
            ch = self.peek()
            if ch == "":
                raise ParseError("unterminated backtick")
            if ch == "`":
                self.i += 1
                return "".join(out)
            if ch == "\\" and self.at("`\\$", 1):
                out.append(self.peek(1))
                self.i += 2
                continue
            out.append(ch)
            self.i += 1

    def posix_dollar(self, b: _Builder, *, quoted: bool) -> bool:
        nxt = self.peek(1)
        if nxt == "(":
            if self.peek(2) == "(":
                self.i += 3
                if _hides_command(self.read_balanced("(", ")")):
                    raise HiddenCommand("command substitution inside an arithmetic expansion")
                if self.peek() != ")":
                    raise ParseError("unbalanced arithmetic expansion")
                self.i += 1
                b.dynamic()
                return False
            self.i += 2
            b.subs.append(self.nested(self.read_balanced("(", ")")))
            b.dynamic()
            return False
        if nxt == "{":
            self.i += 2
            body = self.read_balanced("{", "}")
            if _hides_command(body):
                raise HiddenCommand("command substitution inside a parameter expansion")
            name = ""
            for c in body.lstrip("!#"):
                if c not in _VAR_CHARS:
                    break
                name += c
            return self.expanded(b, name, quoted=quoted)
        if nxt == "'" and not quoted:
            self.i += 2
            b.add(self.ansi_c())
            b.ansi_c = True
            return False
        if nxt == '"' and not quoted:
            self.i += 2
            self.posix_double(b)
            return False
        if nxt and nxt in _VAR_FIRST:
            j = self.i + 1
            while j < len(self.s) and self.s[j] in _VAR_CHARS:
                j += 1
            name = self.s[self.i + 1 : j]
            self.i = j
            return self.expanded(b, name, quoted=quoted)
        if nxt and nxt in "0123456789@*#?$!-":
            self.i += 2
            b.dynamic(nxt)
            return False
        b.add("$")
        self.i += 1
        return False

    def expanded(self, b: _Builder, name: str, *, quoted: bool) -> bool:
        if name == "IFS" and not quoted:
            self.flags.add("ifs")
            return True
        b.dynamic(name)
        return False

    def ansi_c(self) -> str:
        out: list[str] = []
        while True:
            ch = self.peek()
            if ch == "":
                raise ParseError("unterminated $'...'")
            if ch == "'":
                self.i += 1
                return "".join(out)
            if ch != "\\":
                out.append(ch)
                self.i += 1
                continue
            esc = self.peek(1)
            self.i += 2
            if esc in _ANSI_SIMPLE:
                out.append(_ANSI_SIMPLE[esc])
            elif esc in "xuU":
                width = {"x": 2, "u": 4, "U": 8}[esc]
                digits = ""
                while (
                    len(digits) < width and self.peek() and self.peek() in "0123456789abcdefABCDEF"
                ):
                    digits += self.peek()
                    self.i += 1
                if not digits:
                    raise ParseError("bad escape in $'...'")
                out.append(chr(int(digits, 16)))
            elif esc in "01234567":
                digits = esc
                while len(digits) < 3 and self.peek() and self.peek() in "01234567":
                    digits += self.peek()
                    self.i += 1
                out.append(chr(int(digits, 8) & 0xFF))
            else:
                raise ParseError("bad escape in $'...'")

    def windows_char(self, b: _Builder) -> None:
        ch = self.s[self.i]
        if ch in "`^":
            nxt = self.peek(1)
            if nxt == "":
                raise ParseError("trailing escape character")
            self.i += 2
            if nxt != "\n":
                b.add(nxt)
        elif ch == "'":
            self.i += 1
            b.started = True
            while True:
                end = self.s.find("'", self.i)
                if end < 0:
                    raise ParseError("unterminated single quote")
                b.add(self.s[self.i : end])
                self.i = end + 1
                if self.peek() != "'":
                    break
                b.add("'")
                self.i += 1
        elif ch == '"':
            self.i += 1
            self.windows_double(b)
        elif ch == "$":
            self.windows_dollar(b)
        elif ch == "%":
            self.percent(b)
        else:
            b.add(ch)
            self.i += 1

    def windows_double(self, b: _Builder) -> None:
        b.started = True
        while True:
            ch = self.peek()
            if ch == "":
                raise ParseError("unterminated double quote")
            if ch == '"':
                if self.peek(1) == '"':
                    b.add('"')
                    self.i += 2
                    continue
                self.i += 1
                return
            if ch == "`":
                if self.peek(1) == "":
                    raise ParseError("trailing escape character")
                b.add(self.peek(1))
                self.i += 2
            elif ch == "$":
                self.windows_dollar(b)
            elif ch == "%":
                self.percent(b)
            else:
                b.add(ch)
                self.i += 1

    def windows_dollar(self, b: _Builder) -> None:
        nxt = self.peek(1)
        if nxt == "(":
            self.i += 2
            b.subs.append(self.nested(self.read_balanced("(", ")")))
            b.dynamic()
        elif nxt == "{":
            self.i += 2
            b.dynamic(self.read_balanced("{", "}"))
        elif nxt and (nxt in _VAR_CHARS or nxt in "?$^"):
            j = self.i + 1
            while j < len(self.s) and (self.s[j] in _VAR_CHARS or self.s[j] == ":"):
                j += 1
            b.dynamic(self.s[self.i + 1 : j])
            self.i = max(j, self.i + 2)
        else:
            b.add("$")
            self.i += 1

    def percent(self, b: _Builder) -> None:
        j = self.i + 1
        while j < len(self.s) and (self.s[j] in _VAR_CHARS or self.s[j] in "~:,=-"):
            j += 1
        if j < len(self.s) and self.s[j] == "%" and j > self.i + 1:
            b.dynamic(self.s[self.i + 1 : j])
            self.i = j + 1
            return
        b.add("%")
        self.i += 1

    def here_string(self, b: _Builder) -> None:
        quote = self.peek(1)
        end = self.s.find("\n" + quote + "@", self.i + 2)
        if end < 0:
            raise ParseError("unterminated here-string")
        body = self.s[self.i + 2 : end]
        b.add(body.removeprefix("\r\n").removeprefix("\n"))
        self.i = end + 3


def _hides_command(body: str) -> bool:
    """True when skipped text could start a command: `$(`, a backtick, `<(` or `>(`."""
    return any(marker in body for marker in ("$(", "`", "<(", ">("))


def parse_script(
    text: str, dialect: Dialect, depth: int = 0, budget: list[int] | None = None
) -> Script:
    """Read `text` in `dialect`. Raises `ParseError` when it cannot be read with confidence."""
    shared = budget if budget is not None else [MAX_WORDS]
    try:
        return _Reader(text, dialect, depth, shared).script()
    except RecursionError as exc:
        raise ParseError("nesting too deep") from exc
