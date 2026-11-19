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

from ciso.governance.lexer_posix import PosixWords
from ciso.governance.lexer_types import (
    DYN,
    MAX_DEPTH,
    MAX_WORDS,
    POSIX_STOP,
    REDIRECT_OPERATORS,
    WINDOWS_STOP,
    Dialect,
    HiddenCommand,
    ParseError,
    Redirect,
    Script,
    Stage,
    Word,
    WordBuilder,
)
from ciso.governance.lexer_windows import WindowsWords
from ciso.governance.readonly_words import arithmetic_unsafe

__all__ = [
    "DYN",
    "MAX_DEPTH",
    "MAX_WORDS",
    "Dialect",
    "HiddenCommand",
    "ParseError",
    "Redirect",
    "Script",
    "Stage",
    "Word",
    "parse_script",
]


class _Reader(PosixWords, WindowsWords):
    """The full reader: script structure here, words in the dialect mixins."""

    def nested(self, text: str, dialect: Dialect | None = None) -> Script:
        return parse_script(text, dialect or self.dialect, self.depth + 1, self.budget)

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
            elif ch == "(" and posix and self.peek(1) == "(" and not words:
                self.arithmetic_command()
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

    def arithmetic_command(self) -> None:
        """`(( expr ))`: never read-only; a hidden command or a variable in it makes the
        text unreadable, because bash evaluates names again (review Q1)."""
        self.i += 1
        body = self.read_balanced("(", ")")
        if not (body.startswith("(") and body.endswith(")")):
            raise ParseError("not an arithmetic command")
        if arithmetic_unsafe(body[1:-1]):
            raise HiddenCommand("arithmetic command that may run a command")
        self.flags.add("arith")

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
            for operator in REDIRECT_OPERATORS:
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

    # --- word level ------------------------------------------------------------

    def word(self) -> Word | None:
        start = self.i
        b = WordBuilder()
        stop = POSIX_STOP if self.dialect is Dialect.POSIX else WINDOWS_STOP
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


def parse_script(
    text: str, dialect: Dialect, depth: int = 0, budget: list[int] | None = None
) -> Script:
    """Read `text` in `dialect`. Raises `ParseError` when it cannot be read with confidence."""
    shared = budget if budget is not None else [MAX_WORDS]
    try:
        return _Reader(text, dialect, depth, shared).script()
    except RecursionError as exc:
        raise ParseError("nesting too deep") from exc
