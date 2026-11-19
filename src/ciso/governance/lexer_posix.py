"""POSIX (sh/bash) word reading: quotes, `$'..'`, `$(..)`, backticks, `${..}`,
arithmetic and here-documents."""

from __future__ import annotations

import re

from ciso.governance.lexer_base import ReaderBase
from ciso.governance.lexer_types import (
    ANSI_SIMPLE,
    VAR_CHARS,
    VAR_FIRST,
    HiddenCommand,
    ParseError,
    Word,
    WordBuilder,
    hides_command,
)
from ciso.governance.readonly_words import arithmetic_unsafe

#: A subscript bash cannot evaluate as code: digits, `@` or `*`.
_SAFE_SUBSCRIPT_RE = re.compile(r"\[([0-9]+|@|\*)\]")


class PosixWords(ReaderBase):
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
                if not quoted and hides_command(body):
                    # An unquoted here-document expands substitutions even when it only
                    # feeds data to a reader such as `cat`.
                    raise HiddenCommand("command substitution inside a here-document")
                return body
            lines.append(line)
            if nl < 0:
                break
            pos = nl + 1
        raise ParseError("here-document is not terminated")

    def posix_char(self, b: WordBuilder) -> bool:
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

    def posix_double(self, b: WordBuilder) -> None:
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

    def posix_dollar(self, b: WordBuilder, *, quoted: bool) -> bool:
        nxt = self.peek(1)
        if nxt == "(":
            if self.peek(2) == "(":
                self.i += 3
                if arithmetic_unsafe(self.read_balanced("(", ")")):
                    # A name inside is evaluated again as arithmetic, which runs any
                    # substitution in its value or subscript (review Q1).
                    raise HiddenCommand("arithmetic expansion that may run a command")
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
            if hides_command(body):
                raise HiddenCommand("command substitution inside a parameter expansion")
            name = ""
            for c in body.lstrip("!#"):
                if c not in VAR_CHARS:
                    break
                name += c
            rest = body.lstrip("!#")[len(name) :]
            if rest.startswith("[") and not _SAFE_SUBSCRIPT_RE.match(rest):
                raise HiddenCommand("array subscript that may run a command")
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
        if nxt and nxt in VAR_FIRST:
            j = self.i + 1
            while j < len(self.s) and self.s[j] in VAR_CHARS:
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

    def expanded(self, b: WordBuilder, name: str, *, quoted: bool) -> bool:
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
            if esc in ANSI_SIMPLE:
                out.append(ANSI_SIMPLE[esc])
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
