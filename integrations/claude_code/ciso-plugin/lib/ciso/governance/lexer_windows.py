"""PowerShell and cmd word reading: quotes, escapes, `$(..)`, `${..}`, `%VAR%` and
here-strings."""

from __future__ import annotations

from ciso.governance.lexer_base import ReaderBase
from ciso.governance.lexer_types import VAR_CHARS, Dialect, ParseError, Script, WordBuilder


class WindowsWords(ReaderBase):
    def windows_char(self, b: WordBuilder) -> None:
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

    def windows_double(self, b: WordBuilder) -> None:
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

    def windows_dollar(self, b: WordBuilder) -> None:
        nxt = self.peek(1)
        if nxt == "(":
            self.i += 2
            b.subs.append(self.nested(self.read_balanced("(", ")")))
            b.dynamic()
        elif nxt == "{":
            self.i += 2
            b.dynamic(self.read_balanced("{", "}"))
        elif nxt and (nxt in VAR_CHARS or nxt in "?$^"):
            j = self.i + 1
            while j < len(self.s) and (self.s[j] in VAR_CHARS or self.s[j] == ":"):
                j += 1
            b.dynamic(self.s[self.i + 1 : j])
            self.i = max(j, self.i + 2)
        else:
            b.add("$")
            self.i += 1

    def percent(self, b: WordBuilder) -> None:
        j = self.i + 1
        while j < len(self.s) and (self.s[j] in VAR_CHARS or self.s[j] in "~:,=-"):
            j += 1
        if j < len(self.s) and self.s[j] == "%" and j > self.i + 1:
            b.dynamic(self.s[self.i + 1 : j])
            self.i = j + 1
            return
        b.add("%")
        self.i += 1

    def here_string(self, b: WordBuilder) -> None:
        quote = self.peek(1)
        end = self.s.find("\n" + quote + "@", self.i + 2)
        if end < 0:
            raise ParseError("unterminated here-string")
        body = self.s[self.i + 2 : end].removeprefix("\r\n").removeprefix("\n")
        self.i = end + 3
        if quote == "'":
            b.add(body)
            return
        # `@"..."@` expands like a double-quoted string (review C2, Q5): its body is read
        # with the same rules, except that a double quote inside it is plain text.
        inner = _Body(body, self.dialect, self.depth + 1, self.budget, self)
        while inner.i < len(inner.s):
            ch = inner.s[inner.i]
            if ch == "`" and inner.peek(1):
                b.add(inner.peek(1))
                inner.i += 2
            elif ch == "$":
                inner.windows_dollar(b)
            else:
                b.add(ch)
                inner.i += 1


class _Body(WindowsWords):
    """Reads the body of an expandable here-string; nested code goes to the outer reader."""

    def __init__(
        self, text: str, dialect: Dialect, depth: int, budget: list[int], outer: ReaderBase
    ) -> None:
        super().__init__(text, dialect, depth, budget)
        self.outer = outer

    def nested(self, text: str, dialect: Dialect | None = None) -> Script:
        return self.outer.nested(text, dialect)
