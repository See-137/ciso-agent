"""The cursor and helpers every dialect of the shell command reader shares."""

from __future__ import annotations

from ciso.governance.lexer_types import (
    MAX_DEPTH,
    POWERSHELL_EQUIVALENTS,
    Dialect,
    ParseError,
    Script,
    Word,
)


class ReaderBase:
    """Position in the text, nesting depth and the shared word budget."""

    def __init__(self, text: str, dialect: Dialect, depth: int, budget: list[int]) -> None:
        if depth > MAX_DEPTH:
            raise ParseError("nesting too deep")
        # PowerShell reads Unicode quotes, dashes and spaces as their ASCII forms; so does
        # this reading (review C3, M2). The POSIX shells treat them as letters.
        self.s = text.translate(POWERSHELL_EQUIVALENTS) if dialect is Dialect.WINDOWS else text
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
        """Read `text` one level deeper. Implemented by the full reader."""
        raise NotImplementedError

    def word(self) -> Word | None:
        """Read one word. Implemented by the full reader."""
        raise NotImplementedError

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
