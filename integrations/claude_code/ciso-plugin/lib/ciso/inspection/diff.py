"""Unified diff parser for `git diff` and `git format-patch` output.

Returns, per file: old and new path, the change type, a binary marker, and the added and
removed lines with their line numbers. Anything the parser does not understand inside a
file's headers or hunks raises `MalformedDiff`, so a diff crafted to hide lines from the
inspector is reported as not inspected instead of passing. Messages never quote content.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Final

from ciso.common.errors import ValidationFailed

#: Most files one diff may change before it is refused as too large to inspect.
MAX_DIFF_FILES: Final = 2000

DEV_NULL: Final = "/dev/null"

_DIFF_GIT = re.compile(r"diff --git (?P<rest>.+)")
_HUNK = re.compile(
    r"@@ -(?P<os>\d{1,9})(?:,(?P<oc>\d{1,9}))? \+(?P<ns>\d{1,9})(?:,(?P<nc>\d{1,9}))? @@.*"
)
_FORMAT_PATCH_START = re.compile(r"From [0-9a-f]{7,64} .*")
_EXTENDED = re.compile(
    r"(?:old mode|new mode|deleted file mode|new file mode) [0-7]{6}"
    r"|(?:similarity|dissimilarity) index \d{1,3}%"
    r"|index [0-9a-f]{4,64}\.\.[0-9a-f]{4,64}(?: [0-7]{6})?"
    r"|(?:rename|copy) (?:from|to) .+"
)
_BINARY = re.compile(r"Binary files (?P<old>.+) and (?P<new>.+) differ")
_ESCAPES: Final = {"t": "\t", "n": "\n", '"': '"', "\\": "\\", "r": "\r"}


class MalformedDiff(ValidationFailed):
    """The text is not a diff this parser can read completely."""


class ChangeType(StrEnum):
    ADDED = "added"
    DELETED = "deleted"
    MODIFIED = "modified"
    RENAMED = "renamed"
    COPIED = "copied"


@dataclass(frozen=True, slots=True)
class DiffLine:
    number: int
    text: str = field(repr=False)


@dataclass(frozen=True, slots=True)
class FileDiff:
    old_path: str
    new_path: str
    change: ChangeType
    binary: bool = False
    added: tuple[DiffLine, ...] = ()
    removed: tuple[DiffLine, ...] = ()

    @property
    def touched_paths(self) -> tuple[str, ...]:
        """Every real path the change writes, deletes or renames (no `/dev/null`)."""
        paths = (self.new_path, self.old_path)
        return tuple(dict.fromkeys(p for p in paths if p and p != DEV_NULL))


@dataclass(slots=True)
class _Building:
    old_path: str = ""
    new_path: str = ""
    change: ChangeType = ChangeType.MODIFIED
    binary: bool = False
    added: list[DiffLine] = field(default_factory=list)
    removed: list[DiffLine] = field(default_factory=list)

    def freeze(self) -> FileDiff:
        old, new = self.old_path, self.new_path
        if self.change is ChangeType.MODIFIED:
            if old == DEV_NULL:
                self.change = ChangeType.ADDED
            elif new == DEV_NULL:
                self.change = ChangeType.DELETED
        if not (old or new):
            raise MalformedDiff("a file in the diff has no path")
        return FileDiff(
            old_path=old or new,
            new_path=new or old,
            change=self.change,
            binary=self.binary,
            added=tuple(self.added),
            removed=tuple(self.removed),
        )


def _unquote(raw: str) -> str:
    """A git path: C-quoted when it holds unusual characters, prefixed `a/` or `b/`."""
    text = raw.split("\t", 1)[0] if not raw.startswith('"') else raw
    if text.startswith('"'):
        if not text.endswith('"') or len(text) < 2:
            raise MalformedDiff("unterminated quoted path")
        body, out, i = text[1:-1], [], 0
        while i < len(body):
            ch = body[i]
            if ch == "\\" and i + 1 < len(body):
                nxt = body[i + 1]
                if nxt in _ESCAPES:
                    out.append(_ESCAPES[nxt])
                    i += 2
                    continue
                octal = body[i + 1 : i + 4]
                if len(octal) == 3 and all(c in "01234567" for c in octal):
                    out.append(chr(int(octal, 8)))
                    i += 4
                    continue
                raise MalformedDiff("bad escape in quoted path")
            out.append(ch)
            i += 1
        text = "".join(out)
    if text == DEV_NULL:
        return text
    return text[2:] if text[:2] in {"a/", "b/"} else text


def _split_git_header(rest: str) -> tuple[str, str]:
    """Old and new path from `diff --git a/X b/Y` (ambiguous with spaces; best effort)."""
    if rest.startswith('"'):
        end = rest.find('" ', 1)
        if end == -1:
            raise MalformedDiff("bad diff --git header")
        return _unquote(rest[: end + 1]), _unquote(rest[end + 2 :])
    half = (len(rest) - 1) // 2
    if len(rest) % 2 == 1 and rest[half] == " " and rest[2:half] == rest[half + 3 :]:
        return _unquote(rest[:half]), _unquote(rest[half + 1 :])
    marker = rest.find(" b/")
    if marker == -1:
        raise MalformedDiff("bad diff --git header")
    return _unquote(rest[:marker]), _unquote(rest[marker + 1 :])


class _Parser:
    def __init__(self, lines: list[str]) -> None:
        self.lines = lines
        self.i = 0
        self.files: list[FileDiff] = []
        self.in_preamble = True

    def run(self) -> tuple[FileDiff, ...]:
        while self.i < len(self.lines):
            line = self.lines[self.i]
            git = _DIFF_GIT.fullmatch(line)
            if git:
                self._file(_Building(*_split_git_header(git.group("rest"))), git=True)
            elif line.startswith("--- ") and self._peek(1).startswith("+++ "):
                self._file(_Building(), git=False)
            else:
                self._outside_file(line)
            if len(self.files) > MAX_DIFF_FILES:
                raise MalformedDiff("too many files in the diff")
        return tuple(self.files)

    def _outside_file(self, line: str) -> None:
        """Text between files. Free text is allowed only in a format-patch preamble (mail
        header, commit message, diffstat) or after a signature; elsewhere a stray line
        could be an added line hidden outside its hunk, so it is refused."""
        if _FORMAT_PATCH_START.fullmatch(line) or line in {"-- ", "--"}:
            self.in_preamble = True
        elif not self.in_preamble and line.strip():
            raise MalformedDiff(f"unexpected line outside a hunk at diff line {self.i + 1}")
        self.i += 1

    def _peek(self, ahead: int) -> str:
        index = self.i + ahead
        return self.lines[index] if index < len(self.lines) else ""

    def _file(self, item: _Building, *, git: bool) -> None:
        if git:
            self.i += 1
            self._extended_headers(item)
        line = self.lines[self.i] if self.i < len(self.lines) else ""
        if line.startswith("--- "):
            if not self._peek(1).startswith("+++ "):
                raise MalformedDiff(f"missing new-file header at diff line {self.i + 2}")
            item.old_path = _unquote(line[4:])
            item.new_path = _unquote(self._peek(1)[4:])
            self.i += 2
            self._hunks(item)
        elif not git:
            raise MalformedDiff(f"expected a file header at diff line {self.i + 1}")
        self.files.append(item.freeze())
        self.in_preamble = False

    def _extended_headers(self, item: _Building) -> None:
        while self.i < len(self.lines):
            line = self.lines[self.i]
            if line.startswith("--- ") or _DIFF_GIT.fullmatch(line):
                return
            binary = _BINARY.fullmatch(line)
            if binary or line == "GIT binary patch":
                item.binary = True
                self._skip_binary_body()
                return
            if not _EXTENDED.fullmatch(line):
                if line == "" or line.startswith("-- ") or line == "--":
                    return
                raise MalformedDiff(f"unknown file header at diff line {self.i + 1}")
            self._apply_header(item, line)
            self.i += 1

    def _apply_header(self, item: _Building, line: str) -> None:
        if line.startswith("new file mode"):
            item.change, item.old_path = ChangeType.ADDED, DEV_NULL
        elif line.startswith("deleted file mode"):
            item.change, item.new_path = ChangeType.DELETED, DEV_NULL
        elif line.startswith(("rename from ", "copy from ")):
            item.old_path = _unquote(line.split(" from ", 1)[1])
        elif line.startswith(("rename to ", "copy to ")):
            item.new_path = _unquote(line.split(" to ", 1)[1])
            item.change = ChangeType.RENAMED if line[0] == "r" else ChangeType.COPIED

    def _skip_binary_body(self) -> None:
        self.i += 1
        while self.i < len(self.lines) and not _DIFF_GIT.fullmatch(self.lines[self.i]):
            if self.lines[self.i].startswith("-- ") or self.lines[self.i] == "--":
                return
            self.i += 1

    def _hunks(self, item: _Building) -> None:
        if not _HUNK.fullmatch(self._peek(0)):
            if item.change in {ChangeType.RENAMED, ChangeType.COPIED} or self._peek(0) == "":
                return
            raise MalformedDiff(f"expected a hunk at diff line {self.i + 1}")
        while self.i < len(self.lines):
            hunk = _HUNK.fullmatch(self.lines[self.i])
            if hunk is None:
                return
            self.i += 1
            self._hunk_body(item, hunk)

    def _hunk_body(self, item: _Building, hunk: re.Match[str]) -> None:
        old_no, new_no = int(hunk.group("os")), int(hunk.group("ns"))
        old_left = int(hunk.group("oc")) if hunk.group("oc") is not None else 1
        new_left = int(hunk.group("nc")) if hunk.group("nc") is not None else 1
        while old_left > 0 or new_left > 0:
            if self.i >= len(self.lines):
                raise MalformedDiff("diff ends inside a hunk")
            line = self.lines[self.i]
            self.i += 1
            tag, text = line[:1], line[1:]
            if tag == "\\":
                continue
            if tag == "+" and new_left > 0:
                item.added.append(DiffLine(new_no, text))
                new_no, new_left = new_no + 1, new_left - 1
            elif tag == "-" and old_left > 0:
                item.removed.append(DiffLine(old_no, text))
                old_no, old_left = old_no + 1, old_left - 1
            elif tag in {" ", ""} and old_left > 0 and new_left > 0:
                old_no, new_no = old_no + 1, new_no + 1
                old_left, new_left = old_left - 1, new_left - 1
            else:
                raise MalformedDiff(f"hunk line does not match its header at diff line {self.i}")
        while self._peek(0).startswith("\\"):
            self.i += 1


def parse_unified_diff(text: str) -> tuple[FileDiff, ...]:
    """Parse `git diff` or `git format-patch` text. Raises `MalformedDiff`.

    Text before the first file (a format-patch mail header, the commit message, the
    diffstat) and the signature after the last hunk are skipped. Returns no files for text
    that holds no file change; the caller decides what that means.
    """
    lines = text.split("\n")
    if lines and lines[-1] == "":
        lines.pop()
    return _Parser([line.removesuffix("\r") for line in lines]).run()
