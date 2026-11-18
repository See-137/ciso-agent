"""Anchored, segment-aware glob patterns for target attributes and paths.

No regular expression ever comes from a ruleset. A pattern is split on its separator
(`/` for paths, branches and repositories, `.` for hosts and servers) and matched segment
by segment:

- `*` matches any run of characters inside one segment, never the separator;
- `?` matches exactly one character inside one segment;
- `**` (a whole segment on its own) matches zero or more whole segments.

The whole value must match (anchored at both ends). `casefold=True` compares without
case: restrictive rules (deny, ask) and the danger lists match that way, because a
case-insensitive file system or server could treat `Main` as `main`.
"""

from __future__ import annotations

import re

#: Longest pattern accepted from a ruleset.
MAX_PATTERN_CHARS = 256
#: Most segments in a value or pattern; longer values are cut and never match an allow.
MAX_SEGMENTS = 64

_PATTERN_RE = re.compile(r"[A-Za-z0-9_.*?/@+=~ -]{1,256}")
_HOST_PATTERN_RE = re.compile(r"[A-Za-z0-9_*?.:-]{1,256}")

#: Which separator each target attribute uses.
SEPARATORS: dict[str, str] = {
    "repository": "/",
    "branch": "/",
    "path": "/",
    "remote": "/",
    "host": ".",
    "server": ".",
}


def check_pattern(pattern: str, separator: str) -> str:
    """Validate a ruleset pattern. Raises ValueError on anything outside the grammar."""
    allowed = _HOST_PATTERN_RE if separator == "." else _PATTERN_RE
    if len(pattern) > MAX_PATTERN_CHARS or not allowed.fullmatch(pattern):
        raise ValueError(f"bad glob pattern: {pattern!r}")
    segments = pattern.split(separator)
    if len(segments) > MAX_SEGMENTS:
        raise ValueError("glob pattern has too many segments")
    for index, segment in enumerate(segments):
        if "**" in segment and segment != "**":
            raise ValueError("`**` must be a whole glob segment")
        # A leading separator (an absolute path) is the only empty segment allowed.
        if segment == "" and (index != 0 or len(segments) == 1 or separator != "/"):
            raise ValueError("empty segment in glob pattern")
    return pattern


def _segment_match(pattern: str, value: str) -> bool:
    """`*` and `?` inside one segment, iterative with backtracking on the last star."""
    p = v = 0
    star = -1
    mark = 0
    while v < len(value):
        if p < len(pattern) and pattern[p] in ("?", value[v]) and pattern[p] != "*":
            p += 1
            v += 1
        elif p < len(pattern) and pattern[p] == "*":
            star = p
            mark = v
            p += 1
        elif star != -1:
            p = star + 1
            mark += 1
            v = mark
        else:
            return False
    while p < len(pattern) and pattern[p] == "*":
        p += 1
    return p == len(pattern)


def _match_segments(pattern: list[str], value: list[str]) -> bool:
    # Dynamic programming over segment positions: no recursion, bounded by MAX_SEGMENTS.
    rows = len(pattern) + 1
    cols = len(value) + 1
    table = [[False] * cols for _ in range(rows)]
    table[0][0] = True
    for i in range(1, rows):
        seg = pattern[i - 1]
        if seg == "**":
            table[i][0] = table[i - 1][0]
        for j in range(1, cols):
            if seg == "**":
                table[i][j] = table[i - 1][j] or table[i][j - 1]
            else:
                table[i][j] = table[i - 1][j - 1] and _segment_match(seg, value[j - 1])
    return table[-1][-1]


def glob_match(pattern: str, value: str, separator: str = "/", *, casefold: bool) -> bool:
    """True when `value` matches `pattern` in full. Never raises on odd input."""
    if casefold:
        pattern = pattern.casefold()
        value = value.casefold()
    wanted = pattern.split(separator)
    actual = value.split(separator)
    if len(wanted) > MAX_SEGMENTS or len(actual) > MAX_SEGMENTS:
        return False
    return _match_segments(wanted, actual)


def normalize_path(value: str) -> str:
    """Forward slashes, no empty or `.` segments, `..` folded where it can be.

    A leading `/` is kept (absolute path). A drive letter stays as its own segment.
    """
    text = value.replace("\\", "/")
    absolute = text.startswith("/")
    out: list[str] = []
    for segment in text.split("/"):
        if segment in ("", "."):
            continue
        if segment == ".." and out and out[-1] != "..":
            out.pop()
            continue
        out.append(segment)
    joined = "/".join(out)
    return "/" + joined if absolute else joined


def path_matches_any(patterns: tuple[str, ...], value: str) -> bool:
    """Case-insensitive match of a path-like value against danger patterns."""
    path = normalize_path(value)
    if not path:
        return False
    return any(glob_match(p, path, "/", casefold=True) for p in patterns)
