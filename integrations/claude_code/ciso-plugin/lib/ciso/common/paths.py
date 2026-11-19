"""One normaliser for every dangerous-path decision, and a "could these meet" matcher.

A path in a command or a target is text the operating system will interpret later, often
with rules the text does not show: Windows drops trailing dots and spaces, reads
`name::$DATA` as `name`, resolves 8.3 short names (`ABCDEF~1`), and a shell expands `~`,
variables and glob characters. `normalise_path` undoes what it can and marks what it
cannot know, so a sensitive path cannot be hidden behind an alias of its own name.

`may_match(pattern, path)` answers "could the file this text names be one the pattern
names". It is strict where the text is unknown: a path with unknown text (a variable, a
command substitution) may be any path at all and matches every pattern; a short-name
segment may be any one segment; glob characters in the path (`*`, `?`, `[..]`, `{..}`)
match when some name fits both the path's glob and the pattern's. Patterns use the
anchored, segment-aware syntax of the rulesets: `*` and `?` inside one segment, `**` as a
whole segment for zero or more segments, `/` as the separator, compared without case.
"""

from __future__ import annotations

import re
import unicodedata
from collections import deque
from collections.abc import Callable, Sequence
from typing import NamedTuple

#: Longest path text read; longer text is unknown (it may be anything).
MAX_PATH_CHARS = 4096
#: Most segments read; a longer path is unknown.
MAX_PATH_SEGMENTS = 128
#: The segment that stands for the user's home directory.
HOME = "~"
#: A segment glob that matches any number of whole segments.
ANY_SEGMENTS = "**"

_HOME_RE = re.compile(
    r"(~[+-]|~[a-z0-9_.-]*|\$home|\$\{home\}|%userprofile%|\$env:userprofile|\$\{env:userprofile\}"
    r"|%homedrive%%homepath%)(?=/|$)"
)
_VARIABLE_RE = re.compile(r"\$[{(a-z_]|%[a-z_][a-z0-9_]*%")
_DEVICE_PREFIXES = ("//?/", "//./", "/??/")
_DRIVE_RE = re.compile(r"([a-z]:)(.*)")
#: An 8.3 short name: up to six characters, `~`, a number, an optional short extension.
_SHORT_NAME_RE = re.compile(r"[^~]{1,6}~[0-9]{1,6}(\.[^.]{0,3})?")
_BRACES_RE = re.compile(r"\{[^{}]*\}")


class NormalisedPath(NamedTuple):
    """Case-folded segments in glob syntax. An absolute path starts with an empty segment.

    `unknown` is True when part of the text cannot be known before it runs; such a path
    may be any path and `may_match` says yes to every pattern.
    """

    segments: tuple[str, ...]
    unknown: bool = False

    @property
    def text(self) -> str:
        return "/".join(self.segments) if self.segments != ("",) else "/"

    @property
    def empty(self) -> bool:
        return not self.segments and not self.unknown


#: A place nobody can name: any number of segments.
UNKNOWN_LOCATION = NormalisedPath((ANY_SEGMENTS,))


def _segment(part: str, *, windows: bool) -> str:
    """One segment with Windows aliases undone and short names widened to `*`."""
    if part in (".", "..", "", HOME, ANY_SEGMENTS):
        return part
    if windows:
        part = part.partition(":")[0]
        part = part.rstrip(" .")
        if not part:
            return "."
        if _SHORT_NAME_RE.fullmatch(part):
            return "*"
    return _BRACES_RE.sub("*", part)


def normalise_path(text: str, *, windows: bool) -> NormalisedPath:
    """Normalise `text` as a path. `windows=True` also applies the Windows rewrites
    (backslash separator, device prefixes, drive letters, trailing dots and spaces, stream
    suffixes, 8.3 short names); callers that do not know the target system pass True.
    """
    if len(text) > MAX_PATH_CHARS:
        return NormalisedPath((), unknown=True)
    unknown = any(unicodedata.category(ch) == "Cc" for ch in text)
    value = text.casefold()
    if windows:
        value = value.replace("\\", "/")
        for prefix in _DEVICE_PREFIXES:
            if value.startswith(prefix):
                value = value[len(prefix) :]
                break
    home = _HOME_RE.match(value)
    if home is not None:
        word = home.group(1)
        lead = ANY_SEGMENTS if word in ("~+", "~-") else HOME
        value = lead + value[home.end() :]
    absolute = value.startswith("/")
    parts = value.split("/")
    if windows and parts:
        drive = _DRIVE_RE.fullmatch(parts[0])
        if drive is not None:
            parts = [drive.group(1), *([drive.group(2)] if drive.group(2) else []), *parts[1:]]
    if len(parts) > MAX_PATH_SEGMENTS:
        return NormalisedPath((), unknown=True)
    out: list[str] = []
    for index, raw in enumerate(parts):
        keep_drive = windows and index == 0 and _DRIVE_RE.fullmatch(raw) is not None
        segment = raw if keep_drive else _segment(raw, windows=windows)
        if _VARIABLE_RE.search(raw.partition(":")[0] if windows else raw):
            unknown = True
        if segment in ("", "."):
            continue
        if segment == ".." and out and out[-1] not in ("..", ANY_SEGMENTS):
            out.pop()
            continue
        out.append(segment)
    segments = ("", *out) if absolute else tuple(out)
    return NormalisedPath(segments, unknown)


def join_paths(base: NormalisedPath, path: NormalisedPath) -> NormalisedPath:
    """`path` read from directory `base`. An absolute, drive or home path ignores `base`."""
    first = path.segments[0] if path.segments else None
    if first is not None and (first in ("", HOME, ANY_SEGMENTS) or _DRIVE_RE.fullmatch(first)):
        return path
    out = list(base.segments)
    for segment in path.segments:
        if segment == ".." and out and out[-1] not in ("..", ANY_SEGMENTS, ""):
            out.pop()
        else:
            out.append(segment)
    return NormalisedPath(tuple(out), base.unknown or path.unknown)


# --- matching ----------------------------------------------------------------------------

#: A character token: ("*",), ("?",), ("set", body) or ("lit", char).
_Token = tuple[str, ...]
_STAR: _Token = ("*",)
_ANY: _Token = ("?",)


def _tokens(segment: str) -> list[_Token]:
    """A segment glob as tokens: `*`, `?`, a `[..]` set, or a literal character."""
    out: list[_Token] = []
    i = 0
    while i < len(segment):
        ch = segment[i]
        end = segment.find("]", i + 2) if ch == "[" else -1
        if ch == "*":
            out.append(_STAR)
        elif ch == "?":
            out.append(_ANY)
        elif end > 0:
            out.append(("set", segment[i + 1 : end]))
            i = end
        else:
            out.append(("lit", ch))
        i += 1
    return out


def _set_has(body: str, ch: str) -> bool:
    negated = body[:1] in ("!", "^")
    chars = body[1:] if negated else body
    hit = False
    j = 0
    while j < len(chars):
        if j + 2 < len(chars) and chars[j + 1] == "-":
            hit = hit or chars[j] <= ch <= chars[j + 2]
            j += 3
        else:
            hit = hit or chars[j] == ch
            j += 1
    return hit != negated


def _chars_meet(a: _Token, b: _Token) -> bool:
    """Some single character fits both tokens (neither is `*`)."""
    if _ANY in (a, b):
        return True
    if a[0] == "lit" and b[0] == "lit":
        return a[1] == b[1]
    if a[0] == "lit":
        return _set_has(b[1], a[1])
    if b[0] == "lit":
        return _set_has(a[1], b[1])
    return True  # two sets: assume they share a character (the strict answer)


def _meet[T](left: Sequence[T], right: Sequence[T], star: T, step: Callable[[T, T], bool]) -> bool:
    """Whether two star patterns share a match.

    `star` is the token that matches any run (of characters, or of segments); `step(a, b)`
    says whether two other tokens can match the same unit. A breadth-first walk over
    position pairs, so at most `len(left) * len(right)` states and no recursion.
    """
    seen: set[tuple[int, int]] = set()
    queue: deque[tuple[int, int]] = deque([(0, 0)])
    while queue:
        i, j = queue.popleft()
        if (i, j) in seen:
            continue
        seen.add((i, j))
        if i == len(left) and j == len(right):
            return True
        a_star = i < len(left) and left[i] == star
        b_star = j < len(right) and right[j] == star
        if a_star:
            queue.append((i + 1, j))
            if j < len(right):
                queue.append((i, j + 1))
        if b_star:
            queue.append((i, j + 1))
            if i < len(left):
                queue.append((i + 1, j))
        both = i < len(left) and j < len(right)
        if both and not a_star and not b_star and step(left[i], right[j]):
            queue.append((i + 1, j + 1))
    return False


def _segments_meet(pattern: str, segment: str) -> bool:
    """A pattern segment and a path segment could name the same file.

    When the path segment holds a `*`, the pattern's own `*` are read as empty: the path's
    glob must be able to spell the sensitive name, not merely share an end with it (so
    `*.py` does not meet `id_rsa*`, while `id_*` does).
    """
    if "" in (pattern, segment):
        return pattern == segment  # the root of an absolute path meets only the root
    path_tokens = _tokens(segment)
    wanted = _tokens(pattern)
    if _STAR in path_tokens:
        wanted = [t for t in wanted if t != _STAR]
    return _meet(wanted, path_tokens, _STAR, _chars_meet)


def may_match(pattern: str, path: NormalisedPath) -> bool:
    """True when the file `path` names could be one `pattern` names (see module doc)."""
    if path.unknown:
        return True
    if not path.segments:
        return False
    wanted = pattern.casefold().split("/")
    actual = list(path.segments)
    if len(wanted) > MAX_PATH_SEGMENTS or len(actual) > MAX_PATH_SEGMENTS:
        return True
    return _meet(wanted, actual, ANY_SEGMENTS, _segments_meet)
