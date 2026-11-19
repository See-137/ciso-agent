"""Review code with the bundled inspector: a whole repository, the staged change, or a
commit range (one inspection per commit, so a secret added then removed is still found).

Whole-repository review inspects every tracked file (or, outside git, every file under
the folder except `.git`, `node_modules` and virtual environments) as if it were being
written: the path against the sensitive-path rules, the content for secrets, risky code
and scan-suppression tricks. Binary and oversized files are counted as not inspected.

Links are never followed (review L3): a symbolic link or junction anywhere on a file's
path below the root, or a file whose resolved path is outside the resolved root, is
skipped and counted; directory walks do not descend into links; files are read with a
bounded read.
"""

from __future__ import annotations

import os
import re
import stat
from dataclasses import dataclass, field
from pathlib import Path
from typing import Final

from ciso.app.change_decide import merge_inspections
from ciso.common.activity import ActionKind, InspectionFinding, InspectionInput, InspectionResult
from ciso.inspection import MAX_CONTENT_CHARS, Inspector, inspect_diff
from ciso_plugin.gitrun import SafeGit
from ciso_plugin.pushscan import split_commits

#: Most files read in one review.
MAX_REVIEW_FILES: Final = 20_000
#: Most commits read in one range review.
MAX_RANGE_COMMITS: Final = 2_000
ACTION_ID: Final = "review"
_SKIP_DIRS: Final = frozenset({".git", "node_modules", ".venv", "venv", "__pycache__"})
_RANGE: Final = re.compile(r"[A-Za-z0-9._/@^-]{1,200}\.\.[A-Za-z0-9._/@^-]{1,200}")


@dataclass
class ReviewResult:
    findings: list[InspectionFinding] = field(default_factory=list)
    inspected: int = 0
    skipped_binary: int = 0
    skipped_large: int = 0
    skipped_links: int = 0
    incomplete: bool = False
    notes: list[str] = field(default_factory=list)


def _is_link(path: Path) -> bool:
    try:
        info = os.lstat(path)
    except OSError:
        return True  # unreadable: treat as unsafe
    if stat.S_ISLNK(info.st_mode):
        return True
    return path.is_junction()


def _within(root: Path, path: Path) -> bool:
    """True when no component of `path` below `root` is a link and the resolved path
    stays inside the resolved root."""
    try:
        relative = path.relative_to(root)
        current = root
        for part in relative.parts:
            current = current / part
            if _is_link(current):
                return False
        path.resolve(strict=True).relative_to(root.resolve(strict=True))
    except (OSError, ValueError):
        return False
    return True


def _walk(root: Path) -> list[Path]:
    """Every regular file under `root`, never descending into a link."""
    out: list[Path] = []
    for folder, dirs, files in os.walk(root, followlinks=False):
        base = Path(folder)
        dirs[:] = sorted(d for d in dirs if d not in _SKIP_DIRS and not _is_link(base / d))
        out.extend(base / name for name in sorted(files))
    return out


def _tracked_files(git: SafeGit | None, root: Path) -> list[Path]:
    if git is not None:
        result = git.run("ls-files", "-z", "--cached", "--others", "--exclude-standard")
        if result.returncode == 0:
            names = result.stdout.decode("utf-8", errors="replace").split("\0")
            return [root / n for n in names if n]
    return _walk(root)


def _read_bounded(path: Path, limit: int) -> bytes:
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags)
    with os.fdopen(fd, "rb") as handle:
        return handle.read(limit)


def _add(result: ReviewResult, inspection: InspectionResult) -> None:
    result.findings.extend(inspection.findings)
    result.incomplete = result.incomplete or not inspection.complete


def review_files(root: Path, git: SafeGit | None) -> ReviewResult:
    inspector = Inspector()
    result = ReviewResult()
    files = _tracked_files(git, root)
    if len(files) > MAX_REVIEW_FILES:
        result.notes.append(f"Only the first {MAX_REVIEW_FILES} of {len(files)} files were read.")
        result.incomplete = True
        files = files[:MAX_REVIEW_FILES]
    for path in files:
        if not _within(root, path):
            result.skipped_links += 1
            continue
        if not path.is_file():
            continue
        raw = _read_bounded(path, MAX_CONTENT_CHARS * 4 + 1)
        if b"\0" in raw[:8192]:
            result.skipped_binary += 1
            continue
        text = raw.decode("utf-8", errors="replace")
        if len(text) > MAX_CONTENT_CHARS:
            result.skipped_large += 1
            continue
        rel = path.relative_to(root).as_posix()
        item = InspectionInput(
            action_id=ACTION_ID, kind=ActionKind.FILE_WRITE, path=rel, content=text
        )
        _add(result, inspector.inspect(item))
        result.inspected += 1
    return result


def review_staged(git: SafeGit) -> ReviewResult:
    result = ReviewResult()
    diff = git.out(
        "diff",
        "--cached",
        "--no-color",
        "--no-ext-diff",
        "--no-textconv",
        "--no-renames",
        code="diff",
    )
    if not diff:
        result.notes.append("Nothing is staged.")
        return result
    _add(result, inspect_diff(diff + "\n", action_id=ACTION_ID))
    result.inspected = 1
    return result


def review_range(git: SafeGit, spec: str) -> ReviewResult:
    if not _RANGE.fullmatch(spec):
        raise ValueError("range must look like <base>..<head>")
    result = ReviewResult()
    count = git.out("rev-list", "--count", spec, "--", code="rev_list")
    if not count.isdigit() or int(count) > MAX_RANGE_COMMITS:
        raise ValueError(f"the range holds more than {MAX_RANGE_COMMITS} commits")
    log = git.out(
        "log",
        "--no-color",
        "--no-ext-diff",
        "--no-textconv",
        "--no-renames",
        "--diff-merges=first-parent",
        "-p",
        "--format=format:%x01ciso-commit %H",
        spec,
        "--",
        code="log",
    )
    parts: list[InspectionResult | None] = []
    for _sha, diff in split_commits(log):
        if diff.strip():
            parts.append(inspect_diff(diff, action_id=ACTION_ID))
        result.inspected += 1
    if parts:
        _add(result, merge_inspections(ACTION_ID, parts))
    return result


def coverage_notes(result: ReviewResult) -> list[str]:
    notes = list(result.notes)
    notes.append(f"Items inspected: {result.inspected}.")
    if result.skipped_binary or result.skipped_large:
        notes.append(
            f"Not inspected: {result.skipped_binary} binary and {result.skipped_large} "
            "oversized files."
        )
    if result.skipped_links:
        notes.append(
            f"Not inspected: {result.skipped_links} paths that are links or lead outside "
            "the folder (links are never followed)."
        )
    if result.incomplete:
        notes.append("Some content could not be fully inspected (see coverage findings).")
    notes.append(
        "A line scanner cannot prove that no secret is present: encoded, split or computed "
        "values are not found. No tests were run; tests run only in the optional sandbox "
        "add-on."
    )
    return notes
