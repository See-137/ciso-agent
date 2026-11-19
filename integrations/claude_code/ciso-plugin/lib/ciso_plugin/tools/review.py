"""Review code with the bundled inspector: a whole repository, the staged change, or a
commit range (one inspection per commit, so a secret added then removed is still found).

Whole-repository review inspects every tracked file (or, outside git, every file under
the folder except `.git`, `node_modules` and virtual environments) as if it were being
written: the path against the sensitive-path rules, the content for secrets, risky code
and scan-suppression tricks. Binary and oversized files are counted as not inspected.
"""

from __future__ import annotations

import re
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
    incomplete: bool = False
    notes: list[str] = field(default_factory=list)


def _tracked_files(git: SafeGit | None, root: Path) -> list[Path]:
    if git is not None:
        result = git.run("ls-files", "-z", "--cached", "--others", "--exclude-standard")
        if result.returncode == 0:
            names = result.stdout.decode("utf-8", errors="replace").split("\0")
            return [root / n for n in names if n]
    out = []
    for path in root.rglob("*"):
        if any(part in _SKIP_DIRS for part in path.relative_to(root).parts):
            continue
        if path.is_file():
            out.append(path)
    return out


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
        if not path.is_file():
            continue
        raw = path.read_bytes()[: MAX_CONTENT_CHARS * 4 + 1]
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
    if result.incomplete:
        notes.append("Some content could not be fully inspected (see coverage findings).")
    notes.append(
        "A line scanner cannot prove that no secret is present: encoded, split or computed "
        "values are not found. No tests were run; tests run only in the optional sandbox "
        "add-on."
    )
    return notes
