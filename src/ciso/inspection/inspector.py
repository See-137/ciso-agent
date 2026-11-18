"""Deterministic content inspection of one observed action (spec C3 step 3, C5 step 4).

Pure: no network, no process, no model, no clock, no state between calls. Content is held
only for the call and never logged. A result is incomplete when anything that should
have been inspected was not: content over `MAX_CONTENT_CHARS`, a line over
`MAX_LINE_CHARS`, a malformed or empty diff, a binary change, missing content or path.
"""

from __future__ import annotations

import re
from collections.abc import Collection, Iterable, Mapping
from typing import Final

from ciso.common.activity import (
    MAX_INSPECTION_CHARS,
    ActionKind,
    InspectionInput,
    InspectionResult,
)
from ciso.common.errors import ValidationFailed
from ciso.inspection._collect import Collector, location
from ciso.inspection.code_scan import scan_code
from ciso.inspection.diff import DEV_NULL, MalformedDiff, parse_unified_diff
from ciso.inspection.paths import check_path
from ciso.inspection.rules import (
    BINARY_NOT_INSPECTED,
    CONTENT_MISSING,
    DIFF_EMPTY,
    DIFF_MALFORMED,
    LINE_TOO_LONG,
    PATH_MISSING,
    TOO_LARGE,
)
from ciso.inspection.sandbox import from_sandbox_report
from ciso.inspection.secret_scan import scan_secrets

#: Largest text (content, command or diff) inspected, in characters. The shared contract
#: refuses an `InspectionInput` whose content is longer, so through `Inspector.inspect`
#: this limit is enforced at construction; `inspect_diff` still checks it for raw text.
MAX_CONTENT_CHARS: Final = MAX_INSPECTION_CHARS
#: Longest single line inspected; longer lines make the result incomplete.
MAX_LINE_CHARS: Final = 8192

CHECK_SIZE: Final = "inspection.size"
CHECK_PATHS: Final = "inspection.paths"
CHECK_SECRETS: Final = "inspection.secrets"
CHECK_CODE: Final = "inspection.code_risk"
CHECK_DIFF: Final = "inspection.diff"

#: Shown as the location of findings in a shell command.
COMMAND_LABEL: Final = "command"

_WRITES: Final = frozenset({ActionKind.FILE_WRITE, ActionKind.FILE_EDIT})
_DIFFS: Final = frozenset({ActionKind.GIT_COMMIT, ActionKind.GIT_PUSH})
_NEEDS_CONTENT: Final = frozenset({*_WRITES, *_DIFFS, ActionKind.PROMPT})
_CHECK_ID = re.compile(r"[a-z][a-z0-9_.-]{0,47}")

type _Lines = list[tuple[int, str]]


def _bounded(lines: Iterable[tuple[int, str]], path: str, out: Collector) -> _Lines:
    """Lines short enough to inspect. Longer ones mark the result incomplete, once."""
    kept: _Lines = []
    first_long: int | None = None
    for number, text in lines:
        if len(text) > MAX_LINE_CHARS:
            first_long = number if first_long is None else first_long
            continue
        kept.append((number, text))
    if first_long is not None:
        out.incomplete(LINE_TOO_LONG, location(path, first_long))
    return kept


def _inspect_text(text: str, path: str, out: Collector, *, code: bool) -> None:
    if len(text) > MAX_CONTENT_CHARS:
        out.incomplete(TOO_LARGE, location(path))
        return
    numbered = ((n, line.removesuffix("\r")) for n, line in enumerate(text.split("\n"), 1))
    lines = _bounded(numbered, path, out)
    out.ran(CHECK_SECRETS)
    scan_secrets(lines, path, out)
    if code:
        out.ran(CHECK_CODE)
        scan_code(lines, path, out)


def _inspect_diff_into(text: str, out: Collector) -> None:
    out.ran(CHECK_DIFF)
    if len(text) > MAX_CONTENT_CHARS:
        out.incomplete(TOO_LARGE, "diff")
        return
    try:
        files = parse_unified_diff(text)
    except MalformedDiff as exc:
        out.incomplete(DIFF_MALFORMED, str(exc))
        return
    if not files:
        out.incomplete(DIFF_EMPTY)
        return
    for check in (CHECK_PATHS, CHECK_SECRETS, CHECK_CODE):
        out.ran(check)
    for item in files:
        shown = item.new_path if item.new_path != DEV_NULL else item.old_path
        for path in item.touched_paths:
            check_path(path, out)
        if item.binary:
            out.incomplete(BINARY_NOT_INSPECTED, location(shown))
        lines = _bounded(((line.number, line.text) for line in item.added), shown, out)
        scan_secrets(lines, shown, out)
        scan_code(lines, shown, out)


def inspect_diff(diff_text: str, *, action_id: str) -> InspectionResult:
    """Inspect a `git diff` / `git format-patch` text: touched paths, and added lines only."""
    out = Collector()
    out.ran(CHECK_SIZE)
    _inspect_diff_into(diff_text, out)
    return out.result(action_id)


class Inspector:
    """Runs every deterministic check that applies to an action's kind.

    - file write or edit: target path, then secrets and risky code in the content (every
      line of the new content counts as added);
    - commit or push: the content is a diff, inspected with `inspect_diff`;
    - prompt: secrets in the text;
    - shell command, or any other kind that carries text: secrets and risky code.

    `required_sandbox_checks` is the set of sandbox check ids every change must pass; it
    has no default, and while it is unset no sandbox result is ever complete.
    """

    def __init__(self, *, required_sandbox_checks: Collection[str] | None = None) -> None:
        if required_sandbox_checks is not None:
            if isinstance(required_sandbox_checks, str):
                raise ValidationFailed("required_sandbox_checks must be a collection of ids")
            for check_id in required_sandbox_checks:
                if not isinstance(check_id, str) or not _CHECK_ID.fullmatch(check_id):
                    raise ValidationFailed("required sandbox check ids must be short ids")
        self._required = (
            frozenset(required_sandbox_checks) if required_sandbox_checks is not None else None
        )

    def inspect(self, item: InspectionInput) -> InspectionResult:
        out = Collector()
        out.ran(CHECK_SIZE)
        if item.kind in _WRITES:
            out.ran(CHECK_PATHS)
            if item.path:
                check_path(item.path, out)
            else:
                out.incomplete(PATH_MISSING)
        if item.content is None:
            needs_command = item.kind is ActionKind.SHELL_COMMAND and item.command is None
            if item.kind in _NEEDS_CONTENT or needs_command:
                out.incomplete(CONTENT_MISSING)
        elif item.kind in _DIFFS:
            _inspect_diff_into(item.content, out)
        else:
            code = item.kind is not ActionKind.PROMPT
            _inspect_text(item.content, item.path, out, code=code)
        if item.command is not None:
            _inspect_text(item.command, COMMAND_LABEL, out, code=True)
        return out.result(item.action_id)

    def inspect_diff(self, diff_text: str, *, action_id: str) -> InspectionResult:
        return inspect_diff(diff_text, action_id=action_id)

    def from_sandbox_report(
        self, report: Mapping[str, object], *, action_id: str
    ) -> InspectionResult:
        return from_sandbox_report(report, action_id=action_id, required_checks=self._required)
