"""What `decide` adds for pushes and commits (docs/skill/decision-api.md, pre-push).

- `split_change_ref`: a decide request may carry `change_id` and `change_head` next to
  the hook report; they are taken off before the report goes to the intake (whose
  envelope is closed).
- `needs_change`: the field a deny carries when the only thing missing is the change.
- `merge_inspections`: the command's, the diff's and the sandbox's results as ONE
  `InspectionResult` for the action: complete only when every part is complete.
"""

from __future__ import annotations

import re
from collections.abc import Sequence
from typing import Any, Final

from ciso.app.change_shape import ChangeKind, ChangeShape
from ciso.common.activity import (
    MAX_FINDINGS,
    InspectionFinding,
    InspectionResult,
    Severity,
)
from ciso.common.schemas import Model

CHANGE_ID_FIELD: Final = "change_id"
CHANGE_HEAD_FIELD: Final = "change_head"
#: Most entries `InspectionResult.checks_run` can hold.
MAX_CHECKS_RUN: Final = 64
_CHANGE_ID_RE: Final = re.compile(r"chg_[0-9A-HJKMNP-TV-Z]{26}")
_HEAD_RE: Final = re.compile(r"[0-9a-f]{40}|[0-9a-f]{64}")

SANDBOX_UNAVAILABLE: Final = InspectionFinding(
    check_id="sandbox.unavailable",
    category="coverage",
    severity=Severity.MEDIUM,
    detail="The sandbox could not check this change",
    remediation="Push again later; if it keeps happening, contact the security team",
)
MERGE_TRUNCATED: Final = InspectionFinding(
    check_id="inspection.merge_truncated",
    category="coverage",
    severity=Severity.MEDIUM,
    detail="Too many results to keep; the change counts as not fully inspected",
)


class ChangeRef(Model):
    change_id: str
    head: str


class NeedsChange(Model):
    """Tells the client what to build and upload: `kind` push or commit, the remote and
    destination branch the command names (None when it names none), and `source`, the
    local branch the push sends (None: HEAD)."""

    kind: ChangeKind
    remote: str | None = None
    branch: str | None = None
    source: str | None = None

    @classmethod
    def of(cls, shape: ChangeShape) -> NeedsChange:
        return cls(kind=shape.kind, remote=shape.remote, branch=shape.branch, source=shape.source)


def split_change_ref(request: Any) -> tuple[Any, ChangeRef | None]:
    """The request without the change fields, and the reference they make. Raises
    `ValueError` when only one of the two is present or either is malformed."""
    if not isinstance(request, dict):
        return request, None
    has_id, has_head = CHANGE_ID_FIELD in request, CHANGE_HEAD_FIELD in request
    if not has_id and not has_head:
        return request, None
    change_id, head = request.get(CHANGE_ID_FIELD), request.get(CHANGE_HEAD_FIELD)
    if not (isinstance(change_id, str) and _CHANGE_ID_RE.fullmatch(change_id)):
        raise ValueError("bad change_id")
    if not (isinstance(head, str) and _HEAD_RE.fullmatch(head)):
        raise ValueError("bad change_head")
    rest = {k: v for k, v in request.items() if k not in (CHANGE_ID_FIELD, CHANGE_HEAD_FIELD)}
    return rest, ChangeRef(change_id=change_id, head=head)


def sandbox_failed(action_id: str) -> InspectionResult:
    """The result used when the sandbox could not check the change: never complete."""
    return InspectionResult(
        action_id=action_id,
        checks_run=("sandbox.report",),
        findings=(SANDBOX_UNAVAILABLE,),
        complete=False,
    )


def merge_inspections(
    action_id: str, results: Sequence[InspectionResult | None]
) -> InspectionResult:
    """One result for `action_id`. A missing part (None) makes it incomplete."""
    checks: list[str] = []
    findings: list[InspectionFinding] = []
    complete = True
    for result in results:
        if result is None:
            complete = False
            continue
        complete = complete and result.complete
        checks.extend(c for c in result.checks_run if c not in checks)
        findings.extend(result.findings)
    if len(checks) > MAX_CHECKS_RUN:
        checks, complete = checks[:MAX_CHECKS_RUN], False
    if len(findings) > MAX_FINDINGS:
        order = list(Severity)
        ranked = sorted(findings, key=lambda f: -order.index(f.severity))
        findings, complete = [*ranked[: MAX_FINDINGS - 1], MERGE_TRUNCATED], False
    return InspectionResult(
        action_id=action_id, checks_run=tuple(checks), findings=tuple(findings), complete=complete
    )
