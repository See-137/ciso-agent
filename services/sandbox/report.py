"""The sandbox report, in the exact wire format the governance lane consumes.

    {"job_id": str, "head": str|null,
     "checks": [{"check_id": str, "status": "passed|failed|error|skipped",
      "findings": [{"rule": str, "category": str, "severity": "info|low|medium|high|critical",
                    "path": str, "line": int|null, "message": str}],
      "tests": {"passed": int, "failed": int, "errors": int}}]}

`head` is the commit a bundle job's HEAD was verified to be, and scanned under (review
M2); null for a tar job and whenever the bundle did not match what the job stated.

Every text field is cleaned (`safe_text`) before it enters a model, because scanner output
is untrusted and ends up in front of people and in the audit log.
"""

from __future__ import annotations

import unicodedata
from enum import StrEnum
from typing import Annotated, Any, Final

from pydantic import AfterValidator, Field

from ciso.common.activity import Severity, clean_text
from ciso.common.schemas import Model

MAX_RULE_CHARS: Final = 128
MAX_CATEGORY_CHARS: Final = 32
MAX_PATH_CHARS: Final = 512
MAX_MESSAGE_CHARS: Final = 512
#: Most findings carried by one check (the parsers cap and mark truncation below this).
MAX_FINDINGS_PER_CHECK: Final = 500


class Status(StrEnum):
    PASSED = "passed"
    FAILED = "failed"
    ERROR = "error"
    SKIPPED = "skipped"


def safe_text(value: str, limit: int) -> str:
    """Untrusted text made clean: control and format characters become `?`, outer
    whitespace is trimmed, and the result is cut to `limit` characters."""
    replaced = "".join(
        "?" if unicodedata.category(ch) in {"Cc", "Cf", "Zl", "Zp"} else ch for ch in value
    )
    return replaced.strip()[:limit].strip()


class ReportFinding(Model):
    """One finding. Text fields must already be clean text (see `finding`)."""

    rule: Annotated[str, Field(min_length=1, max_length=MAX_RULE_CHARS), AfterValidator(clean_text)]
    category: Annotated[
        str, Field(min_length=1, max_length=MAX_CATEGORY_CHARS), AfterValidator(clean_text)
    ]
    severity: Severity
    path: Annotated[str, Field(max_length=MAX_PATH_CHARS), AfterValidator(clean_text)]
    line: Annotated[int, Field(ge=1, strict=True)] | None
    message: Annotated[str, Field(max_length=MAX_MESSAGE_CHARS), AfterValidator(clean_text)]


class TestCounts(Model):
    __test__ = False  # not a pytest class

    passed: Annotated[int, Field(ge=0, strict=True)] = 0
    failed: Annotated[int, Field(ge=0, strict=True)] = 0
    errors: Annotated[int, Field(ge=0, strict=True)] = 0


class CheckReport(Model):
    check_id: Annotated[str, Field(pattern=r"^[a-z][a-z0-9_]{0,31}$")]
    status: Status
    findings: Annotated[tuple[ReportFinding, ...], Field(max_length=MAX_FINDINGS_PER_CHECK)] = ()
    tests: TestCounts = Field(default_factory=TestCounts)


class Report(Model):
    job_id: Annotated[str, Field(min_length=1, max_length=64)]
    head: Annotated[str, Field(pattern=r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")] | None = None
    checks: tuple[CheckReport, ...]

    def to_wire(self) -> dict[str, Any]:
        """The JSON-ready dict in the fixed format (enums as strings, tuples as lists)."""
        return self.model_dump(mode="json")


def validate_wire(data: Any) -> Report:
    """Parse a wire-format dict back into a `Report`; raises on any deviation."""
    return Report.model_validate(data)


def finding(
    rule: str,
    category: str,
    severity: Severity,
    message: str,
    path: str = "",
    line: int | None = None,
) -> ReportFinding:
    """A finding from possibly untrusted values; every text is cleaned and bounded."""
    return ReportFinding(
        rule=safe_text(rule, MAX_RULE_CHARS) or "unknown",
        category=safe_text(category, MAX_CATEGORY_CHARS) or "unknown",
        severity=severity,
        path=safe_text(path, MAX_PATH_CHARS),
        line=line if line is not None and line >= 1 else None,
        message=safe_text(message, MAX_MESSAGE_CHARS),
    )


def error_check(check_id: str, code: str, message: str) -> CheckReport:
    """A check that could not run. `code` becomes the rule `sandbox.<code>`."""
    return CheckReport(
        check_id=check_id,
        status=Status.ERROR,
        findings=(finding(f"sandbox.{code}", "sandbox", Severity.INFO, message),),
    )


#: Worst first: the status a merged check takes.
_STATUS_ORDER: Final = (Status.ERROR, Status.FAILED, Status.PASSED, Status.SKIPPED)


def merge_checks(first: CheckReport, second: CheckReport) -> CheckReport:
    """One check from two runs of the same check (gitleaks over history and over the
    tree): the worse status, the findings of both without repeats (capped, with a note when
    cut), and the test counts added."""
    status = min(first.status, second.status, key=_STATUS_ORDER.index)
    found: list[ReportFinding] = []
    for item in (*first.findings, *second.findings):
        if item not in found:
            found.append(item)
    if len(found) > MAX_FINDINGS_PER_CHECK:
        note = finding(
            "sandbox.findings_truncated",
            "sandbox",
            Severity.INFO,
            f"{len(found)} findings; only the first {MAX_FINDINGS_PER_CHECK - 1} are listed",
        )
        found = [*found[: MAX_FINDINGS_PER_CHECK - 1], note]
    tests = TestCounts(
        passed=first.tests.passed + second.tests.passed,
        failed=first.tests.failed + second.tests.failed,
        errors=first.tests.errors + second.tests.errors,
    )
    return CheckReport(check_id=first.check_id, status=status, findings=tuple(found), tests=tests)
