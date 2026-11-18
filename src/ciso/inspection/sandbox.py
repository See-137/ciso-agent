"""Turns the sandbox service's JSON report into inspection findings.

Report format (closed: any other field, type or value makes the report malformed):

    {"job_id": str,
     "checks": [{"check_id": str,
                 "status": "passed" | "failed" | "error" | "skipped",
                 "findings": [{"rule", "category", "severity", "path", "line", "message"}],
                 "tests": {"passed": n, "failed": n, "errors": n}}]}

`findings` and `tests` may be left out. Types are checked strictly (a number in quotes is
not a number). A malformed report, a check that errored, or a required check that is
missing or skipped makes the result incomplete. Failed or errored tests become one
`sandbox.test_failure` finding of severity high per check.

The sandbox's `message` is outside text: it is kept only if it holds nothing secret-like,
and it is passed through the vault's redactor all the same.
"""

from __future__ import annotations

import json
from collections.abc import Collection, Mapping
from typing import Annotated, Final, Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from ciso.common.activity import InspectionFinding, InspectionResult, Severity, Text
from ciso.inspection._collect import Collector, location
from ciso.inspection.rules import Rule
from ciso.inspection.secret_scan import scan_secrets
from ciso.vault import SecretRedactor

#: Largest report accepted, as serialised JSON characters.
MAX_REPORT_CHARS: Final = 1_048_576
#: Most checks in one report (the result can list at most 64 checks run, with ours).
MAX_REPORT_CHECKS: Final = 48
#: Most findings one check may report.
MAX_CHECK_FINDINGS: Final = 1000
#: Largest test count or line number accepted.
MAX_COUNT: Final = 10_000_000

_ID = r"^[a-z][a-z0-9_.-]{0,47}$"

REPORT_MALFORMED = Rule(
    "sandbox.report_malformed",
    "coverage",
    Severity.HIGH,
    "The sandbox report is malformed and was not used",
    "Run the sandbox again; if it repeats, check the sandbox service version",
)
CHECK_ERROR = Rule(
    "sandbox.check_error",
    "coverage",
    Severity.MEDIUM,
    "A sandbox check could not run",
    "Run the sandbox again; the change counts as not inspected until the check runs",
)
REQUIRED_MISSING = Rule(
    "sandbox.required_check_missing",
    "coverage",
    Severity.HIGH,
    "A required sandbox check is missing from the report or was skipped",
    "Run the sandbox with every required check enabled",
)
NOT_CONFIGURED = Rule(
    "sandbox.not_configured",
    "coverage",
    Severity.MEDIUM,
    "No required sandbox checks are configured, so the report cannot be judged complete",
    "Configure the list of sandbox checks every change must pass",
)
CHECK_FAILED = Rule(
    "sandbox.check_failed",
    "sandbox",
    Severity.HIGH,
    "A sandbox check failed without reporting details",
    "Open the sandbox job log, fix the cause and run the sandbox again",
)
TEST_FAILURE = Rule(
    "sandbox.test_failure",
    "test_failure",
    Severity.HIGH,
    "Project tests failed or errored in the sandbox",
    "Fix the failing tests before the change is pushed",
)
SANDBOX_RULES: Final[tuple[Rule, ...]] = (
    REPORT_MALFORMED,
    CHECK_ERROR,
    REQUIRED_MISSING,
    NOT_CONFIGURED,
    CHECK_FAILED,
    TEST_FAILURE,
)

_Count = Annotated[int, Field(ge=0, le=MAX_COUNT)]


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)


class _Finding(_Strict):
    rule: Annotated[str, Field(pattern=_ID)]
    category: Annotated[str, Field(pattern=r"^[a-z][a-z0-9_]{0,31}$")]
    severity: Severity
    path: Text
    line: _Count | None
    message: Text


class _Tests(_Strict):
    passed: _Count
    failed: _Count
    errors: _Count


class _Check(_Strict):
    check_id: Annotated[str, Field(pattern=_ID)]
    status: Literal["passed", "failed", "error", "skipped"]
    findings: Annotated[tuple[_Finding, ...], Field(max_length=MAX_CHECK_FINDINGS)] = ()
    tests: _Tests | None = None


class _Report(_Strict):
    job_id: Annotated[str, Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")]
    checks: Annotated[tuple[_Check, ...], Field(max_length=MAX_REPORT_CHECKS)]


def _parse(report: object) -> _Report | None:
    if not isinstance(report, Mapping):
        return None
    try:
        encoded = json.dumps(dict(report), allow_nan=False)
    except (TypeError, ValueError, RecursionError):
        return None
    if len(encoded) > MAX_REPORT_CHARS:
        return None
    try:
        parsed = _Report.model_validate_json(encoded, strict=True)
    except ValidationError:
        return None
    ids = [check.check_id for check in parsed.checks]
    return parsed if len(ids) == len(set(ids)) else None


def _safe_message(message: str, redactor: SecretRedactor) -> str:
    probe = Collector()
    scan_secrets([(1, message)], "", probe)
    if probe.result("probe").findings:
        return "message withheld: it looked like it held a secret"
    return redactor.redact(message)


def _finding(check_id: str, item: _Finding, redactor: SecretRedactor) -> InspectionFinding:
    return InspectionFinding(
        check_id=f"sandbox.{item.rule}",
        category=item.category,
        severity=item.severity,
        detail=_safe_message(item.message, redactor) or f"reported by sandbox check {check_id}",
        location=location(item.path, item.line),
    )


def _add_check(check: _Check, out: Collector, redactor: SecretRedactor) -> None:
    if check.status == "error":
        out.incomplete(CHECK_ERROR, f"sandbox check {check.check_id}")
        return
    out.ran(f"sandbox.{check.check_id}")
    for item in check.findings:
        out.add_finding(_finding(check.check_id, item, redactor))
    tests = check.tests
    if tests is not None and (tests.failed or tests.errors):
        out.add(
            TEST_FAILURE,
            f"sandbox check {check.check_id}: {tests.failed} failed, {tests.errors} errors",
        )
    elif check.status == "failed" and not check.findings:
        out.add(CHECK_FAILED, f"sandbox check {check.check_id}")


def from_sandbox_report(
    report: Mapping[str, object],
    *,
    action_id: str,
    required_checks: Collection[str] | None,
) -> InspectionResult:
    """Findings from one sandbox report. Pure: reads nothing but its arguments.

    `required_checks` is the set of check ids every change must pass. None or empty means
    it is not configured, and the result is then never complete.
    """
    out = Collector()
    out.ran("sandbox.report")
    parsed = _parse(report)
    if parsed is None:
        out.incomplete(REPORT_MALFORMED)
        return out.result(action_id)
    if not required_checks:
        out.incomplete(NOT_CONFIGURED)
    redactor = SecretRedactor()
    for check in parsed.checks:
        if check.status == "skipped":
            continue
        _add_check(check, out, redactor)
    present = {check.check_id for check in parsed.checks if check.status != "skipped"}
    for required in sorted(set(required_checks or ()) - present):
        out.incomplete(REQUIRED_MISSING, f"sandbox check {required}")
    return out.result(action_id)
