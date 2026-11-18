"""Turning each tool's native output into a `CheckReport`. Anything unexpected is `error`.

Formats (read 2026-11-18; fixtures in tests/services/sandbox/fixtures, see SOURCES.md):
- gitleaks: JSON array of `report.Finding` (Go field names: RuleID, Description, File,
  StartLine, Secret, Match, ...). We run it with `--exit-code 0`, so exit 0 is a finished
  scan and any other exit is a scan error. `Secret`, `Match` and `Message` are never read.
- semgrep `--json`: `{"results": [cli_match], "errors": [cli_error], ...}`, cli_match has
  `check_id`, `path`, `start.line`, `extra.message`, `extra.severity`. Exit 0 or 1 is a
  finished scan; 2 and above are errors. `extra.lines` (source text) is never read.
- pytest `--junitxml`: `testsuite` elements with tests/failures/errors/skipped. Exit 0 all
  passed, 1 some failed, 5 no tests collected; others are errors.
- `go test -json`: one test2json event per line; a build failure is a `fail` with
  `FailedBuild`.
- `npm test`: no structured output; the exit code decides and counts are unavailable.
"""

from __future__ import annotations

import json
import re
import xml.etree.ElementTree as ET
from collections.abc import Callable
from typing import Any, Final

from services.sandbox.backend import RunOutcome
from services.sandbox.report import (
    MAX_FINDINGS_PER_CHECK,
    CheckReport,
    ReportFinding,
    Status,
    TestCounts,
    error_check,
    finding,
)

from ciso.common.activity import Severity

#: Findings kept per check; the last slot is used to say the list was cut.
MAX_REPORT_FINDINGS: Final = MAX_FINDINGS_PER_CHECK

_WORK_PREFIXES = ("/work/src/", "./")
_SEMGREP_SEVERITY: Final = {
    "CRITICAL": Severity.CRITICAL,
    "ERROR": Severity.HIGH,
    "HIGH": Severity.HIGH,
    "WARNING": Severity.MEDIUM,
    "MEDIUM": Severity.MEDIUM,
    "LOW": Severity.LOW,
    "INFO": Severity.INFO,
    "INVENTORY": Severity.INFO,
    "EXPERIMENTAL": Severity.INFO,
}
_XML_DECLS = re.compile(r"<!\s*(DOCTYPE|ENTITY)", re.IGNORECASE)


class Unparseable(ValueError):
    """The tool's output did not have the documented shape."""


def _runtime_error(check_id: str, result: RunOutcome) -> CheckReport | None:
    """An error report when the container did not finish normally, else None."""
    if result.timed_out:
        return error_check(check_id, "wall_time_exceeded", "the run exceeded its wall time")
    if result.output_exceeded:
        return error_check(check_id, "output_limit_exceeded", "the run exceeded its output cap")
    if result.exit_code in (None, 125, 126, 127):
        return error_check(check_id, "runtime_failed", "the container could not be run")
    if result.exit_code == 137:
        return error_check(check_id, "killed", "the container was killed (memory or signal)")
    return None


def _guarded(
    check_id: str, result: RunOutcome, parse: Callable[[RunOutcome], CheckReport]
) -> CheckReport:
    early = _runtime_error(check_id, result)
    if early is not None:
        return early
    try:
        return parse(result)
    except (Unparseable, ValueError, TypeError, KeyError, ET.ParseError):
        return error_check(check_id, "unparseable_output", "tool output was not understood")


def _field(obj: Any, key: str, kind: type) -> Any:
    if not isinstance(obj, dict) or key not in obj or not isinstance(obj[key], kind):
        raise Unparseable(key)
    value = obj[key]
    if kind is int and isinstance(value, bool):
        raise Unparseable(key)
    return value


def _rel(path: str) -> str:
    for prefix in _WORK_PREFIXES:
        if path.startswith(prefix):
            return path[len(prefix) :]
    return path


def _capped(findings: list[ReportFinding]) -> tuple[ReportFinding, ...]:
    if len(findings) <= MAX_REPORT_FINDINGS:
        return tuple(findings)
    note = finding(
        "sandbox.findings_truncated",
        "sandbox",
        Severity.INFO,
        f"{len(findings)} findings; only the first {MAX_REPORT_FINDINGS - 1} are listed",
    )
    return (*findings[: MAX_REPORT_FINDINGS - 1], note)


def _scan_status(findings: list[ReportFinding]) -> Status:
    serious = any(f.severity is not Severity.INFO for f in findings)
    return Status.FAILED if serious else Status.PASSED


def _json(stdout: bytes) -> Any:
    if not stdout.strip():
        raise Unparseable("empty output")
    return json.loads(stdout.decode("utf-8"))


def parse_gitleaks(result: RunOutcome, check_id: str = "secrets") -> CheckReport:
    def parse(res: RunOutcome) -> CheckReport:
        if res.exit_code != 0:
            return error_check(check_id, "tool_failed", "the secret scanner reported an error")
        data = _json(res.stdout)
        if not isinstance(data, list):
            raise Unparseable("not a list")
        found = [
            finding(
                rule=_field(item, "RuleID", str),
                category="secret",
                severity=Severity.HIGH,
                message=_field(item, "Description", str),
                path=_rel(_field(item, "File", str)),
                line=_field(item, "StartLine", int),
            )
            for item in data
        ]
        return CheckReport(check_id=check_id, status=_scan_status(found), findings=_capped(found))

    return _guarded(check_id, result, parse)


def _semgrep_finding(item: Any) -> ReportFinding:
    extra = _field(item, "extra", dict)
    severity = _SEMGREP_SEVERITY.get(_field(extra, "severity", str))
    if severity is None:
        raise Unparseable("severity")
    return finding(
        rule=_field(item, "check_id", str),
        category="code",
        severity=severity,
        message=_field(extra, "message", str),
        path=_rel(_field(item, "path", str)),
        line=_field(_field(item, "start", dict), "line", int),
    )


def parse_semgrep(result: RunOutcome, check_id: str = "code") -> CheckReport:
    def parse(res: RunOutcome) -> CheckReport:
        if res.exit_code not in (0, 1):
            return error_check(check_id, "tool_failed", "the code scanner reported an error")
        data = _json(res.stdout)
        results = _field(data, "results", list)
        errors = _field(data, "errors", list)
        if any(isinstance(e, dict) and e.get("level") == "error" for e in errors):
            return error_check(check_id, "scanner_error", "the code scanner could not finish")
        found = [_semgrep_finding(item) for item in results]
        status = _scan_status(found)
        if errors:
            found.append(
                finding(
                    "sandbox.scanner_warnings",
                    "sandbox",
                    Severity.INFO,
                    f"the code scanner reported {len(errors)} non-fatal problems",
                )
            )
        return CheckReport(check_id=check_id, status=status, findings=_capped(found))

    return _guarded(check_id, result, parse)


def _tested(check_id: str, exit_code: int | None, counts: TestCounts) -> CheckReport:
    """Passed/failed from counts, which must agree with the exit code (0 = none failed)."""
    bad = counts.failed + counts.errors
    if (exit_code == 0) != (bad == 0):
        return error_check(check_id, "inconsistent_result", "exit code and test counts differ")
    if bad == 0 and counts.passed == 0:
        return CheckReport(
            check_id=check_id,
            status=Status.SKIPPED,
            findings=(finding("sandbox.no_tests", "test", Severity.INFO, "no tests ran"),),
            tests=counts,
        )
    findings: tuple[ReportFinding, ...] = ()
    if bad:
        message = f"{counts.failed} tests failed, {counts.errors} errors"
        findings = (finding("tests.failed", "test", Severity.MEDIUM, message),)
    status = Status.FAILED if bad else Status.PASSED
    return CheckReport(check_id=check_id, status=status, findings=findings, tests=counts)


def _junit_counts(stdout: bytes) -> TestCounts:
    text = stdout.decode("utf-8")  # strict: another encoding could hide a declaration
    if _XML_DECLS.search(text):
        raise Unparseable("DOCTYPE or ENTITY in test report")
    root = ET.fromstring(text)  # noqa: S314 - declarations refused above, size capped
    suites = [root] if root.tag == "testsuite" else list(root.iter("testsuite"))
    if root.tag not in ("testsuite", "testsuites"):
        raise Unparseable("not a junit report")
    total = failed = errors = skipped = 0
    for suite in suites:
        values = [int(suite.attrib[k]) for k in ("tests", "failures", "errors", "skipped")]
        if min(values) < 0:
            raise Unparseable("negative count")
        total, failed, errors, skipped = (
            a + b for a, b in zip((total, failed, errors, skipped), values, strict=True)
        )
    passed = total - failed - errors - skipped
    if passed < 0:
        raise Unparseable("counts do not add up")
    return TestCounts(passed=passed, failed=failed, errors=errors)


def parse_pytest(result: RunOutcome, check_id: str = "tests") -> CheckReport:
    def parse(res: RunOutcome) -> CheckReport:
        if res.exit_code == 5:
            return CheckReport(
                check_id=check_id,
                status=Status.SKIPPED,
                findings=(finding("sandbox.no_tests", "test", Severity.INFO, "no tests found"),),
            )
        if res.exit_code not in (0, 1):
            return error_check(check_id, "tool_failed", "the test run was interrupted")
        return _tested(check_id, res.exit_code, _junit_counts(res.stdout))

    return _guarded(check_id, result, parse)


def _go_counts(stdout: bytes) -> TestCounts:
    passed = failed = errors = 0
    failing_packages: set[str] = set()
    package_fails: list[str] = []
    for line in stdout.decode("utf-8").splitlines():
        if not line.strip():
            continue
        event = json.loads(line)
        action = _field(event, "Action", str)
        package = event.get("Package", "") if isinstance(event, dict) else ""
        test = event.get("Test")
        if test:
            if action == "pass":
                passed += 1
            elif action == "fail":
                failed += 1
                failing_packages.add(package)
        elif action == "fail":
            if event.get("FailedBuild"):
                errors += 1
            else:
                package_fails.append(package)
    errors += sum(1 for p in package_fails if p not in failing_packages)
    return TestCounts(passed=passed, failed=failed, errors=errors)


def parse_go_test(result: RunOutcome, check_id: str = "tests") -> CheckReport:
    def parse(res: RunOutcome) -> CheckReport:
        if res.exit_code not in (0, 1):
            return error_check(check_id, "tool_failed", "the test run was interrupted")
        return _tested(check_id, res.exit_code, _go_counts(res.stdout))

    return _guarded(check_id, result, parse)


def parse_npm_test(result: RunOutcome, check_id: str = "tests") -> CheckReport:
    def parse(res: RunOutcome) -> CheckReport:
        note = finding(
            "sandbox.test_counts_unavailable",
            "sandbox",
            Severity.INFO,
            "npm test has no structured output; the exit code decided",
        )
        status = Status.PASSED if res.exit_code == 0 else Status.FAILED
        return CheckReport(check_id=check_id, status=status, findings=(note,))

    return _guarded(check_id, result, parse)
