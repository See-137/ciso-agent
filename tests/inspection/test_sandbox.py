"""Sandbox report adapter: strict schema, required checks, test failures, messages."""

from __future__ import annotations

import copy
from typing import Any

import pytest
from tests.inspection.samples import SERVICE_TOKEN, ids

from ciso.common.activity import Severity
from ciso.inspection import Inspector, from_sandbox_report
from ciso.inspection.sandbox import MAX_REPORT_CHECKS

pytestmark = pytest.mark.unit

REQUIRED = ("secret_scan", "tests")


def report(**overrides: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "job_id": "job-42",
        "checks": [
            {"check_id": "secret_scan", "status": "passed", "findings": []},
            {
                "check_id": "tests",
                "status": "passed",
                "tests": {"passed": 10, "failed": 0, "errors": 0},
            },
        ],
    }
    base.update(overrides)
    return base


def run(data: Any, required: Any = REQUIRED) -> Any:
    return from_sandbox_report(data, action_id="act_s", required_checks=required)


def test_clean_report_is_complete() -> None:
    result = run(report())
    assert result.complete is True
    assert result.findings == ()
    assert result.checks_run == ("sandbox.report", "sandbox.secret_scan", "sandbox.tests")
    assert result.action_id == "act_s"


def test_findings_are_mapped() -> None:
    data = report()
    data["checks"][0] = {
        "check_id": "secret_scan",
        "status": "failed",
        "findings": [
            {
                "rule": "generic-api-key",
                "category": "secret",
                "severity": "high",
                "path": "src/app.py",
                "line": 7,
                "message": "Possible credential in source",
            }
        ],
    }
    (finding,) = run(data).findings
    assert finding.check_id == "sandbox.generic-api-key"
    assert (finding.category, finding.severity) == ("secret", Severity.HIGH)
    assert finding.location == "src/app.py:7"
    assert finding.detail == "Possible credential in source"


def test_failed_tests_become_a_high_test_failure() -> None:
    data = report()
    data["checks"][1]["status"] = "failed"
    data["checks"][1]["tests"] = {"passed": 8, "failed": 2, "errors": 1}
    result = run(data)
    assert ids(result) == ["sandbox.test_failure"]
    finding = result.findings[0]
    assert (finding.category, finding.severity) == ("test_failure", Severity.HIGH)
    assert finding.location == "sandbox check tests: 2 failed, 1 errors"
    assert result.complete is True


def test_failed_check_without_details_is_reported() -> None:
    data = report()
    data["checks"][0]["status"] = "failed"
    assert ids(run(data)) == ["sandbox.check_failed"]


def test_errored_check_is_incomplete_and_not_listed_as_run() -> None:
    data = report()
    data["checks"][0]["status"] = "error"
    result = run(data)
    assert result.complete is False
    assert "sandbox.check_error" in ids(result)
    assert "sandbox.secret_scan" not in result.checks_run


def test_missing_or_skipped_required_check_is_incomplete() -> None:
    data = report()
    del data["checks"][1]
    missing = run(data)
    assert (missing.complete, ids(missing)) == (False, ["sandbox.required_check_missing"])
    assert missing.findings[0].location == "sandbox check tests"
    skipped = report()
    skipped["checks"][1]["status"] = "skipped"
    result = run(skipped)
    assert result.complete is False
    assert "sandbox.tests" not in result.checks_run


def test_skipped_optional_check_is_fine() -> None:
    data = report()
    data["checks"].append({"check_id": "lint", "status": "skipped"})
    result = run(data)
    assert result.complete is True
    assert "sandbox.lint" not in result.checks_run


@pytest.mark.parametrize("required", [None, ()])
def test_unconfigured_required_checks_never_complete(required: Any) -> None:
    result = run(report(), required)
    assert (result.complete, ids(result)) == (False, ["sandbox.not_configured"])


def test_inspector_passes_its_required_checks() -> None:
    assert (
        Inspector(required_sandbox_checks=REQUIRED)
        .from_sandbox_report(report(), action_id="act_s")
        .complete
    )
    assert not Inspector().from_sandbox_report(report(), action_id="act_s").complete


def _mutate(path: tuple[Any, ...], value: Any) -> dict[str, Any]:
    data = copy.deepcopy(report())
    target: Any = data
    for key in path[:-1]:
        target = target[key]
    target[path[-1]] = value
    return data


_FINDING = {
    "rule": "r1",
    "category": "secret",
    "severity": "high",
    "path": "a.py",
    "line": 1,
    "message": "m",
}


@pytest.mark.parametrize(
    "data",
    [
        report(extra=1),
        _mutate(("checks", 0, "unknown"), 1),
        _mutate(("checks", 0, "status"), "maybe"),
        _mutate(("checks", 1, "tests", "failed"), "2"),
        _mutate(("checks", 1, "tests", "failed"), True),
        _mutate(("checks", 1, "tests", "failed"), -1),
        _mutate(("checks", 1, "tests", "failed"), 1.5),
        _mutate(("checks", 0, "findings"), [{**_FINDING, "line": "1"}]),
        _mutate(("checks", 0, "findings"), [{**_FINDING, "severity": "urgent"}]),
        _mutate(("checks", 0, "findings"), [{**_FINDING, "message": "two\nlines"}]),
        _mutate(("checks", 0, "findings"), [{**_FINDING, "rule": "Bad Rule"}]),
        _mutate(("checks", 0, "findings"), [{**_FINDING, "more": 1}]),
        _mutate(("checks", 0, "check_id"), "tests"),  # duplicate id
        _mutate(("checks", 0, "status"), {1, 2}),  # not JSON
        report(job_id=7),
        {"checks": []},
        report(checks=[{"check_id": f"c{i}", "status": "passed"} for i in range(49)]),
        "not a mapping",
        None,
    ],
)
def test_malformed_report_is_incomplete(data: Any) -> None:
    result = run(data)
    assert (result.complete, ids(result)) == (False, ["sandbox.report_malformed"])
    assert result.checks_run == ("sandbox.report",)


def test_check_count_bound_is_inclusive() -> None:
    checks = [{"check_id": f"c{i}", "status": "passed"} for i in range(MAX_REPORT_CHECKS)]
    assert run(report(checks=checks), ("c0",)).complete is True


def test_oversized_report_is_malformed() -> None:
    finding = {**_FINDING, "message": "m" * 500}
    checks = [
        {"check_id": f"c{i}", "status": "passed", "findings": [finding] * 1000} for i in range(3)
    ]
    assert ids(run(report(checks=checks), ("c0",))) == ["sandbox.report_malformed"]


def test_secret_like_message_is_withheld() -> None:
    message = f"found token {SERVICE_TOKEN} in file"
    data = _mutate(("checks", 0, "findings"), [{**_FINDING, "message": message}])
    (finding,) = run(data).findings
    assert finding.detail == "message withheld: it looked like it held a secret"
