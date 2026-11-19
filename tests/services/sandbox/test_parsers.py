"""Scanner and test-runner outputs become the fixed report format; anything odd is `error`.

Fixture shapes come from the tools' documented formats; see fixtures/SOURCES.md.
"""

from __future__ import annotations

import json
from typing import Any

import pytest
from services.sandbox.report import CheckReport, Report, validate_wire
from tests.services.sandbox.support import fixture_bytes, outcome

from services.sandbox import parsers

pytestmark = pytest.mark.unit

STATUSES = {"passed", "failed", "error", "skipped"}
SEVERITIES = {"info", "low", "medium", "high", "critical"}


def assert_wire_check(check: dict[str, Any]) -> None:
    """Independent check of the fixed format, not using the module's own models."""
    assert set(check) == {"check_id", "status", "findings", "tests"}
    assert isinstance(check["check_id"], str)
    assert check["status"] in STATUSES
    assert set(check["tests"]) == {"passed", "failed", "errors"}
    assert all(type(v) is int and v >= 0 for v in check["tests"].values())
    for f in check["findings"]:
        assert set(f) == {"rule", "category", "severity", "path", "line", "message"}
        assert all(isinstance(f[k], str) for k in ("rule", "category", "path", "message"))
        assert f["severity"] in SEVERITIES
        assert f["line"] is None or (type(f["line"]) is int and f["line"] >= 1)


def wire(check: CheckReport) -> dict[str, Any]:
    data = Report(job_id="job-1", checks=(check,)).to_wire()
    json.dumps(data)
    validate_wire(data)
    assert set(data) == {"job_id", "head", "checks"}
    assert data["head"] is None
    assert_wire_check(data["checks"][0])
    return data["checks"][0]  # type: ignore[no-any-return]


# --- gitleaks ---------------------------------------------------------------------------


def test_gitleaks_findings() -> None:
    check = wire(parsers.parse_gitleaks(outcome(0, fixture_bytes("gitleaks_report.json"))))
    assert check["check_id"] == "secrets"
    assert check["status"] == "failed"
    assert [(f["rule"], f["path"], f["line"]) for f in check["findings"]] == [
        ("generic-api-key", "app/config.py", 3),
        ("aws-access-token", "deploy/env.sh", 1),
    ]
    assert {f["severity"] for f in check["findings"]} == {"high"}
    assert {f["category"] for f in check["findings"]} == {"secret"}


def test_gitleaks_never_copies_secret_or_match() -> None:
    raw = json.loads(fixture_bytes("gitleaks_report.json"))
    raw[0]["Secret"] = "AKIAPLANTEDSECRETVALUE"
    raw[0]["Match"] = "key=AKIAPLANTEDSECRETVALUE"
    raw[0]["Message"] = "commit message AKIAPLANTEDSECRETVALUE"
    check = wire(parsers.parse_gitleaks(outcome(0, json.dumps(raw).encode())))
    assert "AKIAPLANTEDSECRETVALUE" not in json.dumps(check)


def test_gitleaks_no_findings_passes() -> None:
    check = wire(parsers.parse_gitleaks(outcome(0, b"[]")))
    assert check["status"] == "passed"
    assert check["findings"] == []


@pytest.mark.parametrize(
    "stdout",
    [b"", b"not json", b"{}", b'[{"RuleID": 3}]', b'[{"RuleID": "r", "File": "a"}]', b"[1]"],
)
def test_gitleaks_unparseable_is_error(stdout: bytes) -> None:
    check = wire(parsers.parse_gitleaks(outcome(0, stdout)))
    assert check["status"] == "error"
    assert check["findings"][0]["rule"] == "sandbox.unparseable_output"


def test_gitleaks_nonzero_exit_is_error() -> None:
    # We run gitleaks with --exit-code 0, so any non-zero exit is a scan error.
    check = wire(parsers.parse_gitleaks(outcome(1, b"[]")))
    assert check["status"] == "error"
    assert check["findings"][0]["rule"] == "sandbox.tool_failed"


# --- semgrep ----------------------------------------------------------------------------


def test_semgrep_findings_and_severity_mapping() -> None:
    check = wire(parsers.parse_semgrep(outcome(0, fixture_bytes("semgrep_report.json"))))
    assert check["check_id"] == "code"
    assert check["status"] == "failed"
    assert [(f["rule"], f["path"], f["line"], f["severity"]) for f in check["findings"]] == [
        ("python.lang.security.audit.eval-detected.eval-detected", "app/handler.py", 14, "medium"),
        ("python.lang.security.dangerous-subprocess-use", "app/run.py", 2, "high"),
    ]
    assert {f["category"] for f in check["findings"]} == {"code"}


@pytest.mark.parametrize(
    ("given", "expected"),
    [
        ("CRITICAL", "critical"),
        ("ERROR", "high"),
        ("HIGH", "high"),
        ("WARNING", "medium"),
        ("MEDIUM", "medium"),
        ("LOW", "low"),
        ("INFO", "info"),
        ("INVENTORY", "info"),
        ("EXPERIMENTAL", "info"),
    ],
)
def test_semgrep_every_documented_severity(given: str, expected: str) -> None:
    raw = json.loads(fixture_bytes("semgrep_report.json"))
    raw["results"] = raw["results"][:1]
    raw["results"][0]["extra"]["severity"] = given
    check = wire(parsers.parse_semgrep(outcome(0, json.dumps(raw).encode())))
    assert check["findings"][0]["severity"] == expected
    assert check["status"] == ("passed" if expected == "info" else "failed")


def test_semgrep_never_copies_matched_lines() -> None:
    raw = json.loads(fixture_bytes("semgrep_report.json"))
    raw["results"][0]["extra"]["lines"] = "password = 'PLANTEDLINECONTENT'"
    check = wire(parsers.parse_semgrep(outcome(0, json.dumps(raw).encode())))
    assert "PLANTEDLINECONTENT" not in json.dumps(check)


def test_semgrep_fatal_error_entry_is_error() -> None:
    raw = json.loads(fixture_bytes("semgrep_report.json"))
    raw["errors"] = [{"code": 2, "level": "error", "type": "SemgrepError", "message": "x"}]
    check = wire(parsers.parse_semgrep(outcome(0, json.dumps(raw).encode())))
    assert check["status"] == "error"
    assert check["findings"][0]["rule"] == "sandbox.scanner_error"


def test_semgrep_warning_entry_is_reported_but_not_fatal() -> None:
    raw = json.loads(fixture_bytes("semgrep_report.json"))
    raw["results"] = []
    raw["errors"] = [{"code": 3, "level": "warn", "type": "Syntax error", "message": "x"}]
    check = wire(parsers.parse_semgrep(outcome(0, json.dumps(raw).encode())))
    assert check["status"] == "passed"
    assert [f["rule"] for f in check["findings"]] == ["sandbox.scanner_warnings"]


@pytest.mark.parametrize(
    "stdout",
    [
        b"",
        b"[]",
        b'{"results": "x", "errors": []}',
        b'{"results": [{"check_id": "a"}], "errors": []}',
        b'{"results": [], "errors": [], "x": 1',
    ],
)
def test_semgrep_unparseable_is_error(stdout: bytes) -> None:
    check = wire(parsers.parse_semgrep(outcome(0, stdout)))
    assert check["status"] == "error"


def test_semgrep_unknown_severity_is_error() -> None:
    raw = json.loads(fixture_bytes("semgrep_report.json"))
    raw["results"][0]["extra"]["severity"] = "SPICY"
    check = wire(parsers.parse_semgrep(outcome(0, json.dumps(raw).encode())))
    assert check["status"] == "error"


@pytest.mark.parametrize("code", [2, 3, 4, 5, 7, 8, 13, 99])
def test_semgrep_error_exit_codes(code: int) -> None:
    check = wire(parsers.parse_semgrep(outcome(code, fixture_bytes("semgrep_report.json"))))
    assert check["status"] == "error"


# --- pytest -----------------------------------------------------------------------------


def test_pytest_junit_counts() -> None:
    check = wire(parsers.parse_pytest(outcome(1, fixture_bytes("pytest_junit_failed.xml"))))
    assert check["check_id"] == "tests"
    assert check["status"] == "failed"
    assert check["tests"] == {"passed": 2, "failed": 1, "errors": 1}


def test_pytest_junit_passed() -> None:
    check = wire(parsers.parse_pytest(outcome(0, fixture_bytes("pytest_junit_passed.xml"))))
    assert check["status"] == "passed"
    assert check["tests"] == {"passed": 2, "failed": 0, "errors": 0}
    assert check["findings"] == []


def test_pytest_exit_and_counts_must_agree() -> None:
    check = wire(parsers.parse_pytest(outcome(0, fixture_bytes("pytest_junit_failed.xml"))))
    assert check["status"] == "error"
    check = wire(parsers.parse_pytest(outcome(1, fixture_bytes("pytest_junit_passed.xml"))))
    assert check["status"] == "error"


def test_pytest_no_tests_collected_is_skipped() -> None:
    check = wire(parsers.parse_pytest(outcome(5, b"")))
    assert check["status"] == "skipped"


@pytest.mark.parametrize("code", [2, 3, 4])
def test_pytest_interrupted_or_internal_error(code: int) -> None:
    check = wire(parsers.parse_pytest(outcome(code, fixture_bytes("pytest_junit_passed.xml"))))
    assert check["status"] == "error"


def test_pytest_report_with_doctype_is_refused_even_when_it_says_passed() -> None:
    xml = fixture_bytes("pytest_junit_passed.xml").replace(
        b"?><testsuites", b'?><!DOCTYPE t [<!ENTITY e "x">]><testsuites', 1
    )
    assert b"<!DOCTYPE" in xml
    check = wire(parsers.parse_pytest(outcome(0, xml)))
    assert check["status"] == "error"
    assert check["findings"][0]["rule"] == "sandbox.unparseable_output"


@pytest.mark.parametrize(
    "stdout",
    [
        b"",
        b"<testsuites><testsuite tests='x'/></testsuites>",
        b"<html/>",
        b'<?xml version="1.0"?><!DOCTYPE lolz [<!ENTITY lol "lol">]><testsuites/>',
        b"<testsuites><testsuite tests='1' failures='3' errors='0' skipped='0'/></testsuites>",
    ],
)
def test_pytest_unparseable_or_hostile_xml_is_error(stdout: bytes) -> None:
    check = wire(parsers.parse_pytest(outcome(1, stdout)))
    assert check["status"] == "error"


# --- go test ----------------------------------------------------------------------------


def test_go_test_json_counts_tests_and_build_failures() -> None:
    check = wire(parsers.parse_go_test(outcome(1, fixture_bytes("go_test_failed.jsonl"))))
    assert check["status"] == "failed"
    assert check["tests"] == {"passed": 1, "failed": 1, "errors": 1}


def test_go_test_json_passed() -> None:
    check = wire(parsers.parse_go_test(outcome(0, fixture_bytes("go_test_passed.jsonl"))))
    assert check["status"] == "passed"
    assert check["tests"] == {"passed": 1, "failed": 0, "errors": 0}


def test_go_test_non_json_line_is_error() -> None:
    data = fixture_bytes("go_test_passed.jsonl") + b"panic: something\n"
    check = wire(parsers.parse_go_test(outcome(0, data)))
    assert check["status"] == "error"


def test_go_test_no_tests_is_skipped() -> None:
    line = b'{"Action":"skip","Package":"example.invalid/app"}\n'
    check = wire(parsers.parse_go_test(outcome(0, line)))
    assert check["status"] == "skipped"


def test_go_exit_and_counts_must_agree() -> None:
    check = wire(parsers.parse_go_test(outcome(1, fixture_bytes("go_test_passed.jsonl"))))
    assert check["status"] == "error"


# --- npm test ---------------------------------------------------------------------------


def test_npm_exit_codes() -> None:
    passed = wire(parsers.parse_npm_test(outcome(0, b"anything")))
    failed = wire(parsers.parse_npm_test(outcome(1, b"anything")))
    assert (passed["status"], failed["status"]) == ("passed", "failed")
    assert passed["tests"] == {"passed": 0, "failed": 0, "errors": 0}
    assert passed["findings"][0]["rule"] == "sandbox.test_counts_unavailable"


# --- shared outcome handling ------------------------------------------------------------

ALL_PARSERS = [
    parsers.parse_gitleaks,
    parsers.parse_semgrep,
    parsers.parse_pytest,
    parsers.parse_go_test,
    parsers.parse_npm_test,
]


@pytest.mark.parametrize("parse", ALL_PARSERS)
@pytest.mark.parametrize(
    ("result", "rule"),
    [
        (outcome(None, b"", timed_out=True), "sandbox.wall_time_exceeded"),
        (outcome(None, b"", exceeded=True), "sandbox.output_limit_exceeded"),
        (outcome(125, b""), "sandbox.runtime_failed"),
        (outcome(126, b""), "sandbox.runtime_failed"),
        (outcome(127, b""), "sandbox.runtime_failed"),
        (outcome(137, b""), "sandbox.killed"),
        (outcome(None, b""), "sandbox.runtime_failed"),
    ],
)
def test_runtime_failures_are_errors_for_every_tool(parse: Any, result: Any, rule: str) -> None:
    check = wire(parse(result))
    assert check["status"] == "error"
    assert check["findings"][0]["rule"] == rule


def test_messages_are_cleaned_and_bounded() -> None:
    raw = json.loads(fixture_bytes("gitleaks_report.json"))
    raw[0]["Description"] = "line one\nforged line‮" + "x" * 5000
    raw[0]["File"] = "  path\twith tab  "
    check = wire(parsers.parse_gitleaks(outcome(0, json.dumps(raw).encode())))
    finding = check["findings"][0]
    assert "\n" not in finding["message"]
    assert "‮" not in finding["message"]
    assert len(finding["message"]) <= 512
    assert finding["path"] == "path?with tab"


def test_findings_are_capped(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(parsers, "MAX_REPORT_FINDINGS", 3)
    raw = json.loads(fixture_bytes("gitleaks_report.json"))
    many = [dict(raw[0], StartLine=i + 1) for i in range(10)]
    check = wire(parsers.parse_gitleaks(outcome(0, json.dumps(many).encode())))
    assert len(check["findings"]) == 3
    assert check["findings"][-1]["rule"] == "sandbox.findings_truncated"
    assert check["status"] == "failed"
