"""Gathers findings for one inspection and builds the bounded, clean result."""

from __future__ import annotations

import unicodedata
from typing import Final

from ciso.common.activity import (
    MAX_FINDINGS,
    InspectionFinding,
    InspectionResult,
    Severity,
)
from ciso.inspection.rules import FINDINGS_TRUNCATED, Rule

#: Longest path kept in a finding's location; longer paths keep their last characters.
MAX_LOCATION_PATH_CHARS: Final = 400
_SEVERITY_ORDER: Final = {severity: index for index, severity in enumerate(Severity)}


def safe_path(path: str) -> str:
    """A path fit for a finding: no control or format characters, bounded, trimmed."""
    cleaned = "".join(
        "?" if unicodedata.category(ch) in {"Cc", "Cf", "Zl", "Zp"} else ch for ch in path
    ).strip()
    if len(cleaned) > MAX_LOCATION_PATH_CHARS:
        cleaned = "..." + cleaned[-(MAX_LOCATION_PATH_CHARS - 3) :]
    return cleaned


def location(path: str = "", line: int | None = None, column: int | None = None) -> str:
    """`path:line:column`, leaving out what is unknown. Never holds content."""
    if path:
        where = safe_path(path)
        if line is not None:
            where += f":{line}"
            if column is not None:
                where += f":{column}"
        return where
    if line is None:
        return ""
    return f"line {line}" + (f", col {column}" if column is not None else "")


class Collector:
    """Per-call accumulator. Not shared: every inspection builds its own."""

    def __init__(self) -> None:
        self._checks: list[str] = []
        self._findings: list[InspectionFinding] = []
        self.complete = True

    def ran(self, check: str) -> None:
        if check not in self._checks:
            self._checks.append(check)

    def add(self, rule: Rule, where: str = "") -> None:
        self._findings.append(
            InspectionFinding(
                check_id=rule.rule_id,
                category=rule.category,
                severity=rule.severity,
                detail=rule.detail,
                location=where,
                remediation=rule.remediation,
            )
        )

    def add_finding(self, finding: InspectionFinding) -> None:
        self._findings.append(finding)

    def incomplete(self, rule: Rule, where: str = "") -> None:
        """Record that something that should have been inspected was not."""
        self.complete = False
        self.add(rule, where)

    def result(self, action_id: str) -> InspectionResult:
        findings = self._findings
        complete = self.complete
        if len(findings) > MAX_FINDINGS:
            ranked = sorted(
                range(len(findings)),
                key=lambda i: (-_SEVERITY_ORDER[findings[i].severity], i),
            )
            keep = sorted(ranked[: MAX_FINDINGS - 1])
            dropped = len(findings) - len(keep)
            findings = [findings[i] for i in keep]
            findings.append(
                InspectionFinding(
                    check_id=FINDINGS_TRUNCATED.rule_id,
                    category=FINDINGS_TRUNCATED.category,
                    severity=FINDINGS_TRUNCATED.severity,
                    detail=FINDINGS_TRUNCATED.detail,
                    remediation=FINDINGS_TRUNCATED.remediation,
                    location=f"{dropped} findings dropped",
                )
            )
            complete = False
        return InspectionResult(
            action_id=action_id,
            checks_run=tuple(self._checks),
            findings=tuple(findings),
            complete=complete,
        )
