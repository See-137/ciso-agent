"""The rule table: unique ids, valid contract fields, fixed remediation text."""

from __future__ import annotations

import pytest

from ciso.common.activity import InspectionFinding, Severity, clean_text
from ciso.inspection import ALL_RULES, RULE_TABLE, Rule
from ciso.inspection.catalog import _index

pytestmark = pytest.mark.unit


def test_every_rule_is_indexed_once() -> None:
    assert len(RULE_TABLE) == len(ALL_RULES) == 47  # + bulk_write_broad (Q13), 3 suppression (H3)
    with pytest.raises(ValueError, match="share the id"):
        _index((ALL_RULES[0], Rule(ALL_RULES[0].rule_id, "x", Severity.LOW, "t", "r")))


@pytest.mark.parametrize("rule", ALL_RULES, ids=lambda r: r.rule_id)
def test_rule_builds_a_valid_finding(rule: Rule) -> None:
    finding = InspectionFinding(
        check_id=rule.rule_id, category=rule.category, severity=rule.severity, detail=rule.detail
    )
    assert clean_text(finding.detail) == rule.detail
    assert "Remediation: " in rule.detail
    assert rule.remediation


def test_categories_are_the_documented_ones() -> None:
    assert {r.category for r in ALL_RULES} == {
        "secret",
        "sensitive_path",
        "code_risk",
        "coverage",
        "sandbox",
        "test_failure",
        "scan_suppression",
    }


@pytest.mark.parametrize(
    ("rule_id", "category"),
    [("Bad", "secret"), ("ok.id", "Bad Category"), ("ok.id", "x" * 40)],
)
def test_rule_fields_are_validated(rule_id: str, category: str) -> None:
    with pytest.raises(ValueError, match="bad"):
        Rule(rule_id, category, Severity.LOW, "title", "fix")


def test_overlong_detail_is_refused() -> None:
    with pytest.raises(ValueError, match="too long"):
        Rule("ok.id", "secret", Severity.LOW, "t" * 300, "r" * 300)
