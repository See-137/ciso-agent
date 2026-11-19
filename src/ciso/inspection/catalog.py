"""Every rule this package can report, by id: the table the findings lane documents."""

from __future__ import annotations

from collections.abc import Mapping
from types import MappingProxyType
from typing import Final

from ciso.inspection.code_scan import CODE_RULES
from ciso.inspection.paths import DIRECTORY_RULES, PATH_RULES
from ciso.inspection.rules import COVERAGE_RULES, Rule
from ciso.inspection.sandbox import SANDBOX_RULES
from ciso.inspection.secret_scan import SECRET_RULES
from ciso.inspection.suppression import SUPPRESSION_RULES

ALL_RULES: Final[tuple[Rule, ...]] = (
    *SECRET_RULES,
    *PATH_RULES,
    *DIRECTORY_RULES,
    *SUPPRESSION_RULES,
    *CODE_RULES,
    *COVERAGE_RULES,
    *SANDBOX_RULES,
)


def _index(rules: tuple[Rule, ...]) -> Mapping[str, Rule]:
    table: dict[str, Rule] = {}
    for rule in rules:
        if table.setdefault(rule.rule_id, rule) is not rule:
            raise ValueError(f"two rules share the id {rule.rule_id}")
    return MappingProxyType(table)


#: Rule id -> rule. Sandbox findings use `sandbox.<rule>` ids that are not listed here.
RULE_TABLE: Final[Mapping[str, Rule]] = _index(ALL_RULES)
