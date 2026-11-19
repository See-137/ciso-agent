"""Deterministic content inspection of AI agent actions (docs/skill/spec-draft.md, C3, C5).

Pure functions over text: secrets, sensitive target paths, risky code in added lines, a
unified diff parser and the sandbox report adapter. No network, process or model, and no
secret value ever appears in a result.
"""

from ciso.inspection.catalog import ALL_RULES, RULE_TABLE
from ciso.inspection.diff import (
    MAX_DIFF_FILES,
    ChangeType,
    DiffLine,
    FileDiff,
    MalformedDiff,
    parse_unified_diff,
)
from ciso.inspection.inspector import (
    MAX_CONTENT_CHARS,
    MAX_LINE_CHARS,
    Inspector,
    inspect_diff,
)
from ciso.inspection.paths import directory_rules, sensitive_path_rules
from ciso.inspection.rules import Rule
from ciso.inspection.sandbox import MAX_REPORT_CHARS, from_sandbox_report

__all__ = [
    "ALL_RULES",
    "MAX_CONTENT_CHARS",
    "MAX_DIFF_FILES",
    "MAX_LINE_CHARS",
    "MAX_REPORT_CHARS",
    "RULE_TABLE",
    "ChangeType",
    "DiffLine",
    "FileDiff",
    "Inspector",
    "MalformedDiff",
    "Rule",
    "directory_rules",
    "from_sandbox_report",
    "inspect_diff",
    "parse_unified_diff",
    "sensitive_path_rules",
]
