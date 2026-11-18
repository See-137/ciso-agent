"""The rule record every check uses, and the rules that describe inspection coverage.

A rule has a fixed id, a category, a severity and a fixed remediation text. The findings
lane may not import this package (it sees only `ciso.common`), so the remediation travels
on each finding's own `remediation` field (and, for people reading the raw finding, in
`detail`, see `Rule.detail`).

Severity mapping, applied the same way by every table in this package:

- critical: the change can hand control of the machine, the assistant or the pipeline to
  someone else, or exposes a private key outright.
- high: a live credential or a well-known code-execution or injection pattern.
- medium: a weakening that needs a reason (debug on, wildcard CORS, a suppressed security
  lint) or something that could not be inspected.
- low: worth a look, rarely a problem on its own (a hard-coded host name).
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Final

from ciso.common.activity import Severity

_RULE_ID = re.compile(r"[a-z][a-z0-9_.-]{0,63}")
_CATEGORY = re.compile(r"[a-z][a-z0-9_]{0,31}")
#: Longest title plus remediation, so `detail` always fits the contract's text field.
MAX_DETAIL_CHARS: Final = 500


@dataclass(frozen=True, slots=True)
class Rule:
    """One named check outcome. `title` names the problem; it never quotes the content."""

    rule_id: str
    category: str
    severity: Severity
    title: str
    remediation: str

    def __post_init__(self) -> None:
        if not _RULE_ID.fullmatch(self.rule_id):
            raise ValueError(f"bad rule id: {self.rule_id!r}")
        if not _CATEGORY.fullmatch(self.category):
            raise ValueError(f"bad category for {self.rule_id}")
        if len(self.detail) > MAX_DETAIL_CHARS:
            raise ValueError(f"title and remediation of {self.rule_id} are too long")

    @property
    def detail(self) -> str:
        """The finding text: what was found and the fixed remediation."""
        return f"{self.title}. Remediation: {self.remediation}"


# Coverage: the inspection itself could not do its whole job. Each of these makes the
# result incomplete, so the decision treats the action as not inspected.
COVERAGE = "coverage"

TOO_LARGE = Rule(
    "inspection.too_large",
    COVERAGE,
    Severity.MEDIUM,
    "Content is larger than the inspection limit and was not inspected",
    "Split the change into smaller parts or have a person review it",
)
LINE_TOO_LONG = Rule(
    "inspection.line_too_long",
    COVERAGE,
    Severity.MEDIUM,
    "One or more lines are longer than the inspection limit and were not inspected",
    "Avoid generated or minified content in agent changes, or have a person review it",
)
CONTENT_MISSING = Rule(
    "inspection.content_missing",
    COVERAGE,
    Severity.MEDIUM,
    "The action carries no content to inspect",
    "The integration must send the content of writes, edits, prompts and commits",
)
PATH_MISSING = Rule(
    "inspection.path_missing",
    COVERAGE,
    Severity.MEDIUM,
    "The write or edit names no target path",
    "The integration must send the target path of every write and edit",
)
DIFF_MALFORMED = Rule(
    "inspection.diff_malformed",
    COVERAGE,
    Severity.MEDIUM,
    "The change could not be parsed as a unified diff",
    "Send the output of git diff or git format-patch unchanged",
)
DIFF_EMPTY = Rule(
    "inspection.diff_empty",
    COVERAGE,
    Severity.LOW,
    "The diff contains no file changes",
    "Confirm the change is empty; otherwise send the full diff",
)
BINARY_NOT_INSPECTED = Rule(
    "inspection.binary_not_inspected",
    COVERAGE,
    Severity.MEDIUM,
    "A binary file change was not inspected",
    "Keep binaries out of agent changes or have a person review the file",
)
FINDINGS_TRUNCATED = Rule(
    "inspection.findings_truncated",
    COVERAGE,
    Severity.MEDIUM,
    "More findings than one result can hold; the least severe were dropped",
    "Fix the reported findings and inspect the change again",
)

COVERAGE_RULES: Final[tuple[Rule, ...]] = (
    TOO_LARGE,
    LINE_TOO_LONG,
    CONTENT_MISSING,
    PATH_MISSING,
    DIFF_MALFORMED,
    DIFF_EMPTY,
    BINARY_NOT_INSPECTED,
    FINDINGS_TRUNCATED,
)
