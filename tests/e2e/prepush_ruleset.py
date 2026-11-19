"""A deployment ruleset for the pre-push tests: the packaged default plus two rules the
default does not have yet (requested from the governance owner in the skillI2 report):

- `deny-high-findings-in-scanned-push-or-commit`: a scanned push or commit with any
  finding of high severity or worse (a planted secret, failed tests, a failed check) is
  denied;
- `allow-scanned-push-known-people`: a push whose scan is complete is allowed for a
  known person's organizational or employee-operated agent. A push to a protected branch
  still matches the default's `ask-push-to-protected-branch`, which is stronger.

`python tests/e2e/prepush_ruleset.py <out.json>` writes it (used by the real run)."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

from ciso.governance import DEFAULT_RULESET_PATH

EXTRA_RULES: list[dict[str, Any]] = [
    {
        "id": "deny-high-findings-in-scanned-push-or-commit",
        "description": "A push or commit whose scan found anything of high severity or worse "
        "(a secret, failed tests, a failed sandbox check) is denied. A missing or incomplete "
        "scan denies it too (missing_inspection).",
        "effect": "deny",
        "requires_inspection": True,
        "match": {
            "kinds": ["shell_command", "git_commit", "git_push"],
            "command_classes": ["git_commit", "git_push", "git_force_push"],
            "inspection": {"min_severity": "high"},
        },
    },
    {
        "id": "allow-scanned-push-known-people",
        "description": "A push whose scan is complete is allowed for a known person's "
        "organizational or employee-operated agent; protected branches still ask.",
        "effect": "allow",
        "requires_inspection": True,
        "match": {
            "kinds": ["shell_command", "git_push"],
            "command_classes": ["git_push"],
            "attribution_states": ["verified", "declared"],
            "person_known": True,
            "agent_classes": ["organizational", "employee_operated"],
            "inspection": {"complete": True},
        },
    },
]


def scanned_push_ruleset() -> dict[str, Any]:
    document: dict[str, Any] = json.loads(Path(DEFAULT_RULESET_PATH).read_text(encoding="utf-8"))
    document["version"] = "prepush-test-2026.11.19-1"
    document["rules"] = [*document["rules"], *EXTRA_RULES]
    return document


def write_ruleset(path: Path) -> Path:
    path.write_text(json.dumps(scanned_push_ruleset(), indent=2), encoding="utf-8")
    return path


if __name__ == "__main__":
    write_ruleset(Path(sys.argv[1]))
