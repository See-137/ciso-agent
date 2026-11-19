"""The ruleset the pre-push real run used: now the packaged default unchanged.

The two rules this file used to add (`deny-high-findings-in-scanned-push-or-commit`,
`allow-scanned-push-known-people`) are in the default since
governance-default-2026.11.19-3 (fix round QF1), and `tests/e2e/test_prepush_flow.py`
runs on the default. The file stays only because `integrations/claude_code/README.md`
names `python tests/e2e/prepush_ruleset.py <out.json>` for the real run; it writes the
default, so the command still works. Remove it once the README no longer names it.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

from ciso.governance import DEFAULT_RULESET_PATH


def scanned_push_ruleset() -> dict[str, Any]:
    document: dict[str, Any] = json.loads(Path(DEFAULT_RULESET_PATH).read_text(encoding="utf-8"))
    return document


def write_ruleset(path: Path) -> Path:
    path.write_text(json.dumps(scanned_push_ruleset(), indent=2), encoding="utf-8")
    return path


if __name__ == "__main__":
    write_ruleset(Path(sys.argv[1]))
