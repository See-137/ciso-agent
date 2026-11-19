"""Changes that switch a scanner off (review H3): a HIGH `scan_suppression` finding.

The sandbox's scanners read their configuration from the repository they scan, so a
change can blind them: an allowlist in `.gitleaks.toml`, entries in `.gitleaksignore` or
`.semgrepignore`, a `.gitattributes` line that makes git print a file as binary or through
a driver (`-diff`, `binary`, `diff=`, `filter=`), or an inline marker on the line itself
(`gitleaks:allow`, `nosemgrep`, `nosec`, `noqa: S...`). The configuration files are path
rules (`ciso.inspection.paths`); the lines are checked here, on added lines only (a
removed marker is not a finding). The sandbox lane separately stops honouring them; this
makes the change itself visible, and the default ruleset denies a scanned push or commit
with a finding of high severity or worse.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from typing import Final

from ciso.common.activity import Severity
from ciso.inspection._collect import Collector, location
from ciso.inspection.rules import Rule

SCAN_SUPPRESSION: Final = "scan_suppression"

SCANNER_CONFIG = Rule(
    "suppression.scanner_config",
    SCAN_SUPPRESSION,
    Severity.HIGH,
    "Change to a secret or code scanner's configuration or ignore file",
    "Scanner configuration is set by the security team; remove the file from the change",
)
GITATTRIBUTES_HIDING = Rule(
    "suppression.gitattributes",
    SCAN_SUPPRESSION,
    Severity.HIGH,
    "A git attributes line makes files print as binary or through a driver, hiding them "
    "from diff-based scanners",
    "Remove the -diff, binary, diff= or filter= attribute, or have the security team approve it",
)
INLINE_MARKER = Rule(
    "suppression.inline_marker",
    SCAN_SUPPRESSION,
    Severity.HIGH,
    "An added line carries a marker that tells a scanner to ignore it",
    "Remove the suppression marker and fix what the scanner reports instead",
)

SUPPRESSION_RULES: Final[tuple[Rule, ...]] = (GITATTRIBUTES_HIDING, INLINE_MARKER)

_MARKER: Final = re.compile(
    r"gitleaks:allow|\bnosemgrep\b|\bnosec\b|\bnoqa\s*:\s*(?:[A-Z]+[0-9]*\s*,\s*)*S[0-9]",
    re.IGNORECASE,
)
_HIDING: Final = re.compile(r"-diff|binary|diff=.*|filter=.*", re.IGNORECASE)
_GITATTRIBUTES: Final = ".gitattributes"


def _hides(line: str) -> bool:
    text = line.strip()
    if not text or text.startswith("#"):
        return False
    return any(_HIDING.fullmatch(token) for token in text.split()[1:])


def scan_suppressions(lines: Iterable[tuple[int, str]], path: str, out: Collector) -> None:
    """Add a finding for each added line that suppresses a scanner (module doc)."""
    attributes = path.replace("\\", "/").rsplit("/", 1)[-1].casefold() == _GITATTRIBUTES
    for number, text in lines:
        if attributes and _hides(text):
            out.add(GITATTRIBUTES_HIDING, location(path, number))
        if _MARKER.search(text):
            out.add(INLINE_MARKER, location(path, number))
