"""Markdown reports built from findings (fixed fields only) and their storage."""

from __future__ import annotations

from collections import Counter
from collections.abc import Iterable, Sequence
from datetime import datetime
from pathlib import Path
from typing import Final

from ciso.common.activity import InspectionFinding, Severity

_ORDER: Final = list(Severity)
#: Most findings listed one by one in a report; the rest are counted.
MAX_LISTED: Final = 300


def ranked(findings: Iterable[InspectionFinding]) -> list[InspectionFinding]:
    return sorted(findings, key=lambda f: (-_ORDER.index(f.severity), f.location, f.check_id))


def _cell(text: str) -> str:
    return text.replace("|", "/").replace("\n", " ")


def render(
    title: str,
    scope: str,
    findings: Sequence[InspectionFinding],
    notes: Sequence[str],
    when: datetime,
) -> str:
    counts = Counter(f.severity for f in findings)
    lines = [
        f"# {title}",
        "",
        f"- Scope: {scope}",
        f"- Generated: {when.isoformat(timespec='seconds')}",
        "- Severity counts: "
        + ", ".join(f"{s.value} {counts.get(s, 0)}" for s in reversed(_ORDER)),
        "",
    ]
    if not findings:
        lines += ["No findings. This does not prove there is no problem (see notes).", ""]
    else:
        lines += ["| Severity | Rule | Location | Finding and remediation |", "|---|---|---|---|"]
        for f in ranked(findings)[:MAX_LISTED]:
            lines.append(
                f"| {f.severity.value} | {f.check_id} | {_cell(f.location) or '-'} | "
                f"{_cell(f.detail)} |"
            )
        if len(findings) > MAX_LISTED:
            lines.append(f"| ... | | | {len(findings) - MAX_LISTED} more not listed |")
        lines.append("")
    lines += ["## Notes", ""] + [f"- {n}" for n in notes] + [""]
    return "\n".join(lines)


def save(data_dir: Path | None, prefix: str, text: str, when: datetime) -> Path | None:
    """Write the report under `<data>/reports/`. None when no data directory was given."""
    if data_dir is None:
        return None
    folder = data_dir / "reports"
    folder.mkdir(parents=True, exist_ok=True)
    path = folder / f"{prefix}-{when.strftime('%Y%m%dT%H%M%SZ')}.md"
    path.write_text(text, encoding="utf-8", newline="\n")
    return path
