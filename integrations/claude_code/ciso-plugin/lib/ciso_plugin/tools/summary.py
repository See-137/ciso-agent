"""Summarise the local decision log and findings log, and check their hash chains.

The chains are SHA-256 over public data with no key and no outside anchor: they show an
edited or removed line inside a log, not a log cut short or rewritten from the first
line (review M5). The wording below says exactly that.
"""

from __future__ import annotations

from collections import Counter
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Final

from ciso_plugin.auditlog import read_records, verify
from ciso_plugin.decide import AUDIT_FILE, FINDINGS_FILE

#: Most records read from each log for a summary.
MAX_RECORDS: Final = 50_000
#: Most recent blocked actions listed.
MAX_RECENT: Final = 20


#: What the unanchored chain cannot show (review M5); said with every result.
CHAIN_LIMIT: Final = "truncation and rewriting cannot be detected locally"


def chain_text(records: int, ok: bool, first_break: int | None) -> str:
    """The chain result in words that claim no more than it proves: it detects an edited
    or removed line INSIDE the log, never a log cut short or rebuilt from the start,
    because nothing is anchored outside the user's control."""
    if ok:
        return f"no edits detected in {records} records; {CHAIN_LIMIT}."
    return (
        f"hash chain BROKEN at line {first_break} of {records}: a line was edited or "
        f"removed; {CHAIN_LIMIT}."
    )


def _since(records: list[dict[str, Any]], cutoff: datetime) -> list[dict[str, Any]]:
    out = []
    for record in records:
        try:
            when = datetime.fromisoformat(str(record.get("at")))
        except ValueError:
            continue
        if when >= cutoff:
            out.append(record)
    return out


def summarise(data_dir: Path, days: int, now: datetime) -> str:
    if days < 1 or days > 3650:
        raise ValueError("days must be between 1 and 3650")
    cutoff = now - timedelta(days=days)
    audit_path, findings_path = data_dir / AUDIT_FILE, data_dir / FINDINGS_FILE
    lines = [f"# CISO summary, last {days} days", ""]
    for label, path in (("Decision log", audit_path), ("Findings log", findings_path)):
        chain = verify(path)
        lines.append(f"- {label}: {chain_text(chain.records, chain.ok, chain.first_break)}")
    results = [
        r
        for r in _since(read_records(audit_path, MAX_RECORDS), cutoff)
        if r.get("type") == "ciso.plugin.result"
    ]
    verdicts = Counter(str(r.get("verdict")) for r in results)
    lines.append(
        "- Decisions: " + (", ".join(f"{k} {v}" for k, v in sorted(verdicts.items())) or "none")
    )
    rules = Counter(
        rule
        for r in results
        if r.get("verdict") != "allow"
        for rule in r.get("matched_rule_ids", [])
    )
    reasons = Counter(
        code for r in results if r.get("verdict") != "allow" for code in r.get("reason_codes", [])
    )
    lines += ["", "## Why actions were blocked or held", ""]
    lines += [f"- reason {k}: {v}" for k, v in reasons.most_common(10)] or ["- none"]
    lines += [f"- rule {k}: {v}" for k, v in rules.most_common(10)]
    findings = _since(read_records(findings_path, MAX_RECORDS), cutoff)
    by_rule: Counter[str] = Counter()
    advice: dict[str, str] = {}
    for record in findings:
        for item in record.get("findings", []):
            key = f"{item.get('severity')} {item.get('check_id')}"
            by_rule[key] += 1
            advice.setdefault(key, str(item.get("remediation", "")))
    lines += ["", "## Findings by rule", ""]
    lines += [f"- {k}: {v}. Fix: {advice[k] or 'see the rule'}" for k, v in by_rule.most_common(20)]
    if not by_rule:
        lines.append("- none")
    lines += ["", "## Recent blocked actions", ""]
    blocked = [r for r in results if r.get("verdict") == "deny"][-MAX_RECENT:]
    for r in reversed(blocked):
        target = r.get("target") or {}
        where = target.get("path") or target.get("branch") or target.get("repository") or "-"
        found = ", ".join(r.get("findings", [])) or "no content finding"
        lines.append(f"- {r.get('at')} {r.get('decision_id')} {r.get('kind')} {where}: {found}")
    if not blocked:
        lines.append("- none")
    lines += [
        "",
        "The logs hold decisions, rule ids, kinds, targets and hashes only: no "
        "commands, prompts or file content.",
        "",
    ]
    return "\n".join(lines)
