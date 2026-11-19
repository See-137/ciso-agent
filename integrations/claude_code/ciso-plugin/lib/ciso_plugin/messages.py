"""What the person sees when the plugin blocks or holds an action.

Every text is fixed or built from the engine's fixed explanation and the inspection's
fixed finding fields (rule title, remediation, `path:line`) and fixed reason codes.
Nothing from the command, the prompt, the file content or git configuration (keys or
values, review L2) is ever echoed, so a secret cannot appear here.
"""

from __future__ import annotations

import re
from typing import Final

from ciso.common.activity import InspectionFinding, InspectionResult, Severity, clean_text

#: A reason code: the only text from a refusal that is appended to a message (review L2).
_CODE: Final = re.compile(r"[a-z_]{1,40}")
#: Most findings named in one message; the rest are counted.
MAX_NAMED_FINDINGS: Final = 5
#: Longest message returned to Claude Code.
MAX_MESSAGE_CHARS: Final = 1800
_ORDER: Final = list(Severity)
_SKILL_HINT: Final = (
    " Run the CISO skill (/ciso-agent:ciso) and ask it to summarise your findings for "
    "details and fixes."
)

#: Why the plugin refused before or around the engine. Fixed texts.
NOTES: Final[dict[str, str]] = {
    "push_not_plain": (
        " Pushes and commits by AI agents are scanned before they run, and only one plain "
        "command can be scanned: push one branch at a time and name it (git push <remote> "
        "<branch>, no --force, --all, --tags, --mirror, deletes or refspec lists), or "
        "commit with git commit -m <message>, each on its own."
    ),
    "push_config_redirect": (
        " This repository's git settings redirect or widen the push or run a program "
        "during it, so what would be sent cannot be checked. Remove those settings (the "
        "plugin README, 'Pushes without a sandbox', explains each reason code) or push it "
        "yourself. Reason codes: "
    ),
    "repo_layout": (
        " This repository's working tree or git folder is redirected (core.worktree, "
        "core.bare, a .git file or a linked worktree), so the scan could read another "
        "repository than the one that would push or commit. The person must push or "
        "commit it by hand."
    ),
    "repo_hooks": (
        " This repository has its own git hook programs, which would run during the push "
        "and could change or add to what is sent. Push it yourself, or remove the hooks."
    ),
    "unknown_remote": " Push to a remote configured in this repository, by its name.",
    "no_source_commit": " The branch named in the push does not exist here.",
    "too_many_commits": (
        " The push would send more commits than can be scanned at once. Fetch from the "
        "remote first, or push this branch yourself."
    ),
    "not_a_repository": " The working directory is not a git repository.",
    "git_failed": (
        " git could not be run to read the change, so it could not be scanned. Try again."
    ),
}
FAILURE_TEXT: Final = (
    "CISO plugin: the security check could not run, so this action was blocked "
    "(code: {code}). If this keeps happening, your IT team must check that uv and "
    "Python 3.13 or later are installed and on PATH, and that the plugin is up to date."
)
REFUSAL_TEXTS: Final[dict[str, str]] = {
    "invalid_report": (
        "Blocked: the CISO plugin could not read this action, so it was stopped. "
        "Make sure the plugin is up to date. If it keeps happening, contact the security team."
    ),
    "inspection_failed": (
        "Blocked: the content check could not run, so the action was stopped. Try again. "
        "If it keeps happening, contact the security team."
    ),
    "record_failed": (
        "Blocked: the decision could not be written to the local audit log, so the action "
        "was stopped. If it keeps happening, contact the security team."
    ),
}


def _named(finding: InspectionFinding) -> str:
    where = f" at {finding.location}" if finding.location else ""
    return f"{finding.severity.value}: {finding.detail}{where}"


def findings_text(inspection: InspectionResult | None) -> str:
    if inspection is None or not inspection.findings:
        return ""
    ranked = sorted(inspection.findings, key=lambda f: -_ORDER.index(f.severity))
    named = [_named(f) for f in ranked[:MAX_NAMED_FINDINGS]]
    rest = len(ranked) - len(named)
    more = f" ({rest} more)" if rest > 0 else ""
    return " Found: " + "; ".join(named) + more + "."


def compose(
    explanation: str,
    decision_id: str,
    *,
    inspection: InspectionResult | None = None,
    note: str = "",
    names: tuple[str, ...] = (),
) -> str:
    text = explanation + findings_text(inspection)
    if note in NOTES:
        text += NOTES[note]
        codes = [n for n in names if _CODE.fullmatch(n)]
        if codes:
            text += ", ".join(codes) + "."
    if inspection is not None and inspection.findings:
        text += _SKILL_HINT
    suffix = f" (CISO decision {decision_id})"
    text = text[: MAX_MESSAGE_CHARS - len(suffix)] + suffix
    return clean_text(" ".join(text.split()))


def failure_text(code: str) -> str:
    return FAILURE_TEXT.format(code=code)
