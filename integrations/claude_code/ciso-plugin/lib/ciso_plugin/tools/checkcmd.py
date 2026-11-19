"""Check a planned command or file action against the bundled rules and explain the verdict.

The check uses the same intake, inspector and engine as the hook, with the same local
identity, but records nothing (the action is hypothetical). A push or commit is judged
WITHOUT its git scan here; the real hook scans the change before deciding.
"""

from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path
from typing import Final

from ciso.common.activity import InspectionInput, Verdict
from ciso.common.clock import Clock
from ciso.governance import GovernanceEngine, action_analysis, load_ruleset
from ciso.inspection import Inspector
from ciso.intake import normalize_hook_report
from ciso.intake.hook import FORMAT
from ciso_plugin.auditlog import NullAuditSink
from ciso_plugin.decide import RULESET_RELATIVE, SERVICE_ACTOR, PassThrough, carries_a_change
from ciso_plugin.identity import LocalAttribution, LocalPrincipals
from ciso_plugin.settings import EnvKillSwitch, PluginSettings

TOOLS: Final = frozenset({"Bash", "PowerShell", "Write", "Edit", "Read"})


def check(
    *,
    tool: str,
    command: str | None,
    path: str | None,
    plugin_root: Path,
    environ: Mapping[str, str],
    clock: Clock,
    account: str | None,
) -> str:
    if tool not in TOOLS:
        raise ValueError(f"tool must be one of {sorted(TOOLS)}")
    if tool in {"Bash", "PowerShell"}:
        if not command:
            raise ValueError("--command is required for a shell check")
        tool_input: dict[str, object] = {"command": command}
    elif tool == "Read":
        tool_input = {"file_path": path or ""}
    elif tool == "Write":
        tool_input = {"file_path": path or "", "content": ""}
    else:
        tool_input = {"file_path": path or "", "old_string": "", "new_string": ""}
    payload = {
        "hook_event_name": "PreToolUse",
        "session_id": "check",
        "cwd": "",
        "tool_name": tool,
        "tool_use_id": "check",
        "tool_input": tool_input,
    }
    request = {
        "format": FORMAT,
        "event": "PreToolUse",
        "surface": "cli",
        "claims": [],
        "payload": payload,
    }
    report = normalize_hook_report(
        request, device_actor_id=SERVICE_ACTOR, received_at=clock.now(), redactor=PassThrough()
    )
    settings = PluginSettings.from_env(environ)
    attribution_source = LocalAttribution(account, settings.agent_class)
    ruleset = load_ruleset(plugin_root / RULESET_RELATIVE)
    engine = GovernanceEngine(
        ruleset=ruleset,
        clock=clock,
        audit=NullAuditSink(clock),
        killswitch=EnvKillSwitch(settings.stop_raw),
        principals=LocalPrincipals(attribution_source.actor_id, settings.role),
        service_actor_id=SERVICE_ACTOR,
    )
    action = report.action
    item: InspectionInput | None = report.inspection
    inspection = (
        Inspector().inspect(item) if item is not None and not carries_a_change(action) else None
    )
    decision = engine.decide(action, attribution_source.attribute(action), inspection)
    classes = []
    if ruleset.document is not None:
        classes = sorted(
            c.value for c in action_analysis(action, ruleset.document.classifier_config()).classes
        )
    lines = [
        f"Verdict: {decision.verdict.value}",
        f"Action kind: {action.kind.value}",
        "Classes: " + (", ".join(classes) or "none"),
        "Matched rules: " + (", ".join(decision.matched_rule_ids) or "none (default applied)"),
        "Reasons: " + ", ".join(r.code for r in decision.reasons),
        f"Explanation: {decision.explanation}",
    ]
    if inspection is not None and inspection.findings:
        lines.append(
            "Findings: "
            + "; ".join(
                f"{f.severity.value} {f.check_id} {f.location}" for f in inspection.findings
            )
        )
    if carries_a_change(action):
        lines.append(
            "Note: the real hook scans the commits of a push (or the staged change of a "
            "commit) before deciding; this check does not, so a push shows as held here."
        )
    if decision.verdict is Verdict.ASK:
        lines.append(
            "Ask means the person at the keyboard must confirm it; in a non-interactive run "
            "it is refused."
        )
    return "\n".join(lines)
