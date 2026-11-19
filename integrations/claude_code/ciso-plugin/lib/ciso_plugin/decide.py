"""One enforcing hook call, decided locally with the bundled engine (no server).

Order (the same steps as the service's pipeline, `ciso.app.governance_pipeline`):

1. normalize the hook payload exactly as the service does (`ciso.intake.hook`), with the
   OS account as an unverified claim. The intake's redactor is a pass-through: the command
   and content are classified and inspected as written and never stored;
2. attribute locally (`identity.LocalAttribution`);
3. the plugin's own skill and tool are allowed on their exact shapes (`selfcmd`), but
   only for a verified person with a valid role, and while the stop flag is engaged only
   the parts that write nothing (loading the skill, `summary`); anything else of theirs
   goes to the engine like any other command (review M3);
4. inspect: a push or commit through its git scan (`pushscan`), anything else that
   carries text (file writes and edits, prompts, shell commands, sub-agent prompts) with
   the bundled `Inspector`;
5. decide with the bundled `GovernanceEngine` and the bundled ruleset;
6. record: the engine audits its decision into the chained audit log, then the plugin
   appends its result record and, when there are findings, the findings log.

Any failure in steps 1-6 is a deny for this BEFORE action, with a fixed message and an
audit record when the log can still be written.
"""

from __future__ import annotations

import logging
import secrets
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Final

from ciso.app.change_decide import merge_inspections
from ciso.app.change_shape import ChangeKind, change_shape
from ciso.common.activity import (
    ActionKind,
    Attribution,
    GovernanceDecision,
    InspectionInput,
    InspectionResult,
    ObservedAction,
    Verdict,
)
from ciso.common.clock import Clock
from ciso.common.enums import ActorType, AuditOutcome, InformationState
from ciso.common.ids import new_id
from ciso.common.protocols import AuditEvent
from ciso.governance import (
    ClassifierConfig,
    CommandClass,
    GovernanceEngine,
    GovernanceRuleSet,
    classify_command,
    load_ruleset,
    requires_inspection,
)
from ciso.inspection import Inspector
from ciso.intake import IntakeRefused, normalize_hook_report
from ciso.intake.hook import FORMAT
from ciso.vault import SecretRedactor
from ciso_plugin import messages
from ciso_plugin.auditlog import ChainedLog, LocalAuditSink, NullAuditSink
from ciso_plugin.gitrun import GitError, SafeGit
from ciso_plugin.identity import LocalAttribution, LocalPrincipals
from ciso_plugin.pushscan import ScanRefused, scan_commit, scan_push
from ciso_plugin.selfcmd import own_invocation, writes_nothing
from ciso_plugin.settings import EnvKillSwitch, PluginSettings, stop_engaged

logger = logging.getLogger(__name__)

ENFORCED_EVENTS: Final = frozenset({"PreToolUse", "UserPromptSubmit"})
SERVICE_ACTOR: Final = "ciso-plugin.local"
RULESET_RELATIVE: Final = Path("rules") / "governance-ruleset.json"
AUDIT_FILE: Final = Path("audit") / "decisions.jsonl"
FINDINGS_FILE: Final = Path("findings") / "findings.jsonl"
_INSPECTION_CODES: Final = frozenset({"inspection_missing", "inspection_incomplete"})
_CHANGE_KINDS: Final = frozenset({ActionKind.GIT_PUSH, ActionKind.GIT_COMMIT})
_CHANGE_CLASSES: Final = frozenset(
    {CommandClass.GIT_PUSH, CommandClass.GIT_FORCE_PUSH, CommandClass.GIT_COMMIT}
)
_PROBE: Final = ClassifierConfig(protected_branches=("**",))


@dataclass(frozen=True)
class Outcome:
    verdict: Verdict
    decision_id: str
    message: str


class PassThrough:
    """The intake's redactor in local mode: nothing is stored, so nothing is rewritten
    before classification and inspection (README, "Deviations")."""

    def redact(self, text: str) -> str:
        return text

    def redact_value(self, value: Any) -> Any:
        return value


def carries_a_change(action: ObservedAction) -> bool:
    if action.kind in _CHANGE_KINDS:
        return True
    if action.kind is not ActionKind.SHELL_COMMAND or action.command is None:
        return False
    analysis = classify_command(action.command, _PROBE, truncated=action.command_truncated)
    return bool(analysis.classes & _CHANGE_CLASSES)


def _incomplete(action_id: str, part: InspectionResult | None) -> InspectionResult:
    return merge_inspections(action_id, [part, None])


@dataclass(frozen=True)
class Context:
    plugin_root: Path
    data: Path
    environ: Mapping[str, str]
    clock: Clock
    account: str | None
    settings: PluginSettings
    git: SafeGit | None


class Decider:
    def __init__(self, ctx: Context, ruleset: GovernanceRuleSet | None = None) -> None:
        self._ctx = ctx
        rules = ruleset or load_ruleset(ctx.plugin_root / RULESET_RELATIVE)
        self._audit_log = ChainedLog(ctx.data / AUDIT_FILE, ctx.clock)
        self._findings_log = ChainedLog(ctx.data / FINDINGS_FILE, ctx.clock)
        self._attribution = LocalAttribution(ctx.account, ctx.settings.agent_class)
        self._redactor = SecretRedactor()
        self._inspector = Inspector()
        killswitch = EnvKillSwitch(ctx.settings.stop_raw)
        principals = LocalPrincipals(self._attribution.actor_id, ctx.settings.role)
        self._engine = GovernanceEngine(
            ruleset=rules,
            clock=ctx.clock,
            audit=LocalAuditSink(self._audit_log),
            killswitch=killswitch,
            principals=principals,
            service_actor_id=SERVICE_ACTOR,
        )
        self._probe = GovernanceEngine(
            ruleset=rules,
            clock=ctx.clock,
            audit=NullAuditSink(ctx.clock),
            killswitch=killswitch,
            principals=principals,
            service_actor_id=SERVICE_ACTOR,
        )

    # --- the decision ---------------------------------------------------------------

    def decide(self, payload: Mapping[str, Any]) -> Outcome:
        event = payload.get("hook_event_name")
        if event not in ENFORCED_EVENTS:
            return self._refuse("invalid_report", "unsupported_event")
        try:
            report = normalize_hook_report(
                self._request(str(event), payload),
                device_actor_id=SERVICE_ACTOR,
                received_at=self._ctx.clock.now(),
                redactor=PassThrough(),
            )
        except IntakeRefused as refused:
            return self._refuse("invalid_report", refused.code.value)
        action = report.action
        attribution = self._attribution.attribute(action)
        tool_input = payload.get("tool_input")
        own = (
            own_invocation(action.tool_name, tool_input, self._ctx.plugin_root, self._ctx.data)
            if isinstance(tool_input, dict)
            else None
        )
        if event == "PreToolUse" and own is not None and self._own_permitted(own, attribution):
            return self._own_tool(action)
        try:
            inspection, note, names = self._inspect(action, attribution, report.inspection)
        except Exception as error:
            logger.error("inspection failed: %s", type(error).__name__)
            return self._refuse("inspection_failed", type(error).__name__, action)
        decision = self._engine.decide(action, attribution, inspection)
        try:
            self._record(action, decision, inspection, note)
        except Exception as error:
            logger.error("decision not recorded: %s", type(error).__name__)
            return self._refuse("record_failed", type(error).__name__, action)
        message = ""
        if decision.verdict is not Verdict.ALLOW:
            message = messages.compose(
                decision.explanation,
                decision.decision_id,
                inspection=inspection,
                note=note,
                names=names,
            )
        return Outcome(decision.verdict, decision.decision_id, message)

    def _own_permitted(self, part: str, attribution: Attribution) -> bool:
        """The own skill and tool skip the engine only for a verified person with a valid
        role, and under the stop flag only when they write nothing (review M3)."""
        settings = self._ctx.settings
        if attribution.state is not InformationState.VERIFIED or settings.role is None:
            return False
        return not stop_engaged(settings.stop_raw) or writes_nothing(part)

    def _request(self, event: str, payload: Mapping[str, Any]) -> dict[str, Any]:
        claims = []
        if self._ctx.account is not None:
            claims.append({"kind": "os_account", "subject": self._ctx.account, "verified": False})
        return {
            "format": FORMAT,
            "event": event,
            "surface": "cli",
            "claims": claims,
            "payload": dict(payload),
            "report_id": secrets.token_hex(16),
        }

    # --- inspection -----------------------------------------------------------------

    def _plain(
        self, action: ObservedAction, item: InspectionInput | None
    ) -> InspectionResult | None:
        """The command text's own inspection, read as a shell command."""
        command = None if item is None else item.command
        if command is None:
            return None
        plain = InspectionInput(
            action_id=action.action_id, kind=ActionKind.SHELL_COMMAND, command=command
        )
        return self._inspector.inspect(plain)

    def _inspect(
        self, action: ObservedAction, attribution: Attribution, item: InspectionInput | None
    ) -> tuple[InspectionResult | None, str, tuple[str, ...]]:
        if carries_a_change(action):
            return self._inspect_change(action, attribution, item)
        if item is not None:
            return self._inspector.inspect(item), "", ()
        if requires_inspection(action):
            return InspectionResult(action_id=action.action_id, complete=False), "", ()
        return None, "", ()

    def _inspect_change(
        self, action: ObservedAction, attribution: Attribution, item: InspectionInput | None
    ) -> tuple[InspectionResult | None, str, tuple[str, ...]]:
        plain = self._plain(action, item)
        probe = self._probe.decide(action, attribution, None)
        codes = {reason.code for reason in probe.reasons}
        if probe.verdict is Verdict.DENY and not codes <= _INSPECTION_CODES:
            return _incomplete(action.action_id, plain), "", ()
        shape = change_shape(action)
        if shape is None:
            return _incomplete(action.action_id, plain), "push_not_plain", ()
        if self._ctx.git is None:
            return _incomplete(action.action_id, plain), "git_failed", ()
        git = self._ctx.git
        try:
            if shape.kind is ChangeKind.PUSH:
                scanned = scan_push(git, shape, action.action_id)
            else:
                scanned = scan_commit(git, action.action_id)
        except ScanRefused as refused:
            return _incomplete(action.action_id, plain), refused.code, refused.names
        except GitError as error:
            note = error.code if error.code in messages.NOTES else "git_failed"
            return _incomplete(action.action_id, plain), note, ()
        return merge_inspections(action.action_id, [plain, scanned]), "", ()

    # --- records --------------------------------------------------------------------

    def _target(self, action: ObservedAction) -> dict[str, str]:
        return {key: self._redactor.redact(value) for key, value in action.target.items()}

    def _record(
        self,
        action: ObservedAction,
        decision: GovernanceDecision,
        inspection: InspectionResult | None,
        note: str,
    ) -> None:
        findings = [] if inspection is None else list(inspection.findings)
        self._audit_log.append(
            {
                "type": "ciso.plugin.result",
                "decision_id": decision.decision_id,
                "verdict": decision.verdict.value,
                "reason_codes": [r.code for r in decision.reasons],
                "matched_rule_ids": list(decision.matched_rule_ids),
                "kind": action.kind.value,
                "tool": action.tool_name,
                "session_id": action.session_id,
                "person": decision.attribution.person_ref,
                "agent_class": decision.attribution.agent_class.value,
                "target": self._target(action),
                "content_sha256": action.content_sha256,
                "content_bytes": action.content_bytes,
                "inspection_complete": None if inspection is None else inspection.complete,
                "findings": [f"{f.check_id}:{f.severity.value}" for f in findings],
                "note": note,
            }
        )
        if findings:
            self._findings_log.append(
                {
                    "decision_id": decision.decision_id,
                    "verdict": decision.verdict.value,
                    "kind": action.kind.value,
                    "tool": action.tool_name,
                    "target": self._target(action),
                    "findings": [
                        {
                            "check_id": f.check_id,
                            "category": f.category,
                            "severity": f.severity.value,
                            "detail": f.detail,
                            "location": self._redactor.redact(f.location),
                            "remediation": f.remediation,
                        }
                        for f in findings
                    ],
                }
            )

    def _event(
        self, name: str, outcome: AuditOutcome, details: dict[str, Any], target: str
    ) -> None:
        LocalAuditSink(self._audit_log).append(
            AuditEvent(
                actor_id=SERVICE_ACTOR,
                actor_type=ActorType.SERVICE,
                action=name,
                target=target,
                outcome=outcome,
                details=details,
            )
        )

    def _own_tool(self, action: ObservedAction) -> Outcome:
        decision_id = new_id("dec")
        details = {
            "decision_id": decision_id,
            "verdict": "allow",
            "tool": action.tool_name,
            "session_id": action.session_id,
            "rule": "local-allow-own-skill-and-tool",
        }
        try:
            self._event("ciso.plugin.own_tool", AuditOutcome.SUCCESS, details, action.action_id)
        except Exception as error:
            logger.error("own tool not recorded: %s", type(error).__name__)
            return self._refuse("record_failed", type(error).__name__, action)
        return Outcome(Verdict.ALLOW, decision_id, "")

    def _refuse(self, reason: str, code: str, action: ObservedAction | None = None) -> Outcome:
        decision_id = new_id("dec")
        details: dict[str, Any] = {"decision_id": decision_id, "reason": reason, "code": code}
        if action is not None:
            details |= {"kind": action.kind.value, "session_id": action.session_id}
        try:
            target = "" if action is None else action.action_id
            self._event("ciso.plugin.refuse", AuditOutcome.DENIED, details, target)
        except Exception as error:
            logger.error("refusal not recorded: %s", type(error).__name__)
        text = messages.REFUSAL_TEXTS[reason] + f" (CISO decision {decision_id})"
        return Outcome(Verdict.DENY, decision_id, text)
