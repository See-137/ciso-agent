"""The decision pipeline behind `POST /v1/governance/decide` and `POST /v1/activity`
(docs/skill/decision-api.md; spec section 4, steps 1-7).

Order for one hook report, from a device the API layer already authenticated:

1. normalize (`ciso.intake.normalize_hook_report`): the request becomes one
   `ObservedAction` plus the content to inspect, held in memory only. The device name is
   the registered name of the authenticated device (`device_names`), never the request's;
   a request naming another device is refused (review H4, queue Q8);
2. attribute (`AgentRegistry.attribute`): person and agent behind the session;
3. inspect, when `requires_inspection(action)` (`Inspector.inspect` on the normalized
   input). A push or commit is inspected through its uploaded change
   (docs/skill/decision-api.md, "Pre-push change upload"):
   - asked WITHOUT a change, its inspection is incomplete and the ruleset's
     `missing_inspection: deny` refuses it. When that is the only reason and the command
     is one plain git push or commit (`ciso.app.change_shape`), the deny carries
     `needs_change` and the client uploads the change and asks again; otherwise the
     engineer is told to use the plain form (`PLAIN_COMMAND_NOTE`);
   - asked WITH `change_id` and `change_head`: the change must belong to this device and
     session, be unexpired and match the command and head (`ChangeService.resolve`), or
     the answer is `change_refused`. While the sandbox report is not back the answer is
     `checks_pending`. Then the command's, the diff's and the sandbox's results are merged
     into one inspection and the rules decide (a commit has no sandbox run);
4. decide (`GovernanceEngine.decide`, which audits the decision itself). An allowed push
   asked with its change records its head as approved for its repository and branch
   (`ChangeService.record_approved`, review H1);
5. record findings (`FindingsService.record`): for decide, every decision; for activity,
   denials only.

Decide never raises and never answers allow by accident: any step that fails becomes a
deny with a fixed message, a fresh decision id and an audit record of the refusal
(`governance.pipeline.refuse`). Activity never blocks anything; a failed step raises
`FailClosed` (the API answers 503, the client drops the record and the gap is visible).
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from enum import StrEnum
from typing import Any, Final

from ciso.app.change_decide import (
    ChangeRef,
    NeedsChange,
    merge_inspections,
    sandbox_failed,
    split_change_ref,
)
from ciso.app.change_models import ChangeRefused, ChangeState, ResolvedChange
from ciso.app.change_shape import change_shape
from ciso.app.changes import ChangeService
from ciso.common.activity import (
    ActionKind,
    GovernanceDecision,
    InspectionInput,
    InspectionResult,
    ObservedAction,
    Phase,
    Verdict,
)
from ciso.common.clock import Clock
from ciso.common.enums import ActorType, AuditOutcome
from ciso.common.errors import FailClosed, ValidationFailed
from ciso.common.ids import new_id
from ciso.common.protocols import AuditEvent, AuditSink, Redactor
from ciso.common.schemas import Model
from ciso.findings import FindingsService
from ciso.governance import (
    MESSAGES,
    ClassifierConfig,
    CommandClass,
    GovernanceEngine,
    ReasonCode,
    classify_command,
    requires_inspection,
)
from ciso.inspection import Inspector
from ciso.intake import IntakeRefused, NormalizedReport, normalize_hook_report

logger = logging.getLogger(__name__)

REFUSE_ACTION: Final = "governance.pipeline.refuse"
ACTIVITY_ACTION: Final = "governance.activity"

#: Added to the message of a refused push or commit whose change can be scanned: the
#: AI-governance client uploads it and asks again. Fixed text; nothing is echoed.
CHANGE_SCAN_NOTE: Final = (
    " The change must be scanned first: an up-to-date AI-governance client sends it for "
    "scanning and asks again automatically."
)
#: Added when the push or commit is not one plain git command, so its change cannot be
#: scanned before it runs.
PLAIN_COMMAND_NOTE: Final = (
    " Pushes and commits by AI agents are scanned before they run, and only a single plain "
    "command that names one branch can be scanned: push one branch at a time and name it, "
    "as in git push <remote> <branch> (no bare git push, no --all, --tags, --mirror, "
    "deletes or refspec lists), or commit with git commit -m <message>, each on its own."
)
#: Reason codes that mean only the inspection was missing.
_INSPECTION_CODES: Final = frozenset(
    {ReasonCode.INSPECTION_INCOMPLETE.value, ReasonCode.INSPECTION_MISSING.value}
)
_HELD_KINDS: Final = frozenset({ActionKind.GIT_PUSH, ActionKind.GIT_COMMIT})
_CHANGE_CLASSES: Final = frozenset(
    {CommandClass.GIT_PUSH, CommandClass.GIT_FORCE_PUSH, CommandClass.GIT_COMMIT}
)
#: Probe config: every branch counts, only "does this commit or push" is asked.
_PROBE: Final = ClassifierConfig(protected_branches=("**",))


def carries_a_change(action: ObservedAction) -> bool:
    """True for a push or commit, including one inside a shell command. Its change content
    is not part of a hook report in this build, so its inspection is never complete."""
    if action.kind in _HELD_KINDS:
        return True
    if action.kind is not ActionKind.SHELL_COMMAND or action.command is None:
        return False
    classes = classify_command(action.command, _PROBE, truncated=action.command_truncated)
    return bool(classes.classes & _CHANGE_CLASSES)


class PipelineReason(StrEnum):
    """Why the pipeline itself refused, before or after the engine decided."""

    INVALID_REPORT = "invalid_report"
    ATTRIBUTION_UNAVAILABLE = "attribution_unavailable"
    INSPECTION_FAILED = "inspection_failed"
    FINDINGS_UNAVAILABLE = "findings_unavailable"
    CHECKS_PENDING = "checks_pending"
    CHANGE_REFUSED = "change_refused"
    INTERNAL_ERROR = "internal_error"


_CONTACT = "If it keeps happening, contact the security team."
PIPELINE_MESSAGES: Final[dict[PipelineReason, str]] = {
    PipelineReason.INVALID_REPORT: (
        "Blocked: the governance service could not read the report of this action, so it "
        "was stopped. Make sure the AI-governance client is up to date. " + _CONTACT
    ),
    PipelineReason.ATTRIBUTION_UNAVAILABLE: (
        "Blocked: the agent registry could not be consulted, so no decision could be "
        "made. Try again in a moment. " + _CONTACT
    ),
    PipelineReason.INSPECTION_FAILED: (
        "Blocked: the content check could not run, so the action was stopped. Try again "
        "in a moment. " + _CONTACT
    ),
    PipelineReason.FINDINGS_UNAVAILABLE: (
        "Blocked: the decision could not be recorded, so the action was stopped. Try again "
        "in a moment. " + _CONTACT
    ),
    PipelineReason.CHECKS_PENDING: (
        "Held: the pre-push checks of this change are still running. Retry the push in a "
        "minute; it goes ahead once the checks pass."
    ),
    PipelineReason.CHANGE_REFUSED: (
        "Blocked: the scan result sent with this action does not belong to it (unknown, "
        "expired, from another session, or for different commits). Retry the action so "
        "the change is scanned again. " + _CONTACT
    ),
    PipelineReason.INTERNAL_ERROR: MESSAGES[ReasonCode.INTERNAL_ERROR],
}


class DecideResponse(Model):
    """The decision-API response body."""

    verdict: Verdict
    decision_id: str
    reason: str
    message: str
    #: Present only on a deny whose sole reason is the missing change (see module doc).
    needs_change: NeedsChange | None = None


class ActivityResponse(Model):
    recorded: bool
    action_id: str


class _Refused(Exception):
    def __init__(self, reason: PipelineReason, action: ObservedAction | None = None,
                 code: str = "") -> None:  # fmt: skip
        super().__init__(reason.value)
        self.reason = reason
        self.action = action
        self.code = code


class DecisionPipeline:
    def __init__(
        self,
        *,
        clock: Clock,
        audit: AuditSink,
        redactor: Redactor,
        attribution: Any,
        inspector: Inspector,
        engine: GovernanceEngine,
        findings: FindingsService,
        actor_id: str,
        device_names: Callable[[str], str | None],
        changes: ChangeService | None = None,
    ) -> None:
        self._clock = clock
        self._audit = audit
        self._redactor = redactor
        self._attribution = attribution
        self._inspector = inspector
        self._engine = engine
        self._findings = findings
        self._actor = actor_id
        self._device_names = device_names
        self._changes = changes

    # --- decide ----------------------------------------------------------------------

    def decide(self, request: Any, *, device_actor_id: str) -> DecideResponse:
        """Allow, deny or ask for one BEFORE report. Never raises."""
        try:
            return self._decide(request, device_actor_id)
        except _Refused as refused:
            return self._refusal(refused)
        except Exception as exc:
            logger.error("governance pipeline failed: %s", type(exc).__name__)
            return self._refusal(_Refused(PipelineReason.INTERNAL_ERROR))

    def _decide(self, request: Any, device_actor_id: str) -> DecideResponse:
        try:
            request, ref = split_change_ref(request)
        except ValueError:
            raise _Refused(PipelineReason.INVALID_REPORT, code="invalid_change_ref") from None
        report = self._normalize(request, device_actor_id)
        action = report.action
        inspection: InspectionResult | None
        change: ResolvedChange | None = None
        if ref is not None:
            inspection, change = self._change_inspection(action, report, ref, device_actor_id)
            decision = self._engine.decide(action, self._attribute(action), inspection)
        else:
            decision, inspection = self.judge(action, report)
        try:
            self.record_findings(decision, action, inspection)
        except Exception as exc:
            logger.error("governance pipeline: findings not recorded (%s)", type(exc).__name__)
            raise _Refused(PipelineReason.FINDINGS_UNAVAILABLE, action) from exc
        if change is not None and decision.verdict is Verdict.ALLOW:
            self._approve_head(change, decision.decision_id)
        return _response(decision, action, inspection, attached=ref is not None)

    def _approve_head(self, change: ResolvedChange, decision_id: str) -> None:
        """An allowed, fully scanned push: its head becomes a base later pushes may start
        their scan from (review H1). Not recorded means a later push scans more, never
        less, so a failure here is logged and the allow stands."""
        if self._changes is None:
            return
        try:
            self._changes.record_approved(change, decision_id=decision_id)
        except Exception as exc:
            logger.error("governance pipeline: head not recorded (%s)", type(exc).__name__)

    def judge(
        self, action: ObservedAction, report: NormalizedReport | None
    ) -> tuple[GovernanceDecision, InspectionResult | None]:
        """Steps 2-4 for one normalized action. Raises `_Refused` for a failed step."""
        attribution = self._attribute(action)
        inspection = self._inspect(action, report)
        return self._engine.decide(action, attribution, inspection), inspection

    def _attribute(self, action: ObservedAction) -> Any:
        try:
            return self._attribution.attribute(action)
        except Exception as exc:
            logger.error("governance pipeline: attribution failed (%s)", type(exc).__name__)
            raise _Refused(PipelineReason.ATTRIBUTION_UNAVAILABLE, action) from exc

    def _change_inspection(
        self, action: ObservedAction, report: NormalizedReport, ref: ChangeRef, device: str
    ) -> tuple[InspectionResult, ResolvedChange]:
        """The merged inspection of a push or commit asked with its change, and the change.
        Raises `_Refused` (change_refused, checks_pending, inspection_failed)."""
        shape = change_shape(action)
        if shape is None or not carries_a_change(action) or self._changes is None:
            raise _Refused(PipelineReason.CHANGE_REFUSED, action, code="change_not_applicable")
        try:
            change = self._changes.resolve(
                ref.change_id, device_actor_id=device, session_id=action.session_id,
                shape=shape, head=ref.head,
            )  # fmt: skip
        except ChangeRefused as refused:
            raise _Refused(PipelineReason.CHANGE_REFUSED, action, code=refused.code.value) from None
        except Exception as exc:
            logger.error("governance pipeline: change lookup failed (%s)", type(exc).__name__)
            raise _Refused(PipelineReason.INSPECTION_FAILED, action) from exc
        if change.state is ChangeState.PENDING:
            raise _Refused(PipelineReason.CHECKS_PENDING, action)
        parts = [self._inspect_plain(action, report), change.diff]
        if change.state is ChangeState.FAILED:
            parts.append(sandbox_failed(action.action_id))
        elif change.state is ChangeState.DONE:
            parts.append(change.sandbox)
        return merge_inspections(action.action_id, parts), change

    def _inspect_plain(
        self, action: ObservedAction, report: NormalizedReport
    ) -> InspectionResult | None:
        """The command text's own inspection (secrets and risky code in it). Read as a
        shell command: the change itself is inspected through its upload, and the intake's
        `git_push` / `git_commit` kinds would otherwise ask for content here."""
        command = None if report.inspection is None else report.inspection.command
        if command is None:
            return None
        item = InspectionInput(
            action_id=action.action_id, kind=ActionKind.SHELL_COMMAND, command=command
        )
        try:
            return self._inspector.inspect(item)
        except Exception as exc:
            logger.error("governance pipeline: inspection failed (%s)", type(exc).__name__)
            raise _Refused(PipelineReason.INSPECTION_FAILED, action) from exc

    def record_findings(
        self,
        decision: GovernanceDecision,
        action: ObservedAction,
        inspection: InspectionResult | None,
    ) -> None:
        """Step 5. Raises when the findings could not be recorded; callers refuse."""
        self._findings.record(decision, action, inspection, decision_id=decision.decision_id)

    def _normalize(self, request: Any, device_actor_id: str) -> NormalizedReport:
        try:
            device_name = self._device_names(device_actor_id)
        except Exception as exc:
            logger.error("governance pipeline: device directory failed (%s)", type(exc).__name__)
            raise _Refused(PipelineReason.ATTRIBUTION_UNAVAILABLE) from exc
        try:
            return normalize_hook_report(
                request,
                device_actor_id=device_actor_id,
                device_name=device_name,
                received_at=self._clock.now(),
                redactor=self._redactor,
            )
        except IntakeRefused as refused:
            raise _Refused(PipelineReason.INVALID_REPORT, code=refused.code.value) from None

    def _inspect(
        self, action: ObservedAction, report: NormalizedReport | None
    ) -> InspectionResult | None:
        if not requires_inspection(action):
            return None
        item = None if report is None else report.inspection
        if item is None:
            return InspectionResult(action_id=action.action_id, complete=False)
        try:
            result = self._inspector.inspect(item)
        except Exception as exc:
            logger.error("governance pipeline: inspection failed (%s)", type(exc).__name__)
            raise _Refused(PipelineReason.INSPECTION_FAILED, action) from exc
        if result.complete and carries_a_change(action):
            return result.model_copy(update={"complete": False})
        return result

    def _refusal(self, refused: _Refused) -> DecideResponse:
        decision_id = new_id("dec")
        details: dict[str, Any] = {"decision_id": decision_id, "reason": refused.reason.value}
        if refused.code:
            details["refusal_code"] = refused.code
        target = ""
        if refused.action is not None:
            target = refused.action.action_id
            details["session_id"] = refused.action.session_id
            details["kind"] = refused.action.kind.value
        self._emit(REFUSE_ACTION, target, AuditOutcome.DENIED, details, required=False)
        return DecideResponse(
            verdict=Verdict.DENY,
            decision_id=decision_id,
            reason=refused.reason.value,
            message=PIPELINE_MESSAGES[refused.reason],
        )

    # --- activity --------------------------------------------------------------------

    def record_activity(self, request: Any, *, device_actor_id: str) -> ActivityResponse:
        """Record one AFTER report. Raises `ValidationFailed` (a refused report or a
        BEFORE event) or `FailClosed` (a step failed); never blocks anything."""
        try:
            report = self._normalize(request, device_actor_id)
        except _Refused as refused:
            raise ValidationFailed(f"activity report refused: {refused.code}") from None
        action = report.action
        if action.phase is not Phase.AFTER:
            raise ValidationFailed("a BEFORE event must be asked through decide")
        try:
            decision, inspection = self.judge(action, report)
            if decision.verdict is Verdict.DENY:
                self.record_findings(decision, action, inspection)
        except _Refused as refused:
            raise FailClosed(f"activity not recorded: {refused.reason.value}") from None
        except Exception as exc:
            logger.error("governance activity not recorded (%s)", type(exc).__name__)
            raise FailClosed("activity not recorded") from None
        return ActivityResponse(recorded=True, action_id=action.action_id)

    # --- audit -----------------------------------------------------------------------

    def _emit(self, action: str, target: str, outcome: AuditOutcome, details: dict[str, Any],
              *, required: bool) -> None:  # fmt: skip
        event = AuditEvent(
            actor_id=self._actor,
            actor_type=ActorType.SERVICE,
            action=action,
            target=target,
            outcome=outcome,
            details=details,
        )
        try:
            self._audit.append(event)
        except Exception as exc:
            logger.error("governance pipeline: %s not audited (%s)", action, type(exc).__name__)
            if required:
                raise FailClosed(f"{action} could not be audited") from exc


def _response(
    decision: GovernanceDecision,
    action: ObservedAction,
    inspection: InspectionResult | None,
    *,
    attached: bool = False,
) -> DecideResponse:
    """The API answer. A deny whose only reasons are the missing inspection of a push or
    commit that can be scanned carries `needs_change` (never when a change was attached)."""
    message = decision.explanation
    needs: NeedsChange | None = None
    held = (
        not attached
        and carries_a_change(action)
        and inspection is not None
        and not inspection.complete
        and decision.verdict is not Verdict.ALLOW
    )
    if held:
        shape = change_shape(action)
        only_inspection = all(r.code in _INSPECTION_CODES for r in decision.reasons)
        if shape is not None and only_inspection and decision.verdict is Verdict.DENY:
            needs = NeedsChange.of(shape)
            message = message + CHANGE_SCAN_NOTE
        else:
            message = message + PLAIN_COMMAND_NOTE
    return DecideResponse(
        verdict=decision.verdict,
        decision_id=decision.decision_id,
        reason=decision.reasons[0].code,
        message=message,
        needs_change=needs,
    )
