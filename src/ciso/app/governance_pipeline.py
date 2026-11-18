"""The decision pipeline behind `POST /v1/governance/decide` and `POST /v1/activity`
(docs/skill/decision-api.md; spec section 4, steps 1-7).

Order for one hook report, from a device the API layer already authenticated:

1. normalize (`ciso.intake.normalize_hook_report`): the request becomes one
   `ObservedAction` plus the content to inspect, held in memory only;
2. attribute (`AgentRegistry.attribute`): person and agent behind the session;
3. inspect, when `requires_inspection(action)` (`Inspector.inspect` on the normalized
   input). A push or commit carries no change content in this build (the sandbox lane
   uploads it later), so its inspection is incomplete and the ruleset's
   `missing_inspection: deny` refuses it; the engineer is told so (`PUSH_HELD_NOTE`);
4. decide (`GovernanceEngine.decide`, which audits the decision itself);
5. record findings (`FindingsService.record`): for decide, every decision; for activity,
   denials only.

Decide never raises and never answers allow by accident: any step that fails becomes a
deny with a fixed message, a fresh decision id and an audit record of the refusal
(`governance.pipeline.refuse`). Activity never blocks anything; a failed step raises
`FailClosed` (the API answers 503, the client drops the record and the gap is visible).
"""

from __future__ import annotations

import logging
from enum import StrEnum
from typing import Any, Final

from ciso.common.activity import (
    ActionKind,
    GovernanceDecision,
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

#: Added to the message of a refused push or commit whose change content was not there to
#: inspect. Fixed text; nothing from the action is echoed.
PUSH_HELD_NOTE: Final = (
    " Pushes and commits by AI agents are held until the pre-push scan of the change is "
    "available on this service; push this change yourself after review, or ask the "
    "security team."
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
    PipelineReason.INTERNAL_ERROR: MESSAGES[ReasonCode.INTERNAL_ERROR],
}


class DecideResponse(Model):
    """The decision-API response body."""

    verdict: Verdict
    decision_id: str
    reason: str
    message: str


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
    ) -> None:
        self._clock = clock
        self._audit = audit
        self._redactor = redactor
        self._attribution = attribution
        self._inspector = inspector
        self._engine = engine
        self._findings = findings
        self._actor = actor_id

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
        report = self._normalize(request, device_actor_id)
        action = report.action
        decision, inspection = self.judge(action, report)
        try:
            self.record_findings(decision, action, inspection)
        except Exception as exc:
            logger.error("governance pipeline: findings not recorded (%s)", type(exc).__name__)
            raise _Refused(PipelineReason.FINDINGS_UNAVAILABLE, action) from exc
        return _response(decision, action, inspection)

    def judge(
        self, action: ObservedAction, report: NormalizedReport | None
    ) -> tuple[GovernanceDecision, InspectionResult | None]:
        """Steps 2-4 for one normalized action. Raises `_Refused` for a failed step."""
        try:
            attribution = self._attribution.attribute(action)
        except Exception as exc:
            logger.error("governance pipeline: attribution failed (%s)", type(exc).__name__)
            raise _Refused(PipelineReason.ATTRIBUTION_UNAVAILABLE, action) from exc
        inspection = self._inspect(action, report)
        return self._engine.decide(action, attribution, inspection), inspection

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
            return normalize_hook_report(
                request,
                device_actor_id=device_actor_id,
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
    decision: GovernanceDecision, action: ObservedAction, inspection: InspectionResult | None
) -> DecideResponse:
    message = decision.explanation
    held = (
        carries_a_change(action)
        and inspection is not None
        and not inspection.complete
        and decision.verdict is not Verdict.ALLOW
    )
    if held:
        message = message + PUSH_HELD_NOTE
    return DecideResponse(
        verdict=decision.verdict,
        decision_id=decision.decision_id,
        reason=decision.reasons[0].code,
        message=message,
    )
