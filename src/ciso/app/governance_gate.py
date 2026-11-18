"""The central gate endpoint's logic (spec C4; `ciso.intake.central_gate`).

The assistant platform posts signed frames and expects `{"action": "allow"}` or a deny.
For one delivery:

1. no gate configured (`governance.central_gate_*` unset): deny;
2. `CentralGate.receive` verifies size, signature, time and replay, then parses. A frame
   type this build does not know is ALLOWED, as the platform's documentation requires
   for forward compatibility, but only after its signature held, and it is audited;
3. any other refusal (bad signature, replay, malformed frame): deny with the reason code;
4. each action of the frame goes through the decision pipeline (attribute, inspect,
   decide, record findings); one verdict covers the frame (`render_frame_verdict`);
5. a failure to decide is a deny. The gate's own failure behaviour belongs to the
   platform; this endpoint never answers an error that could be read as "no opinion".

Every delivery is audited as `governance.central_gate`.
"""

from __future__ import annotations

import logging
from collections.abc import Mapping
from typing import Any, Final

from ciso.app.governance_pipeline import DecisionPipeline
from ciso.common.enums import ActorType, AuditOutcome
from ciso.common.protocols import AuditEvent, AuditSink
from ciso.intake import (
    CentralGate,
    IntakeRefused,
    NormalizedReport,
    RefusalCode,
    render_frame_verdict,
    render_refusal,
)

logger = logging.getLogger(__name__)

GATE_ACTION: Final = "governance.central_gate"
NOT_CONFIGURED: Final = "not_configured"
DECISION_FAILED: Final = "decision_failed"
_DENY_TEXT: Final = (
    "The company's AI governance service could not check this request, so it was stopped."
)


def _deny(reference: str) -> dict[str, str]:
    return {"action": "deny", "deny_reason": _DENY_TEXT, "reference_id": reference}


class GateEndpoint:
    def __init__(
        self,
        gate: CentralGate | None,
        *,
        pipeline: DecisionPipeline,
        audit: AuditSink,
        actor_id: str,
    ) -> None:
        self._gate = gate
        self._pipeline = pipeline
        self._audit = audit
        self._actor = actor_id

    @property
    def configured(self) -> bool:
        return self._gate is not None

    def answer(self, headers: Mapping[str, str], body: bytes) -> dict[str, str]:
        """The verdict body for one delivery. Never raises."""
        gate = self._gate
        if gate is None:
            self._record(AuditOutcome.DENIED, {"reason": NOT_CONFIGURED})
            return _deny(NOT_CONFIGURED)
        try:
            frame = gate.receive(headers, body)
        except IntakeRefused as refused:
            if refused.code is RefusalCode.UNKNOWN_FRAME_TYPE:
                details = {"reason": refused.code.value, "verdict": "allow"}
                if self._record(AuditOutcome.SUCCESS, details):
                    return {"action": "allow"}
                return _deny(DECISION_FAILED)
            self._record(AuditOutcome.DENIED, {"reason": refused.code.value})
            return render_refusal(refused)
        except Exception as exc:
            logger.error("central gate: delivery failed (%s)", type(exc).__name__)
            self._record(AuditOutcome.FAILED, {"reason": DECISION_FAILED})
            return _deny(DECISION_FAILED)
        inspections = {item.action_id: item for item in frame.inspections}
        decisions = []
        try:
            for action in frame.actions:
                found = inspections.get(action.action_id)
                report = NormalizedReport(action=action, inspection=found)
                decision, inspection = self._pipeline.judge(action, report)
                self._pipeline.record_findings(decision, action, inspection)
                decisions.append(decision)
        except Exception as exc:
            logger.error("central gate: decision failed (%s)", type(exc).__name__)
            self._record(AuditOutcome.FAILED, {"reason": DECISION_FAILED,
                                               "request_id": frame.request_id})  # fmt: skip
            return _deny(DECISION_FAILED)
        verdict = render_frame_verdict(decisions)
        outcome = AuditOutcome.SUCCESS if verdict["action"] == "allow" else AuditOutcome.DENIED
        self._record(outcome, {"request_id": frame.request_id, "verdict": verdict["action"],
                               "decision_ids": [d.decision_id for d in decisions]})  # fmt: skip
        return verdict

    def _record(self, outcome: AuditOutcome, details: dict[str, Any]) -> bool:
        """Audit one delivery. False when the log refused the record."""
        event = AuditEvent(
            actor_id=self._actor,
            actor_type=ActorType.SERVICE,
            action=GATE_ACTION,
            outcome=outcome,
            details=details,
        )
        try:
            self._audit.append(event)
        except Exception as exc:
            logger.error("central gate: delivery not audited (%s)", type(exc).__name__)
            return False
        return True
