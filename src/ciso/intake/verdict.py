"""The verdict body returned to the central gate.

Shape from the platform's endpoint documentation ("Return a verdict"): HTTP 200 with
`{"action": "allow"}` or `{"action": "deny", "deny_reason": ..., "reference_id": ...}`.
`deny_reason` is shown to the person, at most 500 characters. `reference_id` is at most
50 characters from `[A-Za-z0-9._:/-]`, recorded by the platform, never shown.

The gate can only allow or deny, so `ask` is rendered as deny: a held action may not run
while nobody can be asked through this channel. One verdict covers a whole frame, so a
frame is allowed only when every one of its decisions allows.
"""

from __future__ import annotations

import re
from collections.abc import Sequence

from ciso.common.activity import GovernanceDecision, Verdict
from ciso.intake.errors import IntakeRefused

MAX_DENY_REASON_CHARS = 500
MAX_REFERENCE_ID_CHARS = 50
_REFERENCE = re.compile(r"[A-Za-z0-9._:/-]{1,50}")


def _deny(reason: str, reference: str) -> dict[str, str]:
    body = {"action": "deny", "deny_reason": reason[:MAX_DENY_REASON_CHARS]}
    if _REFERENCE.fullmatch(reference):
        body["reference_id"] = reference
    return body


def render_verdict(decision: GovernanceDecision) -> dict[str, str]:
    """The body for one decision. Only `allow` allows."""
    if decision.verdict is Verdict.ALLOW:
        return {"action": "allow"}
    reason = decision.explanation or (
        f"Stopped by the company's AI policy ({decision.reasons[0].code})."
    )
    return _deny(reason, decision.action_id)


def render_frame_verdict(decisions: Sequence[GovernanceDecision]) -> dict[str, str]:
    """One body for a frame: the first non-allow decision, or allow when all allow.
    No decisions at all is a deny."""
    if not decisions:
        return _deny("No decision was reached for this request, so it was stopped.", "")
    for decision in decisions:
        if decision.verdict is not Verdict.ALLOW:
            return render_verdict(decision)
    return {"action": "allow"}


def render_refusal(refused: IntakeRefused) -> dict[str, str]:
    """A deny for a delivery the intake refused (malformed or not authenticated)."""
    reason = (
        "The company's AI governance service could not check this request, so it was "
        f"stopped (reason: {refused.code.value})."
    )
    return _deny(reason, refused.code.value)
