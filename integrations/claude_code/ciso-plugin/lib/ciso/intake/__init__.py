"""Intake of reported AI-agent activity (docs/skill/spec-draft.md, components C2 and C4).

Two formats, both pure and deterministic, no network:

- `assistant_hook_v1`: a hook report posted to the decision API
  (docs/skill/decision-api.md) -> `normalize_hook_report`.
- `central_gate_v1`: a signed frame from the assistant platform's central gate ->
  `CentralGate.receive`, answered with `render_verdict` / `render_frame_verdict`.

Bad input is refused with a `RefusalCode`; it never becomes an allow.
"""

from ciso.intake.central_gate import FORMAT as CENTRAL_GATE_FORMAT
from ciso.intake.central_gate import MAX_GATE_BODY_BYTES, CentralGate
from ciso.intake.errors import IntakeRefused, RefusalCode, SignatureRefused
from ciso.intake.hook import DEVICE_TARGET_KEY, MAX_REQUEST_BYTES, normalize_hook_report
from ciso.intake.hook import FORMAT as HOOK_FORMAT
from ciso.intake.models import MAX_TOOL_CALLS_PER_FRAME, GateFrame, NormalizedReport
from ciso.intake.replay import BoundedSeenMessages, SeenMessages
from ciso.intake.signature import VerifiedDelivery, verify_standard_webhook
from ciso.intake.verdict import (
    MAX_DENY_REASON_CHARS,
    render_frame_verdict,
    render_refusal,
    render_verdict,
)

__all__ = [
    "CENTRAL_GATE_FORMAT",
    "DEVICE_TARGET_KEY",
    "HOOK_FORMAT",
    "MAX_DENY_REASON_CHARS",
    "MAX_GATE_BODY_BYTES",
    "MAX_REQUEST_BYTES",
    "MAX_TOOL_CALLS_PER_FRAME",
    "BoundedSeenMessages",
    "CentralGate",
    "GateFrame",
    "IntakeRefused",
    "NormalizedReport",
    "RefusalCode",
    "SeenMessages",
    "SignatureRefused",
    "VerifiedDelivery",
    "normalize_hook_report",
    "render_frame_verdict",
    "render_refusal",
    "render_verdict",
    "verify_standard_webhook",
]
