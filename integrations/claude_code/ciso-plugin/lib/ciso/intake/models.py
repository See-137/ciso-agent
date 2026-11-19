"""What the intake hands on: one action (or several, for a gate tool call frame) plus the
content the inspection lane needs, held in memory only."""

from __future__ import annotations

from typing import Annotated, Literal

from pydantic import Field

from ciso.common.activity import InspectionInput, ObservedAction, Text
from ciso.common.schemas import Model

#: Most tool calls accepted in one central gate tool call frame.
MAX_TOOL_CALLS_PER_FRAME = 64


class NormalizedReport(Model):
    """One hook report. `inspection` carries the redacted command, the redacted prompt or
    the file content for the inspection lane; its content never appears in a repr and
    must never be stored."""

    action: ObservedAction
    inspection: InspectionInput | None = None


class GateFrame(Model):
    """One signed central gate frame. A prompt frame gives one action; a tool call frame
    gives one action per tool call, in the order the model produced them. The platform's
    single verdict covers the whole frame (see `render_frame_verdict`)."""

    request_id: Text
    frame_type: Literal["prompt", "tool_call"]
    actions: Annotated[
        tuple[ObservedAction, ...], Field(min_length=1, max_length=MAX_TOOL_CALLS_PER_FRAME)
    ]
    inspections: Annotated[
        tuple[InspectionInput, ...], Field(max_length=MAX_TOOL_CALLS_PER_FRAME)
    ] = ()
