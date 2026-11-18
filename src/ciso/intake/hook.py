"""`assistant_hook_v1`: a hook report posted to the decision API (docs/skill/decision-api.md).

The envelope is a closed schema: `format`, `event`, `surface`, `claims`, `payload`, and
an optional `device` (missing or null: no device), at most `MAX_REQUEST_BYTES` of JSON.
The payload is the hook's own input, passed through unchanged by the client; its known
fields are checked and its other fields are ignored, because the assistant adds fields
between releases. The device name also becomes the `device` target attribute.

Who reported it: the device actor the API layer authenticated from the bearer token is
the one verified claim. Every claim the client sends stays unverified, and a client that
marks one verified is refused.

The action id is derived from the session id, the event and the tool_use_id (tool
events), prompt_id (prompt and stop events), agent_id (subagent start) or the session
start source, so a retried report is the same action. Two SessionStart reports for the
same session and the same source (two resumes) get the same id; that is a known limit.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from datetime import datetime
from typing import Any

from ciso.common.activity import (
    MAX_ENTRIES,
    ActionKind,
    ActivitySource,
    IdentityClaim,
    Phase,
    clean_text,
)
from ciso.common.protocols import Redactor
from ciso.intake.build import Origin, build_action, derive_action_id, make_claim, prompt_view
from ciso.intake.errors import IntakeRefused, RefusalCode, refuse
from ciso.intake.jsonshape import check_json_value, encoded_size
from ciso.intake.models import NormalizedReport
from ciso.intake.tools import ToolView, classify_tool

FORMAT = "assistant_hook_v1"
#: Largest accepted request, in bytes of compact JSON (decision-api.md: 256 KiB).
MAX_REQUEST_BYTES = 256 * 1024
#: Deepest accepted nesting of the request.
MAX_REQUEST_DEPTH = 32

REQUIRED_KEYS = frozenset({"format", "event", "surface", "claims", "payload"})
ENVELOPE_KEYS = REQUIRED_KEYS | {"device"}
#: Target attribute naming the reporting machine. Must equal the agents registry's
#: `DEVICE_TARGET_KEY`, which matches sessions and agents on it (a test pins the two).
DEVICE_TARGET_KEY = "device"
CLAIM_KEYS = frozenset({"kind", "subject", "verified"})
TOOL_EVENTS = frozenset({"PreToolUse", "PostToolUse"})
EVENTS: Mapping[str, Phase] = {
    "PreToolUse": Phase.BEFORE,
    "UserPromptSubmit": Phase.BEFORE,
    "PostToolUse": Phase.AFTER,
    "SessionStart": Phase.AFTER,
    "SessionEnd": Phase.AFTER,
    "SubagentStart": Phase.AFTER,
    "Stop": Phase.AFTER,
}

_SURFACE = re.compile(r"[a-z][a-z0-9_-]{0,31}")
_DEVICE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}")
_IDENT = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}")
_TOOL_NAME = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_.:-]{0,255}")
_SESSION_SOURCE = re.compile(r"[a-z_]{1,32}")


def _matching(value: Any, pattern: re.Pattern[str]) -> str:
    if not isinstance(value, str) or not pattern.fullmatch(value):
        raise refuse(RefusalCode.INVALID_FIELD)
    return value


def _clean(value: Any) -> str:
    if not isinstance(value, str):
        raise refuse(RefusalCode.INVALID_FIELD)
    try:
        return clean_text(value)
    except ValueError:
        raise refuse(RefusalCode.INVALID_FIELD) from None


def _envelope(request: Any) -> dict[str, Any]:
    if not isinstance(request, dict):
        raise refuse(RefusalCode.INVALID_FIELD)
    check_json_value(request, max_depth=MAX_REQUEST_DEPTH, code=RefusalCode.NOT_JSON)
    if encoded_size(request) > MAX_REQUEST_BYTES:
        raise refuse(RefusalCode.REQUEST_TOO_LARGE)
    keys = set(request)
    if keys - ENVELOPE_KEYS:
        raise refuse(RefusalCode.UNKNOWN_FIELD)
    if REQUIRED_KEYS - keys:
        raise refuse(RefusalCode.MISSING_FIELD)
    if request["format"] != FORMAT:
        raise refuse(RefusalCode.UNSUPPORTED_FORMAT)
    if not isinstance(request["payload"], dict):
        raise refuse(RefusalCode.INVALID_FIELD)
    return request


def _claims(raw: Any, device: str | None, device_actor_id: str) -> tuple[IdentityClaim, ...]:
    if not isinstance(raw, list) or len(raw) > MAX_ENTRIES - 2:
        raise refuse(RefusalCode.INVALID_FIELD)
    claims = []
    for item in raw:
        if not isinstance(item, dict) or set(item) != CLAIM_KEYS:
            raise refuse(RefusalCode.INVALID_FIELD)
        if item["verified"] is True:
            raise refuse(RefusalCode.CLAIM_MARKED_VERIFIED)
        if item["verified"] is not False or not isinstance(item["kind"], str):
            raise refuse(RefusalCode.INVALID_FIELD)
        claims.append(make_claim(item["kind"], _clean(item["subject"]), verified=False))
    if device is not None:
        claims.append(make_claim("device_name", device, verified=False))
    claims.append(make_claim("device_actor", device_actor_id, verified=True))
    return tuple(claims)


def _repository(cwd: str | None) -> dict[str, str]:
    if not cwd:
        return {}
    parts = [part for part in re.split(r"[/\\]", cwd) if part]
    if not parts or (len(parts) == 1 and parts[0].endswith(":")):
        return {}
    return {"repository": parts[-1]}


def _required_id(payload: Mapping[str, Any], key: str) -> str:
    if key not in payload or payload[key] is None:
        raise refuse(RefusalCode.MISSING_CORRELATION_ID)
    return _matching(payload[key], _IDENT)


def _event_view(
    event: str, payload: Mapping[str, Any], cwd: str | None, redactor: Redactor
) -> tuple[str, str, ToolView]:
    """(correlation id, tool name, view) for one event."""
    if event in TOOL_EVENTS:
        if "tool_name" not in payload or "tool_input" not in payload:
            raise refuse(RefusalCode.MISSING_FIELD)
        tool_name = _matching(payload["tool_name"], _TOOL_NAME)
        tool_input = payload["tool_input"]
        if not isinstance(tool_input, dict):
            raise refuse(RefusalCode.INVALID_FIELD)
        correlation = _required_id(payload, "tool_use_id")
        view = classify_tool(tool_name, tool_input, cwd=cwd, redactor=redactor)
        return correlation, tool_name, view
    if event == "UserPromptSubmit":
        correlation = _required_id(payload, "prompt_id")
        prompt = payload.get("prompt")
        if not isinstance(prompt, str):
            raise refuse(RefusalCode.INVALID_FIELD)
        return correlation, "", prompt_view(prompt)
    if event == "SubagentStart":
        correlation = _required_id(payload, "agent_id")
        agent_type = payload.get("agent_type")
        target = {"agent_type": _clean(agent_type)} if agent_type else {}
        return correlation, "", ToolView(ActionKind.SUBAGENT, target)
    if event == "SessionStart":
        source = payload.get("source", "unknown")
        return (
            "start:" + _matching(source, _SESSION_SOURCE),
            "",
            ToolView(ActionKind.SESSION_START, {}),
        )
    if event == "SessionEnd":
        return "end", "", ToolView(ActionKind.SESSION_END, {})
    prompt_id = payload.get("prompt_id")
    correlation = "stop:" + (_matching(prompt_id, _IDENT) if prompt_id is not None else "")
    return correlation, "", ToolView(ActionKind.OTHER_TOOL, {"event": event})


def normalize_hook_report(
    request: Any,
    *,
    device_actor_id: str,
    received_at: datetime,
    redactor: Redactor,
) -> NormalizedReport:
    """Validate a decision-API request and map it to one `ObservedAction`.

    Raises `IntakeRefused` with a `RefusalCode` for anything malformed; the caller stops
    the action. Does not mutate `request`.
    """
    envelope = _envelope(request)
    event = envelope["event"]
    if not isinstance(event, str) or event not in EVENTS:
        raise refuse(RefusalCode.UNKNOWN_EVENT)
    payload: dict[str, Any] = envelope["payload"]
    for key in ("session_id", "hook_event_name"):
        if key not in payload:
            raise refuse(RefusalCode.MISSING_FIELD)
    if payload["hook_event_name"] != event:
        raise refuse(RefusalCode.EVENT_MISMATCH)
    session_id = _matching(payload["session_id"], _IDENT)
    cwd = _clean(payload["cwd"]) if payload.get("cwd") is not None else None
    surface = _matching(envelope["surface"], _SURFACE)
    raw_device = envelope.get("device")
    device = None if raw_device is None else _matching(raw_device, _DEVICE)
    claims = _claims(envelope["claims"], device, _clean_actor(device_actor_id))
    correlation, tool_name, view = _event_view(event, payload, cwd, redactor)
    origin = Origin(session_id, ActivitySource.HOOK, EVENTS[event], surface, received_at, claims)
    action, inspection = build_action(
        action_id=derive_action_id("hk", FORMAT, session_id, event, correlation),
        origin=origin,
        tool_name=tool_name,
        view=view,
        target={**_repository(cwd), **view.target, **_device_target(device)},
        redactor=redactor,
    )
    return NormalizedReport(action=action, inspection=inspection)


def _clean_actor(device_actor_id: str) -> str:
    try:
        value = _clean(device_actor_id)
    except IntakeRefused:
        raise refuse(RefusalCode.INVALID_FIELD) from None
    if not value:
        raise refuse(RefusalCode.INVALID_FIELD)
    return value


def _device_target(device: str | None) -> dict[str, str]:
    """Merged last, so a tool view could not overwrite the reporting machine. No view sets
    this key today, so no test can reach the ordering; it is defence in depth."""
    return {} if device is None else {DEVICE_TARGET_KEY: device}
