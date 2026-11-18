"""Turning a `ToolView` into the contract records, for both formats.

Contract validation errors from pydantic quote the offending input value, which could be
a secret or content, so they are replaced by a bare `INVALID_FIELD` refusal with the
exception chain suppressed.
"""

from __future__ import annotations

import hashlib
from datetime import datetime
from typing import NamedTuple

from pydantic import ValidationError

from ciso.common.activity import (
    ActionKind,
    ActivitySource,
    IdentityClaim,
    InspectionInput,
    ObservedAction,
    Phase,
)
from ciso.common.protocols import Redactor
from ciso.intake.errors import RefusalCode, refuse
from ciso.intake.tools import ToolView, content_digest

#: Hex characters of the hash kept in an action id. 40 keeps gate ids within the
#: platform's 50-character reference id limit.
ACTION_ID_HEX = 40
_SEPARATOR = "\x1f"


def derive_action_id(prefix: str, *parts: str) -> str:
    """Deterministic id from parts that are already clean text (no control characters),
    so joining them with a unit separator is unambiguous."""
    digest = hashlib.sha256(_SEPARATOR.join(parts).encode("utf-8")).hexdigest()
    return f"{prefix}_{digest[:ACTION_ID_HEX]}"


class Origin(NamedTuple):
    """Fields that describe where a report came from, the same for every action in it."""

    session_id: str
    source: ActivitySource
    phase: Phase
    surface: str
    received_at: datetime
    claims: tuple[IdentityClaim, ...]


def _inspection(action_id: str, view: ToolView, redactor: Redactor) -> InspectionInput | None:
    if view.command is not None:
        return InspectionInput(action_id=action_id, kind=view.kind, command=view.command)
    if view.content is not None:
        return InspectionInput(
            action_id=action_id, kind=view.kind, path=view.path, content=view.content
        )
    if view.prompt is not None:
        return InspectionInput(
            action_id=action_id, kind=view.kind, content=redactor.redact(view.prompt)
        )
    return None


def build_action(
    *,
    action_id: str,
    origin: Origin,
    tool_name: str,
    view: ToolView,
    target: dict[str, str],
    redactor: Redactor,
) -> tuple[ObservedAction, InspectionInput | None]:
    """The action and its inspection input. Target values are redacted as well: a path
    or a remote can carry a credential."""
    digest, size = content_digest(view.content) if view.content is not None else (None, None)
    clean_target = {key: redactor.redact(value) for key, value in target.items() if value}
    try:
        action = ObservedAction(
            action_id=action_id,
            session_id=origin.session_id,
            source=origin.source,
            phase=origin.phase,
            kind=view.kind,
            tool_name=tool_name,
            surface=origin.surface,
            received_at=origin.received_at,
            identity_claims=origin.claims,
            target=clean_target,
            command=view.command,
            command_truncated=view.truncated,
            content_sha256=digest,
            content_bytes=size,
        )
        return action, _inspection(action_id, view, redactor)
    except ValidationError:
        raise refuse(RefusalCode.INVALID_FIELD) from None


def make_claim(kind: str, subject: str, *, verified: bool) -> IdentityClaim:
    try:
        return IdentityClaim(kind=kind, subject=subject, verified=verified)
    except ValidationError:
        raise refuse(RefusalCode.INVALID_FIELD) from None


def prompt_view(text: str) -> ToolView:
    return ToolView(ActionKind.PROMPT, {}, prompt=text)
