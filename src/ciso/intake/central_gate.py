"""`central_gate_v1`: frames the assistant platform posts to the company's verdict endpoint.

Order of checks for one delivery: body size, then the Standard Webhooks signature (secret
resolved by reference on every delivery, so a rotation takes effect at once), then replay
memory, then the frame. Nothing is parsed before the signature holds.

Frame rules (platform endpoint documentation):

- `type` is `prompt` or `tool_call`. Any other type is refused with `unknown_frame_type`.
  The platform asks endpoints to allow unknown types; that choice belongs to the caller
  (the API lane), never to the intake.
- Unknown top-level fields, unknown content block types and unknown `tool_info` kinds are
  ignored, as the documentation requires; the fields this module reads are checked.
- `request_id` must equal the signed `webhook-id`.
- The actor's `id` and `email_address` become verified identity claims (the frame is
  signed by the platform). `session_id` is opaque and, for the command-line assistant,
  client-asserted: best effort only. A frame without one gets
  `unsessioned:<request_id>`, so sessionless frames are never merged into one session.
- A prompt frame gives one `prompt` action whose inspection content is the redacted text
  of the LAST message (text, tool result and attachment text); earlier messages were the
  last message of an earlier frame. A tool call frame gives one action per `tool_use`
  block of its last (assistant) message.
"""

from __future__ import annotations

from collections.abc import Iterator, Mapping
from datetime import timedelta
from typing import Any

from ciso.common.activity import (
    MAX_FIELD_CHARS,
    ActionKind,
    ActivitySource,
    IdentityClaim,
    InspectionInput,
    ObservedAction,
    Phase,
    clean_text,
)
from ciso.common.clock import Clock
from ciso.common.errors import CisoError, FailClosed
from ciso.common.protocols import Redactor, SecretResolver
from ciso.intake.build import Origin, build_action, derive_action_id, make_claim, prompt_view
from ciso.intake.errors import RefusalCode, SignatureRefused, refuse
from ciso.intake.jsonshape import loads_strict
from ciso.intake.models import MAX_TOOL_CALLS_PER_FRAME, GateFrame
from ciso.intake.replay import SeenMessages
from ciso.intake.signature import VerifiedDelivery, verify_standard_webhook
from ciso.intake.tools import ToolView, classify_tool

FORMAT = "central_gate_v1"
#: Largest body accepted: the protocol's own maximum (64 MiB).
MAX_GATE_BODY_BYTES = 64 * 1024 * 1024
#: Deepest accepted JSON nesting of a frame.
MAX_FRAME_DEPTH = 64
FRAME_TYPES = frozenset({"prompt", "tool_call"})

_MALFORMED = RefusalCode.MALFORMED_FRAME


def _text(value: Any, *, nullable: bool = False) -> str | None:
    """A clean, bounded string from the frame, or None where null is allowed."""
    if value is None and nullable:
        return None
    if not isinstance(value, str) or len(value) > MAX_FIELD_CHARS:
        raise refuse(_MALFORMED)
    try:
        return clean_text(value)
    except ValueError:
        raise refuse(_MALFORMED) from None


def _object(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise refuse(_MALFORMED)
    return value


class CentralGate:
    """Verifies and parses central gate deliveries. Holds references, never secret values.

    `tolerance_seconds` (signature timestamp window) has no default: `None` refuses every
    delivery. `seen` is the caller's bounded replay memory.
    """

    def __init__(
        self,
        *,
        secrets: SecretResolver,
        secret_ref: str,
        clock: Clock,
        redactor: Redactor,
        seen: SeenMessages,
        tolerance_seconds: int | None = None,
        previous_secret_ref: str | None = None,
    ) -> None:
        if tolerance_seconds is not None and tolerance_seconds <= 0:
            raise ValueError("signature tolerance must be a positive number of seconds")
        self._secrets = secrets
        self._refs = (
            (secret_ref,)
            if previous_secret_ref is None
            else (
                secret_ref,
                previous_secret_ref,
            )
        )
        self._clock = clock
        self._redactor = redactor
        self._seen = seen
        self._tolerance = tolerance_seconds

    def __repr__(self) -> str:
        return f"CentralGate(secret_refs={self._refs!r}, tolerance_seconds={self._tolerance})"

    def receive(self, headers: Mapping[str, str], body: bytes) -> GateFrame:
        """Verify one delivery and parse its frame. Raises `IntakeRefused` (a
        `SignatureRefused` for authentication failures) with a reason code."""
        if len(body) > MAX_GATE_BODY_BYTES:
            raise refuse(RefusalCode.BODY_TOO_LARGE)
        now = self._clock.now()
        delivery = verify_standard_webhook(
            headers, body, secrets=self._resolve(), now=now, tolerance_seconds=self._tolerance
        )
        self._remember(delivery)
        frame = _object(loads_strict(body, max_depth=MAX_FRAME_DEPTH, code=_MALFORMED))
        return self._parse(frame, delivery, now)

    def _resolve(self) -> Iterator[str]:
        for ref in self._refs:
            try:
                yield self._secrets.get(ref).reveal()
            except CisoError:
                raise SignatureRefused(RefusalCode.SIGNING_SECRET_UNAVAILABLE) from None

    def _remember(self, delivery: VerifiedDelivery) -> None:
        if self._tolerance is None:
            raise SignatureRefused(RefusalCode.TOLERANCE_UNSET)
        until = delivery.signed_at + timedelta(seconds=self._tolerance)
        try:
            fresh = self._seen.remember(delivery.message_id, now=self._clock.now(), until=until)
        except FailClosed:
            raise SignatureRefused(RefusalCode.REPLAY_MEMORY_UNAVAILABLE) from None
        if not fresh:
            raise SignatureRefused(RefusalCode.REPLAYED_MESSAGE)

    def _parse(self, frame: dict[str, Any], delivery: VerifiedDelivery, now: Any) -> GateFrame:
        request_id = _text(frame.get("request_id"))
        if request_id != delivery.message_id:
            raise refuse(RefusalCode.REQUEST_ID_MISMATCH)
        frame_type = frame.get("type")
        if not isinstance(frame_type, str):
            raise refuse(_MALFORMED)
        if frame_type not in FRAME_TYPES:
            raise refuse(RefusalCode.UNKNOWN_FRAME_TYPE)
        session = _text(frame.get("session_id"), nullable=True)
        source = _object(frame.get("source"))
        origin = Origin(
            session_id=session if session else f"unsessioned:{request_id}",
            source=ActivitySource.CENTRAL_GATE,
            phase=Phase.BEFORE,
            surface=_text(source.get("application"), nullable=True) or "",
            received_at=now,
            claims=_actor_claims(_object(frame.get("actor"))),
        )
        last = _last_message(frame.get("messages"))
        if frame_type == "prompt":
            built = [self._prompt(request_id, origin, last)]
        else:
            built = self._tool_calls(request_id, origin, last)
        return GateFrame(
            request_id=request_id,
            frame_type="prompt" if frame_type == "prompt" else "tool_call",
            actions=tuple(action for action, _ in built),
            inspections=tuple(item for _, item in built if item is not None),
        )

    def _prompt(
        self, request_id: str, origin: Origin, last: dict[str, Any]
    ) -> tuple[ObservedAction, InspectionInput | None]:
        text = "\n".join(_block_texts(last["content"]))
        return build_action(
            action_id=derive_action_id("cg", FORMAT, origin.session_id, "prompt", request_id),
            origin=origin,
            tool_name="",
            view=prompt_view(text),
            target={},
            redactor=self._redactor,
        )

    def _tool_calls(
        self, request_id: str, origin: Origin, last: dict[str, Any]
    ) -> list[tuple[ObservedAction, InspectionInput | None]]:
        if last.get("role") != "assistant":
            raise refuse(_MALFORMED)
        blocks = [block for block in last["content"] if block["type"] == "tool_use"]
        if not blocks:
            raise refuse(_MALFORMED)
        if len(blocks) > MAX_TOOL_CALLS_PER_FRAME:
            raise refuse(RefusalCode.TOO_MANY_TOOL_CALLS)
        return [
            self._tool_call(request_id, origin, index, block) for index, block in enumerate(blocks)
        ]

    def _tool_call(
        self, request_id: str, origin: Origin, index: int, block: dict[str, Any]
    ) -> tuple[ObservedAction, InspectionInput | None]:
        use_id = _text(block.get("id"), nullable=True) or f"{request_id}#{index}"
        tool_name = _text(block.get("tool_name"), nullable=True) or ""
        tool_input = block.get("input")
        tool_input = {} if tool_input is None else _object(tool_input)
        info = _object(block.get("tool_info"))
        provider = _text(info.get("type"))
        view = (
            classify_tool(tool_name, tool_input, cwd=None, redactor=self._redactor)
            if tool_name
            else ToolView(ActionKind.OTHER_TOOL, {})
        )
        target = {**view.target, **_provider_target(info, provider or "")}
        if view.kind is ActionKind.OTHER_TOOL and provider == "third_party":
            view = view._replace(kind=ActionKind.CONNECTOR_CALL)
        if view.kind is ActionKind.CONNECTOR_CALL and "server" not in target:
            toolset = _text(info.get("toolset_name"), nullable=True)
            if toolset:
                target["server"] = toolset
        return build_action(
            action_id=derive_action_id("cg", FORMAT, origin.session_id, "tool_call", use_id),
            origin=origin,
            tool_name=tool_name,
            view=view,
            target=target,
            redactor=self._redactor,
        )


def _actor_claims(actor: dict[str, Any]) -> tuple[IdentityClaim, ...]:
    """Verified claims for a `user` actor; a future actor kind gives none."""
    kind = _text(actor.get("type"))
    if kind != "user":
        return ()
    claims = []
    account = _text(actor.get("id"), nullable=True)
    email = _text(actor.get("email_address"), nullable=True)
    if account:
        claims.append(make_claim("assistant_account", account, verified=True))
    if email:
        claims.append(make_claim("assistant_email", email, verified=True))
    return tuple(claims)


def _provider_target(info: dict[str, Any], provider: str) -> dict[str, str]:
    target = {"provider": provider}
    origin = _text(info.get("origin"), nullable=True)
    if origin:
        target["origin"] = origin
        verified = info.get("verified_origin")
        target["origin_verified"] = "true" if verified is True else "false"
    return target


def _last_message(messages: Any) -> dict[str, Any]:
    """The last message, with its content blocks checked. Earlier messages must be
    objects; their content is not read."""
    if not isinstance(messages, list) or not messages:
        raise refuse(_MALFORMED)
    if not all(isinstance(message, dict) for message in messages):
        raise refuse(_MALFORMED)
    last: dict[str, Any] = messages[-1]
    content = last.get("content")
    if not isinstance(content, list):
        raise refuse(_MALFORMED)
    for block in content:
        if not isinstance(block, dict) or not isinstance(block.get("type"), str):
            raise refuse(_MALFORMED)
    return last


def _block_texts(blocks: list[dict[str, Any]]) -> Iterator[str]:
    """Text a person could read in the blocks; unknown block types are skipped."""
    for block in blocks:
        kind = block["type"]
        key = {"text": "text", "tool_result": "content", "attachment": "text"}.get(kind)
        if key is None:
            continue
        value = block.get(key)
        if value is None and kind == "attachment":
            continue
        if not isinstance(value, str):
            raise refuse(_MALFORMED)
        yield value
