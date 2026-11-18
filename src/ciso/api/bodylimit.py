"""Request body cap for every route (decision-api.md: a report is at most 256 KiB).

A request whose `Content-Length` is over the route's limit, not a number, or whose
streamed body grows past it, is answered 413 with a fixed body, before or instead of
whatever the route would have answered. The central gate route has the platform's own
larger limit. The limits are structural bounds (named constants), not safety settings.

The middleware must sit INSIDE the request middleware (added first), so a refusal is a
normal response the request middleware sees, not an exception it would turn into 500.
"""

from __future__ import annotations

import json
from collections.abc import Awaitable, Callable, Mapping, MutableMapping
from typing import Any, Final

Scope = MutableMapping[str, Any]
Message = MutableMapping[str, Any]
Receive = Callable[[], Awaitable[Message]]
Send = Callable[[Message], Awaitable[None]]
ASGIApp = Callable[[Scope, Receive, Send], Awaitable[None]]

#: Default cap, equal to the decision API's request limit.
MAX_BODY_BYTES: Final = 256 * 1024
#: The central gate's protocol maximum (`ciso.intake.MAX_GATE_BODY_BYTES`).
MAX_GATE_BODY_BYTES: Final = 64 * 1024 * 1024
TOO_LARGE_BODY: Final = {"error": "request_too_large", "message": "the request body is too large"}


class _TooLarge(Exception):
    pass


async def _send_413(send: Send) -> None:
    body = json.dumps(TOO_LARGE_BODY).encode()
    await send(
        {
            "type": "http.response.start",
            "status": 413,
            "headers": [(b"content-type", b"application/json")],
        }
    )
    await send({"type": "http.response.body", "body": body})


def _declared_length(scope: Scope) -> int | None:
    """The Content-Length header as a number; -1 when present but not a plain number."""
    for name, value in scope.get("headers", ()):
        if name.lower() == b"content-length":
            text = value.decode("latin-1")
            return int(text) if text.isdigit() else -1
    return None


class BodyLimitMiddleware:
    def __init__(
        self, app: ASGIApp, *, default_limit: int, limits: Mapping[str, int] | None = None
    ) -> None:
        self.app = app
        self.default_limit = default_limit
        self.limits = dict(limits or {})

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        limit = self.limits.get(str(scope.get("path", "")), self.default_limit)
        declared = _declared_length(scope)
        if declared is not None and (declared < 0 or declared > limit):
            await _send_413(send)
            return
        state = {"received": 0, "over": False, "answered": False}

        async def limited_receive() -> Message:
            message = await receive()
            if message["type"] == "http.request":
                state["received"] += len(message.get("body", b""))
                if state["received"] > limit:
                    state["over"] = True
                    raise _TooLarge
            return message

        async def guarded_send(message: Message) -> None:
            if not state["over"]:
                await send(message)
                return
            if not state["answered"]:  # replace whatever the route answered
                state["answered"] = True
                await _send_413(send)

        try:
            await self.app(scope, limited_receive, guarded_send)
        except _TooLarge:
            if not state["answered"]:
                state["answered"] = True
                await _send_413(send)
