"""The control-plane API (plan T1.15; FR-003, NFR-005, G22, G28; ADR-0012).

`create_app(container)` builds a new app each call; there is no global app. The built-in
documentation pages and the default OpenAPI route are off (they are unauthenticated and
the pages load scripts from a public network); the OpenAPI document, which is the
interface description in this build (G28), is served at `/v1/openapi.json` to an
authenticated caller.

Error bodies are short and fixed per status; exception text never reaches a client. A
refusal that carries a stable reason code (an approval or external-inference refusal)
also gets that code in a `reason` field: the enum value, never the message. An unexpected
exception is logged through the redacting handler and answered 500 with a correlation id
only. Every authenticated request is audited (`api.request`) when it ends. Every request
body is capped (`ciso.api.bodylimit`): 413 past the route's limit.
"""

from __future__ import annotations

import json
import logging
import re
from collections.abc import Awaitable, Callable, MutableMapping
from enum import StrEnum
from typing import Any

import anyio
from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from pydantic import ValidationError

from ciso.api.bodylimit import MAX_BODY_BYTES, MAX_GATE_BODY_BYTES, BodyLimitMiddleware
from ciso.api.deps import (
    STATE_PRINCIPAL,
    STATE_ROUTE,
    UNAUTHENTICATED_BODY,
    ApiError,
    undeclared_routes,
)
from ciso.api.ratelimit import RateLimiter
from ciso.api.routers.agents import register_agent_routes
from ciso.api.routers.approvals import register_approval_routes
from ciso.api.routers.devices import register_device_routes
from ciso.api.routers.external_inference import register_external_inference_routes
from ciso.api.routers.findings import register_findings_routes
from ciso.api.routers.governance import register_governance_routes
from ciso.api.routers.system import register_system_routes
from ciso.app.change_models import MAX_CHANGE_BODY_BYTES
from ciso.app.container import Container
from ciso.common.enums import AuditOutcome
from ciso.common.errors import (
    AuthenticationError,
    AuthorizationError,
    CisoError,
    Conflict,
    FailClosed,
    InferenceUnavailable,
    IntegrityFailure,
    NotFound,
    PreconditionFailed,
    ValidationFailed,
    VerificationMismatch,
)
from ciso.common.ids import new_id
from ciso.common.principal import Principal
from ciso.common.protocols import AuditEvent

logger = logging.getLogger(__name__)

Scope = MutableMapping[str, Any]
Message = MutableMapping[str, Any]
Receive = Callable[[], Awaitable[Message]]
Send = Callable[[Message], Awaitable[None]]
ASGIApp = Callable[[Scope, Receive, Send], Awaitable[None]]

CORRELATION_HEADER = "x-correlation-id"

#: Platform error -> (status, short code, fixed message). First match wins.
ERROR_STATUS: tuple[tuple[type[CisoError], int, str, str], ...] = (
    (AuthorizationError, 403, "forbidden", "not permitted"),
    (IntegrityFailure, 503, "integrity_failure", "an integrity check failed"),
    (FailClosed, 503, "unavailable", "a required control is unavailable"),
    (InferenceUnavailable, 503, "unavailable", "a required service is unavailable"),
    (ValidationFailed, 422, "invalid_request", "the request is not valid"),
    (NotFound, 404, "not_found", "not found"),
    (Conflict, 409, "conflict", "the request conflicts with current state"),
    (PreconditionFailed, 409, "conflict", "a precondition no longer holds"),
    (VerificationMismatch, 409, "conflict", "the result could not be verified"),
)


def status_for(exc: CisoError) -> tuple[int, str, str]:
    for kind, status, code, message in ERROR_STATUS:
        if isinstance(exc, kind):
            return status, code, message
    return 500, "internal_error", "internal error"


#: The shape of a reason code: a short enum value. Anything else is not sent.
_CODE_RE = re.compile(r"[a-z][a-z0-9_]{0,63}")


def reason_fields(exc: BaseException) -> dict[str, str]:
    """The stable reason codes an error carries, for the response body.

    `reason` is sent only when it is a `StrEnum` member (the approvals and external
    inference reason codes are), `approval_reason` only when it has the shape of such a
    value. A free-text reason, like the exception message itself, is never sent.
    """
    fields: dict[str, str] = {}
    reason = getattr(exc, "reason", None)
    if isinstance(reason, StrEnum) and _CODE_RE.fullmatch(reason.value):
        fields["reason"] = reason.value
    nested = getattr(exc, "approval_reason", None)
    if isinstance(nested, str) and _CODE_RE.fullmatch(nested):
        fields["approval_reason"] = nested
    return fields


def _unauthenticated_response() -> JSONResponse:
    return JSONResponse(
        dict(UNAUTHENTICATED_BODY), status_code=401, headers={"WWW-Authenticate": "Bearer"}
    )


async def _api_error(request: Request, exc: Exception) -> JSONResponse:
    assert isinstance(exc, ApiError)
    if exc.status == 401:
        return _unauthenticated_response()
    return JSONResponse(
        {**exc.extra, "error": exc.code, "message": exc.message},
        status_code=exc.status,
        headers=exc.headers,
    )


async def _ciso_error(request: Request, exc: Exception) -> JSONResponse:
    assert isinstance(exc, CisoError)
    if isinstance(exc, AuthenticationError):
        return _unauthenticated_response()
    status, code, message = status_for(exc)
    logger.info("api: %s answered %s (%s)", request.url.path, status, type(exc).__name__)
    return JSONResponse(
        {**reason_fields(exc), "error": code, "message": message}, status_code=status
    )


async def _invalid_request(request: Request, exc: Exception) -> JSONResponse:
    assert isinstance(exc, RequestValidationError)
    fields = sorted({".".join(str(part) for part in err.get("loc", ())) for err in exc.errors()})
    return JSONResponse(
        {"error": "invalid_request", "message": "the request is not valid", "fields": fields},
        status_code=422,
    )


async def _invalid_model(request: Request, exc: Exception) -> JSONResponse:
    """A record a service built from request data did not validate. Fixed body: the
    validation message can quote the input."""
    assert isinstance(exc, ValidationError)
    return JSONResponse(
        {"error": "invalid_request", "message": "the request is not valid"}, status_code=422
    )


class RequestMiddleware:
    """Correlation id, last-resort 500, and the closing `api.request` audit record."""

    def __init__(self, app: ASGIApp, container: Container) -> None:
        self.app = app
        self.container = container

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        correlation_id = new_id("req")
        state = scope.setdefault("state", {})
        state["correlation_id"] = correlation_id
        status = {"code": 500, "started": False}

        async def tracking_send(message: Message) -> None:
            if message["type"] == "http.response.start":
                status["code"] = int(message["status"])
                status["started"] = True
                headers = list(message.get("headers", []))
                headers.append((CORRELATION_HEADER.encode(), correlation_id.encode()))
                message["headers"] = headers
            await send(message)

        try:
            await self.app(scope, receive, tracking_send)
        except Exception:
            logger.exception("api: unexpected error, correlation id %s", correlation_id)
            status["code"] = 500
            if not status["started"]:
                await _send_internal_error(tracking_send, correlation_id)
        principal = state.get(STATE_PRINCIPAL)
        if isinstance(principal, Principal):
            route = str(state.get(STATE_ROUTE, ""))
            await anyio.to_thread.run_sync(
                self._audit_result, principal, scope, route, int(status["code"]), correlation_id
            )

    def _audit_result(
        self, principal: Principal, scope: Scope, route: str, status: int, correlation_id: str
    ) -> None:
        outcome = (
            AuditOutcome.SUCCESS
            if status < 400
            else AuditOutcome.DENIED
            if status in (401, 403, 429)
            else AuditOutcome.FAILED
        )
        event = AuditEvent(
            actor_id=principal.actor_id,
            actor_type=principal.actor_type,
            action="api.request",
            target=route,
            outcome=outcome,
            correlation_id=correlation_id,
            details={"method": str(scope.get("method", "")), "route": route, "status": status},
        )
        try:
            self.container.audit.append(event)
        except Exception as exc:
            logger.error(
                "api: result of %s not audited (%s), correlation id %s",
                route,
                type(exc).__name__,
                correlation_id,
            )


async def _send_internal_error(send: Send, correlation_id: str) -> None:
    body = json.dumps(
        {"error": "internal_error", "message": "internal error", "correlation_id": correlation_id}
    ).encode()
    await send(
        {
            "type": "http.response.start",
            "status": 500,
            "headers": [(b"content-type", b"application/json")],
        }
    )
    await send({"type": "http.response.body", "body": body})


def create_app(container: Container) -> FastAPI:
    """Build the API around `container`. Refuses to build if a route declares no permission."""
    app = FastAPI(
        title="CISO platform control plane",
        version="0.1.0",
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )
    app.state.container = container
    app.state.limiter = RateLimiter(
        container.clock, container.settings.safety.api_rate_limit_per_minute
    )
    register_system_routes(app, container)
    register_approval_routes(app, container)
    register_external_inference_routes(app, container)
    register_governance_routes(app, container)
    register_device_routes(app, container)
    register_agent_routes(app, container)
    register_findings_routes(app, container)
    app.add_exception_handler(ApiError, _api_error)
    app.add_exception_handler(CisoError, _ciso_error)
    app.add_exception_handler(RequestValidationError, _invalid_request)
    app.add_exception_handler(ValidationError, _invalid_model)
    # Added first, so it sits inside the request middleware (see ciso.api.bodylimit).
    app.add_middleware(
        BodyLimitMiddleware,
        default_limit=MAX_BODY_BYTES,
        limits={"/v1/central-gate": MAX_GATE_BODY_BYTES, "/v1/changes": MAX_CHANGE_BODY_BYTES},
    )
    app.add_middleware(RequestMiddleware, container=container)
    undeclared = undeclared_routes(app)
    if undeclared:
        raise RuntimeError(f"routes without a declared permission: {undeclared}")
    return app
