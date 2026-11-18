"""Authentication, authorization and rate limiting for every API route (FR-003, NFR-005, G22).

Every route declares the permission it needs with `Depends(require("<permission>"))`.
`require` checks it server-side against the permissions of the roles whose grants reach
the route's target (`granted`): for a platform-wide route (the default) only roles held
through an unscoped grant count; a resource route passes `target=` (see `require`).
`undeclared_routes(app)` lists any route without a declaration; `create_app` refuses to
build an app that has one, and a test enumerates the routes as well. `route_scope` says
whether a declared route is platform-wide or resource-scoped.

Order of checks inside `require`, chosen so the cheap refusals come first:

1. rate limit not configured: 503 (fail closed, no invented number, G14);
2. client address over its budget: 429, before any token work. Each request is charged to
   the address before authentication and refunded once it authenticates, so a burst of
   bad tokens costs at most `limit` scrypt hashes and audit writes per window;
3. header missing or malformed, or the token refused: 401 with one identical body;
4. authenticated actor over its budget: 429;
5. permission not granted for the route's scope: 403;
6. a state-changing method: refused with 503 while writes are blocked (gated routes,
   see `require`); otherwise the attempt is audited before the handler runs, and an audit
   failure is 503 (blueprint 9.5, `ciso.audit.log` ordering rule).

Two more declarations exist besides `require`:

- `require_device()` declares `governance.report`, the permission of the decide and
  activity routes. No role template grants it (`DEVICE_ONLY_PERMISSIONS`; `granted`
  strips it from any role): it is held only by an authenticated actor of type `service`
  with no roles that the device directory lists as an active device (`ciso.app.devices`).
  Same order as `require`, so each device has its own rate budget (`actor:<id>`). The
  write gate does not apply: the governance engine applies the kill switch itself, so
  reads stay possible while it is engaged.
- `require_signed_webhook()` declares `SIGNED_WEBHOOK`: no bearer token; the handler
  authenticates the delivery by its webhook signature (`ciso.app.governance_gate`). The
  dependency applies the rate limit per client address only.
"""

from __future__ import annotations

import logging
from collections.abc import Callable, Iterator, Mapping
from typing import Any, Final

from fastapi import FastAPI, Request
from fastapi.dependencies.models import Dependant
from fastapi.routing import APIRoute

from ciso.api.ratelimit import RateLimiter
from ciso.app.container import Container
from ciso.common.enums import ActorType, AuditOutcome, KillCapability
from ciso.common.errors import AuthenticationError
from ciso.common.principal import Principal
from ciso.common.protocols import AuditEvent
from ciso.identity import PERMISSIONS, permissions_for

logger = logging.getLogger(__name__)

#: Routes reachable without a token: a liveness probe only. Exactly one entry.
PUBLIC_ROUTES: Final[frozenset[tuple[str, str]]] = frozenset({("GET", "/healthz")})
#: Pseudo-permission: any authenticated principal (used by `whoami`).
AUTHENTICATED: Final = "authenticated"
STATE_CHANGING: Final = frozenset({"POST", "PUT", "PATCH", "DELETE"})
#: Keys under `request.state` that the request middleware reads.
STATE_PRINCIPAL: Final = "ciso_principal"
STATE_ROUTE: Final = "ciso_route"
_PERMISSION_ATTR: Final = "ciso_permission"
_SCOPE_ATTR: Final = "ciso_route_scope"
#: `route_scope` values: the route acts on the whole platform, or on one target resource.
PLATFORM: Final = "platform"
RESOURCE: Final = "resource"
UNAUTHENTICATED_BODY: Final = {"error": "unauthenticated", "message": "authentication required"}
#: The permission of the decide and activity routes; see `require_device`.
DEVICE_PERMISSION: Final = "governance.report"
#: Permissions that no role confers, whatever a template says (defence in depth).
DEVICE_ONLY_PERMISSIONS: Final = frozenset({DEVICE_PERMISSION})
#: Pseudo-permission of a route whose handler authenticates a signed webhook delivery.
SIGNED_WEBHOOK: Final = "signed_webhook"


class ApiError(Exception):
    """A refusal the API answers itself, with a fixed short body. `extra` adds fields of
    stable codes and ids to that body (a reason code, a record id), never free text."""

    def __init__(
        self,
        status: int,
        code: str,
        message: str,
        headers: dict[str, str] | None = None,
        extra: Mapping[str, str] | None = None,
    ) -> None:
        super().__init__(code)
        self.status = status
        self.code = code
        self.message = message
        self.headers = headers or {}
        self.extra = dict(extra or {})


def not_found() -> ApiError:
    return ApiError(404, "not_found", "not found")


def unauthenticated() -> ApiError:
    return ApiError(
        401,
        UNAUTHENTICATED_BODY["error"],
        UNAUTHENTICATED_BODY["message"],
        {"WWW-Authenticate": "Bearer"},
    )


def container_of(request: Request) -> Container:
    container: Container = request.app.state.container
    return container


def correlation_of(request: Request) -> str:
    """The request's correlation id, so service audit records line up with `api.request`."""
    return str(getattr(request.state, "correlation_id", ""))


def limiter_of(request: Request) -> RateLimiter:
    limiter: RateLimiter = request.app.state.limiter
    return limiter


def bearer_token(request: Request) -> str:
    """The token from `Authorization: Bearer <token>`, or 401. The token is never logged."""
    header = request.headers.get("authorization")
    if header is None:
        raise unauthenticated()
    scheme, _, token = header.partition(" ")
    if scheme.lower() != "bearer" or not token or " " in token.strip():
        raise unauthenticated()
    return token.strip()


def _too_many(retry_after: int) -> ApiError:
    return ApiError(
        429, "rate_limited", "too many requests", {"Retry-After": str(max(1, retry_after))}
    )


def _authenticate(request: Request, limiter: RateLimiter) -> Principal:
    container = container_of(request)
    address = f"addr:{request.client.host if request.client else 'unknown'}"
    pre = limiter.hit(address)
    if not pre.allowed:
        raise _too_many(pre.retry_after_seconds)
    token = bearer_token(request)
    try:
        principal = container.authenticator.authenticate(token)
    except AuthenticationError:
        raise unauthenticated() from None
    limiter.refund(address)
    return principal


def _writes_blocked(request: Request) -> bool:
    """True when the gated reader blocks WRITES, or cannot be read (fail closed)."""
    try:
        return bool(container_of(request).killswitch_reader.is_blocked(KillCapability.WRITES))
    except Exception:
        logger.exception("api: write gate unreadable; request refused")
        return True


def _audit_attempt(request: Request, principal: Principal, route: str) -> None:
    event = AuditEvent(
        actor_id=principal.actor_id,
        actor_type=principal.actor_type,
        action="api.request",
        target=route,
        outcome=AuditOutcome.ATTEMPT,
        correlation_id=correlation_of(request),
        details={"method": request.method, "route": route},
    )
    try:
        container_of(request).audit.append(event)
    except Exception as exc:
        logger.error("api: attempt not audited (%s); request refused", type(exc).__name__)
        raise ApiError(503, "audit_unavailable", "the request could not be audited") from exc


#: Reads the target's attributes (`system`, `environment`, `classification`) from a request.
TargetAttributes = Callable[[Request], Mapping[str, str | None]]


def granted(principal: Principal, attributes: Mapping[str, str | None]) -> frozenset[str]:
    """Permissions of the roles whose grants reach a target with `attributes`.

    With no attributes (a platform-wide route) only roles held through at least one
    unscoped grant count: `Principal.covers(role, {})` is false for a narrowed grant,
    because a narrowed attribute that is not supplied never matches.
    """
    roles = principal.covering_roles(principal.roles, attributes)
    return permissions_for(roles) - DEVICE_ONLY_PERMISSIONS


def require(
    permission: str, *, target: TargetAttributes | None = None, gated: bool = True
) -> Callable[[Request], Principal]:
    """A dependency that authenticates the caller and checks `permission`.

    `permission` must exist in `ciso.identity.roles.PERMISSIONS` or be `AUTHENTICATED`.

    Scope. With no `target` (the default) the route acts on the whole platform, and the
    permission counts only if it comes from a role the principal holds through an
    unscoped grant: a `system_owner` narrowed to one system cannot use a platform-wide
    route its role would otherwise allow. A route that acts on one resource passes
    `target`, a function returning that resource's attributes from the request; the
    permission then counts from any role whose grant covers those attributes
    (`Principal.covers`). The routes that name one approval do this; the rest are
    platform-wide.

    Integrity gate. A state-changing request on a `gated` route (the default) is refused
    with 503 `writes_blocked` while the container's `killswitch_reader` blocks WRITES: the
    operator switch is engaged, or start-up could not verify the audit log (blueprint
    10.3). Only the kill-switch routes pass `gated=False`: an operator must be able to
    engage or release the switch whatever the gate says, and those calls audit themselves.
    """
    if permission != AUTHENTICATED and permission not in PERMISSIONS:
        raise ValueError(f"unknown permission: {permission!r}")
    if permission in DEVICE_ONLY_PERMISSIONS:
        raise ValueError(f"{permission!r} is declared through require_device()")

    def dependency(request: Request) -> Principal:
        limiter = limiter_of(request)
        if not limiter.configured:
            raise ApiError(
                503,
                "rate_limit_not_configured",
                "api_rate_limit_per_minute is not set; the API refuses requests",
            )
        principal = _authenticate(request, limiter)
        route_obj = request.scope.get("route")
        route = str(getattr(route_obj, "path", request.url.path))
        setattr(request.state, STATE_PRINCIPAL, principal)
        setattr(request.state, STATE_ROUTE, route)
        decision = limiter.hit(f"actor:{principal.actor_id}")
        if not decision.allowed:
            raise _too_many(decision.retry_after_seconds)
        attributes = {} if target is None else target(request)
        if permission != AUTHENTICATED and permission not in granted(principal, attributes):
            raise ApiError(403, "forbidden", "not permitted")
        if request.method.upper() in STATE_CHANGING:
            if gated and _writes_blocked(request):
                raise ApiError(503, "writes_blocked", "writes are blocked on this platform")
            _audit_attempt(request, principal, route)
        return principal

    setattr(dependency, _PERMISSION_ATTR, permission)
    setattr(dependency, _SCOPE_ATTR, PLATFORM if target is None else RESOURCE)
    dependency.__name__ = f"require_{permission.replace('.', '_')}"
    return dependency


def _configured(limiter: RateLimiter) -> None:
    if not limiter.configured:
        raise ApiError(
            503,
            "rate_limit_not_configured",
            "api_rate_limit_per_minute is not set; the API refuses requests",
        )


def _is_device(request: Request, principal: Principal) -> bool:
    """A service actor with no roles that the device directory lists now. A directory that
    cannot be read refuses the request (503)."""
    if principal.actor_type is not ActorType.SERVICE or principal.roles:
        return False
    try:
        return container_of(request).governance.devices.is_device(principal.actor_id)
    except Exception as exc:
        logger.error("api: device directory unreadable (%s); refused", type(exc).__name__)
        raise ApiError(503, "unavailable", "a required control is unavailable") from exc


def require_device() -> Callable[[Request], Principal]:
    """The dependency of the decide and activity routes. See the module docstring."""

    def dependency(request: Request) -> Principal:
        limiter = limiter_of(request)
        _configured(limiter)
        principal = _authenticate(request, limiter)
        route_obj = request.scope.get("route")
        route = str(getattr(route_obj, "path", request.url.path))
        setattr(request.state, STATE_PRINCIPAL, principal)
        setattr(request.state, STATE_ROUTE, route)
        decision = limiter.hit(f"actor:{principal.actor_id}")
        if not decision.allowed:
            raise _too_many(decision.retry_after_seconds)
        if not _is_device(request, principal):
            raise ApiError(403, "forbidden", "not permitted")
        if request.method.upper() in STATE_CHANGING:
            _audit_attempt(request, principal, route)
        return principal

    setattr(dependency, _PERMISSION_ATTR, DEVICE_PERMISSION)
    setattr(dependency, _SCOPE_ATTR, PLATFORM)
    dependency.__name__ = "require_device"
    return dependency


def require_signed_webhook() -> Callable[[Request], None]:
    """No bearer token: rate-limited per client address; the handler checks the signature."""

    def dependency(request: Request) -> None:
        limiter = limiter_of(request)
        _configured(limiter)
        address = f"addr:{request.client.host if request.client else 'unknown'}"
        decision = limiter.hit(address)
        if not decision.allowed:
            raise _too_many(decision.retry_after_seconds)

    setattr(dependency, _PERMISSION_ATTR, SIGNED_WEBHOOK)
    setattr(dependency, _SCOPE_ATTR, PLATFORM)
    dependency.__name__ = "require_signed_webhook"
    return dependency


# --- route enumeration ----------------------------------------------------------------


def _walk(dependant: Dependant) -> Iterator[Any]:
    for sub in dependant.dependencies:
        yield sub.call
        yield from _walk(sub)


def route_permission(route: APIRoute) -> str | None:
    """The permission a route declares through `require`, or None."""
    for call in _walk(route.dependant):
        declared = getattr(call, _PERMISSION_ATTR, None)
        if isinstance(declared, str):
            return declared
    return None


def route_scope(route: APIRoute) -> str | None:
    """`PLATFORM` or `RESOURCE` for a route declared through `require`, else None."""
    for call in _walk(route.dependant):
        declared = getattr(call, _SCOPE_ATTR, None)
        if isinstance(declared, str):
            return declared
    return None


def route_table(app: FastAPI) -> dict[tuple[str, str], str | None]:
    """(method, path) -> declared permission for every route.

    Anything that is not a plain `APIRoute` (a mount, a plain Starlette route, a router
    added with `include_router`) maps to None and is therefore flagged: routes must be
    registered on the app directly, or this enumeration extended, before they can serve.
    """
    table: dict[tuple[str, str], str | None] = {}
    for route in app.routes:
        path = str(getattr(route, "path", repr(route)))
        if isinstance(route, APIRoute):
            permission = route_permission(route)
            for method in sorted(route.methods or ()):
                table[(method, path)] = permission
        else:
            methods: set[str] | None = getattr(route, "methods", None)
            for method in sorted(methods or {"*"}):
                table[(method, path)] = None
    return table


def undeclared_routes(app: FastAPI) -> list[str]:
    """`METHOD path` for every non-public route that declares no permission."""
    return sorted(
        f"{method} {path}"
        for (method, path), permission in route_table(app).items()
        if permission is None and (method, path) not in PUBLIC_ROUTES
    )
