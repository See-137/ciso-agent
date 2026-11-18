"""Authenticated control-plane API (plan T1.15). Build an app with `create_app(container)`."""

from ciso.api.app import create_app
from ciso.api.deps import AUTHENTICATED, PUBLIC_ROUTES, require, route_table, undeclared_routes
from ciso.api.ratelimit import RateLimiter

__all__ = [
    "AUTHENTICATED",
    "PUBLIC_ROUTES",
    "RateLimiter",
    "create_app",
    "require",
    "route_table",
    "undeclared_routes",
]
