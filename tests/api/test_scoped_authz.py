"""Route permissions respect grant scopes (M1 fix pass item 2; FR-003, blueprint 9.3).

Most routes act on the whole platform. A permission counts for such a route only if it
comes from a role the principal holds through at least one unscoped grant: a
`system_owner` narrowed to one system must not read the platform-wide ruleset. The routes
that name one approval are resource routes (`tests/api/test_approvals_api.py`).
"""

from __future__ import annotations

from typing import Annotated

import pytest
from fastapi import Depends, Request
from fastapi.routing import APIRoute
from tests.api.helpers import Api

from ciso.api import require
from ciso.api.deps import route_scope
from ciso.common.enums import ActorType, Role
from ciso.common.principal import Principal
from ciso.identity import RoleScope

pytestmark = pytest.mark.policy

RULESET = "/v1/policy/ruleset"  # policy.read: held by system_owner
BILLING = "app:billing"
PAYROLL = "app:payroll"


def system_of(request: Request) -> dict[str, str | None]:
    """Target attributes of the test route: the system named in its path."""
    return {"system": request.path_params.get("system")}


#: Module level so FastAPI can resolve the handler's string annotation.
SYSTEM_READ = require("policy.read", target=system_of)


def scoped_owner(api: Api, *grants: RoleScope) -> str:
    """A human system_owner holding one assignment per scope given; returns a token."""
    identity, authn = api.container.identity, api.container.authenticator
    actor = identity.create_actor(api.admin, ActorType.HUMAN, "Owner")
    for scope in grants:
        identity.assign_role(api.admin, actor.id, Role.SYSTEM_OWNER, scope=scope)
    return authn.issue_token(actor.id, api.admin).token


class TestPlatformWideRoutes:
    def test_scoped_system_owner_is_forbidden(self, api: Api) -> None:
        token = scoped_owner(api, RoleScope(systems=frozenset({BILLING})))
        r = api.client.get(RULESET, headers=api.headers(token))
        assert r.status_code == 403
        assert r.json() == {"error": "forbidden", "message": "not permitted"}

    def test_unscoped_system_owner_passes(self, api: Api) -> None:
        token = scoped_owner(api, RoleScope())
        r = api.client.get(RULESET, headers=api.headers(token))
        assert r.status_code == 200, r.text

    def test_one_scoped_and_one_unscoped_grant_of_the_role_passes(self, api: Api) -> None:
        token = scoped_owner(api, RoleScope(systems=frozenset({BILLING})), RoleScope())
        r = api.client.get(RULESET, headers=api.headers(token))
        assert r.status_code == 200, r.text

    def test_only_the_routes_naming_one_approval_are_resource_scoped(self, api: Api) -> None:
        declared = {
            (method, route.path): route_scope(route)
            for route in api.app.routes
            if isinstance(route, APIRoute) and route_scope(route) is not None
            for method in route.methods
        }
        assert len(declared) >= 19
        assert {key for key, scope in declared.items() if scope == "resource"} == {
            ("GET", "/v1/approvals/{approval_id}"),
            ("POST", "/v1/approvals/{approval_id}/approve"),
            ("POST", "/v1/approvals/{approval_id}/reject"),
        }
        assert set(declared.values()) == {"platform", "resource"}


class TestResourceScopedExtension:
    """The extension point future routes use: `require(permission, target=...)`."""

    @staticmethod
    def add_route(api: Api) -> None:
        def handler(system: str, _: Annotated[Principal, Depends(SYSTEM_READ)]) -> dict[str, str]:
            return {"system": system}

        api.app.add_api_route("/v1/test/systems/{system}", handler, methods=["GET"])

    def test_scoped_grant_reaches_its_own_system_only(self, api: Api) -> None:
        self.add_route(api)
        token = scoped_owner(api, RoleScope(systems=frozenset({BILLING})))
        h = api.headers(token)
        assert api.client.get(f"/v1/test/systems/{BILLING}", headers=h).status_code == 200
        assert api.client.get(f"/v1/test/systems/{PAYROLL}", headers=h).status_code == 403

    def test_resource_route_is_reported_as_resource_scoped(self, api: Api) -> None:
        self.add_route(api)
        (route,) = [
            r
            for r in api.app.routes
            if isinstance(r, APIRoute) and r.path == "/v1/test/systems/{system}"
        ]
        assert route_scope(route) == "resource"


class TestKillSwitchStatusIsReadable:
    """Blueprint 11.2: read-only investigation stays available (item 10)."""

    def test_auditor_reads_status_but_cannot_engage_or_release(self, api: Api) -> None:
        _, token = api.actor("Auditor", ActorType.HUMAN, Role.AUDITOR)
        h = api.headers(token)
        r = api.client.get("/v1/killswitch", headers=h)
        assert r.status_code == 200, r.text
        assert {s["capability"] for s in r.json()["capabilities"]} >= {"writes"}
        body = {"capabilities": ["writes"], "reason": "drill"}
        assert api.client.post("/v1/killswitch/engage", json=body, headers=h).status_code == 403
        assert api.client.post("/v1/killswitch/release", json=body, headers=h).status_code == 403
        assert api.container.killswitch.status()  # still readable, nothing changed

    def test_security_admin_reads_status(self, api: Api) -> None:
        r = api.client.get("/v1/killswitch", headers=api.headers(api.admin_token))
        assert r.status_code == 200

    def test_employee_cannot_read_status(self, api: Api) -> None:
        _, token = api.actor("Employee", ActorType.HUMAN, Role.EMPLOYEE)
        assert api.client.get("/v1/killswitch", headers=api.headers(token)).status_code == 403
