"""API skeleton (plan T1.15; FR-003, NFR-005, G22, G28): authentication, permissions,
rate limits, validation, error mapping, audit-before-side-effect, and the route registry."""

from __future__ import annotations

from datetime import timedelta
from pathlib import Path
from typing import Annotated, Any

import pytest
from fastapi import Depends
from tests.api.helpers import Api, ApiFactory

from ciso.api import AUTHENTICATED, PUBLIC_ROUTES, require, route_table, undeclared_routes
from ciso.api.routers.system import MAX_AUDIT_PAGE
from ciso.app.settings import Settings
from ciso.common.enums import ActorType, KillCapability, Role
from ciso.common.errors import (
    AuthorizationError,
    CisoError,
    Conflict,
    FailClosed,
    IntegrityFailure,
    NotFound,
    ValidationFailed,
)
from ciso.common.principal import Principal
from ciso.common.protocols import AuditEvent, AuditReceipt

pytestmark = pytest.mark.policy

WHOAMI = "/v1/system/whoami"
ENGAGE = "/v1/killswitch/engage"
RELEASE = "/v1/killswitch/release"
UNAUTH_BODY = {"error": "unauthenticated", "message": "authentication required"}


def writes_blocked(api: Api) -> bool:
    return api.container.killswitch.is_blocked(KillCapability.WRITES)


def change(reason: str = "drill") -> dict[str, Any]:
    return {"capabilities": ["writes"], "reason": reason}


# --- authentication ------------------------------------------------------------------


class TestAuthentication:
    def test_valid_token_gives_whoami(self, api: Api) -> None:
        r = api.client.get(WHOAMI, headers=api.headers(api.admin_token))
        assert r.status_code == 200
        assert r.json() == {
            "actor_id": api.admin.actor_id,
            "actor_type": "human",
            "roles": ["security_admin"],
        }

    def test_every_refusal_is_401_with_one_identical_body(self, api: Api) -> None:
        _, revoked = api.actor("Revoked", ActorType.HUMAN, Role.AUDITOR)
        authn = api.container.authenticator
        identity = api.container.identity
        assert authn is not None
        assert identity is not None
        authn.revoke_token(revoked.split(".")[0], api.admin)
        disabled_id, disabled = api.actor("Disabled", ActorType.HUMAN, Role.AUDITOR)
        identity.disable_actor(api.admin, disabled_id)
        _, expiring = api.actor("Expiring", ActorType.HUMAN, Role.AUDITOR)

        cases: dict[str, dict[str, str]] = {
            "no header": {},
            "wrong scheme": {"Authorization": f"Basic {api.admin_token}"},
            "no token": {"Authorization": "Bearer "},
            "garbage": {"Authorization": "Bearer not-a-token"},
            "two parts": {"Authorization": f"Bearer {api.admin_token} extra"},
            "revoked": api.headers(revoked),
            "disabled actor": api.headers(disabled),
        }
        responses = {name: api.client.get(WHOAMI, headers=h) for name, h in cases.items()}
        api.clock.advance(timedelta(days=2))  # past the provisional 12 h token lifetime
        responses["expired"] = api.client.get(WHOAMI, headers=api.headers(expiring))

        assert len(responses) == 8
        for name, r in responses.items():
            assert r.status_code == 401, name
            assert r.json() == UNAUTH_BODY, name
            assert r.headers["www-authenticate"] == "Bearer", name
            assert api.admin_token not in r.text

    def test_token_never_reaches_logs(self, api: Api) -> None:
        api.client.get(WHOAMI, headers=api.headers(api.admin_token))
        api.client.get(WHOAMI, headers={"Authorization": "Bearer tok_garbage.secretpart123"})
        output = api.logs.getvalue()
        assert "authenticated" in output  # the log was written at all
        assert api.admin_token not in output
        assert api.admin_token.split(".")[1] not in output
        assert "secretpart123" not in output


# --- route registry ------------------------------------------------------------------


class TestRouteRegistry:
    def test_every_route_declares_a_permission(self, api: Api) -> None:
        table = route_table(api.app)
        assert len(table) >= 10
        assert undeclared_routes(api.app) == []

    def test_public_allowlist_is_exactly_the_liveness_probe(self) -> None:
        assert frozenset({("GET", "/healthz")}) == PUBLIC_ROUTES

    def test_checker_flags_a_route_without_permission(self, api: Api) -> None:
        api.app.add_api_route("/v1/leak", lambda: {"leak": True}, methods=["GET"])
        assert undeclared_routes(api.app) == ["GET /v1/leak"]

    def test_checker_accepts_a_route_with_permission(self, api: Api) -> None:
        def handler(_: Annotated[Principal, Depends(require("audit.read"))]) -> dict[str, str]:
            return {}

        api.app.add_api_route("/v1/declared", handler, methods=["GET"])
        assert undeclared_routes(api.app) == []
        assert route_table(api.app)[("GET", "/v1/declared")] == "audit.read"

    def test_unknown_permission_name_is_refused(self) -> None:
        with pytest.raises(ValueError, match="unknown permission"):
            require("audit.raed")

    def test_no_route_changes_policy(self, api: Api) -> None:
        policy_routes = [key for key in route_table(api.app) if "policy" in key[1]]
        assert policy_routes == [("GET", "/v1/policy/ruleset")]
        assert all(method == "GET" for method, path in route_table(api.app) if "audit" in path)

    def test_liveness_is_public_and_constant(self, make_api: ApiFactory) -> None:
        api = make_api(api_rate_limit_per_minute=None)
        r = api.client.get("/healthz")
        assert r.status_code == 200
        assert r.json() == {"status": "alive"}


# --- authorization -------------------------------------------------------------------


class TestAuthorization:
    def test_employee_is_refused_audit_engage_and_ruleset(self, api: Api) -> None:
        _, token = api.actor("Employee", ActorType.HUMAN, Role.EMPLOYEE)
        h = api.headers(token)
        assert api.client.get("/v1/audit", params={"limit": 5}, headers=h).status_code == 403
        assert api.client.post(ENGAGE, json=change(), headers=h).status_code == 403
        assert api.client.get("/v1/policy/ruleset", headers=h).status_code == 403
        assert api.client.get(WHOAMI, headers=h).status_code == 200  # authenticated works
        assert writes_blocked(api) is False

    def test_auditor_reads_audit_but_cannot_engage(self, api: Api) -> None:
        _, token = api.actor("Auditor", ActorType.HUMAN, Role.AUDITOR)
        h = api.headers(token)
        r = api.client.get("/v1/audit", params={"limit": 50}, headers=h)
        assert r.status_code == 200
        assert len(r.json()["records"]) > 0
        assert api.client.post(ENGAGE, json=change(), headers=h).status_code == 403
        assert writes_blocked(api) is False

    def test_agent_token_is_refused_on_engage(self, api: Api) -> None:
        _, token = api.actor("Orchestrator", ActorType.AGENT)
        r = api.client.post(ENGAGE, json=change(), headers=api.headers(token))
        assert r.status_code == 403
        assert r.json() == {"error": "forbidden", "message": "not permitted"}
        assert writes_blocked(api) is False

    def test_security_admin_engages_and_releases_end_to_end(self, api: Api) -> None:
        h = api.headers(api.admin_token)
        r = api.client.post(ENGAGE, json=change("incident 7"), headers=h)
        assert r.status_code == 200, r.text
        assert r.json()["capabilities"][0]["engaged"] is True
        assert writes_blocked(api) is True
        status = api.client.get("/v1/killswitch", headers=h).json()["capabilities"]
        assert {s["capability"]: s["engaged"] for s in status}["writes"] is True

        r = api.client.post(RELEASE, json=change("all clear"), headers=h)
        assert r.status_code == 200, r.text
        assert writes_blocked(api) is False

        page = api.client.get(
            "/v1/audit",
            params={"limit": MAX_AUDIT_PAGE, "action_prefix": "killswitch.", "outcome": "success"},
            headers=h,
        ).json()["records"]
        changes = [rec for rec in page if rec["action"] != "killswitch.initialise"]
        assert [rec["action"] for rec in changes] == ["killswitch.engage", "killswitch.release"]
        assert changes[0]["details"]["reason"] == "incident 7"
        requests = api.container.audit.query(limit=MAX_AUDIT_PAGE, action_prefix="api.request")
        posts = [r for r in requests if r.details["method"] == "POST"]
        assert [(r.outcome.value, r.details.get("status")) for r in posts] == [
            ("attempt", None),
            ("success", 200),
            ("attempt", None),
            ("success", 200),
        ]
        assert api.client.get("/v1/audit/verify", headers=h).json()["status"] == "ok"


# --- rate limiting -------------------------------------------------------------------


class TestRateLimit:
    def test_unset_limit_refuses_authenticated_routes(self, make_api: ApiFactory) -> None:
        api = make_api(api_rate_limit_per_minute=None)
        r = api.client.get(WHOAMI, headers=api.headers(api.admin_token))
        assert r.status_code == 503
        assert r.json()["error"] == "rate_limit_not_configured"
        assert api.client.get("/healthz").status_code == 200

    def test_over_the_limit_is_429_and_recovers(self, make_api: ApiFactory) -> None:
        api = make_api(api_rate_limit_per_minute=3)
        h = api.headers(api.admin_token)
        codes = [api.client.get(WHOAMI, headers=h).status_code for _ in range(4)]
        assert codes == [200, 200, 200, 429]
        r = api.client.get(WHOAMI, headers=h)
        assert r.status_code == 429
        assert 1 <= int(r.headers["retry-after"]) <= 60
        api.clock.advance(timedelta(seconds=61))
        assert api.client.get(WHOAMI, headers=h).status_code == 200

    def test_bad_token_burst_is_limited_before_authentication(
        self, make_api: ApiFactory, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        api = make_api(api_rate_limit_per_minute=3)
        authn = api.container.authenticator
        calls: list[str] = []
        real = authn.authenticate

        def spy(token: str) -> Principal:
            calls.append("x")
            return real(token)

        monkeypatch.setattr(authn, "authenticate", spy)
        bad_token = "tok_" + "0" * 26 + "." + "wrong" * 7
        bad = {"Authorization": f"Bearer {bad_token}"}
        codes = [api.client.get(WHOAMI, headers=bad).status_code for _ in range(6)]
        assert codes == [401, 401, 401, 429, 429, 429]
        assert len(calls) == 3

    def test_successful_requests_do_not_use_the_address_budget(self, make_api: ApiFactory) -> None:
        api = make_api(api_rate_limit_per_minute=3)
        _, other = api.actor("Other", ActorType.HUMAN, Role.AUDITOR)
        for token in (api.admin_token, other):
            codes = [
                api.client.get(WHOAMI, headers=api.headers(token)).status_code for _ in range(3)
            ]
            assert codes == [200, 200, 200]


# --- validation and errors -----------------------------------------------------------


class TestValidationAndErrors:
    def test_unknown_body_field_is_422(self, api: Api) -> None:
        body = {**change(), "force": True}
        r = api.client.post(ENGAGE, json=body, headers=api.headers(api.admin_token))
        assert r.status_code == 422
        assert r.json()["fields"] == ["body.force"]
        assert writes_blocked(api) is False

    def test_unknown_capability_is_422(self, api: Api) -> None:
        body = {"capabilities": ["everything"], "reason": "x"}
        r = api.client.post(ENGAGE, json=body, headers=api.headers(api.admin_token))
        assert r.status_code == 422

    @pytest.mark.parametrize(
        "params",
        [{}, {"limit": 0}, {"limit": MAX_AUDIT_PAGE + 1}, {"limit": 5, "bogus": "1"}],
    )
    def test_audit_query_validation(self, api: Api, params: dict[str, Any]) -> None:
        r = api.client.get("/v1/audit", params=params, headers=api.headers(api.admin_token))
        assert r.status_code == 422

    def test_audit_paging(self, api: Api) -> None:
        h = api.headers(api.admin_token)
        first = api.client.get("/v1/audit", params={"limit": 2}, headers=h).json()
        assert len(first["records"]) == 2
        assert first["next_after_seq"] == first["records"][-1]["seq"]
        after = first["next_after_seq"]
        second = api.client.get(
            "/v1/audit", params={"limit": 2, "after_seq": after}, headers=h
        ).json()
        assert second["records"][0]["seq"] == after + 1

    def test_unexpected_exception_is_500_without_detail(
        self, api: Api, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        def boom() -> None:
            raise RuntimeError("internal detail password=hunter2-very-secret")

        monkeypatch.setattr(api.container.health, "aggregate", boom)
        r = api.client.get("/v1/system/health", headers=api.headers(api.admin_token))
        assert r.status_code == 500
        body = r.json()
        assert body["error"] == "internal_error"
        assert body["correlation_id"].startswith("req_")
        assert r.headers["x-correlation-id"] == body["correlation_id"]
        assert "hunter2" not in r.text
        assert "RuntimeError" not in r.text
        logged = api.logs.getvalue()
        assert body["correlation_id"] in logged
        assert "hunter2-very-secret" not in logged

    @pytest.mark.parametrize(
        ("error", "status"),
        [
            (AuthorizationError("who"), 403),
            (FailClosed("down"), 503),
            (IntegrityFailure("chain"), 503),
            (ValidationFailed("bad"), 422),
            (NotFound("gone"), 404),
            (Conflict("clash"), 409),
            (CisoError("other"), 500),
        ],
    )
    def test_platform_errors_map_to_status(self, api: Api, error: CisoError, status: int) -> None:
        def handler(_: Annotated[Principal, Depends(require("audit.read"))]) -> None:
            raise error

        api.app.add_api_route("/v1/raises", handler, methods=["GET"])
        r = api.client.get("/v1/raises", headers=api.headers(api.admin_token))
        assert r.status_code == status
        assert str(error) not in r.text


# --- audit before side effect --------------------------------------------------------


class FailingRequestAudit:
    """Passes every audit event through except `api.request`, which fails."""

    def __init__(self, real: Any) -> None:
        self.real = real
        self.refused = 0

    def __call__(self, event: AuditEvent) -> AuditReceipt:
        if event.action == "api.request":
            self.refused += 1
            raise FailClosed("audit path unavailable")
        result: AuditReceipt = self.real(event)
        return result


class TestAuditBeforeSideEffect:
    def test_failing_request_audit_turns_post_into_503(
        self, api: Api, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        failing = FailingRequestAudit(api.container.audit.append)
        monkeypatch.setattr(api.container.audit, "append", failing)
        r = api.client.post(ENGAGE, json=change(), headers=api.headers(api.admin_token))
        assert r.status_code == 503
        assert r.json()["error"] == "audit_unavailable"
        assert failing.refused >= 1
        assert writes_blocked(api) is False
        assert api.container.killswitch.pending_audit() == ()

    def test_same_post_succeeds_when_audit_works(self, api: Api) -> None:
        r = api.client.post(ENGAGE, json=change(), headers=api.headers(api.admin_token))
        assert r.status_code == 200
        assert writes_blocked(api) is True


# --- health and openapi --------------------------------------------------------------


class TestSystemRoutes:
    def test_health_detail_needs_a_permission(self, api: Api) -> None:
        assert api.client.get("/v1/system/health").status_code == 401
        _, token = api.actor("Employee", ActorType.HUMAN, Role.EMPLOYEE)
        assert api.client.get("/v1/system/health", headers=api.headers(token)).status_code == 403
        r = api.client.get("/v1/system/health", headers=api.headers(api.admin_token))
        assert r.status_code == 200
        body = r.json()
        states = {c["name"]: c["state"] for c in body["components"]}
        assert set(states) == {
            "operational_database",
            "audit_database",
            "killswitch",
            "readiness",
            "integrity",
            "log_records",
            "inference",
            "authentication_audit",
            "audit_integrity",
        }
        # These settings configure no witness, so integrity is degraded and so is overall;
        # every other component is healthy.
        assert states.pop("integrity") == "degraded"
        assert set(states.values()) == {"healthy"}, body
        assert body["overall"] == "degraded", body

    def test_unknown_component_keeps_overall_from_healthy(self, api: Api) -> None:
        def broken() -> Any:
            raise RuntimeError("probe")

        api.container.health.register("probe", broken)
        body = api.client.get("/v1/system/health", headers=api.headers(api.admin_token)).json()
        assert body["overall"] == "unknown"

    def test_ruleset_summary(self, api: Api) -> None:
        r = api.client.get("/v1/policy/ruleset", headers=api.headers(api.admin_token))
        assert r.status_code == 200
        body = r.json()
        assert set(body) == {"version", "content_hash", "deny_all", "deny_reason"}
        assert body["deny_all"] is False
        assert body["content_hash"] == api.container.policy.ruleset.content_hash

    def test_openapi_needs_authentication(self, api: Api) -> None:
        for path in ("/openapi.json", "/docs", "/redoc", "/docs/oauth2-redirect"):
            assert api.client.get(path).status_code in (401, 404), path
        assert api.client.get("/v1/openapi.json").status_code == 401
        r = api.client.get("/v1/openapi.json", headers=api.headers(api.admin_token))
        assert r.status_code == 200
        assert "/v1/audit" in r.json()["paths"]

    def test_whoami_is_authenticated_pseudo_permission(self, api: Api) -> None:
        assert route_table(api.app)[("GET", WHOAMI)] == AUTHENTICATED


class TestDegradedApi:
    def test_degraded_container_still_answers_liveness_and_refuses_tokens(
        self, make_api: ApiFactory, tmp_path: Path
    ) -> None:
        settings = Settings(data_dir=tmp_path / "bare").model_copy(
            update={
                "safety": Settings().safety.model_copy(update={"api_rate_limit_per_minute": 10})
            }
        )
        api = make_api(settings)
        assert api.container.readiness().ready is False
        r = api.client.get(WHOAMI, headers={"Authorization": "Bearer tok_x.y"})
        assert r.status_code == 401
        assert api.client.get("/healthz").status_code == 200

    def test_full_audit_outage_refuses_writes_and_logs_unaudited_reads(
        self, api: Api, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        def down(event: AuditEvent) -> AuditReceipt:
            raise FailClosed("audit path unavailable")

        monkeypatch.setattr(api.container.audit, "append", down)
        h = api.headers(api.admin_token)
        r = api.client.post(ENGAGE, json=change(), headers=h)
        assert r.status_code == 503
        assert r.json()["error"] == "audit_unavailable"
        assert writes_blocked(api) is False
        assert api.client.get(WHOAMI, headers=h).status_code == 200
        assert "/v1/system/whoami not audited" in api.logs.getvalue()
