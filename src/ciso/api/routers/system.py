"""System routes: liveness, health, identity of the caller, audit, kill switch, ruleset.

Read-only except the kill switch. There is deliberately no route that changes policy, the
caller's roles or audit records (blueprint 9.2). Permissions used where the identity
module has no exact one are listed with the route.
"""

from __future__ import annotations

from typing import Annotated, Any, Final

from fastapi import Depends, FastAPI, Query, Request
from pydantic import Field

from ciso.api.deps import AUTHENTICATED, require
from ciso.app.container import Container
from ciso.common.enums import AuditOutcome, KillCapability
from ciso.common.principal import Principal
from ciso.common.schemas import Model, UtcDatetime

#: Largest page `GET /v1/audit` returns. A caller pages with `after_seq`.
MAX_AUDIT_PAGE: Final = 500
MAX_REASON: Final = 500

#: Closest existing permissions for routes the identity module has no permission for:
#: health detail and the OpenAPI document (`registry.read`). Missing: system.health.read,
#: api.describe. Kill-switch status is `killswitch.read`, held by `security_admin` and
#: `auditor`: read-only investigation stays available (blueprint 11.2).
HEALTH_PERMISSION: Final = "registry.read"
OPENAPI_PERMISSION: Final = "registry.read"
KILLSWITCH_STATUS_PERMISSION: Final = "killswitch.read"

LIVENESS_BODY: Final = {"status": "alive"}


class AuditQuery(Model):
    """Query string of `GET /v1/audit`. Unknown parameters are refused."""

    limit: int = Field(ge=1, le=MAX_AUDIT_PAGE)
    actor: str | None = Field(default=None, max_length=200)
    action_prefix: str | None = Field(default=None, max_length=200)
    outcome: AuditOutcome | None = None
    since: UtcDatetime | None = None
    until: UtcDatetime | None = None
    after_seq: int | None = Field(default=None, ge=0)


class KillSwitchChange(Model):
    capabilities: tuple[KillCapability, ...] = Field(min_length=1, max_length=len(KillCapability))
    reason: str = Field(min_length=1, max_length=MAX_REASON)


def register_system_routes(router: FastAPI, container: Container) -> None:
    """Add the system routes to `router` directly (not through `include_router`), so the
    route enumeration in `ciso.api.deps` sees each route with its declared permission."""

    @router.get("/healthz")
    def liveness() -> dict[str, str]:
        """Public liveness probe. Constant body, no component detail."""
        return dict(LIVENESS_BODY)

    @router.get("/v1/system/health")
    def health(_: Annotated[Principal, Depends(require(HEALTH_PERMISSION))]) -> dict[str, Any]:
        return container.health.aggregate().model_dump(mode="json")

    @router.get("/v1/system/whoami")
    def whoami(principal: Annotated[Principal, Depends(require(AUTHENTICATED))]) -> dict[str, Any]:
        return {
            "actor_id": principal.actor_id,
            "actor_type": principal.actor_type.value,
            "roles": sorted(role.value for role in principal.roles),
        }

    @router.get("/v1/openapi.json", include_in_schema=False)
    def openapi(
        request: Request, _: Annotated[Principal, Depends(require(OPENAPI_PERMISSION))]
    ) -> dict[str, Any]:
        return request.app.openapi()  # type: ignore[no-any-return]

    @router.get("/v1/audit")
    def audit_query(
        query: Annotated[AuditQuery, Query()],
        _: Annotated[Principal, Depends(require("audit.read"))],
    ) -> dict[str, Any]:
        records = container.audit.query(
            limit=query.limit,
            actor_id=query.actor,
            action_prefix=query.action_prefix,
            outcome=query.outcome,
            since=query.since,
            until=query.until,
            after_seq=query.after_seq,
        )
        last = records[-1].seq if len(records) == query.limit else None
        return {
            "records": [record.model_dump(mode="json") for record in records],
            "next_after_seq": last,
        }

    @router.get("/v1/audit/verify")
    def audit_verify(_: Annotated[Principal, Depends(require("audit.read"))]) -> dict[str, Any]:
        return container.audit.verify().model_dump(mode="json")

    @router.get("/v1/killswitch")
    def killswitch_status(
        _: Annotated[Principal, Depends(require(KILLSWITCH_STATUS_PERMISSION))],
    ) -> dict[str, Any]:
        return {"capabilities": [s.model_dump(mode="json") for s in container.killswitch.status()]}

    @router.post("/v1/killswitch/engage")
    def killswitch_engage(
        body: KillSwitchChange,
        principal: Annotated[Principal, Depends(require("killswitch.engage", gated=False))],
    ) -> dict[str, Any]:
        states = container.killswitch.engage(principal, body.capabilities, body.reason)
        return {"capabilities": [s.model_dump(mode="json") for s in states]}

    @router.post("/v1/killswitch/release")
    def killswitch_release(
        body: KillSwitchChange,
        principal: Annotated[Principal, Depends(require("killswitch.release", gated=False))],
    ) -> dict[str, Any]:
        states = container.killswitch.release(principal, body.capabilities, body.reason)
        return {"capabilities": [s.model_dump(mode="json") for s in states]}

    @router.get("/v1/policy/ruleset")
    def ruleset(_: Annotated[Principal, Depends(require("policy.read"))]) -> dict[str, Any]:
        rules = container.policy.ruleset
        return {
            "version": rules.version,
            "content_hash": rules.content_hash,
            "deny_all": rules.deny_all,
            "deny_reason": rules.deny_reason,
        }
