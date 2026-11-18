"""AI-agent registry routes (docs/skill/spec-draft.md, S1, S7).

Each route declares its permission; the registry then decides again on the caller as the
identity store sees them now (`ciso.agents.gate`): every change needs an unnarrowed human
`security_admin`, except `suspend`, which the agent's own owner or operator may also do.
Only the caller's actor id is passed on, never the principal's roles.

| Route | Permission |
|---|---|
| `POST /v1/agents` | `agents.manage` |
| `POST /v1/agents/{id}/approve`, `/unsuspend`, `/retire`, `/classify` | `agents.manage` |
| `POST /v1/agents/{id}/suspend` | `agents.suspend` |
| `POST /v1/agents/bindings`, `DELETE /v1/agents/bindings/{id}` | `agents.manage` |
| `GET /v1/agents`, `/v1/agents/coverage-gaps`, `/v1/agents/{id}` | `governance.read` |
| `GET /v1/sessions/{id}` | `governance.read` |
"""

from __future__ import annotations

from typing import Annotated, Any, Final

from fastapi import Depends, FastAPI, Query
from pydantic import Field

from ciso.agents import AgentStatus, Registration
from ciso.agents.models import MAX_LIST
from ciso.api.deps import require
from ciso.app.container import Container
from ciso.common.activity import AgentClass
from ciso.common.principal import Principal
from ciso.common.schemas import Model

MANAGE: Final = require("agents.manage")
SUSPEND: Final = require("agents.suspend")
READ: Final = require("governance.read")


class AgentQuery(Model):
    agent_class: AgentClass | None = None
    status: AgentStatus | None = None
    operator_ref: str | None = Field(default=None, max_length=200)
    limit: int = Field(default=100, ge=1, le=MAX_LIST)


class GapQuery(Model):
    limit: int = Field(default=100, ge=1, le=MAX_LIST)


class Classification(Model):
    agent_class: AgentClass
    owner_ref: str | None = Field(default=None, max_length=200)
    operator_ref: str | None = Field(default=None, max_length=200)


class BindingRequest(Model):
    kind: str = Field(max_length=32)
    subject: str = Field(min_length=1, max_length=512)
    person_ref: str = Field(max_length=200)


def _dump(item: Any) -> dict[str, Any]:
    result: dict[str, Any] = item.model_dump(mode="json")
    return result


def register_agent_routes(router: FastAPI, container: Container) -> None:
    """Add the routes to `router` directly, so the route enumeration sees each one."""
    registry = container.governance.registry
    admin = container.governance.agent_admin

    @router.post("/v1/agents", status_code=201)
    def register(
        body: Registration, principal: Annotated[Principal, Depends(MANAGE)]
    ) -> dict[str, Any]:
        return _dump(admin.register_agent(principal.actor_id, body))

    @router.get("/v1/agents")
    def list_agents(
        query: Annotated[AgentQuery, Query()], _: Annotated[Principal, Depends(READ)]
    ) -> dict[str, Any]:
        found = registry.list_agents(
            agent_class=query.agent_class,
            status=query.status,
            operator_ref=query.operator_ref,
            limit=query.limit,
        )
        return {"agents": [_dump(a) for a in found]}

    @router.get("/v1/agents/coverage-gaps")
    def coverage_gaps(
        query: Annotated[GapQuery, Query()], _: Annotated[Principal, Depends(READ)]
    ) -> dict[str, Any]:
        return {"agents": [_dump(a) for a in registry.list_coverage_gaps(limit=query.limit)]}

    @router.post("/v1/agents/bindings", status_code=201)
    def bind(
        body: BindingRequest, principal: Annotated[Principal, Depends(MANAGE)]
    ) -> dict[str, Any]:
        found = admin.bind_claim(principal.actor_id, body.kind, body.subject, body.person_ref)
        return _dump(found)

    @router.delete("/v1/agents/bindings/{binding_id}")
    def unbind(binding_id: str, principal: Annotated[Principal, Depends(MANAGE)]) -> dict[str, Any]:
        return _dump(admin.unbind_claim(principal.actor_id, binding_id))

    @router.get("/v1/agents/{agent_id}")
    def get_agent(agent_id: str, _: Annotated[Principal, Depends(READ)]) -> dict[str, Any]:
        return _dump(registry.get_agent(agent_id))

    @router.post("/v1/agents/{agent_id}/approve")
    def approve(agent_id: str, principal: Annotated[Principal, Depends(MANAGE)]) -> dict[str, Any]:
        return _dump(admin.approve(principal.actor_id, agent_id))

    @router.post("/v1/agents/{agent_id}/suspend")
    def suspend(agent_id: str, principal: Annotated[Principal, Depends(SUSPEND)]) -> dict[str, Any]:
        return _dump(admin.suspend(principal.actor_id, agent_id))

    @router.post("/v1/agents/{agent_id}/unsuspend")
    def unsuspend(
        agent_id: str, principal: Annotated[Principal, Depends(MANAGE)]
    ) -> dict[str, Any]:
        return _dump(admin.unsuspend(principal.actor_id, agent_id))

    @router.post("/v1/agents/{agent_id}/retire")
    def retire(agent_id: str, principal: Annotated[Principal, Depends(MANAGE)]) -> dict[str, Any]:
        return _dump(admin.retire(principal.actor_id, agent_id))

    @router.post("/v1/agents/{agent_id}/classify")
    def classify(
        agent_id: str, body: Classification, principal: Annotated[Principal, Depends(MANAGE)]
    ) -> dict[str, Any]:
        found = admin.classify(
            principal.actor_id,
            agent_id,
            body.agent_class,
            owner_ref=body.owner_ref,
            operator_ref=body.operator_ref,
        )
        return _dump(found)

    @router.get("/v1/sessions/{session_id}")
    def get_session(session_id: str, _: Annotated[Principal, Depends(READ)]) -> dict[str, Any]:
        return _dump(registry.get_session(session_id))
