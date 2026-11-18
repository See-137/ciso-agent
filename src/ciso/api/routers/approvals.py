"""Approval routes: read requests, approve, reject (plan T2.9; blueprint 9.5, FR-025;
ADR-0016, ADR-0021).

There is deliberately no route that files an approval request: requests are filed by the
component that needs one (the external inference gateway, later the execution broker),
never by a caller naming its own subject.

Who may decide is the approval service's decision, not this module's. A route here only
requires the `approval.decide` permission through a grant that reaches the approval's
target, then hands the AUTHENTICATED principal to the service, which resolves the actor
again and applies the role, scope, separation-of-duties and credential-issuer rules
itself. A refusal comes back with the service's reason code in `reason`.

Scope. The routes that name one approval are resource routes: the target is the stored
approval's own `target` attributes, so a `system_owner` narrowed to one system reaches
approvals for that system only. An unknown id has no attributes, which only an unscoped
grant covers; the handler then answers 404. The list is platform-wide.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Annotated, Any, Final

from fastapi import Depends, FastAPI, Query, Request
from pydantic import Field

from ciso.api.deps import container_of, require
from ciso.app.container import Container
from ciso.approvals import ApprovalNotFound
from ciso.common.enums import Role
from ciso.common.principal import Principal
from ciso.common.schemas import Model

#: Largest page `GET /v1/approvals` returns; `truncated` says when more are pending.
MAX_APPROVAL_PAGE: Final = 500
#: Upper bound on a decision note here; the approval service applies its own rules too.
MAX_NOTE: Final = 2000


def approval_target(request: Request) -> Mapping[str, str | None]:
    """Target attributes of the approval named in the path; none when there is no such
    approval. A store that cannot be read raises, and the request is refused."""
    approval_id = str(request.path_params.get("approval_id", ""))
    try:
        return dict(container_of(request).approvals.get(approval_id).target)
    except ApprovalNotFound:
        return {}


#: Module level so the handlers' string annotations resolve.
READ_ANY = require("approval.read")
READ_ONE = require("approval.read", target=approval_target)
DECIDE = require("approval.decide", target=approval_target)


class PendingQuery(Model):
    """Query string of `GET /v1/approvals`. Unknown parameters are refused."""

    role: Role | None = None
    limit: int = Field(default=100, ge=1, le=MAX_APPROVAL_PAGE)


class Decision(Model):
    """Body of approve and reject. The note is optional; secrets in it are redacted
    before it is stored."""

    note: str = Field(default="", max_length=MAX_NOTE)


def register_approval_routes(router: FastAPI, container: Container) -> None:
    """Add the approval routes to `router` directly (not through `include_router`), so the
    route enumeration in `ciso.api.deps` sees each route with its declared permission."""
    approvals = container.approvals

    @router.get("/v1/approvals")
    def pending(
        query: Annotated[PendingQuery, Query()],
        _: Annotated[Principal, Depends(READ_ANY)],
    ) -> dict[str, Any]:
        """Pending, unexpired requests, oldest first; with `role`, those that role decides."""
        found = approvals.list_pending(role=query.role)
        return {
            "approvals": [record.model_dump(mode="json") for record in found[: query.limit]],
            "truncated": len(found) > query.limit,
        }

    @router.get("/v1/approvals/{approval_id}")
    def read(approval_id: str, _: Annotated[Principal, Depends(READ_ONE)]) -> dict[str, Any]:
        return approvals.get(approval_id).model_dump(mode="json")

    @router.post("/v1/approvals/{approval_id}/approve")
    def approve(
        approval_id: str,
        principal: Annotated[Principal, Depends(DECIDE)],
        body: Decision | None = None,
    ) -> dict[str, Any]:
        note = "" if body is None else body.note
        return approvals.approve(approval_id, principal, note=note).model_dump(mode="json")

    @router.post("/v1/approvals/{approval_id}/reject")
    def reject(
        approval_id: str,
        principal: Annotated[Principal, Depends(DECIDE)],
        body: Decision | None = None,
    ) -> dict[str, Any]:
        note = "" if body is None else body.note
        return approvals.reject(approval_id, principal, note=note).model_dump(mode="json")
