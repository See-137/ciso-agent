"""Findings and alerts routes (spec section 4 steps 6-7, S6).

The route permission is the first gate; the findings service decides again on the
caller's actor id, resolved now (`ciso.findings.access`): reads of all findings and every
transition but acknowledge are for an unnarrowed `security_admin` (reads also for the
`auditor`); a person may acknowledge and list their own findings.

| Route | Permission |
|---|---|
| `GET /v1/findings`, `GET /v1/findings/{id}`, `GET /v1/alerts` | `finding.read` |
| `GET /v1/findings/mine` | `report.read_own` |
| `POST /v1/findings/{id}/acknowledge` | `finding.acknowledge` |
| `POST /v1/findings/{id}/resolve`, `/false-positive`, `/accept-risk` | `finding.update` |
| `POST /v1/findings/{id}/risk-acceptance` | `finding.update` |

Accepting a risk (`ciso.app.risk_acceptance`): an admin files the request with
`POST /v1/findings/{id}/risk-acceptance` (`finding.update`; routed to
`executive_risk_owner`, decided through `/v1/approvals/{id}/approve`), then calls
`accept-risk` with that approval id. The approval must be bound to this finding, granted
by someone other than the caller, and is spent on use; anything else is 409
`risk_acceptance_refused` with a `reason` code.
"""

from __future__ import annotations

from typing import Annotated, Any, Final

from fastapi import Depends, FastAPI, Query
from pydantic import Field

from ciso.api.deps import ApiError, require
from ciso.app.container import Container
from ciso.app.risk_acceptance import RiskAcceptance, RiskAcceptanceRefused
from ciso.common.principal import Principal
from ciso.common.schemas import Model
from ciso.findings import AlertStatus, FindingFilter
from ciso.findings.models import DEFAULT_PAGE, MAX_PAGE, MAX_RECOMMENDATION_CHARS

READ: Final = require("finding.read")
READ_OWN: Final = require("report.read_own")
ACKNOWLEDGE: Final = require("finding.acknowledge")
UPDATE: Final = require("finding.update")


class AlertQuery(Model):
    status: AlertStatus | None = None
    limit: int = Field(default=DEFAULT_PAGE, ge=1, le=MAX_PAGE)


class RiskAcceptanceBody(Model):
    approval_id: str = Field(min_length=1, max_length=128)


class FalsePositive(Model):
    reason: str = Field(min_length=1, max_length=MAX_RECOMMENDATION_CHARS)


def _refused(refused: RiskAcceptanceRefused) -> ApiError:
    return ApiError(
        409,
        "risk_acceptance_refused",
        "the risk acceptance was refused",
        extra={"reason": refused.reason.value},
    )


def _dump(item: Any) -> dict[str, Any]:
    result: dict[str, Any] = item.model_dump(mode="json")
    return result


def register_findings_routes(router: FastAPI, container: Container) -> None:
    """Add the routes to `router` directly, so the route enumeration sees each one."""
    findings = container.governance.findings
    risk = RiskAcceptance(approvals=container.approvals, findings=findings)

    @router.get("/v1/findings")
    def list_findings(
        query: Annotated[FindingFilter, Query()], principal: Annotated[Principal, Depends(READ)]
    ) -> dict[str, Any]:
        return {"findings": [_dump(f) for f in findings.list(principal.actor_id, query)]}

    @router.get("/v1/findings/mine")
    def own_findings(principal: Annotated[Principal, Depends(READ_OWN)]) -> dict[str, Any]:
        return {"findings": [_dump(f) for f in findings.list_own(principal.actor_id)]}

    @router.get("/v1/findings/{finding_id}")
    def get_finding(
        finding_id: str, principal: Annotated[Principal, Depends(READ)]
    ) -> dict[str, Any]:
        return _dump(findings.get(principal.actor_id, finding_id))

    @router.post("/v1/findings/{finding_id}/acknowledge")
    def acknowledge(
        finding_id: str, principal: Annotated[Principal, Depends(ACKNOWLEDGE)]
    ) -> dict[str, Any]:
        return _dump(findings.acknowledge(principal.actor_id, finding_id))

    @router.post("/v1/findings/{finding_id}/resolve")
    def resolve(
        finding_id: str, principal: Annotated[Principal, Depends(UPDATE)]
    ) -> dict[str, Any]:
        return _dump(findings.resolve(principal.actor_id, finding_id))

    @router.post("/v1/findings/{finding_id}/risk-acceptance", status_code=201)
    def request_risk_acceptance(
        finding_id: str, principal: Annotated[Principal, Depends(UPDATE)]
    ) -> dict[str, Any]:
        try:
            return _dump(risk.request(principal, finding_id))
        except RiskAcceptanceRefused as refused:
            raise _refused(refused) from None

    @router.post("/v1/findings/{finding_id}/accept-risk")
    def accept_risk(
        finding_id: str, body: RiskAcceptanceBody, principal: Annotated[Principal, Depends(UPDATE)]
    ) -> dict[str, Any]:
        try:
            return _dump(risk.accept(principal, finding_id, body.approval_id))
        except RiskAcceptanceRefused as refused:
            raise _refused(refused) from None

    @router.post("/v1/findings/{finding_id}/false-positive")
    def false_positive(
        finding_id: str, body: FalsePositive, principal: Annotated[Principal, Depends(UPDATE)]
    ) -> dict[str, Any]:
        found = findings.mark_false_positive(principal.actor_id, finding_id, body.reason)
        return _dump(found)

    @router.get("/v1/alerts")
    def alerts(
        query: Annotated[AlertQuery, Query()], principal: Annotated[Principal, Depends(READ)]
    ) -> dict[str, Any]:
        found = findings.list_alerts(principal.actor_id, query.status, query.limit)
        return {"alerts": [_dump(a) for a in found]}
