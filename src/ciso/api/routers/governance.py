"""AI-activity routes: the decision API, activity intake and the central gate
(docs/skill/decision-api.md; spec C2, C3, C4).

- `POST /v1/governance/decide`: device token only (`governance.report`). Always 200 with
  `{"verdict", "decision_id", "reason", "message"}` once the device is authenticated: a
  report that cannot be read, or any failed step, is a deny with a fixed message
  (`ciso.app.governance_pipeline`). Never a 500 with details.
- `POST /v1/activity`: device token only. 202 `{"recorded": true, "action_id"}`; a report
  that cannot be read, or a BEFORE event, is 422; a failed step is 503. Never blocks.
- `POST /v1/central-gate`: no bearer token. The webhook signature authenticates the
  delivery (`ciso.app.governance_gate`); always 200 with the platform's verdict shape.

The body is read raw (capped by `ciso.api.bodylimit`) and handed to the pipeline as
parsed JSON; the intake validates it.
"""

from __future__ import annotations

import json
from typing import Annotated, Any

from fastapi import Depends, FastAPI, Request
from fastapi.responses import JSONResponse

from ciso.api.deps import require_device, require_signed_webhook
from ciso.app.container import Container
from ciso.common.principal import Principal

DEVICE = require_device()
SIGNED = require_signed_webhook()


async def raw_body(request: Request) -> bytes:
    """The request body as sent (capped by `ciso.api.bodylimit`). The handlers are plain
    functions, so FastAPI runs them, and the pipeline, in its worker threads."""
    return await request.body()


def _parsed(raw: bytes) -> Any:
    """The body as JSON, or None when it is not JSON (the intake then refuses it)."""
    try:
        return json.loads(raw)
    except ValueError:
        return None


def register_governance_routes(router: FastAPI, container: Container) -> None:
    """Add the routes to `router` directly, so the route enumeration sees each one."""
    services = container.governance

    @router.post("/v1/governance/decide")
    def decide(
        device: Annotated[Principal, Depends(DEVICE)], raw: Annotated[bytes, Depends(raw_body)]
    ) -> dict[str, Any]:
        answer = services.pipeline.decide(_parsed(raw), device_actor_id=device.actor_id)
        return answer.model_dump(mode="json")

    @router.post("/v1/activity", status_code=202)
    def activity(
        device: Annotated[Principal, Depends(DEVICE)], raw: Annotated[bytes, Depends(raw_body)]
    ) -> dict[str, Any]:
        answer = services.pipeline.record_activity(_parsed(raw), device_actor_id=device.actor_id)
        return answer.model_dump(mode="json")

    @router.post("/v1/central-gate", dependencies=[Depends(SIGNED)])
    def central_gate(request: Request, raw: Annotated[bytes, Depends(raw_body)]) -> JSONResponse:
        # Every raw header goes on: two spellings of a signature header are refused there.
        return JSONResponse(services.gate.answer(request.headers, raw))
