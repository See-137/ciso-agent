"""External model routes: propose, preview, file for approval, transmit, and read what
was recorded (plan T2.9; blueprint 8.4; FR-018; ADR-0006).

This module and the composition root are the only importers of the external inference
package. Every step goes through the one `ExternalInferenceGateway` the container holds,
and every refusal is the gateway's own: with the shipped settings the feature is off and
each step answers 403 with `reason: feature_disabled`.

Item text is not stored, so preview, authorize and transmit take the proposal back from
the caller. It is passed to the gateway as it arrived; the gateway compares it with the
record `propose` left and builds the payload itself. The acting actor is always the
authenticated principal, never a field of the body: the requester named inside a proposal
is only part of what the gateway compares.

Approving is not done here: the approver decides through the approval routes.
"""

from __future__ import annotations

import base64
from typing import Annotated, Any, Final

from fastapi import Depends, FastAPI, Request
from pydantic import Field

from ciso.api.deps import ApiError, correlation_of, not_found, require
from ciso.app.container import Container
from ciso.common.principal import Principal
from ciso.common.schemas import Model
from ciso.inference.external import (
    MAX_ITEMS,
    ContextItem,
    ExternalRequestProposal,
    ExternalResult,
    ExternalTransmitFailed,
    PayloadPreview,
)

#: Module level so the handlers' string annotations resolve.
REQUEST = require("external_inference.request")
READ = require("external_inference.read")

MAX_NAME: Final = 128
MAX_PURPOSE: Final = 1000
MAX_ID: Final = 64


class ProposalRequest(Model):
    """Body of `POST /v1/external-inference/proposals` (blueprint 8.4 step 1)."""

    purpose: str = Field(min_length=1, max_length=MAX_PURPOSE)
    provider_name: str = Field(min_length=1, max_length=MAX_NAME)
    model_name: str = Field(min_length=1, max_length=MAX_NAME)
    items: tuple[ContextItem, ...] = Field(min_length=1, max_length=MAX_ITEMS)


class ProposalEnvelope(Model):
    """Body of preview and authorize: the proposal exactly as `proposals` returned it."""

    proposal: ExternalRequestProposal


class TransmitRequest(Model):
    proposal: ExternalRequestProposal
    approval_id: str = Field(min_length=1, max_length=MAX_ID)


def preview_body(preview: PayloadPreview) -> dict[str, Any]:
    """What a human is shown (8.4 step 2). `payload_base64` is exactly the bytes that
    would be sent and `payload_sha256` their hash; both are null when nothing may go."""
    raw = preview.preview_bytes
    return {
        "request_id": preview.request_id,
        "provider_name": preview.provider_name,
        "model_name": preview.model_name,
        "purpose": preview.purpose,
        "classification": preview.classification,
        "sendable": preview.sendable,
        "blocked_reason": None if preview.blocked_reason is None else preview.blocked_reason.value,
        "payload_base64": None if raw is None else base64.b64encode(raw).decode("ascii"),
        "payload_sha256": preview.payload_hash,
        "payload_bytes": 0 if raw is None else len(raw),
        "kept": [{"ref": item.ref, "classification": item.classification} for item in preview.kept],
        "dropped": [
            {"ref": item.ref, "classification": item.classification, "reason": item.reason.value}
            for item in preview.dropped
        ],
    }


def result_body(result: ExternalResult) -> dict[str, Any]:
    """The answer (8.4 step 7). `output.text` is untrusted model output: data to read,
    never an instruction; an action it suggests goes through the policy engine."""
    return {
        "record_id": result.record_id,
        "request_id": result.request_id,
        "approval_ref": result.approval_ref,
        "result_ref": result.result_ref,
        "provider_name": result.provider_name,
        "model_name": result.model_name,
        "response_bytes": result.response_bytes,
        "response_digest": result.response_digest,
        "response_metadata": dict(result.response_metadata),
        "output": {"untrusted": True, "text": result.output.unsafe_text()},
    }


def register_external_inference_routes(router: FastAPI, container: Container) -> None:
    """Add the external model routes to `router` directly (not through `include_router`),
    so the route enumeration in `ciso.api.deps` sees each route's declared permission."""
    gateway = container.external_inference

    @router.post("/v1/external-inference/proposals", status_code=201)
    def propose(
        body: ProposalRequest,
        request: Request,
        principal: Annotated[Principal, Depends(REQUEST)],
    ) -> dict[str, Any]:
        """Step 1. Keep the returned proposal: every later step takes it back."""
        proposal = gateway.propose(
            requester_actor_id=principal.actor_id,
            purpose=body.purpose,
            provider_name=body.provider_name,
            model_name=body.model_name,
            items=body.items,
            correlation_id=correlation_of(request),
        )
        return {"proposal": proposal.model_dump(mode="json")}

    @router.post("/v1/external-inference/preview")
    def preview(
        body: ProposalEnvelope,
        request: Request,
        principal: Annotated[Principal, Depends(REQUEST)],
    ) -> dict[str, Any]:
        """Steps 2 and 3: the exact payload, and what was dropped and why."""
        shown = gateway.preview(
            body.proposal, actor_id=principal.actor_id, correlation_id=correlation_of(request)
        )
        return preview_body(shown)

    @router.post("/v1/external-inference/authorizations", status_code=201)
    def authorize(
        body: ProposalEnvelope,
        request: Request,
        principal: Annotated[Principal, Depends(REQUEST)],
    ) -> dict[str, Any]:
        """Step 4: file the approval request for what this proposal minimizes to."""
        authorization = gateway.request_approval(
            body.proposal, actor_id=principal.actor_id, correlation_id=correlation_of(request)
        )
        return authorization.model_dump(mode="json")

    @router.post("/v1/external-inference/transmit")
    def transmit(
        body: TransmitRequest,
        request: Request,
        principal: Annotated[Principal, Depends(REQUEST)],
    ) -> dict[str, Any]:
        """Steps 5 to 7: spend the approval and send once. Never retried."""
        try:
            result = gateway.transmit(
                body.proposal,
                body.approval_id,
                actor_id=principal.actor_id,
                correlation_id=correlation_of(request),
            )
        except ExternalTransmitFailed as failed:
            raise ApiError(
                502,
                "external_transmit_failed",
                "the payload was sent and no usable answer came back; the approval is spent",
                extra={"reason": failed.outcome.value, "record_id": failed.record_id},
            ) from failed
        return result_body(result)

    @router.get("/v1/external-inference/authorizations/{approval_id}")
    def read_authorization(
        approval_id: str, _: Annotated[Principal, Depends(READ)]
    ) -> dict[str, Any]:
        found = gateway.get_authorization(approval_id)
        if found is None:
            raise not_found()
        return found.model_dump(mode="json")

    @router.get("/v1/external-inference/transmissions/{record_id}")
    def read_transmission(record_id: str, _: Annotated[Principal, Depends(READ)]) -> dict[str, Any]:
        found = gateway.get_record(record_id)
        if found is None:
            raise not_found()
        return found.model_dump(mode="json")
