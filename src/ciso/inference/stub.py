"""A deterministic stand-in for a local model (OD-02: no real model is chosen yet).

The output is a pure function of the request: no randomness, no clock. It lets the rest of
the platform be built and tested without a GPU. It is registered through the manifest like
any model artifact would be.
"""

from __future__ import annotations

import json

from ciso.common.schemas import sha256_hex
from ciso.inference.provider import EndpointKind, LocalProvider
from ciso.inference.records import ProviderRequest, ProviderResponse

#: The stub has no weights file, so the manifest pins this fixed descriptor instead.
STUB_DESCRIPTOR = "ciso-stub-local-provider/1"
STUB_MODEL_ID = "stub-local"
STUB_MODEL_VERSION = "1"


class StubLocalProvider(LocalProvider):
    """Answers with a structured echo of the prompt's hash and size, never its content."""

    name = "stub-local"
    model_id = STUB_MODEL_ID
    model_version = STUB_MODEL_VERSION
    endpoint_kind = EndpointKind.IN_PROCESS

    def artifact_sha256(self) -> str:
        return sha256_hex(STUB_DESCRIPTOR)

    def complete(self, request: ProviderRequest) -> ProviderResponse:
        digest = sha256_hex(request.prompt)
        text = json.dumps(
            {
                "stub": True,
                "task_category": request.task_category,
                "prompt_sha256": digest,
                "prompt_chars": len(request.prompt),
            },
            sort_keys=True,
        )
        return ProviderResponse(
            text=text,
            input_tokens=len(request.prompt.split()),
            output_tokens=len(text.split()),
            elapsed_seconds=0.0,
            confidence=int(digest[:2], 16) / 255,
        )
