"""Local inference gateway, stub model and the prompt/model manifest."""

from __future__ import annotations

from ciso.inference.gateway import InferenceGateway
from ciso.inference.manifest import (
    DEFAULT_MANIFEST_PATH,
    Manifest,
    ModelArtifact,
    PromptTemplate,
    load_manifest,
)
from ciso.inference.provider import EndpointKind, LocalProvider
from ciso.inference.records import (
    ContextRef,
    InferenceRequest,
    InferenceResult,
    InvocationLog,
    InvocationRecord,
    ProviderRequest,
    ProviderResponse,
    UntrustedModelOutput,
)
from ciso.inference.stub import StubLocalProvider

__all__ = [
    "DEFAULT_MANIFEST_PATH",
    "ContextRef",
    "EndpointKind",
    "InferenceGateway",
    "InferenceRequest",
    "InferenceResult",
    "InvocationLog",
    "InvocationRecord",
    "LocalProvider",
    "Manifest",
    "ModelArtifact",
    "PromptTemplate",
    "ProviderRequest",
    "ProviderResponse",
    "StubLocalProvider",
    "UntrustedModelOutput",
    "load_manifest",
]
