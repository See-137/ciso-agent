"""The base class every local model provider derives from (blueprint 8.3, 8.4).

Providers are nominal: the gateway accepts an instance only if its exact class appears in
`ciso.inference.registry`. Adding a provider is a code change in that file, reviewed like
any other, never a runtime call. A provider declares where its model runs; the gateway
refuses anything that is not in this process or on this machine's loopback.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from enum import StrEnum

from ciso.inference.records import ProviderRequest, ProviderResponse


class EndpointKind(StrEnum):
    IN_PROCESS = "in_process"
    LOOPBACK = "loopback"
    REMOTE = "remote"


#: The only endpoints the gateway will run against.
ALLOWED_ENDPOINTS: frozenset[EndpointKind] = frozenset(
    {EndpointKind.IN_PROCESS, EndpointKind.LOOPBACK}
)


class LocalProvider(ABC):
    """A model runtime on this host. The gateway reads the identity fields once."""

    @property
    @abstractmethod
    def name(self) -> str: ...

    @property
    @abstractmethod
    def model_id(self) -> str: ...

    @property
    @abstractmethod
    def model_version(self) -> str: ...

    @property
    @abstractmethod
    def endpoint_kind(self) -> EndpointKind: ...

    @abstractmethod
    def artifact_sha256(self) -> str:
        """Hash of the model artifact actually in use, compared with the manifest pin."""

    @abstractmethod
    def complete(self, request: ProviderRequest) -> ProviderResponse:
        """Answer one request. The gateway enforces the deadline; a runtime adapter must
        also enforce its own, because a hung call cannot be killed from outside."""
