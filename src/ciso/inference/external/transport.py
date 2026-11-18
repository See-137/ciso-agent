"""The interface a sender of external model requests must satisfy (blueprint 8.4 step 5).

This build ships no implementation: there is nothing in `src` that can carry bytes to a
provider, and a test counts the implementations to keep it that way (ADR-0006). Adding one
is a reviewed change in a module the network allowlist names.

An implementation must enforce its own deadline. The gateway calls `send` once, never
retries and never tries another provider.
"""

from __future__ import annotations

import re
from typing import Protocol, runtime_checkable

from pydantic import Field, field_validator

from ciso.common.schemas import FrozenMap, Model

MAX_METADATA_FIELDS = 16
_META_KEY_RE = re.compile(r"^[a-z][a-z0-9_]{0,63}$")
# Identifiers and numbers only: no spaces, so a value cannot carry a sentence of the answer.
_META_VALUE_RE = re.compile(r"^[A-Za-z0-9_.:/@+=-]{0,128}$")


class TransportResponse(Model):
    """What came back. `body` is the raw answer; `metadata` is what the provider reports
    about the call (its own request id, token counts, a finish code). Both are untrusted.
    Metadata is limited to short identifier-shaped values so it cannot hold answer text.
    """

    body: bytes = Field(repr=False)
    metadata: FrozenMap[str, str] = Field(default_factory=dict)

    @field_validator("metadata")
    @classmethod
    def _opaque(cls, value: FrozenMap[str, str]) -> FrozenMap[str, str]:
        if len(value) > MAX_METADATA_FIELDS:
            raise ValueError("too many metadata fields")
        for key, item in value.items():
            if not isinstance(key, str) or not _META_KEY_RE.fullmatch(key):
                raise ValueError("bad metadata key")
            if not isinstance(item, str) or not _META_VALUE_RE.fullmatch(item):
                raise ValueError("metadata values must be short identifiers")
        return value


@runtime_checkable
class ExternalTransport(Protocol):
    """Carries one approved payload to one named provider and model."""

    def send(self, *, provider_name: str, model_name: str, payload: bytes) -> TransportResponse:
        """Send exactly `payload`, unchanged, and return the raw answer.

        Raise on any failure. Do not retry, do not fall back to another provider or
        model, and do not log the payload or the answer.
        """
        ...
