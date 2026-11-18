"""Fixtures for the inference tests. Importing tables first registers them for `engine`."""

from __future__ import annotations

from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

import pytest
from sqlalchemy import Engine
from tests.fakes.core import FakeAudit, FakeRedactor
from tests.inference.helpers import FlippingProvider, RemoteProvider, RogueProvider, SpyProvider

import ciso.inference.registry as registry
import ciso.inference.tables as _tables  # noqa: F401
from ciso.common.clock import FixedClock
from ciso.common.db import create_db_engine, init_operational_schema
from ciso.inference import (
    InferenceGateway,
    InferenceRequest,
    Manifest,
    StubLocalProvider,
    load_manifest,
)


@pytest.fixture(autouse=True)
def _registered_test_providers(monkeypatch: pytest.MonkeyPatch) -> None:
    """Registering a provider is a source edit in production; tests patch the constant.

    `RogueProvider` is deliberately left out.
    """
    assert RogueProvider not in registry.REGISTERED_PROVIDER_CLASSES
    monkeypatch.setattr(
        registry,
        "REGISTERED_PROVIDER_CLASSES",
        (*registry.REGISTERED_PROVIDER_CLASSES, SpyProvider, RemoteProvider, FlippingProvider),
    )


@pytest.fixture
def manifest() -> Manifest:
    return load_manifest()


@pytest.fixture
def file_engine(tmp_path: Path) -> Iterator[Engine]:
    eng = create_db_engine(tmp_path / "ops.db")
    init_operational_schema(eng)
    yield eng
    eng.dispose()


@pytest.fixture
def make_gateway(
    engine: Engine, clock: FixedClock, audit: FakeAudit, redactor: FakeRedactor, manifest: Manifest
) -> Callable[..., InferenceGateway]:
    def build(provider: Any = None, **kwargs: Any) -> InferenceGateway:
        kwargs.setdefault("timeout_seconds", 5.0)
        deps: dict[str, Any] = {
            "redactor": redactor,
            "audit": audit,
            "clock": clock,
            "engine": engine,
            "manifest": manifest,
        }
        for name in deps:
            if name in kwargs:
                deps[name] = kwargs.pop(name)
        return InferenceGateway(
            provider if provider is not None else StubLocalProvider(),
            deps["redactor"],
            deps["audit"],
            deps["clock"],
            deps["engine"],
            deps["manifest"],
            **kwargs,
        )

    return build


@pytest.fixture
def make_request() -> Callable[..., InferenceRequest]:
    def build(**overrides: Any) -> InferenceRequest:
        data: dict[str, Any] = {
            "task_category": "summarise",
            "prompt_template_id": "stub",
            "prompt_template_version": 1,
            "inputs": {"evidence": "plain evidence"},
            "context_refs": [{"ref": "evidence:ev_1", "classification": "internal"}],
            "correlation_id": "corr-1",
            "max_output_tokens": 64,
        }
        data.update(overrides)
        return InferenceRequest(**data)

    return build
