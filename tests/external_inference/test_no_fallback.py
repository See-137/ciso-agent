"""No automatic route to an external model (blueprint 8.4 hard requirement; FR-017;
NFR-017; plan row T2.8; gap G19).

A fully enabled external gateway with a spy transport stands next to the local
`InferenceGateway`, on the same database and audit log. The local gateway is then driven
into each failure it really has. Every test shows first that the local failure happened
(the exception and the recorded status), then that the spy transport saw no call, no
approval request was filed and no external-path audit record was written.
"""

from __future__ import annotations

import threading
from collections.abc import Callable, Iterator
from typing import Any

import pytest
from sqlalchemy import Engine
from tests.external_inference.conftest import SpyTransport, approval_rows
from tests.fakes.core import FakeAudit, FakeRedactor
from tests.inference.helpers import SpyProvider, wait_until

import ciso.inference.registry as registry
from ciso.common.clock import FixedClock
from ciso.common.errors import InferenceUnavailable
from ciso.inference import (
    InferenceGateway,
    InferenceRequest,
    InvocationLog,
    ProviderResponse,
    load_manifest,
)
from ciso.inference.external import ExternalInferenceGateway

pytestmark = pytest.mark.external_inference

LocalFactory = Callable[..., InferenceGateway]
CORRELATION = "corr-no-fallback"


@pytest.fixture(autouse=True)
def _spy_provider_registered(monkeypatch: pytest.MonkeyPatch) -> None:
    """Registering a provider is a source edit in production; the test patches the list."""
    monkeypatch.setattr(
        registry,
        "REGISTERED_PROVIDER_CLASSES",
        (*registry.REGISTERED_PROVIDER_CLASSES, SpyProvider),
    )


@pytest.fixture
def external(
    make_gateway: Callable[..., ExternalInferenceGateway], spy: SpyTransport
) -> ExternalInferenceGateway:
    """Enabled, approver role set, classifications allowed, transport wired: the external
    path could send if anything asked it to."""
    gateway = make_gateway()
    assert spy.calls == []
    return gateway


@pytest.fixture
def local(
    engine: Engine, clock: FixedClock, audit: FakeAudit, redactor: FakeRedactor
) -> LocalFactory:
    def build(provider: SpyProvider, **kwargs: Any) -> InferenceGateway:
        kwargs.setdefault("timeout_seconds", 5.0)
        return InferenceGateway(provider, redactor, audit, clock, engine, load_manifest(), **kwargs)

    return build


@pytest.fixture
def request_() -> InferenceRequest:
    return InferenceRequest(
        task_category="summarise",
        prompt_template_id="stub",
        prompt_template_version=1,
        inputs={"evidence": "plain evidence"},
        context_refs=[{"ref": "evidence:ev_1", "classification": "internal"}],
        correlation_id=CORRELATION,
        max_output_tokens=64,
    )


@pytest.fixture
def nothing_external(
    external: ExternalInferenceGateway, spy: SpyTransport, engine: Engine, audit: FakeAudit
) -> Iterator[Callable[[int], None]]:
    """Call the returned check with the number of local provider calls expected."""
    checked: list[bool] = []

    def check(local_audit_events: int) -> None:
        assert spy.calls == []
        assert approval_rows(engine) == 0
        actions = audit.actions()
        assert len(actions) == local_audit_events > 0
        assert set(actions) == {"inference.local.complete"}
        checked.append(True)

    yield check
    assert checked, "the test never asserted that nothing went external"


def _statuses(engine: Engine) -> list[str]:
    return [record.status for record in InvocationLog(engine).for_correlation(CORRELATION)]


def test_local_timeout_does_not_go_external(
    local: LocalFactory,
    request_: InferenceRequest,
    engine: Engine,
    nothing_external: Callable[[int], None],
) -> None:
    gate = threading.Event()
    provider = SpyProvider(gate=gate)
    gateway = local(provider, timeout_seconds=0.1)
    try:
        with pytest.raises(InferenceUnavailable, match="timeout"):
            gateway.complete(request_)
        assert len(provider.calls) == 1
        assert _statuses(engine) == ["timeout"]
        nothing_external(2)
    finally:
        gate.set()
    assert wait_until(lambda: gateway.abandoned_calls == 0)


def test_local_provider_error_does_not_go_external(
    local: LocalFactory,
    request_: InferenceRequest,
    engine: Engine,
    nothing_external: Callable[[int], None],
) -> None:
    provider = SpyProvider(raises=RuntimeError("model runtime crashed"))
    with pytest.raises(InferenceUnavailable, match="provider_error"):
        local(provider).complete(request_)
    assert len(provider.calls) == 1
    assert _statuses(engine) == ["provider_error"]
    nothing_external(2)


def test_low_confidence_answer_is_returned_as_it_is_and_does_not_go_external(
    local: LocalFactory,
    request_: InferenceRequest,
    engine: Engine,
    nothing_external: Callable[[int], None],
) -> None:
    provider = SpyProvider(text='{"answer": "unsure"}', confidence=0.01)
    result = local(provider).complete(request_)
    assert result.confidence == 0.01
    assert result.output.unsafe_text() == '{"answer": "unsure"}'
    assert len(provider.calls) == 1
    assert _statuses(engine) == ["ok"]
    nothing_external(2)


def test_too_many_abandoned_calls_refuses_and_does_not_go_external(
    local: LocalFactory,
    request_: InferenceRequest,
    engine: Engine,
    nothing_external: Callable[[int], None],
) -> None:
    """The nearest thing the local gateway has to queue pressure or an open circuit."""
    gate = threading.Event()
    provider = SpyProvider(gate=gate)
    gateway = local(provider, timeout_seconds=0.1, max_abandoned_calls=None)
    try:
        with pytest.raises(InferenceUnavailable, match="timeout"):
            gateway.complete(request_)
        assert gateway.abandoned_calls == 1
        with pytest.raises(InferenceUnavailable, match="abandoned"):
            gateway.complete(request_)
        assert len(provider.calls) == 1  # the second request never reached the provider
        assert _statuses(engine) == ["timeout"]
        nothing_external(2)
    finally:
        gate.set()
    assert wait_until(lambda: gateway.abandoned_calls == 0)


def test_empty_and_malformed_answers_do_not_go_external(
    local: LocalFactory,
    request_: InferenceRequest,
    engine: Engine,
    nothing_external: Callable[[int], None],
) -> None:
    with pytest.raises(InferenceUnavailable, match="empty"):
        local(SpyProvider(text="   ")).complete(request_)
    broken = ProviderResponse.model_construct(
        text=None, input_tokens=1, output_tokens=1, elapsed_seconds=0.0, confidence=None
    )
    with pytest.raises(InferenceUnavailable, match="malformed"):
        local(SpyProvider(raw=broken)).complete(request_)
    assert _statuses(engine) == ["empty", "malformed"]
    nothing_external(4)


def test_unconfigured_timeout_refuses_and_does_not_go_external(
    local: LocalFactory, request_: InferenceRequest, spy: SpyTransport, engine: Engine,
    external: ExternalInferenceGateway,
) -> None:  # fmt: skip
    provider = SpyProvider()
    with pytest.raises(InferenceUnavailable, match="timeout"):
        local(provider, timeout_seconds=None).complete(request_)
    assert provider.calls == []
    assert spy.calls == []
    assert approval_rows(engine) == 0


def test_the_local_gateway_holds_no_reference_to_the_external_path(
    local: LocalFactory, external: ExternalInferenceGateway, spy: SpyTransport
) -> None:
    gateway = local(SpyProvider())
    held = list(vars(gateway).values())
    assert len(held) >= 10
    assert not any(isinstance(value, ExternalInferenceGateway | SpyTransport) for value in held)
    assert not any(value is external or value is spy for value in held)
