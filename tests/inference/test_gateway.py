"""Local inference gateway: one route, hard deadline, fail closed, untrusted output."""

from __future__ import annotations

import inspect
import threading
import time
from collections.abc import Callable
from typing import Any

import pytest
from tests.conftest import REPO_ROOT
from tests.fakes.core import FakeAudit
from tests.inference.helpers import (
    FlakyAudit,
    SpyProvider,
    StepClock,
    scan_gateway_source,
    wait_until,
)

from ciso.common.errors import FailClosed, InferenceUnavailable
from ciso.inference import (
    InferenceGateway,
    InferenceRequest,
    InvocationLog,
    ProviderResponse,
    StubLocalProvider,
)

GATEWAY_SRC = REPO_ROOT / "src" / "ciso" / "inference" / "gateway.py"

Build = Callable[..., InferenceGateway]
Req = Callable[..., InferenceRequest]


def _walk(value: Any, depth: int = 0) -> list[Any]:
    """Every object reachable through containers held by an attribute, to a small depth."""
    found = [value]
    if depth < 3:
        if isinstance(value, dict):
            for item in [*value.keys(), *value.values()]:
                found.extend(_walk(item, depth + 1))
        elif isinstance(value, list | tuple | set | frozenset):
            for item in value:
                found.extend(_walk(item, depth + 1))
    return found


@pytest.mark.external_inference
class TestNoAlternateRoute:
    def test_gateway_holds_exactly_one_provider_and_no_other_callable(
        self, make_gateway: Build
    ) -> None:
        configured = StubLocalProvider()
        gw = make_gateway(configured)
        from ciso.inference import LocalProvider

        providers = [o for v in vars(gw).values() for o in _walk(v) if isinstance(o, LocalProvider)]
        assert providers == [configured]
        callables = sorted(name for name, v in vars(gw).items() if callable(v))
        assert callables == ["_monotonic"]

    def test_constructor_has_one_provider_parameter_and_no_varargs(self) -> None:
        params = inspect.signature(InferenceGateway.__init__).parameters
        typed = [n for n, p in params.items() if "Provider" in str(p.annotation)]
        assert typed == ["provider"]
        kinds = {p.kind for p in params.values()}
        assert inspect.Parameter.VAR_KEYWORD not in kinds
        assert inspect.Parameter.VAR_POSITIONAL not in kinds

    def test_constructor_rejects_list_and_second_positional_provider(
        self,
        make_gateway: Build,
        redactor: Any,
        audit: FakeAudit,
        clock: Any,
        engine: Any,
        manifest: Any,
    ) -> None:
        a, b = SpyProvider(), SpyProvider()
        with pytest.raises(TypeError):
            make_gateway([a, b])
        with pytest.raises(TypeError):
            InferenceGateway(a, b, redactor, audit, clock, engine, manifest)  # type: ignore[arg-type]
        with pytest.raises(TypeError):
            InferenceGateway(a, redactor, audit, clock, engine, manifest, b)  # type: ignore[misc]

    def test_scan_is_clean_on_the_real_source(self) -> None:
        assert scan_gateway_source(GATEWAY_SRC.read_text(encoding="utf-8")) == []

    def test_scan_flags_a_planted_second_route(self) -> None:
        real = GATEWAY_SRC.read_text(encoding="utf-8")
        planted = real.replace(
            "        self._lock = threading.Lock()",
            "        self._lock = threading.Lock()\n        self._fallback = StubLocalProvider()",
            1,
        )
        assert planted != real
        findings = scan_gateway_source(planted)
        assert any("fallback" in f for f in findings)
        assert any("unexpected attribute self._fallback" in f for f in findings)

    def test_scan_flags_a_renamed_second_route_by_structure(self) -> None:
        real = GATEWAY_SRC.read_text(encoding="utf-8")
        planted = real.replace(
            "        self._lock = threading.Lock()",
            "        self._lock = threading.Lock()\n        self._client = object()",
            1,
        )
        assert any("unexpected attribute self._client" in f for f in scan_gateway_source(planted))

    def test_scan_flags_extra_provider_parameter_and_kwargs(self) -> None:
        src = (
            "class InferenceGateway:\n"
            "    def __init__(self, provider: LocalProvider, other: LocalProvider, **kw): ...\n"
        )
        findings = scan_gateway_source(src)
        assert "__init__ takes *args or **kwargs" in findings
        assert any("provider-typed parameters" in f for f in findings)


@pytest.mark.unit
class TestDeadline:
    def test_hung_provider_hits_the_deadline(
        self, make_gateway: Build, make_request: Req, engine: Any
    ) -> None:
        gate = threading.Event()
        provider = SpyProvider(gate=gate)
        gw = make_gateway(provider, timeout_seconds=0.1)
        started = time.monotonic()
        try:
            with pytest.raises(InferenceUnavailable):
                gw.complete(make_request())
            assert time.monotonic() - started < 3.0
            assert gw.abandoned_calls == 1
            rows = InvocationLog(engine).for_correlation("corr-1")
            assert [r.status for r in rows] == ["timeout"]
            assert rows[0].output_size == 0
        finally:
            gate.set()
        assert wait_until(lambda: gw.abandoned_calls == 0)

    def test_late_result_is_never_returned(self, make_gateway: Build, make_request: Req) -> None:
        # The provider is instant but the gateway's own clock says the call took 10s.
        gw = make_gateway(SpyProvider(), timeout_seconds=5.0, monotonic=StepClock(10.0))
        with pytest.raises(InferenceUnavailable):
            gw.complete(make_request())

    def test_on_time_result_passes_the_same_limit(
        self, make_gateway: Build, make_request: Req
    ) -> None:
        gw = make_gateway(SpyProvider(), timeout_seconds=5.0, monotonic=StepClock(4.0))
        assert gw.complete(make_request()).latency_seconds == 4.0

    def test_provider_reported_elapsed_is_informational_only(
        self, make_gateway: Build, make_request: Req, engine: Any
    ) -> None:
        result = make_gateway(SpyProvider(elapsed=99.0), timeout_seconds=5.0).complete(
            make_request()
        )
        assert result.latency_seconds < 5.0
        rec = InvocationLog(engine).get(result.record_id)
        assert rec is not None
        assert rec.provider_reported_seconds == 99.0
        assert rec.latency_seconds == result.latency_seconds

    def test_provider_raising_timeout_error_is_a_timeout(
        self, make_gateway: Build, make_request: Req, engine: Any
    ) -> None:
        with pytest.raises(InferenceUnavailable):
            make_gateway(SpyProvider(raises=TimeoutError())).complete(make_request())
        assert [r.status for r in InvocationLog(engine).for_correlation("corr-1")] == ["timeout"]

    @pytest.mark.parametrize("limit", [None, 0.0, -1.0, float("nan"), float("inf"), float("-inf")])
    def test_invalid_timeout_refuses_before_anything_happens(
        self, make_gateway: Build, make_request: Req, audit: FakeAudit, limit: float | None
    ) -> None:
        spy = SpyProvider()
        with pytest.raises(InferenceUnavailable):
            make_gateway(spy, timeout_seconds=limit).complete(make_request())
        assert spy.calls == []
        assert audit.events == []

    def test_abandoned_call_blocks_new_work_when_limit_is_none(
        self, make_gateway: Build, make_request: Req
    ) -> None:
        gate = threading.Event()
        spy = SpyProvider(gate=gate, gate_first_call_only=True)
        gw = make_gateway(spy, timeout_seconds=0.1, max_abandoned_calls=None)
        try:
            with pytest.raises(InferenceUnavailable):
                gw.complete(make_request())
            with pytest.raises(InferenceUnavailable, match="abandoned"):
                gw.complete(make_request())
            assert len(spy.calls) == 1
        finally:
            gate.set()
        assert wait_until(lambda: gw.abandoned_calls == 0)
        assert gw.complete(make_request()).output.unsafe_text() == '{"ok": true}'

    def test_configured_maximum_allows_work_below_it(
        self, make_gateway: Build, make_request: Req
    ) -> None:
        gate = threading.Event()
        spy = SpyProvider(gate=gate, gate_first_call_only=True)
        gw = make_gateway(spy, timeout_seconds=0.1, max_abandoned_calls=2)
        try:
            with pytest.raises(InferenceUnavailable):
                gw.complete(make_request())
            assert gw.complete(make_request()).output.unsafe_text() == '{"ok": true}'
        finally:
            gate.set()
        assert wait_until(lambda: gw.abandoned_calls == 0)

    def test_bad_knobs_refuse_construction(self, make_gateway: Build) -> None:
        with pytest.raises(ValueError, match="at least 1"):
            make_gateway(max_abandoned_calls=0)
        with pytest.raises(ValueError, match="secret resolver"):
            make_gateway(digest_key_ref="secret://k")


@pytest.mark.unit
class TestFailurePaths:
    def test_provider_error_raises_and_is_recorded(
        self, make_gateway: Build, make_request: Req, engine: Any
    ) -> None:
        spy = SpyProvider(raises=RuntimeError("boom"))
        with pytest.raises(InferenceUnavailable):
            make_gateway(spy).complete(make_request())
        assert len(spy.calls) == 1
        rec = InvocationLog(engine).for_correlation("corr-1")[0]
        assert (rec.status, rec.error_type, rec.output_size) == (
            "provider_error",
            "RuntimeError",
            0,
        )

    def test_empty_result_raises(self, make_gateway: Build, make_request: Req, engine: Any) -> None:
        with pytest.raises(InferenceUnavailable):
            make_gateway(SpyProvider(text="   ")).complete(make_request())
        assert [r.status for r in InvocationLog(engine).for_correlation("corr-1")] == ["empty"]

    def test_low_confidence_returned_unchanged(
        self, make_gateway: Build, make_request: Req
    ) -> None:
        spy = SpyProvider(text='{"answer": "unsure"}', confidence=0.01)
        result = make_gateway(spy).complete(make_request())
        assert result.confidence == 0.01
        assert result.output.unsafe_text() == '{"answer": "unsure"}'
        assert len(spy.calls) == 1

    @pytest.mark.parametrize(
        "raw",
        [
            ProviderResponse.model_construct(
                text=None, input_tokens=1, output_tokens=1, elapsed_seconds=0.0, confidence=None
            ),
            ProviderResponse.model_construct(
                text="x",
                input_tokens=1,
                output_tokens=1,
                elapsed_seconds=float("nan"),
                confidence=None,
            ),
            ProviderResponse.model_construct(
                text="x", input_tokens=-5, output_tokens=1, elapsed_seconds=0.0, confidence=None
            ),
            object(),
        ],
        ids=["text-none", "nan-elapsed", "negative-tokens", "not-a-response"],
    )
    def test_malformed_response_is_a_recorded_failure(
        self, make_gateway: Build, make_request: Req, engine: Any, audit: FakeAudit, raw: Any
    ) -> None:
        with pytest.raises(InferenceUnavailable):
            make_gateway(SpyProvider(raw=raw)).complete(make_request())
        rec = InvocationLog(engine).for_correlation("corr-1")[0]
        assert rec.status == "malformed"
        assert rec.error_type is not None
        assert [e.outcome.value for e in audit.events] == ["attempt", "failed"]


@pytest.mark.unit
class TestAuditOrder:
    def test_attempt_audit_failure_means_no_provider_call(
        self, make_gateway: Build, make_request: Req, audit: FakeAudit, engine: Any
    ) -> None:
        audit.fail = True
        spy = SpyProvider()
        with pytest.raises(FailClosed):
            make_gateway(spy).complete(make_request())
        assert spy.calls == []
        assert InvocationLog(engine).for_correlation("corr-1") == []

    def test_result_audit_failure_raises_and_returns_nothing(
        self, make_gateway: Build, make_request: Req, engine: Any
    ) -> None:
        flaky = FlakyAudit(fail_on=2)
        spy = SpyProvider()
        result = None
        with pytest.raises(FailClosed):
            result = make_gateway(spy, audit=flaky).complete(make_request())
        assert result is None
        assert len(spy.calls) == 1
        assert [e.outcome.value for e in flaky.events] == ["attempt"]
        # The call did happen, so its record stays and tells the truth.
        assert [r.status for r in InvocationLog(engine).for_correlation("corr-1")] == ["ok"]

    def test_audit_is_called_without_the_write_lock_held(
        self, tmp_path: Any, file_engine: Any, make_gateway: Build, make_request: Req
    ) -> None:
        import sqlite3

        path = tmp_path / "ops.db"
        lock_free: list[bool] = []

        class ProbingAudit(FakeAudit):
            def append(self, event: Any) -> Any:
                con = sqlite3.connect(path, timeout=0.2, isolation_level=None)
                try:
                    con.execute("BEGIN IMMEDIATE")
                    con.execute("ROLLBACK")
                    lock_free.append(True)
                except sqlite3.OperationalError:
                    lock_free.append(False)
                finally:
                    con.close()
                return super().append(event)

        make_gateway(engine=file_engine, audit=ProbingAudit()).complete(make_request())
        assert lock_free == [True, True]
