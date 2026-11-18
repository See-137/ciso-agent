"""The local inference gateway (blueprint 8.3, 8.4; FR-016, FR-017).

The gateway holds exactly one provider. A failure, a missed deadline, a malformed answer
or an empty answer raises `InferenceUnavailable` and nothing else is tried. A weak answer
is returned as it is. Model text is wrapped in `UntrustedModelOutput`.

Deadline: the gateway measures time itself with a monotonic clock and runs the provider
on a worker thread, waiting at most `timeout_seconds`. A late answer is never returned.
A thread cannot be killed, so a call that missed its deadline keeps running until the
provider returns; such calls are counted (`abandoned_calls`) and the gateway refuses new
work while `max_abandoned_calls` of them are outstanding. A real runtime adapter must
enforce its own deadline too. The provider's self-reported elapsed time is recorded for
information only.

Audit order: an ATTEMPT event before the provider is called (if it fails, no call
happens), a short database write for the invocation record, then a RESULT event (if it
fails the call raises `FailClosed` and nothing is returned). The audit sink is never
called while the operational write lock is held. No exception carries a prompt or output
body: failures are raised with only the cause's type name.
"""

from __future__ import annotations

import hmac
import logging
import math
import threading
import time
from collections.abc import Callable
from concurrent.futures import Future
from typing import Any, NamedTuple

from sqlalchemy import Engine

from ciso.common.clock import Clock
from ciso.common.enums import ActorType, AuditOutcome
from ciso.common.errors import FailClosed, InferenceUnavailable, IntegrityFailure, NotFound
from ciso.common.ids import new_id
from ciso.common.protocols import AuditEvent, AuditSink, Redactor, SecretResolver
from ciso.inference.manifest import Manifest, PromptTemplate
from ciso.inference.provider import ALLOWED_ENDPOINTS, LocalProvider
from ciso.inference.records import (
    InferenceRequest,
    InferenceResult,
    InvocationLog,
    InvocationRecord,
    ProviderRequest,
    ProviderResponse,
    UntrustedModelOutput,
)
from ciso.inference.registry import is_registered
from ciso.vault import resolve_key_bytes

_LOG = logging.getLogger(__name__)
_AUDIT_ACTION = "inference.local.complete"
_AUDIT_ACTOR = "svc_inference"


class _Failed(NamedTuple):
    type_name: str


class _Call:
    """One provider call. `finished` and `abandoned` are guarded by the gateway's lock."""

    def __init__(self) -> None:
        self.future: Future[Any] = Future()
        self.finished = False
        self.abandoned = False


class _Outcome(NamedTuple):
    status: str
    error_type: str | None
    response: ProviderResponse | None
    latency: float


class InferenceGateway:
    """Routes a request to the one configured provider and records what happened.

    `timeout_seconds` must be a finite positive number; anything else (including the
    default `None`) makes every call refuse. `max_abandoned_calls=None` refuses new calls
    once a single call has been abandoned. `digest_key_ref` names the secret used to
    key the stored output digest; with `None` no digest is stored.
    """

    def __init__(
        self,
        provider: LocalProvider,
        redactor: Redactor,
        audit: AuditSink,
        clock: Clock,
        engine: Engine,
        manifest: Manifest,
        *,
        timeout_seconds: float | None = None,
        max_abandoned_calls: int | None = None,
        secrets: SecretResolver | None = None,
        digest_key_ref: str | None = None,
        monotonic: Callable[[], float] = time.monotonic,
    ) -> None:
        if not isinstance(provider, LocalProvider):
            raise TypeError("the gateway takes exactly one LocalProvider instance")
        if not is_registered(provider):
            raise IntegrityFailure("provider class is not registered")
        if provider.endpoint_kind not in ALLOWED_ENDPOINTS:
            raise IntegrityFailure("provider endpoint is not in-process or loopback")
        if max_abandoned_calls is not None and max_abandoned_calls < 1:
            raise ValueError("max_abandoned_calls must be at least 1 or None")
        if digest_key_ref is not None and secrets is None:
            raise ValueError("digest_key_ref needs a secret resolver")
        self._provider = provider
        self._provider_name = provider.name
        self._model_id = provider.model_id
        self._model_version = provider.model_version
        self._check_artifact(manifest)
        self._redactor = redactor
        self._audit = audit
        self._clock = clock
        self._engine = engine
        self._manifest = manifest
        self._timeout = timeout_seconds
        self._max_abandoned = max_abandoned_calls
        self._secrets = secrets
        self._digest_key_ref = digest_key_ref
        self._monotonic = monotonic
        self._lock = threading.Lock()
        self._outstanding = 0

    def _check_artifact(self, manifest: Manifest) -> None:
        try:
            pinned = manifest.model(self._model_id, self._model_version).sha256
        except NotFound:
            raise IntegrityFailure("provider model is not listed in the manifest") from None
        if not hmac.compare_digest(pinned, self._provider.artifact_sha256()):
            raise IntegrityFailure("provider artifact does not match the manifest hash")

    @property
    def abandoned_calls(self) -> int:
        """Calls that missed their deadline and are still running. Health checks read this."""
        with self._lock:
            return self._outstanding

    def complete(self, request: InferenceRequest) -> InferenceResult:
        """Run one request. Raises `InferenceUnavailable` when the provider cannot answer."""
        timeout = self._timeout
        if timeout is None or not math.isfinite(timeout) or timeout <= 0:
            raise InferenceUnavailable("no valid timeout configured; inference refuses to run")
        limit = 1 if self._max_abandoned is None else self._max_abandoned
        if self.abandoned_calls >= limit:
            raise InferenceUnavailable("too many abandoned provider calls are still running")
        template = self._manifest.prompt(
            request.prompt_template_id, request.prompt_template_version
        )
        safe_inputs = {k: self._redactor.redact(v) for k, v in request.inputs.items()}
        provider_request = ProviderRequest(
            prompt=template.render(safe_inputs),
            max_output_tokens=request.max_output_tokens,
            task_category=request.task_category,
            correlation_id=request.correlation_id,
        )
        key = self._digest_key()
        record_id = new_id("inv")
        self._audit_event(record_id, request, template, AuditOutcome.ATTEMPT, {"status": "attempt"})
        outcome = self._run(provider_request, timeout)
        if (
            outcome.response is not None
            and outcome.status == "ok"
            and not outcome.response.text.strip()
        ):
            outcome = outcome._replace(status="empty")
        output = None
        if outcome.response is not None and outcome.status == "ok":
            output = UntrustedModelOutput(outcome.response.text)
        record = self._record(record_id, request, template, outcome, output, key)
        self._store(record)
        ok = output is not None
        self._audit_event(
            record_id,
            request,
            template,
            AuditOutcome.SUCCESS if ok else AuditOutcome.FAILED,
            _result_details(record),
        )
        if output is None or outcome.response is None:
            raise InferenceUnavailable(f"local inference unavailable: {outcome.status}")
        return InferenceResult(
            record_id=record_id,
            output=output,
            confidence=outcome.response.confidence,
            provider_name=self._provider_name,
            model_id=self._model_id,
            model_version=self._model_version,
            prompt_template_id=template.id,
            prompt_template_version=template.version,
            latency_seconds=outcome.latency,
            input_tokens=outcome.response.input_tokens,
            output_tokens=outcome.response.output_tokens,
            correlation_id=request.correlation_id,
        )

    def _digest_key(self) -> bytes | None:
        if self._digest_key_ref is None or self._secrets is None:
            return None
        # Empty or shorter than MIN_KEY_BYTES: FailClosed naming the reference only.
        return resolve_key_bytes(self._secrets, self._digest_key_ref)

    def _run(self, provider_request: ProviderRequest, timeout: float) -> _Outcome:
        """Call the provider under a hard deadline. Never raises, never chains a cause."""
        call = _Call()

        def work() -> None:
            try:
                value: Any = self._provider.complete(provider_request)
            except BaseException as exc:
                value = _Failed(type(exc).__name__)
            with self._lock:
                call.finished = True
                if call.abandoned:
                    self._outstanding -= 1
            call.future.set_result(value)

        started = self._monotonic()
        threading.Thread(target=work, name="inference-call", daemon=True).start()
        timed_out = False
        raw: Any = None
        try:
            raw = call.future.result(timeout=timeout)
        except TimeoutError:
            timed_out = True
        elapsed = self._monotonic() - started
        if timed_out:
            with self._lock:
                if not call.finished:
                    call.abandoned = True
                    self._outstanding += 1
            return _Outcome("timeout", None, None, elapsed)
        if isinstance(raw, _Failed):
            status = "timeout" if raw.type_name == "TimeoutError" else "provider_error"
            return _Outcome(status, raw.type_name, None, elapsed)
        if elapsed > timeout:
            return _Outcome("timeout", None, None, elapsed)
        return self._validated(raw, elapsed)

    @staticmethod
    def _validated(raw: Any, elapsed: float) -> _Outcome:
        response: ProviderResponse | None = None
        error_type: str | None = None
        try:
            response = ProviderResponse.model_validate(raw.model_dump())
        except Exception as exc:
            error_type = type(exc).__name__
        if response is None:
            return _Outcome("malformed", error_type, None, elapsed)
        return _Outcome("ok", None, response, elapsed)

    def _record(
        self,
        record_id: str,
        request: InferenceRequest,
        template: PromptTemplate,
        outcome: _Outcome,
        output: UntrustedModelOutput | None,
        key: bytes | None,
    ) -> InvocationRecord:
        response = outcome.response
        return InvocationRecord(
            id=record_id,
            occurred_at=self._clock.now(),
            provider_name=self._provider_name,
            model_id=self._model_id,
            model_version=self._model_version,
            prompt_template_id=template.id,
            prompt_template_version=template.version,
            prompt_template_sha256=template.sha256,
            task_category=request.task_category,
            context_refs=request.context_refs,
            latency_seconds=outcome.latency,
            provider_reported_seconds=None if response is None else response.elapsed_seconds,
            input_tokens=None if response is None else response.input_tokens,
            output_tokens=None if response is None else response.output_tokens,
            status=outcome.status,
            error_type=outcome.error_type,
            output_size=0 if output is None else output.size,
            output_digest=None if output is None or key is None else output.keyed_digest(key),
            correlation_id=request.correlation_id,
        )

    def _store(self, record: InvocationRecord) -> None:
        """Short transaction, no audit call inside it."""
        failed: str | None = None
        try:
            with self._engine.begin() as conn:
                InvocationLog.insert(conn, record)
        except Exception as exc:
            failed = type(exc).__name__
        if failed is not None:
            _LOG.error("invocation record write failed: %s", failed)
            raise FailClosed(f"invocation record could not be written ({failed})")

    def _audit_event(
        self,
        record_id: str,
        request: InferenceRequest,
        template: PromptTemplate,
        outcome: AuditOutcome,
        extra: dict[str, Any],
    ) -> None:
        event = AuditEvent(
            actor_id=_AUDIT_ACTOR,
            actor_type=ActorType.SERVICE,
            action=_AUDIT_ACTION,
            target=f"inference_invocation:{record_id}",
            outcome=outcome,
            correlation_id=request.correlation_id,
            details={
                "provider": self._provider_name,
                "model_id": self._model_id,
                "model_version": self._model_version,
                "prompt_template_id": template.id,
                "prompt_template_version": template.version,
                "task_category": request.task_category,
                "context_ref_count": len(request.context_refs),
                **extra,
            },
        )
        failed: str | None = None
        try:
            self._audit.append(event)
        except Exception as exc:
            failed = type(exc).__name__
        if failed is not None:
            raise FailClosed(f"audit path unavailable ({failed}); inference stops")


def _result_details(record: InvocationRecord) -> dict[str, Any]:
    return {
        "status": record.status,
        "error_type": record.error_type,
        "latency_seconds": record.latency_seconds,
        "input_tokens": record.input_tokens,
        "output_tokens": record.output_tokens,
        "output_size": record.output_size,
        "output_digest": record.output_digest,
    }
