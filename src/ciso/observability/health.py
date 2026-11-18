"""Component health with "no false healthy" aggregation (NFR-018, blueprint 5.1 #14).

Overall is `healthy` only when at least one component is registered and every one reports
healthy. A check that raises, returns something that is not a `CheckResult`, or runs past
the time limit counts as `unknown`. Ranking, worst first: unhealthy, unknown, degraded,
healthy.

`check_timeout_seconds` is a knob: `None` means no check is run and every component, and
so the aggregate, is `unknown`. Checks run side by side in daemon threads and the call
returns after the limit even if a check is still running; such a check cannot be killed
and its thread is left to finish by itself, so checks should be quick and own their I/O
timeouts. Every reason text passes through the redactor.
"""

from __future__ import annotations

import logging
import math
import threading
from collections.abc import Callable
from concurrent.futures import Future, wait
from enum import StrEnum

from ciso.common.clock import Clock
from ciso.common.errors import Conflict, ValidationFailed
from ciso.common.protocols import Redactor
from ciso.common.schemas import Model, UtcDatetime

log = logging.getLogger(__name__)

_REASON_LIMIT = 200


class HealthState(StrEnum):
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    UNHEALTHY = "unhealthy"
    UNKNOWN = "unknown"


_SEVERITY = {
    HealthState.HEALTHY: 0,
    HealthState.DEGRADED: 1,
    HealthState.UNKNOWN: 2,
    HealthState.UNHEALTHY: 3,
}


class CheckResult(Model):
    state: HealthState
    reason: str = ""


class ComponentHealth(Model):
    name: str
    state: HealthState
    reason: str
    checked_at: UtcDatetime


class HealthReport(Model):
    overall: HealthState
    components: tuple[ComponentHealth, ...]
    checked_at: UtcDatetime


HealthCheck = Callable[[], CheckResult]


def _start(check: HealthCheck) -> Future[CheckResult]:
    future: Future[CheckResult] = Future()

    def run() -> None:
        try:
            future.set_result(check())
        except BaseException as exc:
            future.set_exception(exc)

    threading.Thread(target=run, daemon=True, name="health-check").start()
    return future


class HealthRegistry:
    def __init__(
        self, clock: Clock, *, check_timeout_seconds: float | None, redactor: Redactor
    ) -> None:
        if check_timeout_seconds is not None and (
            isinstance(check_timeout_seconds, bool)
            or not isinstance(check_timeout_seconds, int | float)
            or not math.isfinite(check_timeout_seconds)
            or check_timeout_seconds <= 0
        ):
            raise ValidationFailed("check_timeout_seconds must be finite and positive, or None")
        self._clock = clock
        self._timeout = check_timeout_seconds
        self._redactor = redactor
        self._lock = threading.Lock()
        self._checks: dict[str, HealthCheck] = {}

    def register(self, name: str, check: HealthCheck) -> None:
        if not isinstance(name, str) or not name.strip():
            raise ValidationFailed("component name must not be empty")
        with self._lock:
            if name in self._checks:
                raise Conflict(f"component already registered: {name}")
            self._checks[name] = check

    def aggregate(self) -> HealthReport:
        with self._lock:
            checks = list(self._checks.items())
        now = self._clock.now()
        if self._timeout is None:
            outcomes = {
                n: (HealthState.UNKNOWN, "health checks disabled: no time limit configured")
                for n, _ in checks
            }
        else:
            futures = {n: _start(c) for n, c in checks}
            wait(list(futures.values()), timeout=self._timeout)
            outcomes = {n: self._outcome(n, f) for n, f in futures.items()}
        components = tuple(
            ComponentHealth(name=n, state=s, reason=self._clean(r), checked_at=now)
            for n, (s, r) in outcomes.items()
        )
        if not components:
            overall = HealthState.UNKNOWN
        else:
            overall = max((c.state for c in components), key=lambda s: _SEVERITY[s])
        return HealthReport(overall=overall, components=components, checked_at=now)

    def _outcome(self, name: str, future: Future[CheckResult]) -> tuple[HealthState, str]:
        if not future.done():
            log.warning("health check %s exceeded its time limit", name)
            return HealthState.UNKNOWN, f"check exceeded {self._timeout} s"
        exc = future.exception()
        if exc is not None:
            log.warning("health check %s raised %s", name, type(exc).__name__)
            return HealthState.UNKNOWN, f"check raised {type(exc).__name__}"
        result = future.result()
        if not isinstance(result, CheckResult):
            return HealthState.UNKNOWN, "check did not return a CheckResult"
        return result.state, result.reason

    def _clean(self, reason: str) -> str:
        try:
            return self._redactor.redact(reason)[:_REASON_LIMIT]
        except Exception:
            log.exception("health reason could not be redacted")
            return "reason withheld: redaction failed"
