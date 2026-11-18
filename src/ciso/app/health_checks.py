"""Health checks the composition root registers (gap G18, NFR-018 "no false healthy").

Each check is cheap and bounded. A check that cannot tell reports unhealthy with a reason;
`HealthRegistry` turns a check that raises or overruns into `unknown`, which also keeps
overall from reading healthy. With no `health_check_timeout_seconds` configured, every
component reads `unknown` (the registry's fail-closed reading).
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Final

from sqlalchemy import Engine, text

from ciso.audit import AnchorState, HeadAnchor
from ciso.common.db import read_connection
from ciso.common.errors import FailClosed
from ciso.identity import Authenticator
from ciso.inference import InferenceGateway
from ciso.killswitch import KillSwitch
from ciso.observability import (
    CheckResult,
    HealthRegistry,
    HealthState,
    MetricsRegistry,
    RedactingJsonHandler,
    dropped_records_check,
)

AUTH_AUDIT_GAUGE: Final = "ciso_auth_audit_failures"


def register_health(
    health: HealthRegistry,
    *,
    operational: Engine,
    audit_engine: Engine,
    anchor: HeadAnchor | None,
    killswitch: KillSwitch,
    authenticator: Authenticator,
    inference: InferenceGateway,
    max_abandoned_calls: int | None,
    handler: RedactingJsonHandler,
    metrics: MetricsRegistry,
    missing: tuple[str, ...],
    warnings: tuple[str, ...],
    audit_problems: tuple[str, ...],
) -> None:
    checks: dict[str, Callable[[], CheckResult]] = {
        "operational_database": lambda: database_check(operational),
        "audit_database": lambda: audit_check(audit_engine, anchor, audit_problems),
        "killswitch": lambda: killswitch_check(killswitch),
        "readiness": lambda: listed_check(missing, "missing"),
        "integrity": lambda: listed_check(warnings, "warnings"),
        "log_records": dropped_records_check(handler),
        "inference": lambda: inference_check(inference, max_abandoned_calls),
        "authentication_audit": lambda: auth_audit_check(authenticator, metrics),
    }
    for name, check in checks.items():
        health.register(name, check)


def database_check(engine: Engine) -> CheckResult:
    try:
        with read_connection(engine) as conn:
            conn.execute(text("SELECT 1"))
    except Exception as exc:
        return CheckResult(state=HealthState.UNHEALTHY, reason=type(exc).__name__)
    return CheckResult(state=HealthState.HEALTHY)


def audit_check(
    engine: Engine, anchor: HeadAnchor | None, problems: tuple[str, ...]
) -> CheckResult:
    """Database readable, anchor key loadable, anchor present and authenticated.

    Chain, head-to-anchor agreement and witness are `AuditLog.verify()`'s job
    (`GET /v1/audit/verify`); this check stays cheap.
    """
    if problems:
        return CheckResult(state=HealthState.UNHEALTHY, reason="; ".join(problems))
    if anchor is None:
        return CheckResult(state=HealthState.UNHEALTHY, reason="audit log not built")
    try:
        with read_connection(engine) as conn:
            conn.execute(text("SELECT 1"))
    except Exception as exc:
        return CheckResult(state=HealthState.UNHEALTHY, reason=f"unreadable: {type(exc).__name__}")
    try:
        key = anchor.load_key()
    except FailClosed:
        return CheckResult(
            state=HealthState.UNHEALTHY, reason="anchor key unavailable; appends refused"
        )
    state = anchor.read(key).state
    if state is AnchorState.PRESENT:
        return CheckResult(state=HealthState.HEALTHY, reason="anchor authenticated")
    return CheckResult(state=HealthState.UNHEALTHY, reason=f"anchor {state.value}")


def killswitch_check(killswitch: KillSwitch) -> CheckResult:
    try:
        states = killswitch.status()
    except FailClosed:
        return CheckResult(state=HealthState.UNHEALTHY, reason="state unreadable")
    unverified = [s.capability.value for s in states if not s.recorded or not s.verified]
    if unverified:
        return CheckResult(
            state=HealthState.UNHEALTHY, reason=f"blocked, not verifiable: {unverified}"
        )
    engaged = [s.capability.value for s in states if s.engaged]
    if engaged:
        return CheckResult(state=HealthState.DEGRADED, reason=f"engaged: {engaged}")
    return CheckResult(state=HealthState.HEALTHY)


def listed_check(items: tuple[str, ...], label: str) -> CheckResult:
    """Degraded while anything is listed (readiness gaps, integrity warnings)."""
    if items:
        return CheckResult(state=HealthState.DEGRADED, reason=f"{label}: " + ", ".join(items))
    return CheckResult(state=HealthState.HEALTHY)


def inference_check(gateway: InferenceGateway, limit: int | None) -> CheckResult:
    abandoned = gateway.abandoned_calls
    ceiling = 1 if limit is None else limit
    if abandoned >= ceiling:
        return CheckResult(
            state=HealthState.UNHEALTHY, reason=f"{abandoned} abandoned calls; new calls refused"
        )
    if abandoned:
        return CheckResult(state=HealthState.DEGRADED, reason=f"{abandoned} abandoned calls")
    return CheckResult(state=HealthState.HEALTHY)


def auth_audit_check(authenticator: Authenticator, metrics: MetricsRegistry) -> CheckResult:
    """Publishes `Authenticator.counters()` as gauges; degraded once any audit write failed."""
    counters = authenticator.counters()
    for name, value in counters.items():
        metrics.set_gauge(AUTH_AUDIT_GAUGE, float(value), {"counter": name})
    failing = {name: value for name, value in counters.items() if value}
    if failing:
        return CheckResult(state=HealthState.DEGRADED, reason=f"audit failures: {failing}")
    return CheckResult(state=HealthState.HEALTHY)
