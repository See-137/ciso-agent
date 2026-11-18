"""Start-up and shutdown recovery (T1.17, blueprint 10.3, NFR-008, NFR-018, ADR-0014).

`startup` runs every step below in order and records each outcome. A failing step does not
stop the later read-only steps, but it is recorded in `IntegrityState`, which keeps writes
and L3 runs blocked through `GatedKillSwitch`:

1. `schema`: `init_operational_schema` (creates missing tables, refuses a version mismatch).
2. `killswitch`: `KillSwitch.initialise()`; existing flags are never touched, so an engage
   made before a crash is still engaged.
3. `audit_verify`: `verify()` on the audit log; the result is recorded in `IntegrityState`
   as reported (`ok`, `failed` with reason, `unverifiable` with reason). If verify raises,
   the status is `unverifiable` with reason `audit_verify_raised`.
4. `owed_audit`: owed kill-switch audit records are delivered, only when the audit log
   verified `ok` (writing into a log that is not ok would mix new records into a chain
   nobody can trust). Otherwise the step is `skipped` and the records stay owed.
4a. `killswitch_reconcile`: `KillSwitch.reconcile()` compares each flag with the latest
   audit record for its capability (after delivery, so an engage owed from before a crash
   is in the history). A clear flag the audit log contradicts is forced to blocked by the
   kill switch; that, or a reconcile that cannot run, fails the step and so blocks writes.
   A flag that reads blocked after a release is reported only (blocked is the safe side).
   Every mismatch is listed in `StartupReport.killswitch_mismatches`.
5. `health`: each component named in `AwaitingReports` is registered in the
   `HealthRegistry` and reads `unknown` until it reports; an `audit_integrity` component
   reflects `IntegrityState`. Overall health is therefore not healthy right after start-up.
6. `queue_sweep`: counts leases that expired while the platform was down. Read-only: the
   queue re-leases expired jobs by time.
7. The start-up is audited as `ops.startup` when the audit log verified `ok`; otherwise the
   report says it was not audited and why.

Shutdown (`shutdown`, `WorkGate` and their reports) lives in `ciso.ops.shutdown` and is
re-exported here unchanged.
"""

from __future__ import annotations

import logging
import threading
from collections.abc import Callable, Sequence
from datetime import datetime
from typing import Protocol

from sqlalchemy import Engine, func, select

from ciso.audit import VerifyResult
from ciso.common.clock import Clock
from ciso.common.db import init_operational_schema, read_connection
from ciso.common.enums import ActorType, AuditOutcome, KillCapability
from ciso.common.errors import ValidationFailed
from ciso.common.protocols import AuditEvent
from ciso.common.schemas import Model
from ciso.observability.health import CheckResult, HealthRegistry, HealthState
from ciso.ops.integrity import IntegrityState, IntegrityStatus
from ciso.ops.shutdown import (
    CheckpointResult,
    ShutdownReport,
    WorkGate,
    shutdown,
)
from ciso.workflows import JobState
from ciso.workflows.tables import jobs

logger = logging.getLogger(__name__)

__all__ = [
    "INTEGRITY_COMPONENT",
    "STARTUP_ACTION",
    "STARTUP_ACTOR",
    "AwaitingReports",
    "CheckpointResult",
    "ShutdownReport",
    "StartupReport",
    "StepOutcome",
    "WorkGate",
    "shutdown",
    "startup",
]

STARTUP_ACTOR = "system:startup"
STARTUP_ACTION = "ops.startup"
INTEGRITY_COMPONENT = "audit_integrity"


class VerifiableAuditLog(Protocol):
    def append(self, event: AuditEvent) -> object: ...

    def verify(self) -> VerifyResult: ...


class ReconcileFinding(Protocol):
    """One `ciso.killswitch.Mismatch`, structurally."""

    @property
    def capability(self) -> KillCapability: ...

    @property
    def forced_blocked(self) -> bool: ...

    @property
    def detail(self) -> str: ...


class StartupKillSwitch(Protocol):
    """What start-up needs from `ciso.killswitch.KillSwitch` (kept structural so this
    module does not import the kill-switch package)."""

    def initialise(self) -> None: ...

    def retry_pending_audit(self) -> int: ...

    def pending_audit(self) -> Sequence[object]: ...

    def reconcile(self) -> Sequence[ReconcileFinding]: ...


class StepOutcome(Model):
    name: str
    status: str  # ok, failed, skipped
    detail: str = ""


class StartupReport(Model):
    steps: tuple[StepOutcome, ...]
    audit_status: IntegrityStatus
    audit_reason: str | None
    owed_audit_delivered: int | None
    owed_audit_remaining: int | None
    #: None when reconcile could not run; otherwise one line per mismatch (may be empty).
    killswitch_mismatches: tuple[str, ...] | None
    expired_leases: int | None
    awaiting_components: tuple[str, ...]
    writes_blocked: bool
    startup_audited: bool
    startup_audit_note: str


class AwaitingReports:
    """Components that must report before they count as healthy (connectors, workers).

    Each reads `unknown` from start-up until `report()` is called for it.
    """

    def __init__(self, names: Sequence[str]) -> None:
        self._names = tuple(dict.fromkeys(names))
        self._lock = threading.Lock()
        self._results: dict[str, CheckResult] = {}

    @property
    def names(self) -> tuple[str, ...]:
        return self._names

    def report(self, name: str, result: CheckResult) -> None:
        if name not in self._names:
            raise ValidationFailed(f"unknown component: {name}")
        with self._lock:
            self._results[name] = result

    def check_for(self, name: str) -> Callable[[], CheckResult]:
        def check() -> CheckResult:
            with self._lock:
                result = self._results.get(name)
            if result is None:
                return CheckResult(state=HealthState.UNKNOWN, reason="no report since start-up")
            return result

        return check


def startup(
    *,
    operational_engine: Engine,
    audit_log: VerifiableAuditLog,
    killswitch: StartupKillSwitch,
    integrity: IntegrityState,
    health: HealthRegistry,
    awaiting: AwaitingReports,
    clock: Clock,
) -> StartupReport:
    steps: list[StepOutcome] = []

    def run(name: str, action: Callable[[], str]) -> bool:
        try:
            detail = action()
        except Exception as exc:
            logger.exception("start-up step %s failed", name)
            integrity.block(name)
            steps.append(StepOutcome(name=name, status="failed", detail=_describe(exc)))
            return False
        steps.append(StepOutcome(name=name, status="ok", detail=detail))
        return True

    run("schema", lambda: _init_schema(operational_engine))
    run("killswitch", lambda: _init_killswitch(killswitch))
    _verify(audit_log, integrity, steps)
    audit_ok = integrity.snapshot().status is IntegrityStatus.OK

    delivered: list[int] = []
    remaining: list[int] = []
    if audit_ok:
        run("owed_audit", lambda: _deliver(killswitch, delivered, remaining))
    else:
        skipped = "audit log not verified ok; records stay owed"
        steps.append(StepOutcome(name="owed_audit", status="skipped", detail=skipped))
        run("owed_audit_count", lambda: _count_owed(killswitch, remaining))

    mismatches: list[tuple[str, ...]] = []
    run("killswitch_reconcile", lambda: _reconcile(killswitch, mismatches))

    run("health", lambda: _register_health(health, awaiting, integrity))
    expired: list[int] = []
    run("queue_sweep", lambda: _sweep(operational_engine, clock.now(), expired))

    audited, note = _audit_startup(audit_log, audit_ok, steps, integrity)
    snap = integrity.snapshot()
    return StartupReport(
        steps=tuple(steps),
        audit_status=snap.status,
        audit_reason=snap.reason,
        owed_audit_delivered=delivered[0] if delivered else None,
        owed_audit_remaining=remaining[0] if remaining else None,
        killswitch_mismatches=mismatches[0] if mismatches else None,
        expired_leases=expired[0] if expired else None,
        awaiting_components=awaiting.names,
        writes_blocked=not snap.writes_permitted,
        startup_audited=audited,
        startup_audit_note=note,
    )


def _init_schema(engine: Engine) -> str:
    init_operational_schema(engine)
    return "schema present at the code's versions"


def _init_killswitch(killswitch: StartupKillSwitch) -> str:
    killswitch.initialise()
    return "flags present; existing flags untouched"


def _describe(exc: BaseException) -> str:
    return f"{type(exc).__name__}: {exc}"[:200]


def _verify(
    audit_log: VerifiableAuditLog, integrity: IntegrityState, steps: list[StepOutcome]
) -> None:
    try:
        result = audit_log.verify()
        status, reason = IntegrityStatus(result.status.value), result.reason
    except Exception as exc:
        logger.exception("audit verify raised at start-up")
        status, reason = IntegrityStatus.UNVERIFIABLE, f"audit_verify_raised: {type(exc).__name__}"
    integrity.record_verification(status, reason)
    steps.append(StepOutcome(
        name="audit_verify",
        status="ok" if status is IntegrityStatus.OK else "failed",
        detail=status.value if reason is None else f"{status.value}: {reason}",
    ))  # fmt: skip


def _deliver(killswitch: StartupKillSwitch, delivered: list[int], remaining: list[int]) -> str:
    delivered.append(killswitch.retry_pending_audit())
    remaining.append(len(killswitch.pending_audit()))
    return f"delivered {delivered[0]}, still owed {remaining[0]}"


def _count_owed(killswitch: StartupKillSwitch, remaining: list[int]) -> str:
    remaining.append(len(killswitch.pending_audit()))
    return f"still owed {remaining[0]}"


class KillSwitchDisagrees(Exception):
    """A clear flag contradicted the audit log at start-up (it is now forced blocked)."""


def _reconcile(killswitch: StartupKillSwitch, out: list[tuple[str, ...]]) -> str:
    found = tuple(killswitch.reconcile())
    lines = tuple(
        f"{m.capability.value}: {m.detail}"
        + ("; forced to blocked" if m.forced_blocked else "; left blocked")
        for m in found
    )
    out.append(lines)
    forced = [m.capability.value for m in found if m.forced_blocked]
    if forced:
        raise KillSwitchDisagrees(
            f"flags read clear against the audit log, forced blocked: {', '.join(forced)}"
        )
    return f"{len(found)} mismatches" + (": " + "; ".join(lines) if lines else "")


def _register_health(
    health: HealthRegistry, awaiting: AwaitingReports, integrity: IntegrityState
) -> str:
    def integrity_check() -> CheckResult:
        snap = integrity.snapshot()
        if snap.writes_permitted:
            return CheckResult(state=HealthState.HEALTHY)
        unverified = snap.status is IntegrityStatus.UNVERIFIED
        state = HealthState.UNKNOWN if unverified else HealthState.UNHEALTHY
        reason = f"{snap.status.value}: {snap.reason or ''}"
        if snap.blockers:
            reason += "; failed steps: " + ", ".join(snap.blockers)
        return CheckResult(state=state, reason=reason)

    health.register(INTEGRITY_COMPONENT, integrity_check)
    for name in awaiting.names:
        health.register(name, awaiting.check_for(name))
    return f"{len(awaiting.names)} components awaiting a first report"


def _sweep(engine: Engine, now: datetime, out: list[int]) -> str:
    with read_connection(engine) as conn:
        count = conn.execute(
            select(func.count())
            .select_from(jobs)
            .where(jobs.c.state == JobState.LEASED.value, jobs.c.lease_expires_at <= now)
        ).scalar_one()
    out.append(int(count))
    return f"{count} leases expired while down"


def _audit_startup(
    audit_log: VerifiableAuditLog,
    audit_ok: bool,
    steps: list[StepOutcome],
    integrity: IntegrityState,
) -> tuple[bool, str]:
    if not audit_ok:
        snap = integrity.snapshot()
        return False, f"not audited: audit log is {snap.status.value} ({snap.reason})"
    event = AuditEvent(
        actor_id=STARTUP_ACTOR,
        actor_type=ActorType.SERVICE,
        action=STARTUP_ACTION,
        target="platform",
        outcome=AuditOutcome.SUCCESS
        if all(s.status != "failed" for s in steps)
        else AuditOutcome.FAILED,
        details={"steps": [s.model_dump(mode="json") for s in steps]},
    )
    try:
        audit_log.append(event)
    except Exception as exc:
        logger.exception("start-up could not be audited")
        integrity.block("startup_audit")
        return False, f"not audited: {_describe(exc)}"
    return True, "audited"
