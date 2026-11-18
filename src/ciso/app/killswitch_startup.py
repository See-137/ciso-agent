"""Turning the `ciso.ops` start-up report into readiness entries (blueprint 10.3, 11.2,
ADR-0018, G20, NFR-018).

There is one start-up sequence, `ciso.ops.lifecycle.startup`: schema check, kill-switch
`initialise()`, audit `verify()` (a walk of the whole chain), delivery of owed kill-switch
audit records (only when the log verified ok), kill-switch `reconcile()`, health
registration, a lease sweep and an `ops.startup` audit record. Its outcome is held in an
`IntegrityState` that `GatedKillSwitch` adds to every answer. This module only says what
readiness must list:

- the kill switch refused to initialise (every capability then reads blocked);
- a flag that disagrees with the audit log, or a reconcile that could not run (skipped
  when initialise refused: the flags already read blocked and that is reported);
- an audit log that did not verify `ok` (writes and L3 runs stay blocked);
- any other start-up step that failed.
"""

from __future__ import annotations

from typing import Final, NamedTuple

from sqlalchemy import Engine

from ciso.common.clock import Clock
from ciso.killswitch import KillSwitch, Mismatch
from ciso.observability import HealthRegistry
from ciso.ops import (
    AwaitingReports,
    GatedKillSwitch,
    IntegrityState,
    StartupReport,
    startup,
)
from ciso.ops.lifecycle import VerifiableAuditLog

KILLSWITCH_NOT_INITIALISED: Final = (
    "killswitch (flags not initialised; every capability is blocked)"
)
RECONCILE_FAILED: Final = "killswitch_reconcile"
MISMATCH: Final = "killswitch_mismatch"
AUDIT_INTEGRITY: Final = "audit_integrity"
STEP_FAILED: Final = "startup_step_failed"


def describe_mismatch(mismatch: Mismatch) -> str:
    forced = "; forced to blocked" if mismatch.forced_blocked else "; left blocked"
    return f"{MISMATCH} ({mismatch.capability.value}: {mismatch.detail}{forced})"


def startup_problems(report: StartupReport) -> tuple[str, ...]:
    """What readiness must list for this report (empty when start-up was clean)."""
    failed = {step.name: step.detail for step in report.steps if step.status == "failed"}
    problems: list[str] = []
    if "killswitch" in failed:
        problems.append(KILLSWITCH_NOT_INITIALISED)
    elif report.killswitch_mismatches is None:
        detail = failed.get("killswitch_reconcile", "did not run")
        problems.append(f"{RECONCILE_FAILED} (could not run: {detail})")
    else:
        problems.extend(f"{MISMATCH} ({line})" for line in report.killswitch_mismatches)
    if report.audit_status.value != "ok":
        problems.append(f"{AUDIT_INTEGRITY} ({report.audit_status.value}: {report.audit_reason})")
    for name, detail in failed.items():
        if name not in {"killswitch", "killswitch_reconcile", "audit_verify"}:
            problems.append(f"{STEP_FAILED} ({name}: {detail})")
    if report.audit_status.value == "ok" and not report.startup_audited:
        problems.append(f"{STEP_FAILED} (startup_audit: {report.startup_audit_note})")
    return tuple(problems)


class StartedGate(NamedTuple):
    """The start-up outcome the container keeps: the report, the state behind the gate,
    the gated reader every consumer gets, and what readiness must list."""

    report: StartupReport
    integrity: IntegrityState
    reader: GatedKillSwitch
    problems: tuple[str, ...]


def run_startup(
    *,
    operational: Engine,
    audit: VerifiableAuditLog,
    killswitch: KillSwitch,
    health: HealthRegistry,
    clock: Clock,
) -> StartedGate:
    """Run the one start-up sequence and wrap the kill switch in the integrity gate.

    Registers the `audit_integrity` health component. No component is awaited yet: none
    reports on its own in this build.
    """
    integrity = IntegrityState()
    report = startup(
        operational_engine=operational,
        audit_log=audit,
        killswitch=killswitch,
        integrity=integrity,
        health=health,
        awaiting=AwaitingReports(()),
        clock=clock,
    )
    return StartedGate(
        report=report,
        integrity=integrity,
        reader=GatedKillSwitch(killswitch, integrity),
        problems=startup_problems(report),
    )
