"""Start-up and shutdown recovery (T1.17, blueprint 10.3, NFR-008, NFR-018)."""

from __future__ import annotations

from datetime import timedelta
from pathlib import Path
from typing import Any

import pytest
from sqlalchemy import Engine
from tests.fakes.core import FakeKillSwitch, FakeRedactor
from tests.resilience.conftest import KILLSWITCH_KEY_REF

from ciso.app.killswitch_history import AuditKillSwitchHistory
from ciso.common.enums import ActorType, AuditOutcome, KillCapability
from ciso.common.principal import Principal
from ciso.common.protocols import AuditEvent
from ciso.killswitch import KillSwitch
from ciso.killswitch.integrity import resolve_key
from ciso.killswitch.persist import write_flag
from ciso.observability.health import CheckResult, HealthRegistry, HealthState
from ciso.ops import (
    AwaitingReports,
    GatedKillSwitch,
    IntegrityState,
    IntegrityStatus,
    StartupReport,
    WorkGate,
    shutdown,
    startup,
)

pytestmark = pytest.mark.resilience

CONNECTOR = "connector:fixture"


def make_health(world: Any) -> HealthRegistry:
    return HealthRegistry(world.clock, check_timeout_seconds=30.0, redactor=FakeRedactor())


class _Admin:
    def __init__(self, admin: Principal) -> None:
        self._admin = admin

    def resolve(self, actor_id: str) -> Principal | None:
        return self._admin if actor_id == self._admin.actor_id else None


def reconcilable(world: Any, platform: Any) -> KillSwitch:
    """The platform's kill switch over the same database, with the audit-history reader
    that `reconcile()` needs (the shared fixture builds it without one)."""
    return KillSwitch(
        engine=platform.op_engine,
        audit=platform.sink,
        clock=world.clock,
        principals=_Admin(world.admin),
        secrets=world.secrets,
        key_ref=KILLSWITCH_KEY_REF,
        history=AuditKillSwitchHistory(platform.audit_log),
    )


def run_startup(world: Any, platform: Any) -> tuple[StartupReport, IntegrityState, HealthRegistry]:
    integrity = IntegrityState()
    health = make_health(world)
    report = startup(
        operational_engine=platform.op_engine,
        audit_log=platform.audit_log,
        killswitch=reconcilable(world, platform),
        integrity=integrity,
        health=health,
        awaiting=AwaitingReports([CONNECTOR]),
        clock=world.clock,
    )
    return report, integrity, health


def step(report: StartupReport, name: str) -> str:
    return next(s.status for s in report.steps if s.name == name)


def engage_records(platform: Any) -> int:
    return len(platform.audit_log.query(limit=100, action_prefix="killswitch.engage"))


def populate_and_crash(world: Any) -> Any:
    """First run: install, queue work, lease two jobs, engage WRITES while the audit sink
    is down (so the audit is owed), then die without shutdown."""
    first = world.start()
    first.killswitch.initialise()
    for i in range(3):
        first.queue.enqueue("ingest", {"ref": f"r{i}"}, source="fixture", event_id=f"e{i}")
    assert first.queue.lease(["ingest"], "worker-a") is not None
    assert first.queue.lease(["ingest"], "worker-a") is not None
    first.sink.fail = True
    first.killswitch.engage(world.admin, [KillCapability.WRITES], "incident drill")
    assert len(first.killswitch.pending_audit()) == 1
    first.crash()
    world.clock.advance(seconds=31)  # the two leases expire while the platform is down
    return first


def test_clean_restart_recovers_everything(ops_world: Any) -> None:
    populate_and_crash(ops_world)
    second = ops_world.start()
    report, integrity, health = run_startup(ops_world, second)

    assert [s.name for s in report.steps] == [
        "schema",
        "killswitch",
        "audit_verify",
        "owed_audit",
        "killswitch_reconcile",
        "health",
        "queue_sweep",
    ]
    assert all(s.status == "ok" for s in report.steps), report.steps
    assert report.audit_status is IntegrityStatus.OK
    assert report.owed_audit_delivered == 1
    assert report.owed_audit_remaining == 0
    # Delivered before reconcile, so the pre-crash engage agrees with its flag.
    assert report.killswitch_mismatches == ()
    assert report.expired_leases == 2
    assert report.startup_audited is True
    assert engage_records(second) == 1
    assert len(second.audit_log.query(limit=10, action_prefix="ops.startup")) == 1

    # The engage made before the crash survived; the gate adds nothing beyond it.
    gate = GatedKillSwitch(second.killswitch, integrity)
    assert gate.is_blocked(KillCapability.WRITES) is True
    assert gate.is_blocked(KillCapability.L3_RUNS) is False
    assert gate.is_blocked(KillCapability.ACTIVE_SCANS) is False
    assert report.writes_blocked is False  # integrity allows; the kill switch still blocks

    # Health is not "healthy" until the connector reports.
    assert health.aggregate().overall is HealthState.UNKNOWN
    assert report.awaiting_components == (CONNECTOR,)


def test_owed_audit_is_delivered_exactly_once_across_restarts(ops_world: Any) -> None:
    populate_and_crash(ops_world)
    second = ops_world.start()
    assert run_startup(ops_world, second)[0].owed_audit_delivered == 1
    second.crash()
    third = ops_world.start()
    report = run_startup(ops_world, third)[0]
    assert report.owed_audit_delivered == 0
    assert engage_records(third) == 1


def test_component_reports_turn_health_healthy(ops_world: Any) -> None:
    platform = ops_world.start()
    platform.killswitch.initialise()
    integrity = IntegrityState()
    health = make_health(ops_world)
    awaiting = AwaitingReports([CONNECTOR])
    startup(
        operational_engine=platform.op_engine,
        audit_log=platform.audit_log,
        killswitch=reconcilable(ops_world, platform),
        integrity=integrity,
        health=health,
        awaiting=awaiting,
        clock=ops_world.clock,
    )
    by_name = {c.name: c.state for c in health.aggregate().components}
    assert by_name == {"audit_integrity": HealthState.HEALTHY, CONNECTOR: HealthState.UNKNOWN}
    awaiting.report(CONNECTOR, CheckResult(state=HealthState.HEALTHY))
    assert health.aggregate().overall is HealthState.HEALTHY


def _tamper_audit_row(platform: Any) -> None:
    with platform.audit_engine.begin() as conn:
        conn.exec_driver_sql("DROP TRIGGER audit_record_no_update")
        conn.exec_driver_sql("UPDATE audit_record SET target = 'forged' WHERE seq = 1")


def _assert_reads_still_work(platform: Any, health: HealthRegistry) -> None:
    assert len(platform.killswitch.status()) == len(KillCapability)
    assert sum(platform.queue.stats().counts.values()) == 3
    assert health.aggregate().overall is HealthState.UNHEALTHY


def test_tampered_audit_log_reports_failed_and_blocks_writes(ops_world: Any) -> None:
    first = populate_and_crash(ops_world)
    del first
    middle = ops_world.start()
    middle.audit_log.append(
        AuditEvent(
            actor_id="svc",
            actor_type=ActorType.SERVICE,
            action="test.event",
            outcome=AuditOutcome.SUCCESS,
        )
    )
    _tamper_audit_row(middle)
    middle.crash()

    platform = ops_world.start()
    report, integrity, health = run_startup(ops_world, platform)
    assert report.audit_status is IntegrityStatus.FAILED
    assert report.audit_reason == "hash_mismatch"
    assert step(report, "audit_verify") == "failed"
    assert step(report, "owed_audit") == "skipped"
    assert report.owed_audit_remaining == 1  # still owed, not written into a bad log
    # The owed engage is missing from the history: WRITES reads blocked after initialise,
    # which is reported but not forced (blocked is already the safe side).
    assert report.killswitch_mismatches is not None
    assert [m.split(":")[0] for m in report.killswitch_mismatches] == ["writes"]
    assert "left blocked" in report.killswitch_mismatches[0]
    assert report.writes_blocked is True
    assert report.startup_audited is False
    assert "failed" in report.startup_audit_note

    gate = GatedKillSwitch(platform.killswitch, integrity)
    for cap in KillCapability:
        assert gate.is_blocked(cap) is True
    _assert_reads_still_work(platform, health)
    assert report.expired_leases == 2  # read-only steps still ran


def test_missing_anchor_is_unverifiable_and_blocks_writes(ops_world: Any) -> None:
    populate_and_crash(ops_world)
    ops_world.anchor.unlink()
    platform = ops_world.start()
    report, integrity, health = run_startup(ops_world, platform)
    assert report.audit_status is IntegrityStatus.UNVERIFIABLE
    assert report.audit_reason == "anchor_missing"
    assert report.writes_blocked is True
    gate = GatedKillSwitch(FakeKillSwitch(), integrity)  # inner clear: only integrity speaks
    assert gate.is_blocked(KillCapability.WRITES) is True
    assert gate.is_blocked(KillCapability.L3_RUNS) is True
    assert gate.is_blocked(KillCapability.EXTERNAL_INFERENCE) is True
    _assert_reads_still_work(platform, health)


def test_failing_step_blocks_writes_but_later_steps_run(ops_world: Any) -> None:
    platform = ops_world.start()
    platform.killswitch.initialise()

    class BrokenSchemaEngine:
        """Stands in for an engine whose schema check raises."""

        def __getattr__(self, name: str) -> Any:
            raise RuntimeError("schema store unavailable")

    integrity = IntegrityState()
    report = startup(
        operational_engine=BrokenSchemaEngine(),  # type: ignore[arg-type]
        audit_log=platform.audit_log,
        killswitch=reconcilable(ops_world, platform),
        integrity=integrity,
        health=make_health(ops_world),
        awaiting=AwaitingReports([]),
        clock=ops_world.clock,
    )
    assert step(report, "schema") == "failed"
    assert step(report, "queue_sweep") == "failed"
    assert step(report, "audit_verify") == "ok"
    assert step(report, "health") == "ok"
    assert report.writes_blocked is True
    assert integrity.snapshot().blockers == ("schema", "queue_sweep")
    gate = GatedKillSwitch(FakeKillSwitch(), integrity)
    assert gate.is_blocked(KillCapability.WRITES) is True
    assert gate.is_blocked(KillCapability.EXTERNAL_INFERENCE) is False


def test_flag_cleared_behind_the_audit_log_fails_reconcile_and_blocks(ops_world: Any) -> None:
    first = ops_world.start()
    first.killswitch.initialise()
    first.killswitch.engage(ops_world.admin, [KillCapability.WRITES], "drill")
    key = resolve_key(ops_world.secrets, KILLSWITCH_KEY_REF)
    with first.op_engine.begin() as conn:  # a validly MAC'd release nobody audited
        write_flag(
            conn, KillCapability.WRITES, engaged=False, changed_by="intruder",
            actor_type=ActorType.HUMAN, reason="quiet", via="api", operator="",
            now=ops_world.clock.now(), key=key,
        )  # fmt: skip
    assert first.killswitch.is_blocked(KillCapability.WRITES) is False
    first.crash()

    platform = ops_world.start()
    report, integrity, _ = run_startup(ops_world, platform)
    assert report.audit_status is IntegrityStatus.OK
    assert step(report, "killswitch_reconcile") == "failed"
    assert report.killswitch_mismatches is not None
    assert len(report.killswitch_mismatches) == 1
    assert report.killswitch_mismatches[0].startswith("writes:")
    assert "forced to blocked" in report.killswitch_mismatches[0]
    assert report.writes_blocked is True
    assert "killswitch_reconcile" in integrity.snapshot().blockers
    assert platform.killswitch.is_blocked(KillCapability.WRITES) is True


def test_reconcile_that_cannot_run_blocks_writes(ops_world: Any) -> None:
    platform = ops_world.start()
    platform.killswitch.initialise()
    integrity = IntegrityState()
    report = startup(
        operational_engine=platform.op_engine,
        audit_log=platform.audit_log,
        killswitch=platform.killswitch,  # built without an audit-history reader
        integrity=integrity,
        health=make_health(ops_world),
        awaiting=AwaitingReports([]),
        clock=ops_world.clock,
    )
    assert step(report, "killswitch_reconcile") == "failed"
    assert report.killswitch_mismatches is None
    assert report.audit_status is IntegrityStatus.OK
    assert report.writes_blocked is True
    assert integrity.snapshot().blockers == ("killswitch_reconcile",)


# -- shutdown --------------------------------------------------------------------------


def _db_files(world: Any) -> list[Path]:
    return [p for p in (world.data / "db").iterdir() if p.is_file()]


def _delete_all(world: Any) -> None:
    for path in _db_files(world):
        path.unlink()  # PermissionError on Windows if any handle were still open
    assert _db_files(world) == []


def test_shutdown_without_deadline_does_not_wait(ops_world: Any) -> None:
    platform = ops_world.start()
    platform.queue.enqueue("ingest", {"ref": "r"}, source="fixture", event_id="e1")
    assert platform.queue.lease(["ingest"], "worker-a") is not None
    gate = WorkGate()
    sleeps: list[float] = []
    report = shutdown(
        gate=gate,
        engines=platform.engines,
        queue_engine=platform.op_engine,
        worker_ids=["worker-a"],
        clock=ops_world.clock,
        deadline=None,
        sleep=sleeps.append,
        poll_seconds=1.0,
    )
    assert gate.accepting is False
    assert report.waited is False
    assert "did not wait" in report.wait_note
    assert report.in_flight_remaining == 1
    assert sleeps == []
    assert {c.engine: c.status for c in report.checkpoints} == {
        "operational": "ok",
        "audit": "ok",
    }
    assert report.disposed == ("operational", "audit")
    _delete_all(ops_world)


def test_shutdown_waits_for_in_flight_work_to_finish(ops_world: Any) -> None:
    platform = ops_world.start()
    platform.queue.enqueue("ingest", {"ref": "r"}, source="fixture", event_id="e1")
    job = platform.queue.lease(["ingest"], "worker-a")
    assert job is not None
    sleeps: list[float] = []

    def sleep(seconds: float) -> None:
        sleeps.append(seconds)
        ops_world.clock.advance(seconds=seconds)
        if len(sleeps) == 2:
            platform.queue.complete(job.job_id, "worker-a")

    report = shutdown(
        gate=WorkGate(),
        engines=platform.engines,
        queue_engine=platform.op_engine,
        worker_ids=["worker-a"],
        clock=ops_world.clock,
        deadline=timedelta(seconds=10),
        sleep=sleep,
        poll_seconds=1.0,
    )
    assert report.waited is True
    assert report.in_flight_at_start == 1
    assert report.in_flight_remaining == 0
    assert report.deadline_reached is False
    assert sleeps == [1.0, 1.0]
    _delete_all(ops_world)


def test_shutdown_stops_waiting_at_the_deadline(ops_world: Any) -> None:
    platform = ops_world.start()
    platform.queue.enqueue("ingest", {"ref": "r"}, source="fixture", event_id="e1")
    assert platform.queue.lease(["ingest"], "worker-a") is not None
    platform.queue.enqueue("ingest", {"ref": "s"}, source="fixture", event_id="e2")
    assert platform.queue.lease(["ingest"], "other-process") is not None
    report = shutdown(
        gate=WorkGate(),
        engines=platform.engines,
        queue_engine=platform.op_engine,
        worker_ids=["worker-a"],
        clock=ops_world.clock,
        deadline=timedelta(seconds=5),
        sleep=lambda s: ops_world.clock.advance(seconds=s),
        poll_seconds=2.0,
    )
    assert report.in_flight_at_start == 1  # the other process's lease is not ours
    assert report.deadline_reached is True
    assert report.in_flight_remaining == 1
    assert "deadline reached" in report.wait_note
    _delete_all(ops_world)


@pytest.mark.parametrize("poll", [None, 0.0])
def test_deadline_without_a_poll_interval_refuses_before_stopping(
    ops_world: Any, poll: float | None
) -> None:
    gate = WorkGate()
    engines: dict[str, Engine] = {}
    with pytest.raises(ValueError, match="poll_seconds"):
        shutdown(
            gate=gate,
            engines=engines,
            queue_engine=ops_world.start().op_engine,
            worker_ids=["w"],
            clock=ops_world.clock,
            deadline=timedelta(seconds=5),
            sleep=lambda s: None,
            poll_seconds=poll,
        )
    assert gate.accepting is True
