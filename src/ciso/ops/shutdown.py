"""Shutdown recovery (T1.17, blueprint 10.3, NFR-008, ADR-0014).

`shutdown` stops accepting work (`WorkGate`), waits up to a caller-supplied deadline for
leases held by this process's workers to be completed or released, runs a WAL checkpoint
and disposes every engine. No POSIX signals: the caller decides when to call it.
Split from `ciso.ops.lifecycle` (start-up), which re-exports these names.
"""

from __future__ import annotations

import logging
import threading
from collections.abc import Callable, Mapping, Sequence
from datetime import datetime, timedelta

from sqlalchemy import Engine, func, select

from ciso.common.clock import Clock
from ciso.common.db import read_connection
from ciso.common.errors import ValidationFailed
from ciso.common.schemas import Model
from ciso.workflows import JobState
from ciso.workflows.tables import jobs

logger = logging.getLogger(__name__)


def _describe(exc: BaseException) -> str:
    return f"{type(exc).__name__}: {exc}"[:200]


class WorkGate:
    """`accepting` is True until `stop()`. Workers and the API check it before new work."""

    def __init__(self) -> None:
        self._stopped = threading.Event()

    @property
    def accepting(self) -> bool:
        return not self._stopped.is_set()

    def stop(self) -> None:
        self._stopped.set()


class CheckpointResult(Model):
    engine: str
    status: str  # ok, busy, failed
    detail: str = ""


class ShutdownReport(Model):
    accepting_work: bool
    waited: bool
    wait_note: str
    in_flight_at_start: int
    in_flight_remaining: int
    deadline_reached: bool
    checkpoints: tuple[CheckpointResult, ...]
    disposed: tuple[str, ...]


def shutdown(
    *,
    gate: WorkGate,
    engines: Mapping[str, Engine],
    queue_engine: Engine,
    worker_ids: Sequence[str],
    clock: Clock,
    deadline: timedelta | None,
    sleep: Callable[[float], None] | None = None,
    poll_seconds: float | None = None,
) -> ShutdownReport:
    """Stop, drain up to `deadline`, checkpoint, dispose.

    `deadline=None` means do not wait; the report says so. A deadline needs `sleep` and a
    positive `poll_seconds`: there is no default interval (unset refuses, ValidationFailed,
    before anything is stopped). `queue_engine` must also appear in `engines` to be
    disposed.
    """
    waiter: tuple[Callable[[float], None], float] | None = None
    if deadline is not None:
        if sleep is None or poll_seconds is None or poll_seconds <= 0:
            raise ValidationFailed("waiting for a deadline needs sleep and a positive poll_seconds")
        waiter = (sleep, poll_seconds)
    gate.stop()
    workers = tuple(worker_ids)
    at_start = _in_flight(queue_engine, workers)
    remaining, reached = at_start, False
    if deadline is None or waiter is None:
        waited, note = False, "deadline not given: did not wait for in-flight work"
    else:
        waited = True
        remaining, reached = _drain(queue_engine, workers, clock, clock.now() + deadline, waiter)
        note = (
            f"deadline reached with {remaining} leases still held" if reached
            else "all in-flight leases completed or released"
        )  # fmt: skip
    checkpoints = tuple(_checkpoint(name, eng) for name, eng in engines.items())
    for eng in engines.values():
        eng.dispose()
    return ShutdownReport(
        accepting_work=gate.accepting,
        waited=waited,
        wait_note=note,
        in_flight_at_start=at_start,
        in_flight_remaining=remaining,
        deadline_reached=reached,
        checkpoints=checkpoints,
        disposed=tuple(engines),
    )


def _drain(
    engine: Engine,
    workers: tuple[str, ...],
    clock: Clock,
    end: datetime,
    waiter: tuple[Callable[[float], None], float],
) -> tuple[int, bool]:
    """Poll until no lease is held or `end` passes. Returns (still held, deadline reached)."""
    sleep, poll_seconds = waiter
    remaining = _in_flight(engine, workers)
    while remaining:
        if clock.now() >= end:
            return remaining, True
        sleep(poll_seconds)
        remaining = _in_flight(engine, workers)
    return 0, False


def _in_flight(engine: Engine, workers: tuple[str, ...]) -> int:
    """Jobs leased by these workers and not yet completed, failed or taken over."""
    if not workers:
        return 0
    with read_connection(engine) as conn:
        count = conn.execute(
            select(func.count())
            .select_from(jobs)
            .where(
                jobs.c.state == JobState.LEASED.value,
                jobs.c.lease_owner.in_(workers),
            )
        ).scalar_one()
    return int(count)


def _checkpoint(name: str, engine: Engine) -> CheckpointResult:
    try:
        raw = engine.raw_connection()  # the driver connection, outside any transaction
        try:
            cursor = raw.cursor()
            try:
                row = cursor.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchone()
            finally:
                cursor.close()
        finally:
            raw.close()
    except Exception as exc:
        logger.exception("WAL checkpoint failed for %s", name)
        return CheckpointResult(engine=name, status="failed", detail=_describe(exc))
    busy = bool(row[0]) if row is not None else False
    return CheckpointResult(engine=name, status="busy" if busy else "ok")
