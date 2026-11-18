"""NFR-008, FR-029: queue state survives restarts, concurrent workers and a locked database."""

from __future__ import annotations

from collections import Counter
from collections.abc import Iterator
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any

import pytest
from sqlalchemy import Engine, event, func, select
from tests.fakes.core import FakeAudit, make_principal

import ciso.workflows.tables as workflow_tables
from ciso.common.clock import FixedClock
from ciso.common.db import create_db_engine, init_operational_schema
from ciso.common.enums import ActorType, Role
from ciso.common.errors import Conflict, FailClosed
from ciso.common.principal import Principal
from ciso.workflows import Job, JobQueue, JobState

pytestmark = pytest.mark.resilience

ADMIN = make_principal("human_admin", ActorType.HUMAN, Role.SECURITY_ADMIN)


class Resolver:
    def resolve(self, actor_id: str) -> Principal | None:
        return ADMIN if actor_id == ADMIN.actor_id else None


@pytest.fixture
def db_path(tmp_path: Path) -> Path:
    return tmp_path / "ops.sqlite"


@pytest.fixture
def opened() -> Iterator[list[Engine]]:
    engines: list[Engine] = []
    yield engines
    for eng in engines:
        eng.dispose()


def open_queue(
    db_path: Path,
    opened: list[Engine],
    clock: FixedClock,
    audit: Any,
    *,
    busy_timeout_ms: int | None = None,
) -> tuple[Engine, JobQueue]:
    engine = create_db_engine(db_path)
    if busy_timeout_ms is not None:

        @event.listens_for(engine, "connect")
        def _short_timeout(dbapi_connection: Any, _record: Any) -> None:
            dbapi_connection.execute(f"PRAGMA busy_timeout={busy_timeout_ms}")

    opened.append(engine)
    init_operational_schema(engine)
    queue = JobQueue(
        engine,
        clock,
        audit,
        Resolver(),
        lease_seconds=30,
        max_attempts=3,
        backoff_base_seconds=10,
        backoff_max_seconds=60,
    )
    return engine, queue


def row_count(engine: Engine) -> int:
    with engine.connect() as conn:
        return conn.execute(select(func.count()).select_from(workflow_tables.jobs)).scalar_one()


def enqueue(queue: JobQueue, event_id: str, **kw: Any) -> Job:
    return queue.enqueue("ingest", {"ref": event_id}, source="src", event_id=event_id, **kw).job


# -- restart -------------------------------------------------------------------------------


def test_leased_job_returns_after_restart_and_lease_expiry(
    db_path: Path, opened: list[Engine], clock: FixedClock
) -> None:
    audit = FakeAudit(clock)
    engine1, q1 = open_queue(db_path, opened, clock, audit)
    for i in range(3):
        enqueue(q1, f"e{i}")
    leased = q1.lease(["ingest"], "worker-before-crash")
    assert leased is not None
    engine1.dispose()  # the process dies here

    engine2, q2 = open_queue(db_path, opened, clock, audit)
    assert row_count(engine2) == 3
    stats = q2.stats()
    assert stats.counts[JobState.LEASED] == 1
    assert stats.counts[JobState.PENDING] == 2

    second = q2.lease(["ingest"], "w2")
    third = q2.lease(["ingest"], "w2")
    assert second is not None
    assert third is not None
    assert {second.event_id, third.event_id} == {"e1", "e2"}
    assert q2.lease(["ingest"], "w2") is None

    clock.advance(seconds=31)
    recovered = q2.lease(["ingest"], "w3")
    assert recovered is not None
    assert recovered.job_id == leased.job_id
    assert recovered.attempts == 2
    assert recovered.lease_owner == "w3"
    assert row_count(engine2) == 3  # nothing duplicated, nothing lost


def test_dedupe_holds_across_restart(
    db_path: Path, opened: list[Engine], clock: FixedClock
) -> None:
    audit = FakeAudit(clock)
    engine1, q1 = open_queue(db_path, opened, clock, audit)
    first = enqueue(q1, "e1")
    engine1.dispose()

    engine2, q2 = open_queue(db_path, opened, clock, audit)
    again = q2.enqueue("ingest", {"ref": "e1"}, source="src", event_id="e1")
    assert again.created is False
    assert again.job.job_id == first.job_id
    assert row_count(engine2) == 1


def test_retry_schedule_and_dead_letter_survive_restart(
    db_path: Path, opened: list[Engine], clock: FixedClock
) -> None:
    audit = FakeAudit(clock)
    engine1, q1 = open_queue(db_path, opened, clock, audit)
    enqueue(q1, "e1")
    job = q1.lease(["ingest"], "w1")
    assert job is not None
    failed = q1.fail(job.job_id, "w1", RuntimeError("boom"))
    engine1.dispose()

    engine2, q2 = open_queue(db_path, opened, clock, audit)
    assert q2.lease(["ingest"], "w1") is None  # still backing off
    clock.advance(seconds=10)
    again = q2.lease(["ingest"], "w1")
    assert again is not None
    assert again.job_id == failed.job_id
    assert again.attempts == 2
    q2.fail(again.job_id, "w1", RuntimeError("boom"))
    clock.advance(seconds=20)
    last = q2.lease(["ingest"], "w1")
    assert last is not None
    assert last.attempts == 3
    q2.fail(last.job_id, "w1", RuntimeError("boom"))
    engine2.dispose()

    engine3, q3 = open_queue(db_path, opened, clock, audit)
    dead = q3.dead_letters(10)
    assert [j.job_id for j in dead] == [failed.job_id]
    assert dead[0].last_error == "RuntimeError: boom"
    assert q3.stats().counts[JobState.DEAD] == 1
    assert row_count(engine3) == 1


def test_dead_job_still_blocks_its_key_after_restart(
    db_path: Path, opened: list[Engine], clock: FixedClock
) -> None:
    audit = FakeAudit(clock)
    engine1, q1 = open_queue(db_path, opened, clock, audit)
    enqueue(q1, "a1", ordering_key="K")
    a2 = enqueue(q1, "a2", ordering_key="K")
    for _ in range(3):
        job = q1.lease(["ingest"], "w1")
        assert job is not None
        q1.fail(job.job_id, "w1", RuntimeError("x"))
        clock.advance(seconds=100)
    engine1.dispose()

    _engine2, q2 = open_queue(db_path, opened, clock, audit)
    assert q2.lease(["ingest"], "w2") is None
    assert q2.stats().blocked_ordering_keys == ("K",)
    (dead,) = q2.dead_letters(5)
    q2.replay(dead.job_id, ADMIN.actor_id, "fixed")
    first = q2.lease(["ingest"], "w2")
    assert first is not None
    assert first.event_id == "a1"
    q2.complete(first.job_id, "w2")
    second = q2.lease(["ingest"], "w2")
    assert second is not None
    assert second.job_id == a2.job_id


# -- concurrency -----------------------------------------------------------------------------

JOBS = 300


def drain(queue: JobQueue, worker: str) -> list[str]:
    seen: list[str] = []
    while True:
        job = queue.lease(["ingest"], worker)
        if job is None:
            return seen
        queue.complete(job.job_id, worker, attempt=job.attempts)
        seen.append(job.job_id)


def run_workers(
    queues: list[JobQueue], workers_per_queue: int
) -> tuple[list[str], list[BaseException]]:
    leased: list[str] = []
    errors: list[BaseException] = []
    with ThreadPoolExecutor(max_workers=len(queues) * workers_per_queue) as pool:
        futures = [
            pool.submit(drain, q, f"w{i}-{j}")
            for i, q in enumerate(queues)
            for j in range(workers_per_queue)
        ]
        for future in futures:
            try:
                leased.extend(future.result(timeout=120))
            except BaseException as exc:  # collect every error so the assert shows them all
                errors.append(exc)
    return leased, errors


def test_threads_sharing_one_engine_lease_every_job_exactly_once(
    db_path: Path, opened: list[Engine], clock: FixedClock
) -> None:
    _engine, queue = open_queue(db_path, opened, clock, FakeAudit(clock))
    ids = {enqueue(queue, f"e{i}").job_id for i in range(JOBS)}
    assert len(ids) == JOBS
    leased, errors = run_workers([queue], 8)
    assert errors == []
    assert len(leased) == JOBS
    assert Counter(leased) == Counter(ids)  # each exactly once, none missing
    stats = queue.stats()
    assert stats.counts[JobState.DONE] == JOBS
    assert stats.counts[JobState.PENDING] == 0
    assert stats.counts[JobState.LEASED] == 0


def test_several_engines_on_one_file_lease_every_job_exactly_once(
    db_path: Path, opened: list[Engine], clock: FixedClock
) -> None:
    audit = FakeAudit(clock)
    queues = [open_queue(db_path, opened, clock, audit)[1] for _ in range(4)]
    ids = {enqueue(queues[0], f"e{i}").job_id for i in range(JOBS)}
    leased, errors = run_workers(queues, 2)
    assert errors == []
    assert len(leased) == JOBS
    assert Counter(leased) == Counter(ids)
    assert queues[0].stats().counts[JobState.DONE] == JOBS


def test_concurrent_enqueue_of_one_event_yields_one_job(
    db_path: Path, opened: list[Engine], clock: FixedClock
) -> None:
    audit = FakeAudit(clock)
    queues = [open_queue(db_path, opened, clock, audit)[1] for _ in range(2)]

    def call(i: int) -> tuple[str, bool]:
        result = queues[i % 2].enqueue("ingest", {"n": 1}, source="s", event_id="same")
        return result.job.job_id, result.created

    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(call, range(8)))
    assert len({job_id for job_id, _ in results}) == 1
    assert sum(1 for _, created in results if created) == 1
    assert queues[0].stats().counts[JobState.PENDING] == 1


def test_concurrent_conflicting_enqueues_make_one_job_and_conflicts(
    db_path: Path, opened: list[Engine], clock: FixedClock
) -> None:
    audit = FakeAudit(clock)
    queues = [open_queue(db_path, opened, clock, audit)[1] for _ in range(2)]

    def call(i: int) -> str:
        try:
            queues[i % 2].enqueue("ingest", {"n": i}, source="s", event_id="same")
        except Conflict:
            return "conflict"
        return "ok"

    with ThreadPoolExecutor(max_workers=6) as pool:
        outcomes = Counter(pool.map(call, range(6)))
    assert outcomes["ok"] >= 1  # the winner and any identical repeats
    assert outcomes["ok"] + outcomes["conflict"] == 6
    assert queues[0].stats().counts[JobState.PENDING] == 1


# -- locked database and audit isolation ------------------------------------------------------


def test_a_locked_database_surfaces_as_fail_closed(
    db_path: Path, opened: list[Engine], clock: FixedClock
) -> None:
    audit = FakeAudit(clock)
    _engine, queue = open_queue(db_path, opened, clock, audit, busy_timeout_ms=50)
    job = enqueue(queue, "e1")
    leased = queue.lease(["ingest"], "w1")
    assert leased is not None
    other = create_db_engine(db_path)
    opened.append(other)
    with other.connect() as blocker:
        blocker.exec_driver_sql("SELECT 1")  # begins a transaction that holds the write lock
        with pytest.raises(FailClosed):
            queue.enqueue("ingest", {}, source="s", event_id="e2")
        with pytest.raises(FailClosed):
            queue.lease(["ingest"], "w2")
        with pytest.raises(FailClosed):
            queue.complete(job.job_id, "w1")
        with pytest.raises(FailClosed):
            queue.renew(job.job_id, "w1")
        assert queue.stats().counts[JobState.LEASED] == 1  # plain reads are not blocked
    assert queue.complete(job.job_id, "w1").state is JobState.DONE  # and the lock was the cause


def test_operator_audit_calls_hold_no_database_connection(
    db_path: Path, opened: list[Engine], clock: FixedClock
) -> None:
    holding: list[int] = []
    engine_ref: list[Engine] = []

    class SpyAudit(FakeAudit):
        def append(self, event: Any) -> Any:
            holding.append(engine_ref[0].pool.checkedout())  # type: ignore[attr-defined]
            return super().append(event)

    audit = SpyAudit(clock)
    engine, queue = open_queue(db_path, opened, clock, audit)
    engine_ref.append(engine)
    enqueue(queue, "e1")
    enqueue(queue, "e2")
    for _ in range(2):
        for _ in range(3):
            job = queue.lease(["ingest"], "w1")
            assert job is not None
            queue.fail(job.job_id, "w1", RuntimeError("x"))
            clock.advance(seconds=100)
    dead = queue.dead_letters(5)
    assert len(dead) == 2
    queue.replay(dead[0].job_id, ADMIN.actor_id, "again")
    queue.discard(dead[1].job_id, ADMIN.actor_id, "drop")
    assert len(holding) == 4  # attempt and result for each
    assert holding == [0, 0, 0, 0]
