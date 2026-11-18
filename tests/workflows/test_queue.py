"""Durable queue behaviour: dedupe, leases, backoff, dead-letter, operators, FIFO, fail-closed."""

from __future__ import annotations

import logging
from datetime import timedelta
from typing import Any

import pytest
from sqlalchemy import Engine, update
from tests.fakes.core import FakeAudit

from ciso.common.clock import FixedClock
from ciso.common.enums import ActorType, AuditOutcome
from ciso.common.errors import (
    AuthorizationError,
    Conflict,
    FailClosed,
    NotFound,
    ValidationFailed,
)
from ciso.common.principal import Principal
from ciso.workflows import MAX_LEASE_SCAN_ITERATIONS, Job, JobQueue, JobState
from ciso.workflows import queue as queue_module
from ciso.workflows.tables import jobs

pytestmark = pytest.mark.unit

KNOBS: dict[str, Any] = {
    "lease_seconds": 30,
    "max_attempts": 3,
    "backoff_base_seconds": 10,
    "backoff_max_seconds": 35,
}


class FakeResolver:
    """The identity store as the queue sees it. `fail = True` simulates an outage."""

    def __init__(self, *principals: Principal) -> None:
        self.by_id = {p.actor_id: p for p in principals}
        self.fail = False
        self.calls: list[str] = []

    def resolve(self, actor_id: str) -> Principal | None:
        self.calls.append(actor_id)
        if self.fail:
            raise RuntimeError("identity store down")
        return self.by_id.get(actor_id)


@pytest.fixture
def resolver(
    admin: Principal,
    agent: Principal,
    employee: Principal,
    system_owner: Principal,
    service: Principal,
) -> FakeResolver:
    return FakeResolver(admin, agent, employee, system_owner, service)


def make_queue(
    engine: Engine, clock: FixedClock, audit: FakeAudit, resolver: FakeResolver, **over: Any
) -> JobQueue:
    return JobQueue(engine, clock, audit, resolver, **{**KNOBS, **over})


@pytest.fixture
def queue(engine: Engine, clock: FixedClock, audit: FakeAudit, resolver: FakeResolver) -> JobQueue:
    return make_queue(engine, clock, audit, resolver)


def put(queue: JobQueue, event_id: str = "e1", *, source: str = "src", **kw: Any) -> Job:
    kind = kw.pop("kind", "ingest")
    payload = kw.pop("payload", {"ref": event_id})
    return queue.enqueue(kind, payload, source=source, event_id=event_id, **kw).job


def lease_one(queue: JobQueue, worker: str = "w1") -> Job:
    job = queue.lease(["ingest"], worker)
    assert job is not None
    return job


def kill(queue: JobQueue, clock: FixedClock, key: str | None = None) -> Job:
    """Run a fresh job to dead-letter. Returns the dead job."""
    put(queue, **({"ordering_key": key} if key else {}))
    for _ in range(3):
        job = lease_one(queue)
        last = queue.fail(job.job_id, "w1", RuntimeError("x"))
        clock.advance(seconds=100)
    assert last.state is JobState.DEAD
    return last


# -- enqueue ---------------------------------------------------------------------------


def test_enqueue_returns_created_pending_job(queue: JobQueue) -> None:
    result = queue.enqueue("ingest", {"ref": "e1"}, source="src", event_id="e1")
    assert result.created is True
    assert result.job.state is JobState.PENDING
    assert result.job.attempts == 0
    assert result.job.payload == {"ref": "e1"}
    assert result.job.job_id.startswith("job_")


def test_identical_repeat_returns_existing_job_not_created(queue: JobQueue) -> None:
    first = queue.enqueue("ingest", {"a": 1}, source="s", event_id="e", ordering_key="k")
    second = queue.enqueue("ingest", {"a": 1}, source="s", event_id="e", ordering_key="k")
    assert second.created is False
    assert second.job.job_id == first.job.job_id
    assert queue.stats().counts[JobState.PENDING] == 1


@pytest.mark.parametrize(
    "different",
    [
        {"kind": "other"},
        {"payload": {"zzz": 1}},
        {"ordering_key": "other-key"},
        {"ordering_key": None},
    ],
)
def test_repeat_with_different_content_conflicts(
    queue: JobQueue, different: dict[str, Any]
) -> None:
    base: dict[str, Any] = {"kind": "ingest", "payload": {"a": 1}, "ordering_key": "k"}
    queue.enqueue(
        base["kind"], base["payload"], source="s", event_id="e", ordering_key=base["ordering_key"]
    )
    merged = {**base, **different}
    with pytest.raises(Conflict):
        queue.enqueue(
            merged["kind"],
            merged["payload"],
            source="s",
            event_id="e",
            ordering_key=merged["ordering_key"],
        )
    assert queue.stats().counts[JobState.PENDING] == 1


def test_same_event_id_from_other_source_is_a_different_job(queue: JobQueue) -> None:
    first = put(queue, "e1", source="a")
    second = put(queue, "e1", source="b")
    assert first.job_id != second.job_id
    assert queue.stats().counts[JobState.PENDING] == 2


def test_duplicate_of_a_finished_job_is_still_deduped(queue: JobQueue) -> None:
    job = put(queue)
    lease_one(queue)
    queue.complete(job.job_id, "w1")
    again = queue.enqueue("ingest", {"ref": "e1"}, source="src", event_id="e1")
    assert again.created is False
    assert again.job.job_id == job.job_id
    assert again.job.state is JobState.DONE
    assert queue.lease(["ingest"], "w1") is None


@pytest.mark.parametrize(
    "payload", [{"blob": b"bytes"}, {"x": object()}, {"n": float("nan")}, {"n": float("inf")}]
)
def test_payload_must_be_plain_json(queue: JobQueue, payload: dict[str, Any]) -> None:
    with pytest.raises(ValidationFailed):
        queue.enqueue("ingest", payload, source="s", event_id="e")


def test_job_payload_cannot_be_changed_in_place(queue: JobQueue) -> None:
    job = put(queue, payload={"nested": {"a": [1, 2]}})
    with pytest.raises(TypeError):
        job.payload["nested"] = 1  # type: ignore[index]
    with pytest.raises(TypeError):
        job.payload["nested"]["a"] = 1  # type: ignore[index]
    assert job.payload["nested"]["a"] == (1, 2)


def test_empty_and_overlong_identifiers_are_refused(queue: JobQueue) -> None:
    ok: dict[str, Any] = {"kind": "k", "source": "s", "event_id": "e"}
    limits = {"kind": 128, "source": 128, "event_id": 256}
    for name, limit in limits.items():
        for bad in ("", "  ", "x" * (limit + 1)):
            args = {**ok, name: bad}
            with pytest.raises(ValidationFailed):
                queue.enqueue(args["kind"], {}, source=args["source"], event_id=args["event_id"])
        edge = {**ok, name: "x" * limit}  # exactly at the limit is fine
        queue.enqueue(edge["kind"], {}, source=edge["source"], event_id=edge["event_id"])
    with pytest.raises(ValidationFailed):
        queue.enqueue("k", {}, source="s", event_id="e2", ordering_key="x" * 257)
    with pytest.raises(ValidationFailed):
        queue.enqueue("k", {}, source="s", event_id="e3", ordering_key="")


# -- lease, renew, complete, fail --------------------------------------------------------


def test_lease_returns_job_and_marks_it_leased(queue: JobQueue) -> None:
    put(queue)
    job = lease_one(queue)
    assert job.state is JobState.LEASED
    assert job.lease_owner == "w1"
    assert job.attempts == 1
    assert queue.lease(["ingest"], "w2") is None


def test_lease_filters_by_kind(queue: JobQueue) -> None:
    put(queue, kind="other")
    assert queue.lease(["ingest"], "w1") is None
    job = queue.lease(["other"], "w1")
    assert job is not None
    assert job.kind == "other"


def test_lease_input_validation(queue: JobQueue) -> None:
    with pytest.raises(ValidationFailed):
        queue.lease([], "w1")
    with pytest.raises(ValidationFailed):
        queue.lease(["ingest"], "")
    with pytest.raises(ValidationFailed):
        queue.lease(["ingest"], "w" * 129)


def test_expired_lease_requeues(queue: JobQueue, clock: FixedClock) -> None:
    put(queue)
    first = lease_one(queue)
    clock.advance(seconds=29)
    assert queue.lease(["ingest"], "w2") is None
    clock.advance(seconds=1)
    second = lease_one(queue, "w2")
    assert second.job_id == first.job_id
    assert second.lease_owner == "w2"
    assert second.attempts == 2


def test_stale_worker_cannot_complete_or_fail_after_takeover(
    queue: JobQueue, clock: FixedClock
) -> None:
    put(queue)
    first = lease_one(queue)
    clock.advance(seconds=31)
    second = lease_one(queue, "w2")
    with pytest.raises(Conflict):
        queue.complete(first.job_id, "w1")
    with pytest.raises(Conflict):
        queue.fail(first.job_id, "w1", RuntimeError("late"))
    with pytest.raises(Conflict):
        queue.renew(first.job_id, "w1")
    queue.complete(second.job_id, "w2")
    assert queue.stats().counts[JobState.DONE] == 1


def test_complete_after_expiry_without_takeover_succeeds(
    queue: JobQueue, clock: FixedClock
) -> None:
    put(queue)
    job = lease_one(queue)
    clock.advance(seconds=300)
    done = queue.complete(job.job_id, "w1", attempt=job.attempts)
    assert done.state is JobState.DONE


def test_fail_after_expiry_without_takeover_succeeds(queue: JobQueue, clock: FixedClock) -> None:
    put(queue)
    job = lease_one(queue)
    clock.advance(seconds=300)
    failed = queue.fail(job.job_id, "w1", RuntimeError("x"), attempt=job.attempts)
    assert failed.state is JobState.PENDING


def test_same_worker_old_attempt_cannot_complete_after_new_lease(
    queue: JobQueue, clock: FixedClock
) -> None:
    put(queue)
    first = lease_one(queue)  # attempt 1
    clock.advance(seconds=31)
    second = lease_one(queue)  # same worker id, attempt 2
    assert (first.attempts, second.attempts) == (1, 2)
    with pytest.raises(Conflict):
        queue.complete(first.job_id, "w1", attempt=1)
    assert queue.complete(second.job_id, "w1", attempt=2).state is JobState.DONE


def test_renew_extends_the_lease(queue: JobQueue, clock: FixedClock) -> None:
    put(queue)
    job = lease_one(queue)
    clock.advance(seconds=25)
    renewed = queue.renew(job.job_id, "w1", attempt=job.attempts)
    assert renewed.lease_expires_at == clock.now() + timedelta(seconds=30)
    clock.advance(seconds=25)  # past the original expiry, inside the renewed one
    assert queue.lease(["ingest"], "w2") is None
    clock.advance(seconds=5)
    assert lease_one(queue, "w2").lease_owner == "w2"


def test_renew_needs_lease_knob_and_a_held_lease(
    engine: Engine, clock: FixedClock, audit: FakeAudit, resolver: FakeResolver
) -> None:
    q = make_queue(engine, clock, audit, resolver)
    put(q)
    job = lease_one(q)
    with pytest.raises(Conflict):
        q.renew(job.job_id, "intruder")
    with pytest.raises(NotFound):
        q.renew("job_missing", "w1")
    broken = make_queue(engine, clock, audit, resolver, lease_seconds=None)
    with pytest.raises(FailClosed):
        broken.renew(job.job_id, "w1")


def test_wrong_worker_unknown_job_and_double_complete(queue: JobQueue) -> None:
    put(queue)
    job = lease_one(queue)
    with pytest.raises(Conflict):
        queue.complete(job.job_id, "intruder")
    with pytest.raises(NotFound):
        queue.complete("job_missing", "w1")
    queue.complete(job.job_id, "w1")
    with pytest.raises(Conflict):
        queue.complete(job.job_id, "w1")


def test_every_change_bumps_the_row_version(queue: JobQueue) -> None:
    job = put(queue)
    leased = lease_one(queue)
    renewed = queue.renew(leased.job_id, "w1")
    done = queue.complete(leased.job_id, "w1")
    assert [job.version, leased.version, renewed.version, done.version] == [0, 1, 2, 3]


@pytest.mark.parametrize("operation", ["complete", "fail", "renew", "replay", "discard"])
def test_lost_guard_raises_conflict(
    queue: JobQueue,
    engine: Engine,
    clock: FixedClock,
    monkeypatch: pytest.MonkeyPatch,
    operation: str,
) -> None:
    """Force the row to change between our read and our guarded update."""
    if operation in {"replay", "discard"}:
        job = kill(queue, clock)
    else:
        put(queue)
        job = lease_one(queue)

    real = JobQueue._guarded_update

    def racing(conn: Any, row: Any, **values: Any) -> bool:
        conn.execute(
            update(jobs).where(jobs.c.job_id == row.job_id).values(version=row.version + 1)
        )
        return real(conn, row, **values)

    monkeypatch.setattr(JobQueue, "_guarded_update", staticmethod(racing))
    calls = {
        "complete": lambda: queue.complete(job.job_id, "w1"),
        "fail": lambda: queue.fail(job.job_id, "w1", RuntimeError("x")),
        "renew": lambda: queue.renew(job.job_id, "w1"),
        "replay": lambda: queue.replay(job.job_id, "human_admin", "why"),
        "discard": lambda: queue.discard(job.job_id, "human_admin", "why"),
    }
    with pytest.raises(Conflict):
        calls[operation]()
    monkeypatch.undo()
    with engine.connect() as conn:  # nothing was half-applied by the lost call
        state = conn.execute(jobs.select().where(jobs.c.job_id == job.job_id)).one().state
    assert state == job.state.value


def test_backoff_grows_and_caps(
    engine: Engine, clock: FixedClock, audit: FakeAudit, resolver: FakeResolver
) -> None:
    q = make_queue(engine, clock, audit, resolver, max_attempts=6)
    put(q)
    waits: list[float] = []
    for _ in range(4):
        job = lease_one(q)
        failed = q.fail(job.job_id, "w1", RuntimeError("boom"))
        assert failed.state is JobState.PENDING
        waits.append((failed.available_at - clock.now()).total_seconds())
        clock.advance(seconds=waits[-1] - 1)
        assert q.lease(["ingest"], "w1") is None  # not due yet
        clock.advance(seconds=1)
    assert waits == [10.0, 20.0, 35.0, 35.0]  # 10, 20, then capped (40 -> 35)


def test_retry_ceiling_sends_to_dead_letter(queue: JobQueue, clock: FixedClock) -> None:
    put(queue)
    for attempt in (1, 2, 3):
        job = lease_one(queue)
        assert job.attempts == attempt
        result = queue.fail(job.job_id, "w1", ValueError("long message text " * 40))
        clock.advance(seconds=100)
    assert result.state is JobState.DEAD
    assert queue.lease(["ingest"], "w1") is None
    dead = queue.dead_letters(10)
    assert [j.job_id for j in dead] == [result.job_id]
    assert dead[0].last_error is not None
    assert dead[0].last_error.startswith("ValueError: ")
    assert len(dead[0].last_error) <= 200
    assert queue.stats().counts[JobState.DEAD] == 1


def test_dead_letters_needs_a_positive_limit_and_honours_it(
    queue: JobQueue, clock: FixedClock
) -> None:
    for i in range(3):
        put(queue, f"e{i}")
        for _ in range(3):
            job = lease_one(queue)
            queue.fail(job.job_id, "w1", RuntimeError("x"))
            clock.advance(seconds=100)
    assert len(queue.dead_letters(2)) == 2
    assert len(queue.dead_letters(10)) == 3
    for bad in (0, -1, True):
        with pytest.raises(ValidationFailed):
            queue.dead_letters(bad)  # type: ignore[arg-type]
    with pytest.raises(TypeError):
        queue.dead_letters()  # type: ignore[call-arg]


def test_expiring_lease_on_last_attempt_dead_letters(queue: JobQueue, clock: FixedClock) -> None:
    put(queue)
    for _ in range(3):
        lease_one(queue)
        clock.advance(seconds=31)
    assert queue.lease(["ingest"], "w1") is None
    dead = queue.dead_letters(10)
    assert len(dead) == 1
    assert dead[0].last_error == "LeaseExpired: lease expired on the last attempt"


def test_dead_lettering_is_logged_and_counted(
    engine: Engine,
    clock: FixedClock,
    audit: FakeAudit,
    resolver: FakeResolver,
    caplog: pytest.LogCaptureFixture,
) -> None:
    seen: list[tuple[str, str]] = []
    q = JobQueue(
        engine, clock, audit, resolver, **KNOBS, on_dead_letter=lambda k, r: seen.append((k, r))
    )
    caplog.set_level(logging.WARNING, logger="ciso.workflows.queue")
    kill(q, clock)  # by attempts
    put(q, "e2")
    for _ in range(3):  # by lease expiry
        lease_one(q)
        clock.advance(seconds=31)
    assert q.lease(["ingest"], "w1") is None
    assert seen == [("ingest", "attempts_exhausted"), ("ingest", "lease_expired")]
    messages = [r.getMessage() for r in caplog.records]
    assert "job dead-lettered: kind=ingest reason=attempts_exhausted" in messages
    assert "job dead-lettered: kind=ingest reason=lease_expired" in messages


def test_a_failing_dead_letter_callback_does_not_break_the_queue(
    engine: Engine, clock: FixedClock, audit: FakeAudit, resolver: FakeResolver
) -> None:
    def boom(kind: str, reason: str) -> None:
        raise RuntimeError("metrics down")

    q = JobQueue(engine, clock, audit, resolver, **KNOBS, on_dead_letter=boom)
    assert kill(q, clock).state is JobState.DEAD


# -- operators: replay and discard ----------------------------------------------------------


def test_replay_audit_order_and_effect(
    queue: JobQueue, clock: FixedClock, audit: FakeAudit, admin: Principal
) -> None:
    dead = kill(queue, clock)
    replayed = queue.replay(dead.job_id, admin.actor_id, "fixed the parser")
    assert replayed.state is JobState.PENDING
    assert replayed.attempts == 0
    events = audit.find("workflows.replay")
    assert [e.outcome for e in events] == [AuditOutcome.ATTEMPT, AuditOutcome.SUCCESS]
    assert all(e.actor_id == admin.actor_id for e in events)
    assert all(e.target == f"job:{dead.job_id}" for e in events)
    assert events[0].details["reason"] == "fixed the parser"
    assert queue.dead_letters(10) == []
    assert lease_one(queue, "w9").job_id == dead.job_id


def test_discard_is_audited_and_keeps_the_dedupe_record(
    queue: JobQueue, clock: FixedClock, audit: FakeAudit, admin: Principal
) -> None:
    dead = kill(queue, clock)
    discarded = queue.discard(dead.job_id, admin.actor_id, "obsolete")
    assert discarded.state is JobState.DISCARDED
    assert [e.outcome for e in audit.find("workflows.discard")] == [
        AuditOutcome.ATTEMPT,
        AuditOutcome.SUCCESS,
    ]
    assert queue.dead_letters(10) == []
    again = queue.enqueue("ingest", {"ref": "e1"}, source="src", event_id="e1")
    assert again.created is False
    assert again.job.state is JobState.DISCARDED


@pytest.mark.parametrize("op", ["replay", "discard"])
@pytest.mark.parametrize("who", ["agent", "service", "employee", "system_owner"])
def test_operator_actions_refused_for_non_admin(
    request: pytest.FixtureRequest,
    queue: JobQueue,
    clock: FixedClock,
    audit: FakeAudit,
    who: str,
    op: str,
) -> None:
    principal: Principal = request.getfixturevalue(who)
    dead = kill(queue, clock)
    with pytest.raises(AuthorizationError):
        getattr(queue, op)(dead.job_id, principal.actor_id, "please")
    assert queue.stats().counts[JobState.DEAD] == 1
    events = audit.find(f"workflows.{op}")
    assert [e.outcome for e in events] == [AuditOutcome.DENIED]
    assert events[0].actor_type is principal.actor_type


@pytest.mark.parametrize("op", ["replay", "discard"])
def test_revoked_or_unknown_actor_is_refused_whatever_it_claims(
    queue: JobQueue, clock: FixedClock, resolver: FakeResolver, admin: Principal, op: str
) -> None:
    """The decision uses the identity store now, not any Principal the caller may hold."""
    dead = kill(queue, clock)
    revoked = admin.model_copy(update={"roles": frozenset()})
    resolver.by_id[admin.actor_id] = revoked  # the admin role was revoked since
    with pytest.raises(AuthorizationError):
        getattr(queue, op)(dead.job_id, admin.actor_id, "stale admin")
    with pytest.raises(AuthorizationError):
        getattr(queue, op)(dead.job_id, "nobody_made_this_up", "invented")
    assert resolver.calls[-2:] == [admin.actor_id, "nobody_made_this_up"]
    assert queue.stats().counts[JobState.DEAD] == 1


def test_resolver_returning_a_different_actor_is_refused(
    queue: JobQueue, clock: FixedClock, resolver: FakeResolver, admin: Principal
) -> None:
    dead = kill(queue, clock)
    resolver.by_id["alias"] = admin  # resolves to someone else's identity
    with pytest.raises(AuthorizationError):
        queue.replay(dead.job_id, "alias", "x")


def test_resolver_outage_fails_closed(
    queue: JobQueue, clock: FixedClock, resolver: FakeResolver, admin: Principal
) -> None:
    dead = kill(queue, clock)
    resolver.fail = True
    with pytest.raises(FailClosed):
        queue.replay(dead.job_id, admin.actor_id, "x")
    assert queue.stats().counts[JobState.DEAD] == 1


@pytest.mark.parametrize("op", ["replay", "discard"])
def test_operator_action_blocked_when_attempt_record_fails(
    queue: JobQueue, clock: FixedClock, audit: FakeAudit, admin: Principal, op: str
) -> None:
    dead = kill(queue, clock)
    audit.fail = True
    with pytest.raises(FailClosed):
        getattr(queue, op)(dead.job_id, admin.actor_id, "try")
    audit.fail = False
    assert [j.job_id for j in queue.dead_letters(10)] == [dead.job_id]


def test_result_record_failure_is_reported_after_the_change(
    queue: JobQueue, clock: FixedClock, audit: FakeAudit, admin: Principal
) -> None:
    dead = kill(queue, clock)
    real = audit.append
    count = {"n": 0}

    def second_fails(event: Any) -> Any:
        count["n"] += 1
        if count["n"] == 2:
            raise FailClosed("audit path unavailable")
        return real(event)

    audit.append = second_fails  # type: ignore[method-assign]
    with pytest.raises(FailClosed):
        queue.replay(dead.job_id, admin.actor_id, "x")
    assert queue.dead_letters(10) == []  # the change did happen; the caller is told


def test_operator_conflict_writes_a_failed_result_record(
    queue: JobQueue, audit: FakeAudit, admin: Principal
) -> None:
    job = put(queue)
    with pytest.raises(Conflict):
        queue.replay(job.job_id, admin.actor_id, "not dead")
    with pytest.raises(NotFound):
        queue.replay("job_missing", admin.actor_id, "nope")
    assert [e.outcome for e in audit.find("workflows.replay")] == [
        AuditOutcome.ATTEMPT,
        AuditOutcome.FAILED,
        AuditOutcome.ATTEMPT,
        AuditOutcome.FAILED,
    ]


def test_operator_reason_is_required_and_bounded(
    queue: JobQueue, clock: FixedClock, audit: FakeAudit, admin: Principal
) -> None:
    dead = kill(queue, clock)
    for bad in ("  ", "r" * 501):
        with pytest.raises(ValidationFailed):
            queue.replay(dead.job_id, admin.actor_id, bad)
    assert audit.find("workflows.replay") == []


def test_agent_actor_type_is_what_is_refused(
    queue: JobQueue, clock: FixedClock, agent: Principal
) -> None:
    assert agent.actor_type is ActorType.AGENT
    dead = kill(queue, clock)
    with pytest.raises(AuthorizationError):
        queue.replay(dead.job_id, agent.actor_id, "x")


# -- ordering ---------------------------------------------------------------------------------


def test_fifo_per_ordering_key(queue: JobQueue, clock: FixedClock) -> None:
    a1 = put(queue, "a1", ordering_key="A")
    a2 = put(queue, "a2", ordering_key="A")
    b1 = put(queue, "b1", ordering_key="B")
    assert lease_one(queue, "w1").job_id == a1.job_id
    assert lease_one(queue, "w2").job_id == b1.job_id  # a2 blocked, b1 skips ahead
    assert queue.lease(["ingest"], "w3") is None  # a1 still leased
    queue.fail(a1.job_id, "w1", RuntimeError("x"))
    assert queue.lease(["ingest"], "w3") is None  # a1 waiting to retry still blocks a2
    clock.advance(seconds=10)
    assert lease_one(queue, "w3").job_id == a1.job_id
    queue.complete(a1.job_id, "w3")
    assert lease_one(queue, "w3").job_id == a2.job_id


def test_dead_job_blocks_its_ordering_key_until_replay(
    queue: JobQueue, clock: FixedClock, admin: Principal
) -> None:
    a1 = put(queue, "a1", ordering_key="A")
    a2 = put(queue, "a2", ordering_key="A")
    other = put(queue, "b1", ordering_key="B")
    for _ in range(3):
        job = lease_one(queue)
        assert job.job_id == a1.job_id
        queue.fail(job.job_id, "w1", RuntimeError("x"))
        clock.advance(seconds=100)
    assert queue.stats().blocked_ordering_keys == ("A",)
    # a2 is held; the unrelated key still flows
    assert lease_one(queue, "w2").job_id == other.job_id
    assert queue.lease(["ingest"], "w2") is None
    queue.replay(a1.job_id, admin.actor_id, "fixed")
    assert queue.stats().blocked_ordering_keys == ()
    first = lease_one(queue, "w3")
    assert first.job_id == a1.job_id  # the replayed older event goes before a2
    assert queue.lease(["ingest"], "w4") is None
    queue.complete(first.job_id, "w3")
    assert lease_one(queue, "w4").job_id == a2.job_id


def test_discard_unblocks_the_ordering_key(
    queue: JobQueue, clock: FixedClock, admin: Principal
) -> None:
    a1 = put(queue, "a1", ordering_key="A")
    a2 = put(queue, "a2", ordering_key="A")
    for _ in range(3):
        job = lease_one(queue)
        queue.fail(job.job_id, "w1", RuntimeError("x"))
        clock.advance(seconds=100)
    assert queue.lease(["ingest"], "w1") is None
    queue.discard(a1.job_id, admin.actor_id, "obsolete")
    assert lease_one(queue, "w1").job_id == a2.job_id


def test_jobs_without_ordering_key_are_fifo_by_enqueue(queue: JobQueue) -> None:
    ids = [put(queue, f"e{i}").job_id for i in range(3)]
    assert [lease_one(queue).job_id for _ in range(3)] == ids


def test_dead_job_without_ordering_key_blocks_nothing(queue: JobQueue, clock: FixedClock) -> None:
    kill(queue, clock)
    other = put(queue, "e2")
    assert lease_one(queue, "w2").job_id == other.job_id
    assert queue.stats().blocked_ordering_keys == ()


# -- stats and clocks ---------------------------------------------------------------------------


def test_stats_counts_and_oldest_pending_age(queue: JobQueue, clock: FixedClock) -> None:
    empty = queue.stats()
    assert empty.counts == {s: 0 for s in JobState}
    assert empty.oldest_pending_age_seconds is None
    put(queue, "e1")
    clock.advance(seconds=5)
    put(queue, "e2")
    clock.advance(seconds=5)
    stats = queue.stats()
    assert stats.counts[JobState.PENDING] == 2
    assert stats.oldest_pending_age_seconds == 10.0
    lease_one(queue)
    stats = queue.stats()
    assert stats.counts[JobState.PENDING] == 1
    assert stats.counts[JobState.LEASED] == 1
    assert stats.oldest_pending_age_seconds == 5.0


def test_clock_stepping_backwards_never_gives_a_negative_age(
    queue: JobQueue, clock: FixedClock
) -> None:
    put(queue)
    clock.advance(hours=-1)
    assert queue.stats().oldest_pending_age_seconds == 0.0


def test_clock_stepping_backwards_does_not_extend_a_lease(
    queue: JobQueue, clock: FixedClock
) -> None:
    put(queue)
    first = lease_one(queue)
    clock.advance(hours=-1)  # an hour of lease would remain without clamping
    second = lease_one(queue, "w2")
    assert second.job_id == first.job_id
    assert second.lease_owner == "w2"


def test_clock_stepping_backwards_does_not_extend_a_retry_wait(
    queue: JobQueue, clock: FixedClock
) -> None:
    put(queue)
    job = lease_one(queue)
    queue.fail(job.job_id, "w1", RuntimeError("x"))  # due again in 10 s
    clock.advance(hours=-1)
    assert lease_one(queue, "w2").job_id == job.job_id


def test_lease_expiry_uses_clock(queue: JobQueue, clock: FixedClock) -> None:
    put(queue)
    assert lease_one(queue).lease_expires_at == clock.now() + timedelta(seconds=30)


# -- knobs and failure mapping ---------------------------------------------------------------------


@pytest.mark.parametrize("knob", ["lease_seconds", "max_attempts"])
def test_lease_refuses_when_a_knob_is_none(
    engine: Engine, clock: FixedClock, audit: FakeAudit, resolver: FakeResolver, knob: str
) -> None:
    q = make_queue(engine, clock, audit, resolver, **{knob: None})
    put(q)
    with pytest.raises(FailClosed):
        q.lease(["ingest"], "w1")
    assert q.stats().counts[JobState.PENDING] == 1  # nothing was leased


@pytest.mark.parametrize("knob", ["max_attempts", "backoff_base_seconds", "backoff_max_seconds"])
def test_fail_refuses_when_a_knob_is_none(
    engine: Engine, clock: FixedClock, audit: FakeAudit, resolver: FakeResolver, knob: str
) -> None:
    good = make_queue(engine, clock, audit, resolver)
    put(good)
    job = lease_one(good)
    broken = make_queue(engine, clock, audit, resolver, **{knob: None})
    with pytest.raises(FailClosed):
        broken.fail(job.job_id, "w1", RuntimeError("x"))
    assert good.complete(job.job_id, "w1").state is JobState.DONE  # lease untouched


def test_enqueue_and_read_work_with_all_knobs_none(
    engine: Engine, clock: FixedClock, audit: FakeAudit, resolver: FakeResolver
) -> None:
    q = JobQueue(
        engine,
        clock,
        audit,
        resolver,
        lease_seconds=None,
        max_attempts=None,
        backoff_base_seconds=None,
        backoff_max_seconds=None,
    )
    assert put(q).state is JobState.PENDING
    assert q.stats().counts[JobState.PENDING] == 1
    assert q.dead_letters(5) == []


@pytest.mark.parametrize("knob", ["lease_seconds", "backoff_base_seconds", "backoff_max_seconds"])
@pytest.mark.parametrize(
    "bad", [0, -1, float("nan"), float("inf"), float("-inf"), True, "30", [30]]
)
def test_bad_seconds_knobs_are_refused_at_construction(
    engine: Engine,
    clock: FixedClock,
    audit: FakeAudit,
    resolver: FakeResolver,
    knob: str,
    bad: Any,
) -> None:
    with pytest.raises(ValidationFailed):
        make_queue(engine, clock, audit, resolver, **{knob: bad})


@pytest.mark.parametrize("bad", [0, -1, 2.5, True, float("nan"), float("inf"), "3"])
def test_bad_max_attempts_is_refused_at_construction(
    engine: Engine, clock: FixedClock, audit: FakeAudit, resolver: FakeResolver, bad: Any
) -> None:
    with pytest.raises(ValidationFailed):
        make_queue(engine, clock, audit, resolver, max_attempts=bad)


def test_fractional_seconds_are_fine(
    engine: Engine, clock: FixedClock, audit: FakeAudit, resolver: FakeResolver
) -> None:
    q = make_queue(engine, clock, audit, resolver, lease_seconds=0.5, backoff_base_seconds=0.25)
    put(q)
    assert lease_one(q).lease_expires_at == clock.now() + timedelta(seconds=0.5)


def test_backoff_max_below_base_is_refused(
    engine: Engine, clock: FixedClock, audit: FakeAudit, resolver: FakeResolver
) -> None:
    with pytest.raises(ValidationFailed):
        make_queue(engine, clock, audit, resolver, backoff_base_seconds=50, backoff_max_seconds=10)


def test_lease_scan_is_bounded(
    queue: JobQueue, clock: FixedClock, monkeypatch: pytest.MonkeyPatch
) -> None:
    assert MAX_LEASE_SCAN_ITERATIONS >= 1
    for i in range(3):  # three jobs sitting on their last attempt with expired leases
        put(queue, f"p{i}")
    for _ in range(3):
        for _ in range(3):
            assert queue.lease(["ingest"], "w1") is not None
        clock.advance(seconds=31)
    monkeypatch.setattr(queue_module, "MAX_LEASE_SCAN_ITERATIONS", 2)
    with pytest.raises(FailClosed):
        queue.lease(["ingest"], "w1")
    assert queue.stats().counts[JobState.DEAD] == 2  # progress was kept
    assert queue.lease(["ingest"], "w1") is None  # the third dead-letters, then nothing left
    assert queue.stats().counts[JobState.DEAD] == 3
