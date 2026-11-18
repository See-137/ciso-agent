"""Durable job queue kept in the operational database (blueprint 5.1 #13, 10.3, 13.4).

There is no broker and no thread here. Callers lease a job, do the work, renew the lease if
it runs long, then complete or fail it. All state is in the table, so a restart loses
nothing: a lease nobody renews expires and the job becomes leasable again.

Safety knobs (`lease_seconds`, `max_attempts`, `backoff_*`) are `None` unless the caller
sets them. An operation that needs a knob that is `None` raises `FailClosed` and changes
nothing. A locked or failing database also raises `FailClosed`, never a raw driver error.

Rules a caller should know:

- `(source, event_id)` is the dedupe key. Repeating an identical event returns the
  existing job; the same key with a different kind, payload or ordering key is a `Conflict`.
- Payloads hold references (ids, `EntityRef` strings), never bulk content. The queue checks
  that a payload is plain JSON and that identifiers fit their columns.
- A dead-lettered job blocks its `ordering_key` until a human replays or discards it, so
  a replayed event can never run after newer events for the same key.
- DONE, DEAD and DISCARDED rows are the dedupe record for their `(source, event_id)`.
  They must be kept; there is deliberately no purge, because deleting them would let an
  old event be accepted again.
- Every change is checked with a row version. A lost race raises `Conflict`.
- Replay and discard are decided on the actor id, resolved through the identity store at
  the moment of the call. A `Principal` object handed in is never trusted. The audit
  sink is called outside any database transaction: an ATTEMPT record first, then the
  change, then the RESULT record.
"""

from __future__ import annotations

import json
import logging
from collections.abc import Callable, Sequence
from datetime import datetime, timedelta
from typing import Any

from sqlalchemy import Connection, Engine, and_, exists, func, or_, select, update
from sqlalchemy.exc import IntegrityError

from ciso.common.clock import Clock
from ciso.common.db import read_connection
from ciso.common.enums import ActorType, AuditOutcome, Role
from ciso.common.errors import (
    AuthorizationError,
    CisoError,
    Conflict,
    FailClosed,
    NotFound,
    ValidationFailed,
)
from ciso.common.ids import new_id
from ciso.common.principal import Principal
from ciso.common.protocols import AuditEvent, AuditSink, PrincipalResolver
from ciso.workflows import _support as sup
from ciso.workflows.models import EnqueueResult, Job, JobState, QueueStats, job_from_row
from ciso.workflows.tables import (
    EVENT_ID_MAX,
    KIND_MAX,
    ORDERING_KEY_MAX,
    SOURCE_MAX,
    WORKER_ID_MAX,
    jobs,
)

log = logging.getLogger(__name__)

#: One `lease()` call looks at this many candidates at most (each is dead-lettered, lost to
#: another worker, or leased) before it gives up with `FailClosed`.
MAX_LEASE_SCAN_ITERATIONS = 100
ERROR_MESSAGE_LIMIT = 200
REASON_MAX = 500

#: Called as `callback(kind, reason)` after a job is dead-lettered; reason is `attempts_exhausted`
#: or `lease_expired`. Must be quick. A callback that raises is logged, not propagated.
DeadLetterCallback = Callable[[str, str], None]

_BLOCKING = (JobState.PENDING.value, JobState.LEASED.value, JobState.DEAD.value)


class JobQueue:
    """See module docstring. One instance per process; all state is in the database."""

    def __init__(
        self,
        engine: Engine,
        clock: Clock,
        audit: AuditSink,
        resolver: PrincipalResolver,
        *,
        lease_seconds: float | None,
        max_attempts: int | None,
        backoff_base_seconds: float | None,
        backoff_max_seconds: float | None,
        on_dead_letter: DeadLetterCallback | None = None,
    ) -> None:
        sup.check_seconds("lease_seconds", lease_seconds)
        sup.check_count("max_attempts", max_attempts)
        sup.check_seconds("backoff_base_seconds", backoff_base_seconds)
        sup.check_seconds("backoff_max_seconds", backoff_max_seconds)
        if (
            backoff_base_seconds is not None
            and backoff_max_seconds is not None
            and backoff_max_seconds < backoff_base_seconds
        ):
            raise ValidationFailed("backoff_max_seconds is below backoff_base_seconds")
        self._engine = engine
        self._clock = clock
        self._audit = audit
        self._resolver = resolver
        self._lease_seconds = lease_seconds
        self._max_attempts = max_attempts
        self._backoff_base = backoff_base_seconds
        self._backoff_max = backoff_max_seconds
        self._on_dead_letter = on_dead_letter

    # -- producers ---------------------------------------------------------------------

    @sup.closed_on_db_error
    def enqueue(
        self,
        kind: str,
        payload: dict[str, Any],
        *,
        source: str,
        event_id: str,
        ordering_key: str | None = None,
    ) -> EnqueueResult:
        """Add a job. An identical repeat of `(source, event_id)` returns the existing job
        with `created=False`; a repeat with different content raises `Conflict`.
        """
        sup.check_text("kind", kind, KIND_MAX)
        sup.check_text("source", source, SOURCE_MAX)
        sup.check_text("event_id", event_id, EVENT_ID_MAX)
        if ordering_key is not None:
            sup.check_text("ordering_key", ordering_key, ORDERING_KEY_MAX)
        try:
            body = json.dumps(payload, sort_keys=True, separators=(",", ":"), allow_nan=False)
        except (TypeError, ValueError) as exc:
            raise ValidationFailed(f"payload is not plain JSON: {type(exc).__name__}") from exc
        now = self._clock.now()
        with self._engine.begin() as conn:
            found = self._by_event(conn, source, event_id)
            if found is None:
                values = {
                    "job_id": new_id("job"),
                    "kind": kind,
                    "payload": body,
                    "source": source,
                    "event_id": event_id,
                    "ordering_key": ordering_key,
                    "state": JobState.PENDING.value,
                    "attempts": 0,
                    "version": 0,
                    "available_at": now,
                    "created_at": now,
                    "updated_at": now,
                }
                try:
                    conn.execute(jobs.insert().values(**values))
                except IntegrityError as exc:  # lost a race on a database without a write lock
                    raise Conflict("event was enqueued concurrently; retry") from exc
                return EnqueueResult(
                    job=self._job(self._by_event(conn, source, event_id)), created=True
                )
            if (found.kind, found.payload, found.ordering_key) != (kind, body, ordering_key):
                raise Conflict(f"event {source}/{event_id} already queued with different content")
            return EnqueueResult(job=self._job(found), created=False)

    # -- workers -----------------------------------------------------------------------

    @sup.closed_on_db_error
    def lease(self, kinds: Sequence[str], worker_id: str) -> Job | None:
        """Take the next due job of one of `kinds`, or `None`.

        FIFO per `ordering_key`: a job is skipped while an earlier job with the same key is
        pending, leased, waiting to retry or dead-lettered. A job whose lease expired is
        leasable again; if that was its last attempt it is dead-lettered instead. A lease
        or retry time further in the future than the knobs allow (the clock stepped
        backwards) counts as due, so a clock step never extends a lease.
        """
        if self._lease_seconds is None or self._max_attempts is None:
            raise FailClosed("lease_seconds and max_attempts are not set; refusing to lease")
        if not kinds:
            raise ValidationFailed("lease needs at least one kind")
        for kind in kinds:
            sup.check_text("kind", kind, KIND_MAX)
        sup.check_text("worker_id", worker_id, WORKER_ID_MAX)
        for _ in range(MAX_LEASE_SCAN_ITERATIONS):
            done, job = self._lease_once(list(kinds), worker_id)
            if done:
                return job
        raise FailClosed("lease scan limit reached; try again")

    def _lease_once(self, kinds: list[str], worker_id: str) -> tuple[bool, Job | None]:
        assert self._lease_seconds is not None
        assert self._max_attempts is not None
        now = self._clock.now()
        dead_kind: str | None = None
        result: tuple[bool, Job | None] = (False, None)
        with self._engine.begin() as conn:
            row = self._next_candidate(conn, kinds, now)
            if row is None:
                return True, None
            if row.attempts >= self._max_attempts:
                if self._guarded_update(
                    conn,
                    row,
                    state=JobState.DEAD.value,
                    lease_owner=None,
                    lease_expires_at=None,
                    last_error="LeaseExpired: lease expired on the last attempt",
                    updated_at=now,
                ):
                    dead_kind = row.kind
            elif self._guarded_update(
                conn,
                row,
                state=JobState.LEASED.value,
                attempts=row.attempts + 1,
                lease_owner=worker_id,
                lease_expires_at=now + timedelta(seconds=self._lease_seconds),
                updated_at=now,
            ):
                result = (True, self._job(self._row(conn, row.job_id)))
        if dead_kind is not None:
            self._note_dead(dead_kind, "lease_expired")
        return result

    @sup.closed_on_db_error
    def renew(self, job_id: str, worker_id: str, *, attempt: int | None = None) -> Job:
        """Extend the lease from now. `Conflict` if another worker took the job over."""
        if self._lease_seconds is None:
            raise FailClosed("lease_seconds is not set; refusing to renew")
        now = self._clock.now()
        with self._engine.begin() as conn:
            row = self._held_by(conn, job_id, worker_id, attempt)
            self._must_update(
                conn,
                row,
                lease_expires_at=now + timedelta(seconds=self._lease_seconds),
                updated_at=now,
            )
            return self._job(self._row(conn, job_id))

    @sup.closed_on_db_error
    def complete(self, job_id: str, worker_id: str, *, attempt: int | None = None) -> Job:
        """Mark done. Works if the row is still leased by this worker, even when the lease
        time has passed and nobody took the job over. A takeover wins: `Conflict`.
        `attempt` (the `attempts` of the job returned by `lease`) pins the exact lease.
        """
        now = self._clock.now()
        with self._engine.begin() as conn:
            row = self._held_by(conn, job_id, worker_id, attempt)
            self._must_update(
                conn,
                row,
                state=JobState.DONE.value,
                lease_owner=None,
                lease_expires_at=None,
                updated_at=now,
            )
            return self._job(self._row(conn, job_id))

    @sup.closed_on_db_error
    def fail(
        self, job_id: str, worker_id: str, error: BaseException, *, attempt: int | None = None
    ) -> Job:
        """Record a failure: retry after exponential backoff, or dead-letter at the ceiling.

        Only the error type and a short message are stored, never payload content.
        """
        if self._max_attempts is None or self._backoff_base is None or self._backoff_max is None:
            raise FailClosed("max_attempts and backoff are not set; refusing to fail a job")
        now = self._clock.now()
        dead_kind: str | None = None
        with self._engine.begin() as conn:
            row = self._held_by(conn, job_id, worker_id, attempt)
            if row.attempts >= self._max_attempts:
                values: dict[str, Any] = {"state": JobState.DEAD.value}
                dead_kind = row.kind
            else:
                delay = min(self._backoff_base * (2 ** (row.attempts - 1)), self._backoff_max)
                values = {
                    "state": JobState.PENDING.value,
                    "available_at": now + timedelta(seconds=delay),
                }
            self._must_update(
                conn,
                row,
                lease_owner=None,
                lease_expires_at=None,
                last_error=sup.describe_error(error, ERROR_MESSAGE_LIMIT),
                updated_at=now,
                **values,
            )
            result = self._job(self._row(conn, job_id))
        if dead_kind is not None:
            self._note_dead(dead_kind, "attempts_exhausted")
        return result

    # -- operators ---------------------------------------------------------------------

    @sup.closed_on_db_error
    def dead_letters(self, limit: int) -> list[Job]:
        """The oldest `limit` dead-lettered jobs."""
        if isinstance(limit, bool) or not isinstance(limit, int) or limit < 1:
            raise ValidationFailed("limit must be a positive integer")
        with read_connection(self._engine) as conn:
            rows = conn.execute(
                select(jobs)
                .where(jobs.c.state == JobState.DEAD.value)
                .order_by(jobs.c.seq)
                .limit(limit)
            ).all()
        return [self._job(r) for r in rows]

    def replay(self, job_id: str, actor_id: str, reason: str) -> Job:
        """Put a dead-lettered job back to pending with attempts reset.

        `actor_id` must resolve, now, to a human with `security_admin`. See the module
        docstring for the audit order. `Conflict` if the job is not dead.
        """
        return self._operator_action("replay", job_id, actor_id, reason)

    def discard(self, job_id: str, actor_id: str, reason: str) -> Job:
        """Give up on a dead-lettered job, which unblocks its ordering key. Same rules as
        `replay`. The row is kept as the dedupe record.
        """
        return self._operator_action("discard", job_id, actor_id, reason)

    @sup.closed_on_db_error
    def stats(self) -> QueueStats:
        now = self._clock.now()
        counts = {state: 0 for state in JobState}
        with read_connection(self._engine) as conn:
            for state, n in conn.execute(select(jobs.c.state, func.count()).group_by(jobs.c.state)):
                counts[JobState(state)] = n
            oldest = conn.execute(
                select(jobs.c.created_at)
                .where(jobs.c.state == JobState.PENDING.value)
                .order_by(jobs.c.created_at)
                .limit(1)
            ).scalar()
            blocked = conn.execute(
                select(jobs.c.ordering_key)
                .where(jobs.c.state == JobState.DEAD.value, jobs.c.ordering_key.is_not(None))
                .distinct()
            ).scalars()
            keys = tuple(sorted(str(k) for k in blocked))
        age = None if oldest is None else max(0.0, (now - oldest).total_seconds())
        return QueueStats(counts=counts, oldest_pending_age_seconds=age, blocked_ordering_keys=keys)

    # -- operator internals ------------------------------------------------------------

    def _operator_action(self, action: str, job_id: str, actor_id: str, reason: str) -> Job:
        principal = self._authorize(f"workflows.{action}", job_id, actor_id, reason)
        sup.check_text("reason", reason, REASON_MAX)
        name = f"workflows.{action}"
        details = {"reason": reason}
        self._record(name, principal, job_id, AuditOutcome.ATTEMPT, details)
        try:
            job = self._move_dead_job(job_id, discard=action == "discard")
        except Exception as exc:
            failed = {**details, "error": type(exc).__name__}
            try:
                self._record(name, principal, job_id, AuditOutcome.FAILED, failed)
            except Exception:
                log.exception("result record for %s of %s could not be written", action, job_id)
            raise
        try:
            self._record(name, principal, job_id, AuditOutcome.SUCCESS, details)
        except Exception as exc:
            log.error("%s of %s applied but its result record failed", action, job_id)
            raise FailClosed(f"{action} applied but the audit result record failed") from exc
        return job

    @sup.closed_on_db_error
    def _move_dead_job(self, job_id: str, *, discard: bool) -> Job:
        now = self._clock.now()
        with self._engine.begin() as conn:
            row = self._row(conn, job_id)
            if row.state != JobState.DEAD.value:
                raise Conflict(f"job {job_id} is {row.state}, not dead")
            if discard:
                self._must_update(conn, row, state=JobState.DISCARDED.value, updated_at=now)
            else:
                self._must_update(
                    conn,
                    row,
                    state=JobState.PENDING.value,
                    attempts=0,
                    available_at=now,
                    updated_at=now,
                )
            return self._job(self._row(conn, job_id))

    def _authorize(self, action: str, job_id: str, actor_id: str, reason: str) -> Principal:
        try:
            resolved = self._resolver.resolve(actor_id)
        except Exception as exc:
            raise FailClosed("principal resolver could not answer; refusing") from exc
        allowed = (
            resolved is not None
            and resolved.actor_id == actor_id
            and resolved.is_human
            and resolved.has_role(Role.SECURITY_ADMIN)
        )
        if not allowed or resolved is None:
            who = resolved.actor_type if resolved is not None else ActorType.SERVICE
            self._append(
                AuditEvent(
                    actor_id=actor_id,
                    actor_type=who,
                    action=action,
                    target=f"job:{job_id}",
                    outcome=AuditOutcome.DENIED,
                    details={"reason": reason[:REASON_MAX]},
                )
            )
            raise AuthorizationError(f"{action} needs a current human security_admin")
        return resolved

    def _record(
        self,
        action: str,
        principal: Principal,
        job_id: str,
        outcome: AuditOutcome,
        details: dict[str, Any],
    ) -> None:
        self._append(
            AuditEvent(
                actor_id=principal.actor_id,
                actor_type=principal.actor_type,
                action=action,
                target=f"job:{job_id}",
                outcome=outcome,
                details=details,
            )
        )

    def _append(self, event: AuditEvent) -> None:
        try:
            self._audit.append(event)
        except CisoError:
            raise
        except Exception as exc:
            raise FailClosed("audit path failed") from exc

    # -- row internals -----------------------------------------------------------------

    @staticmethod
    def _job(row: Any) -> Job:
        return job_from_row(row, json.loads(row.payload))

    @staticmethod
    def _by_event(conn: Connection, source: str, event_id: str) -> Any:
        return conn.execute(
            select(jobs).where(jobs.c.source == source, jobs.c.event_id == event_id)
        ).first()

    @staticmethod
    def _row(conn: Connection, job_id: str) -> Any:
        row = conn.execute(select(jobs).where(jobs.c.job_id == job_id)).first()
        if row is None:
            raise NotFound(f"no such job: {job_id}")
        return row

    def _held_by(self, conn: Connection, job_id: str, worker_id: str, attempt: int | None) -> Any:
        row = self._row(conn, job_id)
        if (
            row.state != JobState.LEASED.value
            or row.lease_owner != worker_id
            or (attempt is not None and row.attempts != attempt)
        ):
            raise Conflict(f"worker does not hold the lease on {job_id}")
        return row

    @staticmethod
    def _guarded_update(conn: Connection, row: Any, **values: Any) -> bool:
        """Update only if the row still has the version we read. False means we lost."""
        result = conn.execute(
            update(jobs)
            .where(jobs.c.job_id == row.job_id, jobs.c.version == row.version)
            .values(version=row.version + 1, **values)
        )
        return bool(result.rowcount == 1)

    def _must_update(self, conn: Connection, row: Any, **values: Any) -> None:
        if not self._guarded_update(conn, row, **values):
            raise Conflict(f"job {row.job_id} changed underneath this call")

    def _next_candidate(self, conn: Connection, kinds: list[str], now: datetime) -> Any:
        assert self._lease_seconds is not None
        earlier = jobs.alias("earlier")
        blocked = exists().where(
            earlier.c.ordering_key == jobs.c.ordering_key,
            earlier.c.seq < jobs.c.seq,
            earlier.c.state.in_(_BLOCKING),
        )
        lease_cap = now + timedelta(seconds=self._lease_seconds)
        pending_due = jobs.c.available_at <= now
        if self._backoff_max is not None:
            retry_cap = now + timedelta(seconds=self._backoff_max)
            pending_due = or_(pending_due, jobs.c.available_at > retry_cap)
        due = or_(
            and_(jobs.c.state == JobState.PENDING.value, pending_due),
            and_(
                jobs.c.state == JobState.LEASED.value,
                or_(jobs.c.lease_expires_at <= now, jobs.c.lease_expires_at > lease_cap),
            ),
        )
        stmt = (
            select(jobs).where(jobs.c.kind.in_(kinds), due, ~blocked).order_by(jobs.c.seq).limit(1)
        )
        return conn.execute(stmt).first()

    def _note_dead(self, kind: str, reason: str) -> None:
        log.warning("job dead-lettered: kind=%s reason=%s", kind, reason)
        if self._on_dead_letter is not None:
            try:
                self._on_dead_letter(kind, reason)
            except Exception:
                log.exception("dead-letter callback failed")
