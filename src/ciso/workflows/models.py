"""Value types returned by the queue. All frozen; nothing here changes after creation."""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from ciso.common.schemas import FrozenJson, Model, UtcDatetime


class JobState(StrEnum):
    PENDING = "pending"  # waiting, including waiting out a retry backoff
    LEASED = "leased"
    DONE = "done"  # kept: it is the dedupe record for its (source, event_id)
    DEAD = "dead"  # dead-letter: out of attempts; blocks its ordering key until handled
    DISCARDED = "discarded"  # a human chose to drop a dead job; also kept for dedupe


class Job(Model):
    job_id: str
    kind: str
    payload: FrozenJson
    source: str
    event_id: str
    ordering_key: str | None
    state: JobState
    attempts: int
    version: int
    available_at: UtcDatetime
    lease_owner: str | None
    lease_expires_at: UtcDatetime | None
    last_error: str | None
    created_at: UtcDatetime
    updated_at: UtcDatetime


class EnqueueResult(Model):
    job: Job
    created: bool  # False: an identical event was already queued and `job` is that one


class QueueStats(Model):
    counts: dict[JobState, int]
    oldest_pending_age_seconds: float | None
    #: Ordering keys held up by a dead-lettered job, sorted. Empty when nothing is blocked.
    blocked_ordering_keys: tuple[str, ...]


def job_from_row(row: Any, payload: Any) -> Job:
    return Job(
        job_id=row.job_id,
        kind=row.kind,
        payload=payload,
        source=row.source,
        event_id=row.event_id,
        ordering_key=row.ordering_key,
        state=JobState(row.state),
        attempts=row.attempts,
        version=row.version,
        available_at=row.available_at,
        lease_owner=row.lease_owner,
        lease_expires_at=row.lease_expires_at,
        last_error=row.last_error,
        created_at=row.created_at,
        updated_at=row.updated_at,
    )
