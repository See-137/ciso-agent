"""Queue table. One row per job; all state lives here so a restart loses nothing."""

from __future__ import annotations

from sqlalchemy import Column, Index, Integer, String, Table, Text, UniqueConstraint

from ciso.common.db import UtcDateTime, operational_metadata, register_schema

register_schema("workflows", 1)

#: Column sizes. The queue validates input against these, because SQLite ignores them but
#: other databases do not.
JOB_ID_MAX = 64
KIND_MAX = 128
SOURCE_MAX = 128
EVENT_ID_MAX = 256
ORDERING_KEY_MAX = 256
WORKER_ID_MAX = 128

jobs = Table(
    "workflow_jobs",
    operational_metadata,
    # `seq` is the FIFO order. AUTOINCREMENT so a number is never reused.
    Column("seq", Integer, primary_key=True, autoincrement=True),
    Column("job_id", String(JOB_ID_MAX), nullable=False),
    Column("kind", String(KIND_MAX), nullable=False),
    Column("payload", Text, nullable=False),
    Column("source", String(SOURCE_MAX), nullable=False),
    Column("event_id", String(EVENT_ID_MAX), nullable=False),
    Column("ordering_key", String(ORDERING_KEY_MAX), nullable=True),
    Column("state", String(16), nullable=False),
    Column("attempts", Integer, nullable=False, default=0),
    # Optimistic-lock counter: every update compares and bumps it, never a timestamp.
    Column("version", Integer, nullable=False, default=0),
    Column("available_at", UtcDateTime, nullable=False),
    Column("lease_owner", String(WORKER_ID_MAX), nullable=True),
    Column("lease_expires_at", UtcDateTime, nullable=True),
    Column("last_error", Text, nullable=True),
    Column("created_at", UtcDateTime, nullable=False),
    Column("updated_at", UtcDateTime, nullable=False),
    UniqueConstraint("job_id"),
    UniqueConstraint("source", "event_id"),
    Index("ix_workflow_jobs_state_available", "state", "available_at"),
    Index("ix_workflow_jobs_ordering", "ordering_key", "seq"),
    sqlite_autoincrement=True,
)
