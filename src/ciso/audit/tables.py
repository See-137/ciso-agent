"""The audit database schema. It lives in its own file with its own metadata.

The audit log never shares `operational_metadata`: ordinary writers hold no handle to the
audit database (blueprint §5.1 #14, NFR-016). Triggers make the table append-only and keep
the chain ordered at the storage layer too (NFR-006, ADR-0013).
"""

from __future__ import annotations

from pathlib import Path

from sqlalchemy import (
    CheckConstraint,
    Column,
    Engine,
    Index,
    Integer,
    MetaData,
    String,
    Table,
    Text,
)

from ciso.common.db import NAMING_CONVENTION, UtcDateTime
from ciso.common.errors import ValidationFailed

#: prev_hash of the first record. Fixed so that verify() can start from a known value.
GENESIS_HASH = "0" * 64

#: Separate from operational_metadata on purpose. Only ciso.audit creates these tables.
audit_metadata = MetaData(naming_convention=NAMING_CONVENTION)

audit_record = Table(
    "audit_record",
    audit_metadata,
    Column("id", String(40), primary_key=True),
    Column("seq", Integer, nullable=False, unique=True),
    Column("occurred_at", UtcDateTime, nullable=False),
    Column("actor_id", String(200), nullable=False),
    Column("actor_type", String(16), nullable=False),
    Column("action", String(200), nullable=False),
    Column("target", String(500), nullable=False),
    Column("outcome", String(16), nullable=False),
    Column("correlation_id", String(200), nullable=False),
    Column("details", Text, nullable=False),
    Column("prev_hash", String(64), nullable=False),
    Column("hash", String(64), nullable=False),
    Index("ix_audit_record_actor_id", "actor_id"),
    Index("ix_audit_record_action", "action"),
    Index("ix_audit_record_correlation_id", "correlation_id"),
    Index("ix_audit_record_occurred_at", "occurred_at"),
)

#: One row, written once by `AuditLog.initialise()`. Holds the log's identity, which the
#: anchor also carries under its HMAC, so a wiped-and-recreated log is told apart from the
#: original (gap G4).
audit_meta = Table(
    "audit_meta",
    audit_metadata,
    Column("id", Integer, primary_key=True),
    Column("log_id", String(40), nullable=False),
    Column("created_at", UtcDateTime, nullable=False),
    CheckConstraint("id = 1", name="single_row"),
)

_TRIGGERS = (
    """
    CREATE TRIGGER IF NOT EXISTS audit_record_no_update
    BEFORE UPDATE ON audit_record
    BEGIN
        SELECT RAISE(ABORT, 'audit records are append-only: update refused');
    END
    """,
    """
    CREATE TRIGGER IF NOT EXISTS audit_record_no_delete
    BEFORE DELETE ON audit_record
    BEGIN
        SELECT RAISE(ABORT, 'audit records are append-only: delete refused');
    END
    """,
    """
    CREATE TRIGGER IF NOT EXISTS audit_meta_no_update
    BEFORE UPDATE ON audit_meta
    BEGIN
        SELECT RAISE(ABORT, 'audit log identity is write-once: update refused');
    END
    """,
    """
    CREATE TRIGGER IF NOT EXISTS audit_meta_no_delete
    BEFORE DELETE ON audit_meta
    BEGIN
        SELECT RAISE(ABORT, 'audit log identity is write-once: delete refused');
    END
    """,
    f"""
    CREATE TRIGGER IF NOT EXISTS audit_record_chain_order
    BEFORE INSERT ON audit_record
    WHEN NEW.seq != (SELECT COALESCE(MAX(seq), 0) + 1 FROM audit_record)
      OR NEW.prev_hash != COALESCE(
            (SELECT hash FROM audit_record ORDER BY seq DESC LIMIT 1), '{GENESIS_HASH}')
    BEGIN
        SELECT RAISE(ABORT, 'audit chain: seq or prev_hash does not follow the head');
    END
    """,  # noqa: S608 - constant only, no caller input
)

TRIGGER_NAMES = (
    "audit_record_no_update",
    "audit_record_no_delete",
    "audit_record_chain_order",
    "audit_meta_no_update",
    "audit_meta_no_delete",
)


def init_audit_schema(engine: Engine) -> None:
    """Create the audit tables and their triggers on the audit engine. Safe to call again.

    This does not make the log usable: call `AuditLog.initialise()` once on a new log.

    Pass the audit database's own engine (`create_db_engine(<audit file>)`), never the
    operational one.
    """
    audit_metadata.create_all(engine)
    with engine.begin() as conn:
        for ddl in _TRIGGERS:
            conn.exec_driver_sql(ddl)


def refuse_inside_db_dir(engine: Engine, path: Path, what: str) -> None:
    """Refuse an anchor or witness `path` anywhere under the audit database's directory:
    whoever can restore or replace the database there rolls it back too (review C1)."""
    database = engine.url.database
    if not database or database == ":memory:":
        return
    db_dir = Path(database).resolve().parent
    if Path(path).resolve().is_relative_to(db_dir):
        raise ValidationFailed(f"the audit {what} must not live inside the database directory")
