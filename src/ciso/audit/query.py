"""Read-only queries over audit records (FR-028). Used by `AuditLog.query`."""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import Engine, Select, select
from sqlalchemy.exc import SQLAlchemyError

from ciso.audit.chain import AuditRecord, row_to_record
from ciso.audit.tables import audit_record
from ciso.common.clock import ensure_utc
from ciso.common.db import read_connection
from ciso.common.enums import AuditOutcome
from ciso.common.errors import FailClosed, IntegrityFailure, ValidationFailed


def query_records(
    engine: Engine,
    *,
    limit: int,
    actor_id: str | None = None,
    action_prefix: str | None = None,
    target: str | None = None,
    outcome: AuditOutcome | None = None,
    correlation_id: str | None = None,
    since: datetime | None = None,
    until: datetime | None = None,
    after_seq: int | None = None,
) -> list[AuditRecord]:
    """Records in seq order. `since` is inclusive, `until` exclusive; `limit` > 0.

    Raises ValidationFailed for a bad limit, FailClosed if the database cannot be read and
    IntegrityFailure for a stored row that cannot be parsed.
    """
    if isinstance(limit, bool) or not isinstance(limit, int) or limit < 1:
        raise ValidationFailed("query limit must be a positive integer")
    t = audit_record.c
    stmt: Select[tuple[object, ...]] = select(audit_record).order_by(t.seq).limit(limit)
    if actor_id is not None:
        stmt = stmt.where(t.actor_id == actor_id)
    if action_prefix is not None:
        stmt = stmt.where(t.action.startswith(action_prefix, autoescape=True))
    if target is not None:
        stmt = stmt.where(t.target == target)
    if outcome is not None:
        stmt = stmt.where(t.outcome == AuditOutcome(outcome).value)
    if correlation_id is not None:
        stmt = stmt.where(t.correlation_id == correlation_id)
    if since is not None:
        stmt = stmt.where(t.occurred_at >= ensure_utc(since))
    if until is not None:
        stmt = stmt.where(t.occurred_at < ensure_utc(until))
    if after_seq is not None:
        stmt = stmt.where(t.seq > after_seq)
    try:
        with read_connection(engine) as conn:
            rows = conn.execute(stmt).all()
    except SQLAlchemyError as exc:
        raise FailClosed("audit records could not be read") from exc
    except (ValueError, TypeError) as exc:  # a stored value the driver cannot convert
        raise IntegrityFailure("audit records cannot be parsed") from exc
    return [row_to_record(row) for row in rows]
