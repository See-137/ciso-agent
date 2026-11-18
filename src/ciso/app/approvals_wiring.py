"""How the composition root builds the approval service (plan T2.9; blueprint 9.5,
FR-025; gaps G3, G12, G33; ADR-0016).

`AuditRecordReader` is the `ciso.approvals.AuditRecordLookup` over the real audit log.
The approvals package never imports the audit module; this adapter is what lets `check`
and `consume` read a grant's audit record back, so an approved row that somebody wrote
straight into the approval table is not usable.
"""

from __future__ import annotations

import hmac
from datetime import timedelta

from sqlalchemy import Engine, select
from sqlalchemy.exc import SQLAlchemyError

from ciso.app.audit_wiring import UnavailableAuditLog
from ciso.app.settings import Settings
from ciso.approvals import ApprovalService, AuditRecordView
from ciso.audit import AuditLog, audit_record, record_hash
from ciso.audit.chain import row_to_record
from ciso.common.clock import Clock
from ciso.common.db import read_connection
from ciso.common.errors import FailClosed, IntegrityFailure
from ciso.common.protocols import PrincipalResolver, Redactor


class AuditRecordReader:
    """Finds one audit record by id and hands back its action, target, outcome and actor.

    Raises when the answer cannot be trusted, so the approval service fails closed
    (`AUDIT_UNAVAILABLE`): the audit log could not be built (`FailClosed`), its database
    cannot be read (`FailClosed`), or the stored row does not parse or does not hash to
    its own `hash` column (`IntegrityFailure`). Returns None only when the log is
    readable and holds no record with that id.

    Limit: the check is on the one row. A writer of the audit database who inserts a row
    with a correctly computed hash is caught by `AuditLog.verify()` and the start-up
    gate, not here.
    """

    def __init__(self, audit: AuditLog | UnavailableAuditLog, engine: Engine) -> None:
        self._audit = audit
        self._engine = engine

    def find(self, record_id: str) -> AuditRecordView | None:
        if not isinstance(self._audit, AuditLog):
            raise FailClosed("audit log unavailable; a grant's audit record cannot be read")
        if not isinstance(record_id, str) or not record_id:
            return None
        try:
            with read_connection(self._engine) as conn:
                row = conn.execute(
                    select(audit_record).where(audit_record.c.id == record_id)
                ).first()
        except SQLAlchemyError as exc:
            raise FailClosed("audit records could not be read") from exc
        if row is None:
            return None
        record = row_to_record(row)
        if not hmac.compare_digest(record_hash(record), record.hash):
            raise IntegrityFailure("audit record does not match its own hash")
        return AuditRecordView(
            action=record.action,
            target=record.target,
            outcome=record.outcome,
            actor_id=record.actor_id,
        )


def build_approvals(
    settings: Settings,
    *,
    operational: Engine,
    audit: AuditLog | UnavailableAuditLog,
    audit_engine: Engine,
    clock: Clock,
    principals: PrincipalResolver,
    redactor: Redactor,
) -> ApprovalService:
    """The one `ApprovalService`. Expiry and self-approval come from `Settings.safety`
    (unset expiry: nothing can be requested, approved or used; ADR-0019). Decision notes
    go through the redactor, and every use reads the grant's audit record back."""
    ttl = settings.safety.approval_ttl_seconds
    return ApprovalService(
        engine=operational,
        audit=audit,
        clock=clock,
        principals=principals,
        approval_ttl=None if ttl is None else timedelta(seconds=ttl),
        allow_self_approval=settings.safety.allow_self_approval,
        redactor=redactor,
        audit_records=AuditRecordReader(audit, audit_engine),
    )
