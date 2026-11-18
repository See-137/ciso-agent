"""Reads and short write transactions on the approval table.

Nothing here calls the audit sink or the identity resolver, so neither can ever run while
the database write lock is held. Every state change is one conditional UPDATE inside one
`BEGIN IMMEDIATE` transaction and reports whether it changed a row. A database failure
becomes `ApprovalUnavailable(STORE_UNAVAILABLE)`.
"""

from __future__ import annotations

import functools
import json
from collections.abc import Callable
from datetime import datetime
from typing import Any

from sqlalchemy import Engine, select, update
from sqlalchemy.exc import SQLAlchemyError

from ciso.approvals.models import (
    Approval,
    ApprovalReason,
    ApprovalStatus,
    ApprovalUnavailable,
)
from ciso.approvals.tables import approval
from ciso.common.db import read_connection
from ciso.common.enums import Role
from ciso.common.schemas import canonical_json


def _closed[**P, R](func: Callable[P, R]) -> Callable[P, R]:
    @functools.wraps(func)
    def wrapper(*args: P.args, **kwargs: P.kwargs) -> R:
        try:
            return func(*args, **kwargs)
        except SQLAlchemyError as exc:
            raise ApprovalUnavailable(
                ApprovalReason.STORE_UNAVAILABLE,
                f"approval store unavailable: {type(exc).__name__}",
            ) from exc

    return wrapper


def _text_list(raw: str) -> tuple[str, ...]:
    found = json.loads(raw)
    if not isinstance(found, list) or not all(isinstance(item, str) for item in found):
        raise ValueError("expected a JSON list of strings")
    return tuple(found)


def _from_row(row: Any) -> Approval:
    try:
        return Approval(
            approval_id=row.approval_id,
            subject_kind=row.subject_kind,
            subject_hash=row.subject_hash,
            binding=json.loads(row.binding),
            requested_by=row.requested_by,
            requested_by_type=row.requested_by_type,
            parties=_text_list(row.parties),
            required_roles=tuple(Role(r) for r in json.loads(row.required_roles)),
            target=json.loads(row.target),
            status=row.status,
            requested_at=row.requested_at,
            expires_at=row.expires_at,
            correlation_id=row.correlation_id,
            decided_by=row.decided_by,
            decided_at=row.decided_at,
            decided_roles=tuple(Role(r) for r in json.loads(row.decided_roles)),
            decision_note=row.decision_note,
            self_approved=bool(row.self_approved),
            approver_credential_issuer=row.approver_credential_issuer,
            decision_audit_ref=row.decision_audit_ref,
            consumed_at=row.consumed_at,
            consumed_by=row.consumed_by,
        )
    except (ValueError, TypeError) as exc:
        # A row that cannot be read back is never treated as an approval.
        raise ApprovalUnavailable(
            ApprovalReason.RECORD_UNREADABLE, "stored approval could not be read"
        ) from exc


class ApprovalStore:
    def __init__(self, engine: Engine) -> None:
        self._engine = engine

    @_closed
    def insert(self, record: Approval) -> None:
        with self._engine.begin() as conn:
            conn.execute(
                approval.insert().values(
                    approval_id=record.approval_id,
                    subject_kind=record.subject_kind,
                    subject_hash=record.subject_hash,
                    binding=canonical_json(dict(record.binding)),
                    requested_by=record.requested_by,
                    requested_by_type=record.requested_by_type.value,
                    parties=canonical_json(list(record.parties)),
                    required_roles=canonical_json([r.value for r in record.required_roles]),
                    target=canonical_json(dict(record.target)),
                    status=record.status.value,
                    requested_at=record.requested_at,
                    expires_at=record.expires_at,
                    correlation_id=record.correlation_id,
                )
            )

    @_closed
    def find(self, approval_id: str) -> Approval | None:
        with read_connection(self._engine) as conn:
            row = conn.execute(
                select(approval).where(approval.c.approval_id == approval_id)
            ).first()
        return None if row is None else _from_row(row)

    @_closed
    def pending(self, now: datetime) -> tuple[Approval, ...]:
        """Pending and not yet expired, oldest first."""
        with read_connection(self._engine) as conn:
            rows = conn.execute(
                select(approval)
                .where(approval.c.status == ApprovalStatus.PENDING.value)
                .where(approval.c.expires_at > now)
                .order_by(approval.c.requested_at, approval.c.approval_id)
            ).all()
        return tuple(_from_row(row) for row in rows)

    @_closed
    def _change(self, approval_id: str, values: dict[str, Any], *conditions: Any) -> bool:
        with self._engine.begin() as conn:
            result = conn.execute(
                update(approval)
                .where(approval.c.approval_id == approval_id, *conditions)
                .values(**values)
            )
            return result.rowcount == 1

    def decide(
        self,
        approval_id: str,
        *,
        status: ApprovalStatus,
        decided_by: str,
        decided_at: datetime,
        decided_roles: tuple[Role, ...],
        note: str,
        self_approved: bool,
        credential_issuer: str,
    ) -> bool:
        """pending -> approved or rejected, only while pending and unexpired."""
        return self._change(
            approval_id,
            {
                "status": status.value,
                "decided_by": decided_by,
                "decided_at": decided_at,
                "decided_roles": canonical_json([r.value for r in decided_roles]),
                "decision_note": note,
                "self_approved": self_approved,
                "approver_credential_issuer": credential_issuer,
            },
            approval.c.status == ApprovalStatus.PENDING.value,
            approval.c.expires_at > decided_at,
        )

    def confirm_grant(self, approval_id: str, audit_ref: str) -> bool:
        """Record that the grant reached the audit log. Until then it is not usable."""
        return self._change(
            approval_id,
            {"decision_audit_ref": audit_ref},
            approval.c.status == ApprovalStatus.APPROVED.value,
            approval.c.decision_audit_ref.is_(None),
        )

    def consume(self, record: Approval, *, consumed_by: str, now: datetime) -> bool:
        """approved -> consumed, at most once (the single-use guarantee).

        The WHERE clause restates everything stored that `check` relied on, so a row
        that was consumed, voided, expired or re-pointed since it was read is not taken.
        Under `BEGIN IMMEDIATE` two callers cannot both see a row to change.
        """
        return self._change(
            record.approval_id,
            {
                "status": ApprovalStatus.CONSUMED.value,
                "consumed_at": now,
                "consumed_by": consumed_by,
            },
            approval.c.status == ApprovalStatus.APPROVED.value,
            approval.c.consumed_at.is_(None),
            approval.c.decision_audit_ref.is_not(None),
            approval.c.expires_at > now,
            approval.c.subject_kind == record.subject_kind,
            approval.c.subject_hash == record.subject_hash,
            approval.c.binding == canonical_json(dict(record.binding)),
            approval.c.decided_by == record.decided_by,
        )

    def void(self, approval_id: str, *from_statuses: ApprovalStatus) -> bool:
        """Cancel a row that is in one of the named states (callers never name `consumed`).
        Terminal. False means nothing changed (the row is in another state, or gone):
        the caller must not report it as cancelled."""
        return self._change(
            approval_id,
            {"status": ApprovalStatus.VOID.value},
            approval.c.status.in_([status.value for status in from_statuses]),
        )
