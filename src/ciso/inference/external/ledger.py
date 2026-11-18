"""Reads and short write transactions on the external model path's three tables.

Nothing here calls the audit sink, the identity resolver or a transport, so none of them
can run while the database write lock is held. A database failure, or a stored row that
cannot be read back, becomes `FailClosed`: the caller stops.
"""

from __future__ import annotations

import functools
import json
from collections.abc import Callable
from datetime import datetime
from typing import Any

from sqlalchemy import Engine, delete, select, update
from sqlalchemy.exc import SQLAlchemyError

from ciso.common.db import read_connection
from ciso.common.errors import FailClosed
from ciso.common.schemas import canonical_json, thaw
from ciso.inference.external.proposals import ExternalProposalRecord
from ciso.inference.external.records import (
    ExternalAuthorization,
    ExternalTransmissionRecord,
    TransmitOutcome,
)
from ciso.inference.external.tables import (
    external_inference_authorization as authorization_table,
)
from ciso.inference.external.tables import (
    external_inference_proposal as proposal_table,
)
from ciso.inference.external.tables import (
    external_inference_record as record_table,
)


def _closed[**P, R](func: Callable[P, R]) -> Callable[P, R]:
    @functools.wraps(func)
    def wrapper(*args: P.args, **kwargs: P.kwargs) -> R:
        try:
            return func(*args, **kwargs)
        except SQLAlchemyError as exc:
            raise FailClosed(
                f"external inference ledger unavailable: {type(exc).__name__}"
            ) from exc
        except (ValueError, TypeError) as exc:
            raise FailClosed("external inference ledger row could not be read") from exc

    return wrapper


def _labels(items: tuple[Any, ...]) -> str:
    return canonical_json([item.model_dump(mode="json") for item in items])


def _authorization(row: Any) -> ExternalAuthorization:
    data = dict(row._mapping)
    data["kept"] = json.loads(data["kept"])
    data["dropped"] = json.loads(data["dropped"])
    return ExternalAuthorization(**data)


def _record(row: Any) -> ExternalTransmissionRecord:
    data = dict(row._mapping)
    for name in ("kept", "approver_roles", "policy_decision", "response_metadata"):
        data[name] = json.loads(data[name])
    return ExternalTransmissionRecord(**data)


class ExternalLedger:
    def __init__(self, engine: Engine) -> None:
        self._engine = engine

    @_closed
    def insert_proposal(self, item: ExternalProposalRecord) -> None:
        values = item.model_dump()
        values["items"] = _labels(item.items)
        with self._engine.begin() as conn:
            conn.execute(proposal_table.insert().values(**values))

    @_closed
    def find_proposal(self, request_id: str) -> ExternalProposalRecord | None:
        with read_connection(self._engine) as conn:
            row = conn.execute(
                select(proposal_table).where(proposal_table.c.request_id == request_id)
            ).first()
        if row is None:
            return None
        data = dict(row._mapping)
        data["items"] = json.loads(data["items"])
        return ExternalProposalRecord(**data)

    @_closed
    def withdraw_proposal(self, request_id: str) -> bool:
        """Remove a proposal whose recording could not be audited. False: no row went."""
        with self._engine.begin() as conn:
            result = conn.execute(
                delete(proposal_table).where(proposal_table.c.request_id == request_id)
            )
            return result.rowcount == 1

    @_closed
    def insert_authorization(self, item: ExternalAuthorization) -> None:
        values = item.model_dump()
        values["kept"] = _labels(item.kept)
        values["dropped"] = _labels(item.dropped)
        values["required_role"] = item.required_role.value
        with self._engine.begin() as conn:
            conn.execute(authorization_table.insert().values(**values))

    @_closed
    def find_authorization(self, approval_id: str) -> ExternalAuthorization | None:
        with read_connection(self._engine) as conn:
            row = conn.execute(
                select(authorization_table).where(authorization_table.c.approval_id == approval_id)
            ).first()
        return None if row is None else _authorization(row)

    @_closed
    def withdraw_authorization(self, approval_id: str) -> bool:
        """Remove an authorization whose last step could not be audited. Transmit then
        refuses for that approval."""
        with self._engine.begin() as conn:
            result = conn.execute(
                delete(authorization_table).where(authorization_table.c.approval_id == approval_id)
            )
            return result.rowcount == 1

    @_closed
    def insert_record(self, item: ExternalTransmissionRecord) -> None:
        values = item.model_dump()
        values["kept"] = _labels(item.kept)
        values["approver_roles"] = canonical_json([role.value for role in item.approver_roles])
        values["policy_decision"] = canonical_json(thaw(item.policy_decision))
        values["response_metadata"] = canonical_json(dict(item.response_metadata))
        values["outcome"] = item.outcome.value
        with self._engine.begin() as conn:
            conn.execute(record_table.insert().values(**values))

    @_closed
    def complete_record(
        self,
        record_id: str,
        *,
        outcome: TransmitOutcome,
        completed_at: datetime,
        error_type: str | None,
        response_bytes: int | None,
        response_digest: str | None,
        response_metadata: dict[str, str],
        result_ref: str | None,
    ) -> bool:
        """attempted -> final outcome, once."""
        with self._engine.begin() as conn:
            result = conn.execute(
                update(record_table)
                .where(
                    record_table.c.id == record_id,
                    record_table.c.outcome == TransmitOutcome.ATTEMPTED.value,
                )
                .values(
                    outcome=outcome.value,
                    completed_at=completed_at,
                    error_type=error_type,
                    response_bytes=response_bytes,
                    response_digest=response_digest,
                    response_metadata=canonical_json(response_metadata),
                    result_ref=result_ref,
                )
            )
            return result.rowcount == 1

    @_closed
    def mark_unrecorded(self, record_id: str, note: str) -> bool:
        """Flag a row whose payload was handed to the transport but whose closing record
        (this row or the audit event) is incomplete. Works from any outcome; `note` says
        which part is missing and what the outcome was."""
        with self._engine.begin() as conn:
            result = conn.execute(
                update(record_table)
                .where(record_table.c.id == record_id)
                .values(outcome=TransmitOutcome.SENT_UNRECORDED.value, error_type=note[:100])
            )
            return result.rowcount == 1

    @_closed
    def get_record(self, record_id: str) -> ExternalTransmissionRecord | None:
        with read_connection(self._engine) as conn:
            row = conn.execute(select(record_table).where(record_table.c.id == record_id)).first()
        return None if row is None else _record(row)

    @_closed
    def records_for_request(self, request_id: str) -> tuple[ExternalTransmissionRecord, ...]:
        with read_connection(self._engine) as conn:
            rows = conn.execute(
                select(record_table)
                .where(record_table.c.request_id == request_id)
                .order_by(record_table.c.attempted_at, record_table.c.id)
            ).all()
        return tuple(_record(row) for row in rows)
