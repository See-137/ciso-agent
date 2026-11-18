"""Reads and short write transactions on `execution_run` (plan gap G5; review findings
H2, M3, M7, L3, L7).

Nothing here calls the audit sink, the identity resolver, a tool or the kill switch, so
none of them can run while the database write lock is held. The row key is resolved
before a write transaction opens, never inside it.

Every row read is authenticated (`ciso.execution.integrity`): a row that cannot be
parsed or whose MAC does not verify raises `ExecutionStoreError`, for every reader. See
that module for what the MAC cannot show (a deleted row).

Every state change is a compare-and-swap inside one `BEGIN IMMEDIATE` transaction: the
row is read and authenticated, compared with the record the caller last saw (same state,
same run token) and with the caller's extra condition, then rewritten with a new MAC.
It returns the new record, or `None` when the row is no longer what the caller saw.

Any failure, of any type, becomes `ExecutionStoreError` (a `FailClosed`) that names the
kind of failure only: the original exception, which can carry the statement and its
parameters, is not chained.
"""

from __future__ import annotations

import functools
import json
from collections.abc import Callable, Iterable
from datetime import datetime
from enum import StrEnum
from typing import Any, NamedTuple

from sqlalchemy import Engine, select, update

from ciso.common.db import read_connection
from ciso.common.schemas import canonical_json
from ciso.execution.integrity import RowSeal
from ciso.execution.records import ExecutionRecord, ExecutionState, ExecutionStoreError
from ciso.execution.tables import execution_run as _t

_JSON_COLUMNS = {"references": "result_references", "observed": "observed"}


class ClaimOutcome(StrEnum):
    CLAIMED = "claimed"
    DUPLICATE = "duplicate"
    RATE_LIMITED = "rate_limited"


class Claimed(NamedTuple):
    outcome: ClaimOutcome
    #: The row as stored, when claimed. Its id is the earlier row's when an `aborted`
    #: row was taken up again.
    record: ExecutionRecord | None


def _closed[**P, R](func_: Callable[P, R]) -> Callable[P, R]:
    @functools.wraps(func_)
    def wrapper(*args: P.args, **kwargs: P.kwargs) -> R:
        try:
            return func_(*args, **kwargs)
        except ExecutionStoreError:
            raise
        except Exception as exc:
            # `from None`: a database error carries the statement and its parameters,
            # and those hold request text (review finding L7).
            raise ExecutionStoreError(
                f"execution store unavailable: {type(exc).__name__}"
            ) from None

    return wrapper


def _from_row(row: Any) -> ExecutionRecord:
    return ExecutionRecord(
        execution_id=row.execution_id,
        idempotency_key=row.idempotency_key,
        envelope_hash=row.envelope_hash,
        stored_envelope_hash=row.stored_envelope_hash,
        request_id=row.request_id,
        operation=row.operation,
        authority_level=row.authority_level,
        actor_id=row.actor_id,
        actor_type=row.actor_type,
        target_resource=row.target_resource,
        state=row.state,
        policy_outcome=row.policy_outcome,
        ruleset_hash=row.ruleset_hash,
        approval_ref=row.approval_ref,
        run_token=row.run_token,
        claimed_at=row.claimed_at,
        attempt_audit_ref=row.attempt_audit_ref,
        tool_outcome=row.tool_outcome,
        references=tuple(json.loads(row.result_references)),
        tool_detail=row.tool_detail,
        verification_matches=row.verification_matches,
        verification_detail=row.verification_detail,
        observed=tuple(json.loads(row.observed)),
        residual_risk=row.residual_risk,
        error_kind=row.error_kind,
        result_audit_ref=row.result_audit_ref,
        created_at=row.created_at,
        updated_at=row.updated_at,
    )


def _columns(record: ExecutionRecord) -> dict[str, Any]:
    """Record fields as column values. Tuples become canonical JSON lists."""
    out: dict[str, Any] = {}
    for name, value in record.model_dump(mode="python").items():
        if name in _JSON_COLUMNS:
            out[_JSON_COLUMNS[name]] = canonical_json(list(value))
        elif isinstance(value, StrEnum):
            out[name] = value.value
        else:
            out[name] = value
    out["authority_level"] = int(record.authority_level)
    return out


class ExecutionStore:
    def __init__(self, engine: Engine, seal: RowSeal) -> None:
        self._engine = engine
        self._seal = seal

    def require_key(self) -> None:
        """Raise `RowKeyUnset` / `RowKeyUnavailable` unless rows can be authenticated."""
        self._seal.key()

    def _read(self, row: Any, key: bytes) -> ExecutionRecord:
        """The authenticated record for a row. A row that is not exactly what a key
        holder wrote is never handed on as a record."""
        record = _from_row(row)
        if not self._seal.matches(key, record, row.row_mac):
            raise ExecutionStoreError("stored execution failed its integrity check")
        return record

    def _values(self, record: ExecutionRecord, key: bytes) -> dict[str, Any]:
        return {**_columns(record), "row_mac": self._seal.mac(key, record)}

    # --- reads -----------------------------------------------------------------------

    @_closed
    def find_by_key(self, actor_id: str, idempotency_key: str) -> ExecutionRecord | None:
        """The row for this actor's idempotency key. Keys are scoped per actor."""
        key = self._seal.key()
        with read_connection(self._engine) as conn:
            row = conn.execute(
                select(_t).where(_t.c.actor_id == actor_id, _t.c.idempotency_key == idempotency_key)
            ).first()
        return None if row is None else self._read(row, key)

    @_closed
    def find(self, execution_id: str) -> ExecutionRecord | None:
        key = self._seal.key()
        with read_connection(self._engine) as conn:
            row = conn.execute(select(_t).where(_t.c.execution_id == execution_id)).first()
        return None if row is None else self._read(row, key)

    @_closed
    def stored_envelope(self, execution_id: str) -> str | None:
        """The stored (redacted) request text. Compare its SHA-256 with the record's
        `stored_envelope_hash` before using it: this read alone proves nothing."""
        with read_connection(self._engine) as conn:
            row = conn.execute(
                select(_t.c.envelope).where(_t.c.execution_id == execution_id)
            ).first()
        return None if row is None else str(row.envelope)

    @_closed
    def ids_in_states(self, states: Iterable[ExecutionState]) -> tuple[str, ...]:
        """Ids of rows whose state column is one of `states`, oldest first. The rows are
        NOT authenticated here: read each with `find` and decide on that."""
        wanted = [state.value for state in states]
        with read_connection(self._engine) as conn:
            rows = conn.execute(
                select(_t.c.execution_id)
                .where(_t.c.state.in_(wanted))
                .order_by(_t.c.created_at, _t.c.execution_id)
            ).all()
        return tuple(str(row.execution_id) for row in rows)

    @_closed
    def ids_owing_result_audit(self) -> tuple[str, ...]:
        """Ids of rows past `pending` with an audited attempt and no closing audit
        record. A row with no audited attempt is owed nothing: its tool was never
        called and its refusal was the record. Not authenticated: read each with `find`."""
        with read_connection(self._engine) as conn:
            rows = conn.execute(
                select(_t.c.execution_id)
                .where(
                    _t.c.result_audit_ref.is_(None),
                    _t.c.attempt_audit_ref.is_not(None),
                    _t.c.state != ExecutionState.PENDING.value,
                )
                .order_by(_t.c.created_at, _t.c.execution_id)
            ).all()
        return tuple(str(row.execution_id) for row in rows)

    # --- writes ----------------------------------------------------------------------

    @_closed
    def claim(
        self, record: ExecutionRecord, envelope_text: str, *, limit: int, window_start: datetime
    ) -> Claimed:
        """Take the actor's idempotency key for a new run, as a `pending` row.

        Refused as `DUPLICATE` when the key is taken, unless the row there is `aborted`
        for the same envelope hash: that row is then taken up again (same id, same
        `created_at`, everything else from `record`). Refused as `RATE_LIMITED` when
        `limit` other rows for this operation were claimed after `window_start`.

        The lookup, the count and the write share one write transaction, so concurrent
        callers cannot both claim a key or together pass the rate limit. Every row that
        is looked at is authenticated first; one bad row in the window fails the claim.
        A row whose `claimed_at` was edited out of the window, or deleted, is not seen.
        """
        key = self._seal.key()
        with self._engine.begin() as conn:
            taken = conn.execute(
                select(_t).where(
                    _t.c.actor_id == record.actor_id,
                    _t.c.idempotency_key == record.idempotency_key,
                )
            ).first()
            prior = None if taken is None else self._read(taken, key)
            if prior is not None and not (
                prior.state is ExecutionState.ABORTED
                and prior.envelope_hash == record.envelope_hash
            ):
                return Claimed(ClaimOutcome.DUPLICATE, None)
            window = conn.execute(
                select(_t).where(_t.c.operation == record.operation, _t.c.claimed_at > window_start)
            ).all()
            recent = [self._read(row, key) for row in window]
            if prior is not None:
                recent = [row for row in recent if row.execution_id != prior.execution_id]
            if len(recent) >= limit:
                return Claimed(ClaimOutcome.RATE_LIMITED, None)
            if prior is None:
                conn.execute(
                    _t.insert().values(envelope=envelope_text, **self._values(record, key))
                )
                return Claimed(ClaimOutcome.CLAIMED, record)
            again = ExecutionRecord.model_validate(
                {
                    **record.model_dump(),
                    "execution_id": prior.execution_id,
                    "created_at": prior.created_at,
                }
            )
            conn.execute(
                update(_t)
                .where(_t.c.execution_id == prior.execution_id)
                .values(envelope=envelope_text, **self._values(again, key))
            )
            return Claimed(ClaimOutcome.CLAIMED, again)

    @_closed
    def change(
        self,
        seen: ExecutionRecord,
        now: datetime,
        *,
        only_if: Callable[[ExecutionRecord], bool] | None = None,
        **values: Any,
    ) -> ExecutionRecord | None:
        """Set `values` (record field names) on the row, if it is still in the state and
        held by the run token that `seen` shows, and `only_if` (given the authenticated
        current row) agrees. Returns the row as written, or `None` when nothing changed.
        """
        key = self._seal.key()
        with self._engine.begin() as conn:
            row = conn.execute(select(_t).where(_t.c.execution_id == seen.execution_id)).first()
            if row is None:
                return None
            current = self._read(row, key)
            if current.state is not seen.state or current.run_token != seen.run_token:
                return None
            if only_if is not None and not only_if(current):
                return None
            changed = ExecutionRecord.model_validate(
                {**current.model_dump(), **values, "updated_at": now}
            )
            conn.execute(
                update(_t)
                .where(_t.c.execution_id == seen.execution_id)
                .values(**self._values(changed, key))
            )
            return changed

    def mark_attempt_audited(
        self, seen: ExecutionRecord, audit_ref: str, now: datetime
    ) -> ExecutionRecord | None:
        """Store the attempt's audit record id, once. The tool may be called only after
        this returned a record."""
        return self.change(
            seen,
            now,
            only_if=lambda row: row.attempt_audit_ref is None,
            attempt_audit_ref=audit_ref,
        )

    def mark_result_audited(
        self, seen: ExecutionRecord, audit_ref: str, now: datetime
    ) -> ExecutionRecord | None:
        """Store the closing audit record id, once."""
        return self.change(
            seen,
            now,
            only_if=lambda row: row.result_audit_ref is None,
            result_audit_ref=audit_ref,
        )
