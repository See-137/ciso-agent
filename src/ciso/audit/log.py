"""The tamper-evident audit log (FR-028, NFR-006, ADR-0013, gaps G4 and G5).

Ordering rule every caller must follow (G5, blueprint §9.5 and §19.3)
---------------------------------------------------------------------
The audit database and the operational database are separate files, so no transaction
spans both. Therefore:

1. Audit the attempt BEFORE the side effect: `append(... outcome=ATTEMPT ...)` first, then
   do the work, then append the result.
2. An audit failure stops the operation. `append` either returns a receipt for a committed
   record or raises (`FailClosed`, `IntegrityFailure`, `ValidationFailed`). A caller that
   gets an exception must not perform the side effect and must not swallow it.
3. If the result write fails after the side effect already happened, the caller leaves
   its own record in an explicit "outcome unknown" state for later verification; it
   never retries blindly.

Lifecycle
---------
`init_audit_schema(engine)` creates tables. `initialise()` is then called exactly once on
a new log: it creates the random `log_id` (kept in the database and in the anchor). The
composition root stores that id and passes it back as `expected_log_id`, so a log that was
wiped and re-created is `failed`, not "fresh". `open()` checks the log and repairs a
crash; `append`, `verify` and `query` work on an initialised log only.

What the log guarantees
-----------------------
- Append-only: no update or delete method; triggers abort UPDATE and DELETE on records and
  on the identity row.
- `seq` is gapless from 1: `engine.begin()` takes SQLite's write lock (`BEGIN IMMEDIATE`)
  and an in-process lock orders this object's own threads.
- `details` must be JSON-native and is redacted before it is hashed or stored.
- Two-phase anchor (`anchor.py`, `reconcile.py`): `pending` before COMMIT, promotion
  after. A crash between the two is repaired automatically on the next `open`, append or
  verify and recorded as `audit.anchor_recovered`. Every other mismatch is refused.
- Optional head witness (`witness.py`): published after each commit at the configured
  cadence; `verify()` reports `rolled_back` if the chain lost a witnessed head.
- `verify()` walks the chain in a read snapshot without blocking appends, then reconciles
  head, anchor and witness under a brief write lock. It returns `ok` only when all agree.
"""

from __future__ import annotations

import json
import logging
import threading
from datetime import datetime
from functools import partial
from typing import Any

from sqlalchemy import Engine, func, select
from sqlalchemy.exc import IntegrityError, SQLAlchemyError

from ciso.audit.anchor import AnchorEntry, AnchorKey, AnchorState, HeadAnchor
from ciso.audit.chain import (
    GENESIS,
    AuditRecord,
    PreparedEvent,
    build_records,
    entry_of,
    hash_at,
    read_head,
    read_log_id,
    require_json_native,
    require_utf8,
    row_values,
    strict_canonical,
    walk_chain,
)
from ciso.audit.query import query_records
from ciso.audit.reconcile import Decision, VerifyStatus, reconcile
from ciso.audit.tables import audit_meta, audit_record, refuse_inside_db_dir
from ciso.audit.verify import VerifyResult, check_witness, make_result, reconcile_tail
from ciso.audit.witness import FileHeadWitness, HeadWitness
from ciso.common.clock import Clock, ensure_utc
from ciso.common.db import read_connection
from ciso.common.enums import ActorType, AuditOutcome
from ciso.common.errors import CisoError, Conflict, FailClosed, IntegrityFailure, ValidationFailed
from ciso.common.ids import new_id
from ciso.common.protocols import AuditEvent, AuditReceipt, Redactor

logger = logging.getLogger(__name__)

AUDIT_ACTOR_ID = "audit_log"
RECOVERY_ACTION = "audit.anchor_recovered"
#: Fresh-snapshot attempts when another process's crash state appears mid-verify.
VERIFY_ATTEMPTS = 3
_FAIL_CLOSED_REASONS = frozenset(
    {
        "anchor_unreadable",
        "anchor_key_unavailable",
        "anchor_key_mismatch",
        "uninitialised",
        "witness_unreadable",
    }
)


class AuditLog:
    """Append-only, hash-chained, anchored audit log on its own engine.

    `engine`: the audit database's own engine, never the operational one.
    `anchor`: must not live inside the audit database's directory.
    `expected_log_id`: the id `initialise()` returned, remembered by the caller; None
    only before the first initialisation.
    `witness`, `witness_every`: optional rollback witness, published after every
    `witness_every`-th record. With a witness, `witness_every` is required (>= 1).
    """

    def __init__(
        self,
        engine: Engine,
        clock: Clock,
        redactor: Redactor,
        anchor: HeadAnchor,
        *,
        expected_log_id: str | None = None,
        witness: HeadWitness | None = None,
        witness_every: int | None = None,
    ) -> None:
        if witness is not None and (
            isinstance(witness_every, bool)
            or not isinstance(witness_every, int)
            or witness_every < 1
        ):
            raise ValidationFailed("a witness needs witness_every >= 1")
        refuse_inside_db_dir(engine, anchor.path, "anchor")
        if isinstance(witness, FileHeadWitness):
            refuse_inside_db_dir(engine, witness.path, "witness")
        self._engine = engine
        self._clock = clock
        self._redactor = redactor
        self._anchor = anchor
        self._expected = expected_log_id
        self._witness = witness
        self._witness_every = witness_every or 0
        self._lock = threading.Lock()

    # -- identity -------------------------------------------------------------------

    @property
    def log_id(self) -> str | None:
        """The id stored in the database, or None before `initialise()`."""
        try:
            with read_connection(self._engine) as conn:
                return read_log_id(conn)
        except SQLAlchemyError as exc:
            raise FailClosed("audit log identity could not be read") from exc

    def initialise(self) -> str:
        """Create the log identity and the genesis anchor, once. Returns the new log id.

        Refuses (Conflict) if the database has records or an identity, or the anchor file
        exists, or this object was given an `expected_log_id` (that log should exist).

        One exception completes a half-done call: a crash after the genesis anchor was
        written and before the identity row committed leaves an anchor that authenticates
        under this key at genesis (final seq 0, no pending entry) over an empty database.
        That state is completed with the anchor's log id, which is returned. Every other
        existing anchor is refused. (A wiped log whose anchor is still at genesis looks the
        same; nothing was recorded in it, and the caller's `expected_log_id`, which refuses
        above, is what catches a wipe of a log it knew.)
        """
        if self._expected is not None:
            raise Conflict("an existing audit log is expected; refusing to create a new one")
        key = self._anchor.load_key()
        now = ensure_utc(self._clock.now())
        with self._lock:
            resumed = self._half_initialised(key)
            if resumed is None and self._anchor.exists():
                raise Conflict("an audit anchor already exists; refusing to initialise")
            try:
                with self._engine.begin() as conn:
                    count = conn.execute(select(func.count()).select_from(audit_record)).scalar()
                    if read_log_id(conn) is not None or count:
                        raise Conflict("the audit database is not empty")
                    log_id = resumed or new_id("alog")
                    conn.execute(audit_meta.insert().values(id=1, log_id=log_id, created_at=now))
                    if resumed is None:
                        self._anchor.write(key, log_id, GENESIS)
            except SQLAlchemyError as exc:
                raise FailClosed("audit log could not be initialised") from exc
        if resumed is not None:
            logger.warning("audit log initialisation completed after an interrupted start")
        else:
            logger.info("audit log initialised")
        return log_id

    def _half_initialised(self, key: AnchorKey) -> str | None:
        """The anchor's log id when the anchor is exactly what an interrupted
        `initialise()` leaves (authenticated, at genesis, no pending); else None."""
        if not self._anchor.exists():
            return None
        reading = self._anchor.read(key)
        if (
            reading.state is AnchorState.PRESENT
            and reading.final == GENESIS
            and reading.pending is None
            and reading.log_id is not None
        ):
            return reading.log_id
        return None

    def open(self) -> str:
        """Check identity, anchor and witness; repair a crash. Returns the log id or raises."""
        key = self._anchor.load_key()
        log_id = self._commit(key, [])
        with self._lock:
            try:
                with read_connection(self._engine) as conn:
                    witness = check_witness(self._witness, log_id, read_head(conn), conn).refusal
            except SQLAlchemyError as exc:
                raise FailClosed("audit log could not be read") from exc
        if witness is not None:
            raise _refusal(witness)
        return log_id

    # -- append ---------------------------------------------------------------------

    def append(self, event: AuditEvent) -> AuditReceipt:
        """Commit one record, or raise. Never returns without a committed record.

        Refused before anything is written when the log is uninitialised, the anchor does
        not match the head, or a configured witness is unreadable or shows a rollback.
        If the witness publish fails after COMMIT, this raises FailClosed although the
        record is committed: the caller must still not perform the side effect.
        """
        prepared = self._prepare(event)
        key = self._anchor.load_key()
        records: list[AuditRecord] = []
        self._commit(key, [prepared], out=records)
        last = records[-1]
        return AuditReceipt(
            record_id=last.id, seq=last.seq, occurred_at=last.occurred_at, hash=last.hash
        )

    def _prepare(self, event: AuditEvent) -> PreparedEvent:
        if not isinstance(event, AuditEvent):
            raise ValidationFailed("append() takes an AuditEvent")
        for name in ("actor_id", "action", "target", "correlation_id"):
            require_utf8(getattr(event, name), name)
        try:
            require_json_native(event.details)
            strict_canonical(event.details)
        except ValidationFailed:
            raise
        except (RecursionError, TypeError, ValueError) as exc:
            raise ValidationFailed("audit details cannot be serialised as JSON") from exc
        try:
            redacted = self._redactor.redact_value(dict(event.details))
        except Exception as exc:
            raise FailClosed("audit details could not be redacted") from exc
        if not isinstance(redacted, dict):
            raise FailClosed("redactor returned something other than a mapping")
        try:
            require_json_native(redacted)
            text = strict_canonical(redacted)
        except (RecursionError, TypeError, ValueError) as exc:
            raise FailClosed("redactor returned details that are not JSON") from exc
        details = _parse_own(text)
        return PreparedEvent(event, details, ensure_utc(self._clock.now()))

    def _commit(
        self, key: AnchorKey, batch: list[PreparedEvent], out: list[AuditRecord] | None = None
    ) -> str:
        """One transaction: reconcile, recover if needed, insert, pending, commit, promote,
        publish. Returns the log id; committed records are appended to `out`."""
        with self._lock:
            log_id, final, records = self._commit_txn(key, batch)
            if records:
                self._promote(key, log_id, final, entry_of(records[-1]))
                if out is not None:
                    out.extend(records)
                self._publish(log_id, records)
        return log_id

    def _commit_txn(
        self, key: AnchorKey, batch: list[PreparedEvent]
    ) -> tuple[str, AnchorEntry, list[AuditRecord]]:
        try:
            with self._engine.begin() as conn:
                log_id, head = read_log_id(conn), read_head(conn)
                decision = reconcile(
                    db_log_id=log_id,
                    head=head,
                    reading=self._anchor.read(key),
                    expected_log_id=self._expected,
                    hash_at=partial(hash_at, conn),
                )
                if decision.status is not VerifyStatus.OK or log_id is None:
                    raise _refusal(decision)
                final = decision.final or head
                full = list(batch)
                if decision.recovery is not None:
                    logger.warning("audit anchor recovered: %s", decision.recovery.value)
                    full.insert(0, self._recovery_event(decision))
                if not full:
                    return log_id, final, []
                witness = check_witness(self._witness, log_id, head, conn).refusal
                if witness is not None:  # never grow a chain that lost a witnessed head
                    raise _refusal(witness)
                records = build_records(head, full)
                conn.execute(audit_record.insert(), [row_values(r) for r in records])
                self._anchor.write(key, log_id, final, pending=entry_of(records[-1]))
                return log_id, final, records
        except IntegrityError as exc:
            raise IntegrityFailure("audit chain refused the record") from exc
        except SQLAlchemyError as exc:
            raise FailClosed("audit record could not be written") from exc

    def _promote(self, key: AnchorKey, log_id: str, before: AnchorEntry, new: AnchorEntry) -> None:
        """Move pending to final under the write lock, unless another writer already has.

        A failure here is not raised: the record is committed and covered by the signed
        pending entry, and the next writer promotes it (case `promotion_missing`).
        """
        try:
            with self._engine.begin():
                reading = self._anchor.read(key)
                if (
                    reading.state is AnchorState.PRESENT
                    and reading.log_id == log_id
                    and reading.final == before
                    and reading.pending == new
                ):
                    self._anchor.write(key, log_id, new)
        except (FailClosed, SQLAlchemyError):
            logger.warning("audit anchor promotion deferred to the next writer", exc_info=True)

    def _publish(self, log_id: str, records: list[AuditRecord]) -> None:
        if self._witness is None:
            return
        if not any(r.seq % self._witness_every == 0 for r in records):
            return
        last = records[-1]
        try:
            self._witness.publish(log_id, last.seq, last.hash, last.occurred_at)
        except Exception as exc:
            raise FailClosed("audit head could not be published to the witness") from exc

    def _recovery_event(self, decision: Decision) -> PreparedEvent:
        previous = decision.previous
        details: dict[str, Any] = {
            "case": decision.recovery.value if decision.recovery else "",
            "final_seq": previous.final.seq if previous and previous.final else None,
            "pending_seq": previous.pending.seq if previous and previous.pending else None,
        }
        event = AuditEvent(
            actor_id=AUDIT_ACTOR_ID,
            actor_type=ActorType.SERVICE,
            action=RECOVERY_ACTION,
            outcome=AuditOutcome.SUCCESS,
            details=details,
        )
        return PreparedEvent(event, details, ensure_utc(self._clock.now()))

    # -- verify (checks in ciso.audit.verify) ----------------------------------------

    def verify(self) -> VerifyResult:
        """Walk the chain, then reconcile it with the anchor and the witness.

        Raises FailClosed only if the database itself cannot be read.
        """
        for _ in range(VERIFY_ATTEMPTS):
            result = self._verify_once()
            if result is not None:
                return result
        return make_result(VerifyStatus.UNVERIFIABLE, "anchor_recovery_pending")

    def _verify_once(self) -> VerifyResult | None:
        try:
            key: AnchorKey | None = self._anchor.load_key()
        except FailClosed:
            logger.warning("audit verify: anchor key unavailable")
            key = None
        if key is not None:
            self._settle(key)
        try:
            with read_connection(self._engine) as conn:  # snapshot; appends continue
                snap = walk_chain(conn, GENESIS)
            if snap.reason is not None:
                return make_result(VerifyStatus.FAILED, snap.reason, snap.broken_seq, snap)
            with self._lock, self._engine.begin() as conn:  # brief: tail and anchor only
                reading = self._anchor.read(key) if key is not None else None
                return reconcile_tail(conn, snap, reading, self._expected, self._witness)
        except SQLAlchemyError as exc:
            raise FailClosed("audit database could not be read for verification") from exc

    def _settle(self, key: AnchorKey) -> None:
        """Repair a crash before walking. Refusals are reported by the walk, not here."""
        try:
            self._commit(key, [])
        except CisoError as exc:
            logger.info("audit verify: log not writable (%s)", type(exc).__name__)

    # -- query ----------------------------------------------------------------------

    def query(
        self,
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
        See `ciso.audit.query.query_records` for the errors it raises."""
        return query_records(
            self._engine,
            limit=limit,
            actor_id=actor_id,
            action_prefix=action_prefix,
            target=target,
            outcome=outcome,
            correlation_id=correlation_id,
            since=since,
            until=until,
            after_seq=after_seq,
        )


def _refusal(decision: Decision) -> CisoError:
    message = f"audit log refuses the operation: {decision.reason}"
    if decision.reason in _FAIL_CLOSED_REASONS:
        return FailClosed(message)
    return IntegrityFailure(message)


def _parse_own(text: str) -> dict[str, Any]:
    parsed = json.loads(text)
    return dict(parsed)
