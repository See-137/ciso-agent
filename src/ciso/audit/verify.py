"""Verification of the audit log: the result type and the checks `AuditLog.verify()` runs
after its snapshot walk (NFR-006, ADR-0013, review M5 and M8, blueprint §11).

`AuditLog.verify()` walks the whole chain in a read snapshot without the write lock, then
takes the write lock briefly and calls `reconcile_tail` here: walk the records added
since the snapshot, reconcile head with anchor (`reconcile.py`), then compare with the
witness. Only the log object takes locks; these functions take an open connection.
"""

from __future__ import annotations

import logging
from functools import partial
from typing import Final, NamedTuple

from sqlalchemy import Connection

from ciso.audit.anchor import AnchorEntry, AnchorReading
from ciso.audit.chain import GENESIS, Walk, hash_at, read_log_id, walk_chain
from ciso.audit.reconcile import Decision, VerifyStatus, reconcile
from ciso.audit.witness import HeadWitness, ReadingWitness
from ciso.common.errors import IntegrityFailure
from ciso.common.schemas import Model

logger = logging.getLogger(__name__)

#: Warning: the witness ends in a torn write that was ignored (see `ciso.audit.witness`).
WITNESS_TORN_TAIL: Final = "witness_torn_tail"


class VerifyResult(Model):
    """`reason` codes. failed: seq_gap, prev_hash_mismatch, hash_mismatch, row_invalid,
    truncated, anchor_hash_mismatch, anchor_behind_head, anchor_hmac_invalid,
    log_id_mismatch, log_id_unexpected, log_missing, meta_missing, rolled_back,
    witness_invalid. unverifiable: uninitialised, anchor_missing, anchor_unreadable,
    anchor_key_unavailable, anchor_key_mismatch, witness_unreadable,
    anchor_recovery_pending. `witnessed` is False when no witness is configured: the log
    is then not protected against rollback of the database together with its anchor.
    `warnings` name conditions that do not change the status: `witness_torn_tail` (a
    crash cut the witness's last line short; the next publish steps over it)."""

    status: VerifyStatus
    checked: int
    head_seq: int
    head_hash: str
    log_id: str | None = None
    witnessed: bool = False
    first_broken_seq: int | None = None
    reason: str | None = None
    warnings: tuple[str, ...] = ()


class WitnessCheck(NamedTuple):
    """`refusal`: a decision that refuses, or None. `witnessed`: a witness is configured.
    `warnings`: named conditions that do not refuse (`WITNESS_TORN_TAIL`)."""

    refusal: Decision | None
    witnessed: bool
    warnings: tuple[str, ...] = ()


def make_result(
    status: VerifyStatus,
    reason: str | None,
    broken: int | None = None,
    walk: Walk | None = None,
    checked: int | None = None,
    log_id: str | None = None,
    witnessed: bool = False,
    warnings: tuple[str, ...] = (),
) -> VerifyResult:
    head = walk.head if walk is not None else GENESIS
    return VerifyResult(
        status=status,
        checked=checked if checked is not None else (walk.checked if walk else 0),
        head_seq=head.seq,
        head_hash=head.head_hash,
        log_id=log_id,
        witnessed=witnessed,
        first_broken_seq=broken,
        reason=reason,
        warnings=warnings,
    )


def check_witness(
    witness: HeadWitness | None, log_id: str, head: AnchorEntry, conn: Connection
) -> WitnessCheck:
    """A refusal when the chain no longer holds the latest witnessed head (`rolled_back`),
    when the witness fails its own checks (`witness_invalid`) or cannot be read
    (`witness_unreadable`). A torn tail the witness ignored is a warning only."""
    if witness is None:
        return WitnessCheck(None, False)
    try:
        if isinstance(witness, ReadingWitness):
            reading = witness.read(log_id)
            latest, torn = reading.head, reading.torn_tail
        else:
            latest, torn = witness.latest(log_id), False
    except IntegrityFailure:
        return WitnessCheck(Decision(status=VerifyStatus.FAILED, reason="witness_invalid"), True)
    except Exception:
        logger.warning("audit witness unreadable", exc_info=True)
        unreadable = Decision(status=VerifyStatus.UNVERIFIABLE, reason="witness_unreadable")
        return WitnessCheck(unreadable, True)
    warnings = (WITNESS_TORN_TAIL,) if torn else ()
    if latest is None:
        return WitnessCheck(None, True, warnings)
    if head.seq < latest.seq:
        fail = Decision(
            status=VerifyStatus.FAILED, reason="rolled_back", first_broken_seq=head.seq + 1
        )
        return WitnessCheck(fail, True, warnings)
    if hash_at(conn, latest.seq) != latest.head_hash:
        fail = Decision(
            status=VerifyStatus.FAILED, reason="rolled_back", first_broken_seq=latest.seq
        )
        return WitnessCheck(fail, True, warnings)
    return WitnessCheck(None, True, warnings)


def reconcile_tail(
    conn: Connection,
    snap: Walk,
    reading: AnchorReading | None,
    expected_log_id: str | None,
    witness: HeadWitness | None,
) -> VerifyResult | None:
    """Finish a verify under the write lock. `reading` is None when the anchor key is
    unavailable. Returns None when another process's crash state was found: the caller
    repairs it and retries from a fresh snapshot."""
    tail = walk_chain(conn, snap.head)
    checked = snap.checked + tail.checked
    if tail.reason is not None:
        return make_result(VerifyStatus.FAILED, tail.reason, tail.broken_seq, tail, checked)
    log_id = read_log_id(conn)
    decision = reconcile(
        db_log_id=log_id,
        head=tail.head,
        reading=reading,
        expected_log_id=expected_log_id,
        hash_at=partial(hash_at, conn),
    )
    if decision.recovery is not None:
        return None  # another process crashed mid-write: settle and retry
    if decision.status is not VerifyStatus.OK or log_id is None:
        return make_result(
            decision.status,
            decision.reason,
            decision.first_broken_seq,
            tail,
            checked,
            log_id=log_id,
            witnessed=witness is not None,
        )
    refusal, witnessed, warnings = check_witness(witness, log_id, tail.head, conn)
    status = refusal.status if refusal is not None else VerifyStatus.OK
    reason = refusal.reason if refusal is not None else None
    broken = refusal.first_broken_seq if refusal is not None else None
    return make_result(status, reason, broken, tail, checked, log_id, witnessed, warnings)
