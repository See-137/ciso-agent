"""Decide what the database head and the anchor say together (gap G4, NFR-006).

One pure function, `reconcile`, is used by `open()`, by every append and by `verify()`, so
all three agree on what is intact, what is a recoverable crash and what is tampering.

Crash signatures (the only states repaired automatically):

- `commit_not_applied`: the anchor has final = n and pending = m > n, and the database
  head is exactly final (seq n with final's hash). The transaction that wrote `pending`
  never committed. The pending entry is dropped.
- `promotion_missing`: the anchor has final = n and pending = m, and the database head is
  exactly pending (seq m with pending's hash) while the record at n still has final's
  hash. The commit happened, the promotion did not. Pending is promoted.

Anything else is not a crash signature. It is reported (`truncated`,
`anchor_hash_mismatch`, `anchor_behind_head` and so on, all `failed`) and never repaired.

Limit, stated plainly: removing exactly the records of the last transaction together with
rolling the anchor file back to its earlier bytes (or, after a failed promotion, removing
the records the pending entry names) looks the same as "the commit never happened". No
scheme that keeps the anchor on the same host as the database can tell these apart; only
an anchor copy held somewhere the attacker cannot write can (ADR-0013, OD-01).
"""

from __future__ import annotations

from collections.abc import Callable
from enum import StrEnum

from ciso.audit.anchor import AnchorEntry, AnchorReading, AnchorState
from ciso.common.schemas import Model


class VerifyStatus(StrEnum):
    OK = "ok"
    FAILED = "failed"  # evidence of tampering, corruption or a swapped log
    UNVERIFIABLE = "unverifiable"  # cannot be proven intact; never treat as ok


class RecoveryCase(StrEnum):
    COMMIT_NOT_APPLIED = "commit_not_applied"
    PROMOTION_MISSING = "promotion_missing"


class Decision(Model):
    """`final` is the anchor head to build on when status is OK (after any recovery)."""

    status: VerifyStatus
    reason: str | None = None
    first_broken_seq: int | None = None
    final: AnchorEntry | None = None
    recovery: RecoveryCase | None = None
    previous: AnchorReading | None = None


def _fail(reason: str, seq: int | None = None) -> Decision:
    return Decision(status=VerifyStatus.FAILED, reason=reason, first_broken_seq=seq)


def _unverifiable(reason: str) -> Decision:
    return Decision(status=VerifyStatus.UNVERIFIABLE, reason=reason)


def reconcile(
    *,
    db_log_id: str | None,
    head: AnchorEntry,
    reading: AnchorReading | None,
    expected_log_id: str | None,
    hash_at: Callable[[int], str | None],
) -> Decision:
    """Compare the database (`db_log_id`, `head`, `hash_at`) with the anchor `reading`.

    `reading` is None when the anchor key could not be resolved.
    """
    identity = _check_identity(db_log_id, head, reading, expected_log_id)
    if identity is not None:
        return identity
    if reading is None:
        return _unverifiable("anchor_key_unavailable")
    if reading.state is AnchorState.MISSING:
        return _unverifiable("anchor_missing")
    if reading.state is AnchorState.UNREADABLE:
        return _unverifiable("anchor_unreadable")
    if reading.state is AnchorState.KEY_MISMATCH:
        return _unverifiable("anchor_key_mismatch")
    if reading.state is AnchorState.INVALID_MAC or reading.final is None:
        return _fail("anchor_hmac_invalid")
    if reading.log_id != db_log_id:
        return _fail("log_id_mismatch")
    if reading.pending is not None:
        crash = _crash_signature(head, reading.final, reading.pending, hash_at)
        if crash is not None:
            return crash.model_copy(update={"previous": reading})
    return _against_final(head, reading.final, reading.pending, hash_at)


def _check_identity(
    db_log_id: str | None,
    head: AnchorEntry,
    reading: AnchorReading | None,
    expected_log_id: str | None,
) -> Decision | None:
    if db_log_id is None:
        if head.seq > 0:
            return _fail("meta_missing")
        anchor_exists = reading is not None and reading.state is not AnchorState.MISSING
        if expected_log_id is not None or anchor_exists:
            return _fail("log_missing")
        return _unverifiable("uninitialised")
    if expected_log_id is not None and db_log_id != expected_log_id:
        return _fail("log_id_unexpected")
    return None


def _crash_signature(
    head: AnchorEntry,
    final: AnchorEntry,
    pending: AnchorEntry,
    hash_at: Callable[[int], str | None],
) -> Decision | None:
    if head == final:
        return Decision(
            status=VerifyStatus.OK, final=final, recovery=RecoveryCase.COMMIT_NOT_APPLIED
        )
    if head == pending and hash_at(final.seq) == final.head_hash:
        return Decision(
            status=VerifyStatus.OK, final=pending, recovery=RecoveryCase.PROMOTION_MISSING
        )
    return None


def _against_final(
    head: AnchorEntry,
    final: AnchorEntry,
    pending: AnchorEntry | None,
    hash_at: Callable[[int], str | None],
) -> Decision:
    if head.seq < final.seq:
        return _fail("truncated", head.seq + 1)
    if hash_at(final.seq) != final.head_hash:
        return _fail("anchor_hash_mismatch", final.seq)
    if (
        pending is not None
        and head.seq >= pending.seq
        and hash_at(pending.seq) != pending.head_hash
    ):
        return _fail("anchor_hash_mismatch", pending.seq)
    if head.seq > final.seq:
        # With the two-phase anchor no crash leaves the head ahead of the anchor without a
        # matching pending entry, so records beyond `final` were added without the key.
        return _fail("anchor_behind_head", final.seq + 1)
    return Decision(status=VerifyStatus.OK, final=final)
