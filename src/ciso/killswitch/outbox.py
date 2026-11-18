"""Delivery of owed engage records to the audit sink. Review H2, M3.

Rules:
- The action is always `killswitch.engage`; it is not stored and never read from a row.
- The actor type is never read from a row. It follows from how the row can be trusted:
  a MAC-verified `api` row names the human who engaged (only a resolved human
  security_admin can engage through the service); a verified `reconcile` row is the
  fixed reconcile service identity; a `breakglass` row is the fixed `breakglass` identity
  with `ActorType.ANONYMOUS` and the typed operator name as `details.unverified_operator`;
  a row with no MAC is delivered as the fixed `unverified` anonymous identity with the
  stored actor as `details.unverified_actor`.
- A row whose MAC does not verify, or whose content cannot be parsed, is quarantined:
  kept, flagged, never delivered, listed by `quarantined()`.
- A row with a MAC while the key is unavailable stays owed.
- Each row is claimed with a conditional update before delivery, so two delivery loops
  cannot both deliver it. `details.outbox_entry` makes any duplicate recognisable (a
  claim older than `claim_timeout` may be taken over; None means never).
- One bad row never stops the others, and nothing here raises.
"""

from __future__ import annotations

import json
import logging
from collections.abc import Sequence
from datetime import timedelta
from typing import Any

from sqlalchemy import ColumnElement, Engine, and_, func, or_, select, update

from ciso.common.clock import Clock
from ciso.common.db import read_connection
from ciso.common.enums import ActorType, AuditOutcome, KillCapability
from ciso.common.ids import new_id
from ciso.common.protocols import AuditEvent, AuditSink
from ciso.killswitch.integrity import outbox_row_verifies
from ciso.killswitch.models import (
    BREAKGLASS_ACTOR,
    ENGAGE_ACTION,
    OUTBOX_VIAS,
    RECONCILE_ACTOR,
    UNVERIFIED_ACTOR,
    VIA_API,
    VIA_BREAKGLASS,
    VIA_RECONCILE,
    PendingAudit,
)
from ciso.killswitch.tables import killswitch_pending_audit as outbox

logger = logging.getLogger(__name__)


class _Quarantine(Exception):
    """Internal: the row must never be delivered."""


class Outbox:
    def __init__(
        self, *, engine: Engine, audit: AuditSink, clock: Clock, claim_timeout: timedelta | None
    ) -> None:
        self._engine = engine
        self._audit = audit
        self._clock = clock
        self._claim_timeout = claim_timeout

    # --- reading ---------------------------------------------------------------------

    def pending(self) -> tuple[PendingAudit, ...]:
        """Rows still owed (not delivered, not quarantined), oldest first."""
        return self._list(quarantined=False)

    def quarantined(self) -> tuple[PendingAudit, ...]:
        return self._list(quarantined=True)

    def owed_count(self) -> int:
        with read_connection(self._engine) as conn:
            return int(
                conn.execute(
                    select(func.count())
                    .select_from(outbox)
                    .where(outbox.c.delivered_at.is_(None), outbox.c.quarantined.is_(False))
                ).scalar_one()
            )

    def _list(self, *, quarantined: bool) -> tuple[PendingAudit, ...]:
        with read_connection(self._engine) as conn:
            rows = conn.execute(
                select(outbox)
                .where(outbox.c.delivered_at.is_(None), outbox.c.quarantined.is_(quarantined))
                .order_by(outbox.c.seq)
            ).all()
        return tuple(_as_pending(row) for row in rows)

    # --- delivering ------------------------------------------------------------------

    def deliver_all(self, key: bytes | None) -> int:
        """Try every owed row. Returns how many reached the sink. Never raises."""
        try:
            with read_connection(self._engine) as conn:
                seqs = list(
                    conn.execute(
                        select(outbox.c.seq)
                        .where(outbox.c.delivered_at.is_(None), outbox.c.quarantined.is_(False))
                        .order_by(outbox.c.seq)
                    ).scalars()
                )
        except Exception:
            logger.exception("kill switch: cannot list the audit outbox")
            return 0
        return sum(1 for seq in seqs if self.deliver(seq, key))

    def deliver(self, seq: int, key: bytes | None) -> bool:
        """Claim, check and deliver one row. True only if the sink accepted it now."""
        token = new_id("claim")
        try:
            if not self._claim(seq, token):
                return False
            row = self._fetch(seq)
            try:
                event = _event_for(row, key)
            except _Quarantine as why:
                self._release_claim(seq, token, str(why), quarantine=True)
                logger.error("kill switch: outbox row %s quarantined: %s", seq, why)
                return False
            if event is None:
                self._release_claim(seq, token, "MAC key unavailable; row kept owed")
                return False
            try:
                self._audit.append(event)
            except Exception as exc:
                self._release_claim(seq, token, f"audit append failed: {type(exc).__name__}")
                logger.error(
                    "kill switch: audit write failed for outbox row %s; the engage stands "
                    "and the audit is owed (%s)", seq, type(exc).__name__,
                )  # fmt: skip
                return False
        except Exception as exc:
            logger.exception("kill switch: delivering outbox row %s failed", seq)
            self._unclaim_after_error(seq, token, exc)
            return False
        self._mark_delivered(seq, token)
        return True

    def _claim(self, seq: int, token: str) -> bool:
        now = self._clock.now()
        free: ColumnElement[bool] = outbox.c.claimed_by.is_(None)
        if self._claim_timeout is not None:
            free = or_(free, outbox.c.claimed_at < now - self._claim_timeout)
        with self._engine.begin() as conn:
            done = conn.execute(
                update(outbox)
                .where(
                    and_(
                        outbox.c.seq == seq,
                        outbox.c.delivered_at.is_(None),
                        outbox.c.quarantined.is_(False),
                        free,
                    )
                )
                .values(claimed_by=token, claimed_at=now)
            )
        return done.rowcount == 1

    def _fetch(self, seq: int) -> Any:
        with read_connection(self._engine) as conn:
            return conn.execute(select(outbox).where(outbox.c.seq == seq)).one()

    def _release_claim(self, seq: int, token: str, error: str, *, quarantine: bool = False) -> None:
        with self._engine.begin() as conn:
            conn.execute(
                update(outbox)
                .where(outbox.c.seq == seq, outbox.c.claimed_by == token)
                .values(claimed_by=None, claimed_at=None, last_error=error, quarantined=quarantine)
            )

    def _unclaim_after_error(self, seq: int, token: str, exc: Exception) -> None:
        """Give the row back after an unexpected error, so a later pass can try again."""
        try:
            self._release_claim(seq, token, f"delivery error: {type(exc).__name__}")
        except Exception:
            logger.exception("kill switch: could not release the claim on outbox row %s", seq)

    def _mark_delivered(self, seq: int, token: str) -> None:
        """After a successful append. A failure leaves the row claimed (no re-delivery
        until the claim times out) and is logged, never raised."""
        try:
            with self._engine.begin() as conn:
                conn.execute(
                    update(outbox)
                    .where(outbox.c.seq == seq, outbox.c.claimed_by == token)
                    .values(delivered_at=self._clock.now(), last_error="")
                )
        except Exception:
            logger.exception("kill switch: outbox row %s delivered but not marked", seq)


def _parse_caps(raw: str) -> tuple[KillCapability, ...]:
    try:
        values = json.loads(raw)
        if not isinstance(values, list) or not values:
            raise ValueError("not a non-empty list")
        return tuple(KillCapability(value) for value in values)
    except (ValueError, TypeError) as exc:
        raise _Quarantine(f"unreadable capabilities ({exc})") from exc


def _event_for(row: Any, key: bytes | None) -> AuditEvent | None:
    """The audit event for a row, None if it must wait for the key, or _Quarantine."""
    caps = _parse_caps(row.capabilities)
    if row.via not in OUTBOX_VIAS:
        raise _Quarantine(f"unknown origin {row.via!r}")
    verified = False
    if row.mac:
        if key is None:
            return None
        if not outbox_row_verifies(key, row):
            raise _Quarantine("MAC does not verify")
        verified = True
    details: dict[str, Any] = {
        "capabilities": [cap.value for cap in caps],
        "reason": row.reason,
        "origin": row.via,
        "mac_verified": verified,
        "outbox_entry": row.entry_id,
        "outbox_seq": row.seq,
        "recorded_at": row.recorded_at.isoformat(),
    }
    actor_id, actor_type = _actor(row, verified, details)
    return AuditEvent(
        actor_id=actor_id,
        actor_type=actor_type,
        action=ENGAGE_ACTION,
        target=_target(caps),
        outcome=AuditOutcome.SUCCESS,
        details=details,
    )


def _actor(row: Any, verified: bool, details: dict[str, Any]) -> tuple[str, ActorType]:
    if row.via == VIA_BREAKGLASS:
        details["unverified_operator"] = row.operator
        return BREAKGLASS_ACTOR, ActorType.ANONYMOUS
    if verified and row.via == VIA_API:
        return str(row.actor_id), ActorType.HUMAN
    if verified and row.via == VIA_RECONCILE:
        return RECONCILE_ACTOR, ActorType.SERVICE
    details["unverified_actor"] = row.actor_id
    return UNVERIFIED_ACTOR, ActorType.ANONYMOUS


def _target(caps: Sequence[KillCapability]) -> str:
    return "killswitch:" + ",".join(cap.value for cap in caps)


def _as_pending(row: Any) -> PendingAudit:
    try:
        raw = json.loads(row.capabilities)
        caps = tuple(str(v) for v in raw) if isinstance(raw, list) else (str(row.capabilities),)
    except ValueError:
        caps = (str(row.capabilities),)
    return PendingAudit(
        seq=row.seq,
        entry_id=row.entry_id,
        actor_id=row.actor_id,
        capabilities=caps,
        reason=row.reason,
        via=row.via,
        operator=row.operator or "",
        recorded_at=row.recorded_at,
        claimed=row.claimed_by is not None,
        quarantined=bool(row.quarantined),
        last_error=row.last_error or "",
    )
