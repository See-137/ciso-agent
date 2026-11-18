"""Approved channels for L2 notifications and tickets (plan gap G13; blueprint 9.1, 9.5).

A channel is a short name that an operation's channel argument may carry. It maps to a
target, and the target is the name of a LOCAL OUTBOX and nothing else: not a URL, a
host, an e-mail address or a file path (OD-13: no real ticketing or messaging system is
chosen). A channel is proposed, then approved or revoked.

Who decides: approving and revoking need a human who holds `security_admin` without
narrowing, as the identity store sees that actor NOW. The actor id is resolved through
the `PrincipalResolver` on every call; nothing the caller holds is trusted. The proposer
of a channel may not approve it (separation of duties, in the spirit of ADR-0016), and
one actor may hold at most `MAX_OPEN_PROPOSALS_PER_PROPOSER` undecided proposals.

What an approval is for: the administrator passes back the `target`, the `version` and
the digest of the `purpose` of the record they were shown. Any of them differing from
the row refuses, so a proposal that was withdrawn and re-made is never approved by
someone who reviewed the earlier one.

Audit order (plan gap G5): the attempt is audited, the row is changed in one short
transaction, the result is audited. The audit sink and the resolver are never called
while the database write lock is held. A refused name, target or text is audited as
DENIED with a reason code and a digest of the value, never the value.

Approval takes two steps, so the usable state is never committed before its record
exists: the row becomes `approving`, the SUCCESS record is written, then the row becomes
`approved` and stores that record's id. `is_approved` needs both. A crash in between
leaves an `approving` row, which is not usable; an administrator approves again or
revokes. A proposal or approval whose result cannot be audited is undone, and the error
says whether the undo really changed the row; a revocation stands, because it only
removes authority.

Not covered: rows carry no integrity code, so anyone who can write the operational
database can approve a channel without going through this class.
"""

from __future__ import annotations

import logging
import re
from collections.abc import Callable
from typing import Any

from sqlalchemy import Engine, func, select
from sqlalchemy.engine import Connection, Row

from ciso.common.clock import Clock
from ciso.common.db import read_connection
from ciso.common.enums import AuditOutcome
from ciso.common.errors import AuthorizationError, CisoError, Conflict, FailClosed, NotFound
from ciso.common.principal import Principal
from ciso.common.protocols import AuditEvent, AuditSink, PrincipalResolver
from ciso.execution.channel_access import ChannelAccess
from ciso.execution.channel_rules import (
    MAX_OPEN_PROPOSALS_PER_PROPOSER,
    MAX_TEXT,
    OPEN_STATES,
    ChannelDenied,
    ChannelInvalid,
    ChannelRecord,
    ChannelRefusal,
    ChannelStatus,
    is_device_name,
    is_outbox_name,
    purpose_digest,
)
from ciso.execution.tables import execution_channel as _t

__all__ = [
    "APPROVE_ACTION",
    "MAX_OPEN_PROPOSALS_PER_PROPOSER",
    "MAX_TEXT",
    "PROPOSE_ACTION",
    "REVOKE_ACTION",
    "ChannelDenied",
    "ChannelInvalid",
    "ChannelRecord",
    "ChannelRefusal",
    "ChannelRegistry",
    "ChannelStatus",
    "is_device_name",
    "is_outbox_name",
    "purpose_digest",
]

logger = logging.getLogger(__name__)

PROPOSE_ACTION = "execution.channel.propose"
APPROVE_ACTION = "execution.channel.approve"
REVOKE_ACTION = "execution.channel.revoke"

_DIGEST_RE = re.compile(r"[0-9a-f]{64}")
_NOT_AUDITED = "the result could not be audited"

Change = Callable[[Connection, Row[Any] | None], None]


def _record(row: Row[Any]) -> ChannelRecord:
    return ChannelRecord.model_validate(dict(row._mapping))


class ChannelRegistry:
    """Persistent channel records. `is_approved` fits `PolicyContext.is_channel_approved`."""

    def __init__(
        self, engine: Engine, clock: Clock, audit: AuditSink, principals: PrincipalResolver
    ) -> None:
        self._engine = engine
        self._clock = clock
        self._audit = audit
        self._access = ChannelAccess(audit, principals)

    # -- reads ---------------------------------------------------------------------

    def is_approved(self, channel: str) -> bool:
        """Exactly `True` only for a channel that is approved now, whose approval is on
        the audit log, and whose stored target is still an outbox name. Unknown,
        proposed, approving, revoked or malformed: `False`. A read that fails raises
        `FailClosed`, which the policy engine turns into a deny."""
        return self._approved_row(channel) is not None

    def approved_target(self, channel: str) -> str:
        """The outbox an approved channel points at. `AuthorizationError` otherwise."""
        row = self._approved_row(channel)
        if row is None:
            raise AuthorizationError("channel is not approved")
        return str(row.target)

    def _approved_row(self, channel: str) -> Row[Any] | None:
        row = self._read(channel) if is_outbox_name(channel) else None
        if row is None or row.status != ChannelStatus.APPROVED.value:
            return None
        if not row.approval_audit_ref or not is_outbox_name(row.target):
            return None
        return row

    def get(self, channel: str) -> ChannelRecord:
        row = self._read(channel) if is_outbox_name(channel) else None
        if row is None:
            raise NotFound("no such channel")
        return _record(row)

    def records(self) -> tuple[ChannelRecord, ...]:
        """Every channel in any state, by name."""
        try:
            with read_connection(self._engine) as conn:
                rows = conn.execute(select(_t).order_by(_t.c.channel)).all()
        except Exception as exc:
            raise FailClosed("channel records could not be read") from exc
        return tuple(_record(row) for row in rows)

    def _read(self, channel: str) -> Row[Any] | None:
        try:
            with read_connection(self._engine) as conn:
                return conn.execute(select(_t).where(_t.c.channel == channel)).first()
        except Exception as exc:
            raise FailClosed("channel records could not be read") from exc

    # -- changes -------------------------------------------------------------------

    def propose(self, actor_id: str, channel: str, target: str, purpose: str) -> ChannelRecord:
        """Record a channel that is not yet usable. Any known, active actor may propose,
        up to `MAX_OPEN_PROPOSALS_PER_PROPOSER` undecided proposals at once. A revoked
        name may be proposed again and then needs a fresh approval."""
        actor = self._access.authorise(actor_id, PROPOSE_ACTION, channel, admin=False)
        self._access.require_name(actor, PROPOSE_ACTION, channel)
        if not is_outbox_name(target):
            raise self._access.refused(
                actor, PROPOSE_ACTION, channel, ChannelRefusal.BAD_TARGET, target
            )
        why = self._access.text(actor, PROPOSE_ACTION, channel, purpose)
        now = self._clock.now()

        def change(conn: Connection, row: Row[Any] | None) -> None:
            if row is not None and row.status != ChannelStatus.REVOKED.value:
                raise Conflict("channel already exists")
            waiting = conn.execute(
                select(func.count())
                .select_from(_t)
                .where(_t.c.proposed_by == actor.actor_id, _t.c.status.in_(OPEN_STATES))
            ).scalar_one()
            if waiting >= MAX_OPEN_PROPOSALS_PER_PROPOSER:
                raise ChannelDenied(
                    ChannelRefusal.TOO_MANY_OPEN_PROPOSALS,
                    f"{MAX_OPEN_PROPOSALS_PER_PROPOSER} proposals by this actor await a decision",
                )
            fresh = {
                "target": target,
                "status": ChannelStatus.PROPOSED.value,
                "purpose": why,
                "proposed_by": actor.actor_id,
                "proposed_at": now,
                "decided_by": "",
                "decided_at": None,
                "approval_audit_ref": "",
                "revoked_by": "",
                "revoked_at": None,
                "revoke_reason": "",
            }
            if row is None:
                conn.execute(_t.insert().values(channel=channel, version=1, **fresh))
            else:
                self._update(conn, row, fresh)

        details = {"target": target, "purpose": why}
        return self._apply(actor, PROPOSE_ACTION, channel, details, change, undo_on_audit_loss=True)

    def approve(
        self, actor_id: str, channel: str, target: str, *, version: int, purpose_digest: str
    ) -> ChannelRecord:
        """Make a proposed channel usable. `target`, `version` and `purpose_digest` are
        those of the record the administrator reviewed (`ChannelRecord.purpose_digest`):
        the approval is for what was seen, not for whatever is there now. `Conflict`
        when any of them differs; `ChannelDenied` when the actor proposed it."""
        actor = self._access.authorise(actor_id, APPROVE_ACTION, channel, admin=True)
        self._access.require_name(actor, APPROVE_ACTION, channel)
        now = self._clock.now()

        def change(conn: Connection, row: Row[Any] | None) -> None:
            if row is None:
                raise NotFound("no such channel")
            if row.status not in OPEN_STATES:
                raise Conflict("only a proposed channel can be approved")
            if row.proposed_by == actor.actor_id:
                raise ChannelDenied(
                    ChannelRefusal.SELF_APPROVAL, "the proposer of a channel may not approve it"
                )
            if type(version) is not int or row.version != version:
                raise Conflict("the channel is not at the version that was reviewed")
            if row.target != target or not is_outbox_name(row.target):
                raise Conflict("the channel target is not the one being approved")
            if purpose_digest != _digest(row):
                raise Conflict("the channel purpose is not the one that was reviewed")
            decided = {
                "status": ChannelStatus.APPROVING.value,
                "decided_by": actor.actor_id,
                "decided_at": now,
                "approval_audit_ref": "",
            }
            self._update(conn, row, decided)

        details = {
            "target": target,
            "approved_version": version if type(version) is int else "(not a version)",
            "purpose_sha256": purpose_digest if _is_digest(purpose_digest) else "(not a digest)",
        }
        return self._apply(actor, APPROVE_ACTION, channel, details, change, undo_on_audit_loss=True)

    def revoke(self, actor_id: str, channel: str, reason: str) -> ChannelRecord:
        """Withdraw a proposed, approving or approved channel."""
        actor = self._access.authorise(actor_id, REVOKE_ACTION, channel, admin=True)
        self._access.require_name(actor, REVOKE_ACTION, channel)
        why = self._access.text(actor, REVOKE_ACTION, channel, reason)
        now = self._clock.now()

        def change(conn: Connection, row: Row[Any] | None) -> None:
            if row is None:
                raise NotFound("no such channel")
            if row.status == ChannelStatus.REVOKED.value:
                raise Conflict("channel is already revoked")
            revoked = {
                "status": ChannelStatus.REVOKED.value,
                "revoked_by": actor.actor_id,
                "revoked_at": now,
                "revoke_reason": why,
            }
            self._update(conn, row, revoked)

        details = {"reason": why}
        return self._apply(actor, REVOKE_ACTION, channel, details, change, undo_on_audit_loss=False)

    # -- the change itself -----------------------------------------------------------

    def _apply(
        self,
        actor: Principal,
        action: str,
        channel: str,
        details: dict[str, Any],
        change: Change,
        *,
        undo_on_audit_loss: bool,
    ) -> ChannelRecord:
        """Audit the attempt, change the row in one short transaction, audit the result.
        An approval then takes its second step: see `_finish_approval`."""

        def event(outcome: AuditOutcome, **extra: Any) -> AuditEvent:
            return AuditEvent(
                actor_id=actor.actor_id,
                actor_type=actor.actor_type,
                action=action,
                target=f"channel:{channel}",
                outcome=outcome,
                details={**details, **extra},
            )

        try:
            self._audit.append(event(AuditOutcome.ATTEMPT))
        except Exception as exc:
            raise FailClosed("the attempt could not be audited; nothing changed") from exc
        try:
            before, after = self._transact(channel, change)
        except ChannelDenied as exc:
            self._access.audit_quietly(event(AuditOutcome.DENIED, reason=exc.code.value))
            raise
        except CisoError as exc:
            self._access.audit_quietly(event(AuditOutcome.FAILED, error=type(exc).__name__))
            raise
        except Exception as exc:
            self._access.audit_quietly(event(AuditOutcome.FAILED, error=type(exc).__name__))
            raise FailClosed("the channel record could not be changed") from exc
        approving = after.status is ChannelStatus.APPROVING
        decided = ChannelStatus.APPROVED if approving else after.status
        try:
            receipt = self._audit.append(
                event(AuditOutcome.SUCCESS, status=decided.value, version=after.version)
            )
        except Exception as exc:
            if not undo_on_audit_loss:
                raise FailClosed(f"{_NOT_AUDITED}; the channel IS revoked") from exc
            raise FailClosed(self._undo(action, after, before)) from exc
        if not approving:
            return after
        return self._finish_approval(after, receipt.record_id, event)

    def _finish_approval(
        self, written: ChannelRecord, audit_ref: str, event: Callable[..., AuditEvent]
    ) -> ChannelRecord:
        """Second step of an approval: the row becomes usable only now that its SUCCESS
        record exists, and it stores that record's id."""
        problem = {"problem": "approval_not_completed"}
        if not isinstance(audit_ref, str) or not audit_ref:
            self._access.audit_quietly(event(AuditOutcome.FAILED, **problem))
            raise FailClosed("the audit log returned no record id; the channel is NOT approved")
        try:
            done = self._complete_approval(written, audit_ref)
        except Exception as exc:
            self._access.audit_quietly(
                event(AuditOutcome.FAILED, error=type(exc).__name__, **problem)
            )
            raise FailClosed(
                "the approval was audited but could not be stored; the channel is NOT approved"
            ) from exc
        if done is None:
            self._access.audit_quietly(event(AuditOutcome.FAILED, **problem))
            raise Conflict(
                "the channel changed while its approval was being recorded; "
                "it is NOT approved by this call"
            )
        return done

    def _complete_approval(self, written: ChannelRecord, audit_ref: str) -> ChannelRecord | None:
        """`approving` to `approved`, only on the row this call wrote. None when that row
        has changed since."""
        mine = (
            (_t.c.channel == written.channel)
            & (_t.c.version == written.version)
            & (_t.c.status == ChannelStatus.APPROVING.value)
        )
        values = {
            "status": ChannelStatus.APPROVED.value,
            "approval_audit_ref": audit_ref,
            "version": written.version + 1,
        }
        with self._engine.begin() as conn:
            changed = conn.execute(_t.update().where(mine).values(**values)).rowcount
            if changed != 1:
                return None
            after = conn.execute(select(_t).where(_t.c.channel == written.channel)).one()
        return _record(after)

    def _transact(
        self, channel: str, change: Change
    ) -> tuple[dict[str, Any] | None, ChannelRecord]:
        """Run `change` under the write lock. Returns the row before and the record after."""
        query = select(_t).where(_t.c.channel == channel)
        with self._engine.begin() as conn:
            row = conn.execute(query).first()
            change(conn, row)
            after = conn.execute(query).one()
        return (None if row is None else dict(row._mapping)), _record(after)

    @staticmethod
    def _update(conn: Connection, row: Row[Any], values: dict[str, Any]) -> None:
        """Write `values` to the row exactly as it was read. `Conflict` when it is no
        longer at that version: nothing was written."""
        changed = conn.execute(
            _t.update()
            .where(_t.c.channel == row.channel, _t.c.version == row.version)
            .values(version=row.version + 1, **values)
        ).rowcount
        if changed != 1:
            raise Conflict("the channel record changed underneath this change")

    def _undo(self, action: str, written: ChannelRecord, before: dict[str, Any] | None) -> str:
        """Undo a change whose result could not be audited. Returns what truly happened."""
        try:
            undone = self._restore(written, before)
        except Exception:
            logger.exception("channel registry: %s could not be undone", action)
            return f"{_NOT_AUDITED} and the change could NOT be undone"
        if not undone:
            return (
                f"{_NOT_AUDITED} and the change could NOT be undone: the record changed meanwhile"
            )
        return f"{_NOT_AUDITED}; the change was undone"

    def _restore(self, written: ChannelRecord, before: dict[str, Any] | None) -> bool:
        """Put the row back as it was, but only if it is still the row this call wrote.
        True when a row was changed."""
        mine = (_t.c.channel == written.channel) & (_t.c.version == written.version)
        with self._engine.begin() as conn:
            if before is None:
                changed = conn.execute(_t.delete().where(mine)).rowcount
            else:
                values = {key: value for key, value in before.items() if key != "channel"}
                values["version"] = written.version + 1
                changed = conn.execute(_t.update().where(mine).values(**values)).rowcount
        return bool(changed == 1)


def _digest(row: Row[Any]) -> str:
    return purpose_digest(str(row.purpose))


def _is_digest(value: object) -> bool:
    return isinstance(value, str) and _DIGEST_RE.fullmatch(value) is not None
