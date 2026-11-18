"""Operator emergency stop. Blueprint 11.2; FR-030; NFR-017; gap G20; ADR-0018."""

from __future__ import annotations

import logging
import time
from collections.abc import Callable, Iterable, Sequence
from datetime import datetime, timedelta

from sqlalchemy import Connection, Engine, func, select

from ciso.common.clock import Clock
from ciso.common.db import read_connection
from ciso.common.enums import ActorType, AuditOutcome, KillCapability
from ciso.common.errors import AuthorizationError, FailClosed, KillSwitchEngaged
from ciso.common.principal import Principal
from ciso.common.protocols import AuditEvent, AuditSink, PrincipalResolver, SecretResolver
from ciso.killswitch.integrity import (
    capability_reads_blocked,
    flag_row_verifies,
    resolve_key,
)
from ciso.killswitch.models import (
    ENGAGE_ACTION,
    INITIALISE_ACTION,
    INITIALISE_ACTOR,
    RECONCILE_ACTOR,
    RELEASE_ACTION,
    VIA_API,
    VIA_INITIALISE,
    VIA_RECONCILE,
    CapabilityState,
    KillSwitchHistory,
    Mismatch,
    PendingAudit,
)
from ciso.killswitch.outbox import Outbox
from ciso.killswitch.persist import engage_rows, run_write, write_flag
from ciso.killswitch.rules import (
    denial_event,
    fetch_flag,
    normalise_capabilities,
    refusal,
    require_text,
    state_of,
    target_of,
    written_state,
)
from ciso.killswitch.tables import killswitch_flag, killswitch_pending_audit

logger = logging.getLogger(__name__)


class KillSwitch:
    """Persistent emergency-stop flags, one per `KillCapability` (blueprint 11.2).

    Reading: `is_blocked` is true when the flag is engaged, when its row is missing, when
    the row's MAC does not verify, when the MAC key (`key_ref`, resolved through
    `secrets`) is unset or unavailable, and when the state cannot be read at all. With
    `key_ref=None` every capability reads as blocked. `active_scans` also governs deep
    tests (`DEEP_TESTS_CAPABILITY`, gap G20).

    Who: `engage` and `release` decide on `principals.resolve(actor_id)`, never on the
    object handed in. Unknown, disabled, non-human or non-security_admin is refused, and
    so is any resolver failure; when identity is down, the break-glass command is the
    route to engage. Refusals are audited.

    Engage always stores its intent. Flags and an outbox audit row are written in one
    short transaction, retried on a busy database and wrapped in `FailClosed` if it still
    fails. Without the key the rows are stored without a MAC and so read as blocked. After
    the commit nothing can turn the engage into an exception: delivery to the audit sink
    happens afterwards and anything owed stays in `pending_audit()`.

    Release fails closed and never calls the sink while holding the write lock: it needs
    the key and a verifiable current row, delivers everything owed first (refusing if
    anything is still owed), audits an ATTEMPT, changes the flags in a short transaction,
    then audits the result. If the result cannot be audited the flags are engaged again
    and `FailClosed` is raised.

    `initialise()` creates clear rows only on a new installation; `reconcile()` compares
    flags with the audit history and forces a disagreeing clear flag to blocked.
    """

    def __init__(
        self,
        *,
        engine: Engine,
        audit: AuditSink,
        clock: Clock,
        principals: PrincipalResolver,
        secrets: SecretResolver,
        key_ref: str | None,
        history: KillSwitchHistory | None = None,
        claim_timeout: timedelta | None = None,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        self._engine = engine
        self._audit = audit
        self._clock = clock
        self._principals = principals
        self._secrets = secrets
        self._key_ref = key_ref
        self._history = history
        self._sleep = sleep
        self._outbox = Outbox(engine=engine, audit=audit, clock=clock, claim_timeout=claim_timeout)

    # --- reading ---------------------------------------------------------------------

    def is_blocked(self, capability: KillCapability) -> bool:
        return capability_reads_blocked(self._engine, self._key(), capability)

    def require_clear(self, capability: KillCapability) -> None:
        """Raise `KillSwitchEngaged` unless the capability reads as clear."""
        if self.is_blocked(capability):
            raise KillSwitchEngaged(f"kill switch blocks {capability!s}")

    def status(self) -> tuple[CapabilityState, ...]:
        """Every capability as stored and as read. FailClosed when it cannot be read."""
        key = self._key()
        try:
            with read_connection(self._engine) as conn:
                rows = {r.capability: r for r in conn.execute(select(killswitch_flag))}
        except Exception as exc:
            raise FailClosed("kill-switch state cannot be read") from exc
        return tuple(state_of(cap, rows.get(cap.value), key) for cap in KillCapability)

    def pending_audit(self) -> tuple[PendingAudit, ...]:
        """Engage records still owed to the audit sink, oldest first."""
        return self._outbox.pending()

    def quarantined_audit(self) -> tuple[PendingAudit, ...]:
        """Outbox rows that failed their MAC or could not be parsed. Never delivered."""
        return self._outbox.quarantined()

    def retry_pending_audit(self) -> int:
        """Deliver what is owed. Returns how many reached the sink. Never raises."""
        return self._outbox.deliver_all(self._key())

    # --- set-up ----------------------------------------------------------------------

    def initialise(self) -> None:
        """Create clear, MAC'd rows, but only on a genuinely new installation.

        Nothing is created when any flag row, any outbox row, or (with a history reader)
        any `killswitch.*` audit record exists; a missing row then stays blocked and shows
        in `status()` as `recorded=False`. Safe under concurrent callers. Needs the key.
        Without a history reader, a database whose kill-switch rows were all deleted looks
        new: wire the history reader in production.
        """
        key = self._key()
        if key is None:
            raise FailClosed("kill-switch MAC key unavailable; cannot initialise")
        if self._history is not None:
            try:
                seen = self._history.last_killswitch_record(None)
            except Exception as exc:
                raise FailClosed("kill-switch audit history cannot be read") from exc
            if seen is not None:
                logger.info("kill switch: audit history exists; initialise creates nothing")
                return
        now = self._clock.now()

        def create(conn: Connection) -> bool:
            flags = conn.execute(select(func.count()).select_from(killswitch_flag)).scalar_one()
            owed = conn.execute(
                select(func.count()).select_from(killswitch_pending_audit)
            ).scalar_one()
            if flags or owed:
                return False
            for cap in KillCapability:
                write_flag(
                    conn, cap, engaged=False, changed_by=INITIALISE_ACTOR,
                    actor_type=ActorType.SERVICE, reason="new installation",
                    via=VIA_INITIALISE, operator="", now=now, key=key,
                )  # fmt: skip
            return True

        if run_write(self._engine, create, what="kill-switch initialise", sleep=self._sleep):
            self._audit_quietly(
                AuditEvent(
                    actor_id=INITIALISE_ACTOR,
                    actor_type=ActorType.SERVICE,
                    action=INITIALISE_ACTION,
                    target=target_of(tuple(KillCapability)),
                    outcome=AuditOutcome.SUCCESS,
                    details={"capabilities": [c.value for c in KillCapability]},
                )
            )

    # --- changing --------------------------------------------------------------------

    def engage(
        self, principal: Principal, capabilities: Iterable[KillCapability], reason: str
    ) -> tuple[CapabilityState, ...]:
        """Stop the named capabilities. Persists even if the audit sink or key is down."""
        caps = normalise_capabilities(capabilities)
        why = require_text(reason, "reason")
        actor = self._authorise(principal, ENGAGE_ACTION, caps)
        return self._engage(caps, actor.actor_id, ActorType.HUMAN, why, VIA_API)

    def engage_all(self, principal: Principal, reason: str) -> tuple[CapabilityState, ...]:
        return self.engage(principal, tuple(KillCapability), reason)

    def release(
        self, principal: Principal, capabilities: Iterable[KillCapability], reason: str
    ) -> tuple[CapabilityState, ...]:
        """Clear the named capabilities. Every failure leaves them engaged (FailClosed)."""
        caps = normalise_capabilities(capabilities)
        why = require_text(reason, "reason")
        actor = self._authorise(principal, RELEASE_ACTION, caps)
        key = self._key()
        if key is None:
            raise FailClosed("kill-switch MAC key unavailable; nothing was released")
        self._outbox.deliver_all(key)
        if self._outbox.owed_count():
            raise FailClosed("engage records are still owed to the audit log; not released")
        versions = self._verified_versions(caps, key)
        details = {
            "capabilities": [c.value for c in caps],
            "reason": why,
            "versions": {c.value: versions[c] for c in caps},
        }

        def record(outcome: AuditOutcome) -> AuditEvent:
            return AuditEvent(
                actor_id=actor.actor_id, actor_type=ActorType.HUMAN, action=RELEASE_ACTION,
                target=target_of(caps), outcome=outcome, details=details,
            )  # fmt: skip

        try:
            self._audit.append(record(AuditOutcome.ATTEMPT))
        except Exception as exc:
            raise FailClosed("release attempt could not be audited; nothing changed") from exc
        now = self._clock.now()
        try:
            self._clear(caps, versions, actor.actor_id, why, now, key)
        except FailClosed:
            self._audit_quietly(record(AuditOutcome.FAILED))
            raise
        try:
            self._audit.append(record(AuditOutcome.SUCCESS))
        except Exception as exc:
            self._engage(caps, actor.actor_id, ActorType.HUMAN,
                         "release result could not be audited; re-engaged", VIA_API)  # fmt: skip
            raise FailClosed("release result could not be audited; re-engaged") from exc
        return tuple(written_state(c, engaged=False, actor_id=actor.actor_id, reason=why,
                              via=VIA_API, now=now, verified=True) for c in caps)  # fmt: skip

    def _clear(
        self,
        caps: Sequence[KillCapability],
        versions: dict[KillCapability, int],
        actor_id: str,
        reason: str,
        now: datetime,
        key: bytes,
    ) -> None:
        """One short write transaction; refuses if any row changed since it was checked."""

        def clear(conn: Connection) -> None:
            for cap in caps:
                row = fetch_flag(conn, cap)
                if not flag_row_verifies(key, row) or int(row.version) != versions[cap]:
                    raise FailClosed(f"{cap.value} changed during release; nothing released")
                write_flag(
                    conn, cap, engaged=False, changed_by=actor_id, actor_type=ActorType.HUMAN,
                    reason=reason, via=VIA_API, operator="", now=now, key=key,
                )  # fmt: skip

        run_write(self._engine, clear, what="kill-switch release", sleep=self._sleep)

    # --- reconcile -------------------------------------------------------------------

    def reconcile(self) -> tuple[Mismatch, ...]:
        """Compare each flag with the latest audit record for its capability.

        A flag that reads clear while the latest record says engaged, or while there is no
        record at all, is engaged again (actor `system:reconcile`) and so reads blocked
        until a human releases it. A flag that reads blocked while the latest record says
        released or initialised is reported only: blocked is the safe side. Needs the
        history reader; FailClosed without it or when it cannot be read.
        """
        if self._history is None:
            raise FailClosed("no audit history reader; cannot reconcile")
        states = {s.capability: s for s in self.status()}
        found: list[Mismatch] = []
        force: list[KillCapability] = []
        for cap in KillCapability:
            try:
                record = self._history.last_killswitch_record(cap)
            except Exception as exc:
                raise FailClosed("kill-switch audit history cannot be read") from exc
            action = record.action if record is not None else None
            blocked = states[cap].engaged
            if not blocked and action not in (RELEASE_ACTION, INITIALISE_ACTION):
                force.append(cap)
                detail = f"flag reads clear but the latest audit record is {action or 'missing'}"
                found.append(Mismatch(capability=cap, audit_action=action,
                                      flag_reads_blocked=False, forced_blocked=True,
                                      detail=detail))  # fmt: skip
            elif blocked and action in (RELEASE_ACTION, INITIALISE_ACTION):
                found.append(Mismatch(capability=cap, audit_action=action,
                                      flag_reads_blocked=True, forced_blocked=False,
                                      detail=f"flag reads blocked after {action}"))  # fmt: skip
        if force:
            self._engage(tuple(force), RECONCILE_ACTOR, ActorType.SERVICE,
                         "flag disagreed with the audit log", VIA_RECONCILE)  # fmt: skip
            logger.error("kill switch: reconcile forced %s to blocked",
                         ", ".join(c.value for c in force))  # fmt: skip
        return tuple(found)

    # --- internals -------------------------------------------------------------------

    def _key(self) -> bytes | None:
        return resolve_key(self._secrets, self._key_ref)

    def _engage(
        self,
        caps: Sequence[KillCapability],
        actor_id: str,
        actor_type: ActorType,
        reason: str,
        via: str,
    ) -> tuple[CapabilityState, ...]:
        key = self._key()
        if key is None:
            logger.error("kill switch: engaging without the MAC key; rows will read as blocked")
        now = self._clock.now()
        seq = run_write(
            self._engine,
            lambda conn: engage_rows(
                conn, caps, actor_id=actor_id, actor_type=actor_type, reason=reason,
                via=via, operator="", now=now, key=key,
            ),
            what="kill-switch engage",
            sleep=self._sleep,
        )  # fmt: skip
        try:
            self._outbox.deliver(seq, key)
        except Exception:
            logger.exception("kill switch: engage stored; audit delivery deferred")
        return tuple(
            written_state(c, engaged=True, actor_id=actor_id, reason=reason, via=via, now=now,
                          verified=key is not None)
            for c in caps
        )  # fmt: skip

    def _verified_versions(
        self, caps: Sequence[KillCapability], key: bytes
    ) -> dict[KillCapability, int]:
        try:
            with read_connection(self._engine) as conn:
                rows = {cap: fetch_flag(conn, cap) for cap in caps}
        except Exception as exc:
            raise FailClosed("kill-switch state cannot be read; nothing released") from exc
        bad = [cap.value for cap, row in rows.items() if not flag_row_verifies(key, row)]
        if bad:
            raise FailClosed(
                f"cannot verify {', '.join(bad)}; engage again, then release. Nothing released"
            )
        return {cap: int(row.version) for cap, row in rows.items()}

    def _authorise(
        self, principal: Principal, action: str, caps: Sequence[KillCapability]
    ) -> Principal:
        claimed = principal.actor_id
        resolved: Principal | None = None
        try:
            resolved = self._principals.resolve(claimed)
            why = refusal(claimed, resolved)
        except Exception as exc:
            why = f"identity could not be checked ({type(exc).__name__})"
        if resolved is not None and why is None:
            return resolved
        actor_type = resolved.actor_type if resolved is not None else ActorType.ANONYMOUS
        event = denial_event(
            claimed, actor_type, action, caps, why or "refused", AuditOutcome.DENIED
        )
        try:
            self._audit.append(event)
        except Exception as exc:
            raise AuthorizationError(f"{why} (refusal could not be audited)") from exc
        raise AuthorizationError(why or "refused")

    def _audit_quietly(self, event: AuditEvent) -> None:
        try:
            self._audit.append(event)
        except Exception:
            logger.exception("kill switch: audit record %s could not be written", event.action)
