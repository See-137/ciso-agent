"""A bound on audit records for refusals nobody is accountable for (review finding M9).

A refusal before the identity store confirmed the envelope's actor (kill switch engaged,
invalid request, invalid envelope, unknown actor) is caused by whoever can reach
`ExecutionBroker.execute`, under whatever actor id they wrote. Left alone, such a caller
could fill the audit log at will. This class writes at most
`UNVERIFIED_REFUSAL_AUDIT_CAP` such records per `UNVERIFIED_REFUSAL_WINDOW` on the
injected clock. When the cap is reached it writes one summary record; when the next
window opens it writes one more, holding the number of records that were left out.

Both numbers are structural bounds on log volume, not safety parameters: there is no
"unset means unlimited" here and no setting to raise them. The refusals themselves are
never suppressed, only their individual records. Refusals of a confirmed actor are not
counted here; limiting those callers is the caller-facing layer's job (plan gap G22).

The count is per broker object and lives in memory: a restart opens a new window.
"""

from __future__ import annotations

import logging
import threading
from datetime import datetime, timedelta

from ciso.common.clock import Clock
from ciso.common.enums import ActorType, AuditOutcome
from ciso.common.protocols import AuditEvent, AuditSink
from ciso.execution.records import BROKER_ACTOR_ID

logger = logging.getLogger(__name__)

#: Most individual records for unconfirmed refusals per window. Structural bound.
UNVERIFIED_REFUSAL_AUDIT_CAP = 20
#: Length of the window the cap applies to. Structural bound.
UNVERIFIED_REFUSAL_WINDOW = timedelta(minutes=1)
#: Audit action of the summary records. Value is a wire format: do not rename.
REFUSALS_SUPPRESSED_ACTION = "execution.refusals_suppressed"


class UnconfirmedRefusals:
    def __init__(self, audit: AuditSink, clock: Clock) -> None:
        self._audit = audit
        self._clock = clock
        self._lock = threading.Lock()
        self._window_start: datetime | None = None
        self._written = 0
        self._suppressed = 0

    def record(self, event: AuditEvent) -> None:
        """Write `event`, or count it once the window's cap is used up. Never raises:
        the refusal it describes is raised by the caller either way."""
        try:
            now = self._clock.now()
        except Exception:
            logger.error("execution: refusal not audited, the clock could not be read")
            return
        carried, write_event, cap_reached = 0, False, False
        with self._lock:
            start = self._window_start
            if start is None or now - start >= UNVERIFIED_REFUSAL_WINDOW:
                carried = self._suppressed
                self._window_start, self._written, self._suppressed = now, 0, 0
            if self._written < UNVERIFIED_REFUSAL_AUDIT_CAP:
                self._written += 1
                write_event = True
            else:
                self._suppressed += 1
                cap_reached = self._suppressed == 1
        # The audit sink is called outside the lock.
        if carried:
            self._append(self._summary("window_closed", suppressed=carried))
        if write_event:
            self._append(event)
        elif cap_reached:
            self._append(self._summary("cap_reached"))

    @staticmethod
    def _summary(state: str, **extra: int) -> AuditEvent:
        return AuditEvent(
            actor_id=BROKER_ACTOR_ID,
            actor_type=ActorType.SERVICE,
            action=REFUSALS_SUPPRESSED_ACTION,
            outcome=AuditOutcome.DENIED,
            details={
                "state": state,
                "cap": UNVERIFIED_REFUSAL_AUDIT_CAP,
                "window_seconds": int(UNVERIFIED_REFUSAL_WINDOW.total_seconds()),
                **extra,
            },
        )

    def _append(self, event: AuditEvent) -> None:
        try:
            self._audit.append(event)
        except Exception as exc:
            logger.error("execution: refusal record not audited (%s)", type(exc).__name__)
