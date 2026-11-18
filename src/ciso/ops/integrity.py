"""Write gate that depends on audit integrity (blueprint 10.3, 11.2, NFR-017, NFR-018).

`IntegrityState` holds the outcome of the latest audit-log verification and any start-up
step that failed. `GatedKillSwitch` wraps the real kill switch and adds that state to every
answer, so "if verify fails, the write capability stays blocked" holds without any caller
having to remember a second check: anything that consults a `KillSwitchReader` before it
acts consults this gate.

Truth table (blocked = True). "inner" is the wrapped kill switch; an inner read that raises
counts as blocked. `blockers` are start-up steps that failed.

| capability          | inner blocked | status ok | unverified | unverifiable | failed | blockers |
|---------------------|---------------|-----------|------------|--------------|--------|----------|
| writes              | blocked       | clear     | blocked    | blocked      | blocked| blocked  |
| l3_runs             | blocked       | clear     | blocked    | blocked      | blocked| blocked  |
| external_inference  | blocked       | clear     | clear      | blocked      | blocked| clear    |
| active_scans        | blocked       | clear     | clear      | blocked      | blocked| clear    |

Why `unverifiable` blocks external inference and active scans although it is not proven
tampering: a missing anchor is exactly what an attacker who deleted it would leave behind,
and these two capabilities send data out of, or probe outside of, the platform; their trail
must be trustworthy. `unverified` (verification has not run yet) only blocks writes and L3.

Reads, monitoring and evidence preservation have no `KillCapability`, so this gate never
blocks them (blueprint 11.2: "monitoring ... and read-only investigation should remain
available").
"""

from __future__ import annotations

import logging
import threading
from enum import StrEnum

from ciso.common.enums import KillCapability
from ciso.common.protocols import KillSwitchReader
from ciso.common.schemas import Model

logger = logging.getLogger(__name__)


class IntegrityStatus(StrEnum):
    UNVERIFIED = "unverified"  # no verification has run since start-up
    OK = "ok"
    UNVERIFIABLE = "unverifiable"  # cannot be proven intact; never treated as ok
    FAILED = "failed"  # evidence of tampering or corruption


#: Capabilities that need a verified audit log (status ok and no failed start-up step).
NEEDS_VERIFIED = frozenset({KillCapability.WRITES, KillCapability.L3_RUNS})
#: Capabilities blocked whenever the audit log is known bad or cannot be proven intact.
NEEDS_NOT_COMPROMISED = frozenset({KillCapability.EXTERNAL_INFERENCE, KillCapability.ACTIVE_SCANS})
_COMPROMISED = frozenset({IntegrityStatus.UNVERIFIABLE, IntegrityStatus.FAILED})


class IntegritySnapshot(Model):
    status: IntegrityStatus
    reason: str | None = None
    blockers: tuple[str, ...] = ()

    @property
    def writes_permitted(self) -> bool:
        return self.status is IntegrityStatus.OK and not self.blockers


class IntegrityState:
    """Thread-safe holder of the latest verification outcome.

    Starts `unverified`. `record_verification` replaces the status with the result of a
    verification, good or bad: a later failed check blocks again, a later successful one
    clears an earlier failure. `block` adds a start-up failure that only a new start-up (a
    new instance) clears.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._snapshot = IntegritySnapshot(status=IntegrityStatus.UNVERIFIED)

    def record_verification(self, status: IntegrityStatus, reason: str | None = None) -> None:
        status = IntegrityStatus(status)
        if status is IntegrityStatus.UNVERIFIED:
            raise ValueError("a verification result cannot be 'unverified'")
        with self._lock:
            self._snapshot = self._snapshot.model_copy(update={"status": status, "reason": reason})
        if status is not IntegrityStatus.OK:
            logger.error("audit integrity is %s (%s); writes stay blocked", status.value, reason)

    def block(self, step: str) -> None:
        """Record a failed start-up step. Writes and L3 runs stay blocked."""
        with self._lock:
            if step not in self._snapshot.blockers:
                blockers = (*self._snapshot.blockers, step)
                self._snapshot = self._snapshot.model_copy(update={"blockers": blockers})

    def snapshot(self) -> IntegritySnapshot:
        with self._lock:
            return self._snapshot


class GatedKillSwitch:
    """A `KillSwitchReader` that is blocked when the inner switch is, or when integrity
    does not allow the capability (see the module table)."""

    def __init__(self, inner: KillSwitchReader, integrity: IntegrityState) -> None:
        self._inner = inner
        self._integrity = integrity

    def is_blocked(self, capability: KillCapability) -> bool:
        try:
            cap = KillCapability(capability)
            inner_blocked = bool(self._inner.is_blocked(cap))
        except Exception:
            logger.exception("gated kill switch: inner state unreadable; treating as blocked")
            return True
        if inner_blocked:
            return True
        snap = self._integrity.snapshot()
        if cap in NEEDS_VERIFIED:
            return not snap.writes_permitted
        if cap in NEEDS_NOT_COMPROMISED:
            return snap.status in _COMPROMISED
        return False
