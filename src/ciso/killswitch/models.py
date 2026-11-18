"""Value types and the audit-history seam for the kill switch. Blueprint 11.2; ADR-0018."""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from ciso.common.enums import KillCapability
from ciso.common.schemas import Model, UtcDatetime

ENGAGE_ACTION = "killswitch.engage"
RELEASE_ACTION = "killswitch.release"
INITIALISE_ACTION = "killswitch.initialise"

VIA_API = "api"
VIA_BREAKGLASS = "breakglass"
VIA_RECONCILE = "reconcile"
VIA_INITIALISE = "initialise"
OUTBOX_VIAS = frozenset({VIA_API, VIA_BREAKGLASS, VIA_RECONCILE})

#: Fixed identities. None of them is a person, and none is ever taken from a stored row.
BREAKGLASS_ACTOR = "breakglass"
RECONCILE_ACTOR = "system:reconcile"
INITIALISE_ACTOR = "system:initialise"
UNVERIFIED_ACTOR = "unverified"

#: Deep tests are governed by the active-scans flag (gap G20). Discovery checks this.
DEEP_TESTS_CAPABILITY = KillCapability.ACTIVE_SCANS


class CapabilityState(Model):
    """One capability as stored and as read.

    `engaged` is the effective reading, the same answer `is_blocked` gives: true when
    the stored flag is engaged, when no row exists (`recorded=False`), and when the row
    cannot be verified (`verified=False`). `stored_engaged` is what the row itself says,
    which is not to be trusted when `verified` is false.
    """

    capability: KillCapability
    engaged: bool
    recorded: bool
    verified: bool
    stored_engaged: bool | None = None
    version: int | None = None
    changed_by: str | None = None
    changed_at: UtcDatetime | None = None
    reason: str | None = None
    via: str | None = None
    operator: str | None = None


class PendingAudit(Model):
    """An outbox row that has not reached the audit sink. `capabilities` is as stored."""

    seq: int
    entry_id: str
    actor_id: str
    capabilities: tuple[str, ...]
    reason: str
    via: str
    operator: str
    recorded_at: UtcDatetime
    claimed: bool
    quarantined: bool
    last_error: str


class KillSwitchRecord(Model):
    """The latest successful kill-switch audit record touching a capability."""

    action: str
    capabilities: tuple[KillCapability, ...]


class Mismatch(Model):
    """A flag that disagrees with the audit history, from `KillSwitch.reconcile()`."""

    capability: KillCapability
    audit_action: str | None
    flag_reads_blocked: bool
    forced_blocked: bool
    detail: str


@runtime_checkable
class KillSwitchHistory(Protocol):
    """Read access to the audit log's kill-switch records. Backed by the audit log.

    Returns the latest record with outcome `success` whose action is
    `killswitch.engage`, `killswitch.release` or `killswitch.initialise` and that names
    `capability` (or any capability, when it is None). None when there is no such
    record. Raises when the history cannot be read.
    """

    def last_killswitch_record(
        self, capability: KillCapability | None = None
    ) -> KillSwitchRecord | None: ...
