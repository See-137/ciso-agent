"""`KillSwitchHistory` backed by the audit log (ADR-0018, G20).

The kill switch asks for the latest successful kill-switch record so that `initialise()`
never re-creates clear flags over a history that says otherwise. Records are read in
pages in seq order; the kill-switch history is short, so a full scan is cheap.
"""

from __future__ import annotations

from typing import Final, Protocol

from ciso.audit import AuditRecord
from ciso.common.enums import AuditOutcome, KillCapability
from ciso.killswitch import KillSwitchRecord

_ACTIONS: Final = frozenset({"killswitch.engage", "killswitch.release", "killswitch.initialise"})
_PAGE: Final = 500


class _Queryable(Protocol):
    def query(
        self,
        *,
        limit: int,
        action_prefix: str | None = None,
        outcome: AuditOutcome | None = None,
        after_seq: int | None = None,
    ) -> list[AuditRecord]: ...


class AuditKillSwitchHistory:
    """Reads kill-switch records from the audit log. Raises when the log cannot be read."""

    def __init__(self, audit: _Queryable) -> None:
        self._audit = audit

    def last_killswitch_record(
        self, capability: KillCapability | None = None
    ) -> KillSwitchRecord | None:
        latest: KillSwitchRecord | None = None
        after: int | None = None
        while True:
            page = self._audit.query(
                limit=_PAGE,
                action_prefix="killswitch.",
                outcome=AuditOutcome.SUCCESS,
                after_seq=after,
            )
            for record in page:
                found = _as_record(record)
                if found is not None and (capability is None or capability in found.capabilities):
                    latest = found
            if len(page) < _PAGE:
                return latest
            after = page[-1].seq


def _as_record(record: AuditRecord) -> KillSwitchRecord | None:
    if record.action not in _ACTIONS:
        return None
    raw = record.details.get("capabilities", [])
    names = raw if isinstance(raw, list | tuple) else []
    known = {cap.value for cap in KillCapability}
    caps = tuple(KillCapability(n) for n in names if n in known)
    return KillSwitchRecord(action=record.action, capabilities=caps)
