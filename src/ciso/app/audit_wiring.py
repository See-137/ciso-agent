"""Opening the audit log with a remembered identity (ADR-0013, G4).

The operational database remembers the id of the audit log it is paired with
(`ciso.app.tables.app_state`). On every start:

- nothing remembered, key usable and the log not yet initialised: `initialise()` and
  remember the new id;
- an id remembered but the audit database file is gone: the log was wiped. It is never
  re-initialised; the log is built with `expected_log_id`, so it refuses, and the problem
  is reported in readiness and health;
- otherwise `open()` checks identity, anchor and witness and repairs a crash; whatever it
  refuses is reported.

When the anchor would sit inside the audit database's directory (`data_dir/db/` or below),
`AuditLog` refuses to be built (an anchor beside the database is rolled back with it). The
container then uses `UnavailableAuditLog`, which refuses every call, and reports the
setting as missing. The default anchor (`data_dir/anchor/`) is outside that directory and
is accepted; that it still shares the data directory is an integrity warning
(`Settings.integrity_warnings`), not a refusal. The same refusal applies to a witness file
inside that directory.

Witness (review C1). `build_witness` returns a `FileHeadWitness` only when the witness
path, its key reference and `safety.audit_witness_every` are all set; the log then
publishes a signed head every that many appends. With anything less no witness is built,
the log reports `witnessed=False`, and `Settings.integrity_warnings` says why. A witness
whose key does not resolve is still built, so appends refuse (fail closed) rather than run
unwitnessed; the unresolvable key is listed in readiness.
"""

from __future__ import annotations

import logging
from datetime import datetime
from pathlib import Path

from sqlalchemy import Engine, select

from ciso.app.settings import Settings
from ciso.app.tables import AUDIT_LOG_ID_KEY, app_state
from ciso.audit import AuditLog, AuditRecord, FileHeadWitness, HeadAnchor, VerifyResult
from ciso.common.clock import Clock
from ciso.common.db import read_connection
from ciso.common.enums import AuditOutcome
from ciso.common.errors import CisoError, Conflict, FailClosed, NotFound
from ciso.common.protocols import (
    AuditEvent,
    AuditReceipt,
    Redactor,
    RevealableSecret,
    SecretResolver,
)

logger = logging.getLogger(__name__)

AUDIT_WIPED = "audit_log_wiped (a log id is remembered but the audit database is missing)"
ANCHOR_NOT_ISOLATED = (
    "audit_anchor_path (the anchor must not live inside the audit database's directory)"
)
WITNESS_NOT_ISOLATED = (
    "audit_witness_path (the witness must not live inside the audit database's directory)"
)
#: Stand-in reference for an anchor whose key is not usable. Never looked up.
UNSET_ANCHOR_REF = "secret://audit_hmac_key_unset"


class RefusingResolver:
    """A resolver for a key that must not be used: every lookup is `NotFound`."""

    def __init__(self, why: str) -> None:
        self._why = why

    def get(self, ref: str) -> RevealableSecret:
        raise NotFound(self._why)


class UnavailableAuditLog:
    """Stands in for an audit log that cannot be built. Every call raises `FailClosed`."""

    def __init__(self, why: str) -> None:
        self._why = why

    @property
    def log_id(self) -> str | None:
        return None

    def append(self, event: AuditEvent) -> AuditReceipt:
        raise FailClosed(f"audit log unavailable: {self._why}")

    def verify(self) -> VerifyResult:
        raise FailClosed(f"audit log unavailable: {self._why}")

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
        raise FailClosed(f"audit log unavailable: {self._why}")


def remembered_log_id(operational: Engine) -> str | None:
    with read_connection(operational) as conn:
        row = conn.execute(
            select(app_state.c.value).where(app_state.c.key == AUDIT_LOG_ID_KEY)
        ).first()
    return None if row is None else str(row.value)


def _remember(operational: Engine, log_id: str, clock: Clock) -> None:
    with operational.begin() as conn:
        conn.execute(
            app_state.insert().values(key=AUDIT_LOG_ID_KEY, value=log_id, recorded_at=clock.now())
        )


def _inside(db_file: Path, path: Path) -> bool:
    return path.resolve().is_relative_to(db_file.resolve().parent)


def build_witness(settings: Settings, resolver: SecretResolver) -> FileHeadWitness | None:
    """A witness when path, key reference and cadence are all set; otherwise None."""
    path, key_ref = settings.audit_witness_path, settings.audit_witness_key_ref
    if path is None or key_ref is None or settings.safety.audit_witness_every is None:
        return None
    return FileHeadWitness(path, resolver, key_ref)


def open_audit(
    *,
    audit_engine: Engine,
    operational: Engine,
    audit_db: Path,
    anchor_path: Path,
    key_ref: str | None,
    resolver: SecretResolver,
    key_usable: bool,
    audit_db_existed: bool,
    redactor: Redactor,
    clock: Clock,
    witness: FileHeadWitness | None = None,
    witness_every: int | None = None,
) -> tuple[AuditLog | UnavailableAuditLog, HeadAnchor | None, tuple[str, ...]]:
    """Build and open the audit log. Returns the log, its anchor and any problems."""
    if _inside(audit_db, anchor_path):
        logger.error("start-up: audit anchor is inside the database directory; audit refused")
        return UnavailableAuditLog("anchor not isolated"), None, (ANCHOR_NOT_ISOLATED,)
    if witness is not None and _inside(audit_db, witness.path):
        logger.error("start-up: audit witness is inside the database directory; audit refused")
        return UnavailableAuditLog("witness not isolated"), None, (WITNESS_NOT_ISOLATED,)
    remembered = remembered_log_id(operational)
    problems: list[str] = []
    if remembered is not None and not audit_db_existed:
        logger.error("start-up: audit database missing for a remembered log; appends refused")
        problems.append(AUDIT_WIPED)
    if key_ref is None or not key_usable:
        anchor = HeadAnchor(
            anchor_path, RefusingResolver("audit key not usable"), key_ref or UNSET_ANCHOR_REF
        )
    else:
        anchor = HeadAnchor(anchor_path, resolver, key_ref)
    audit = AuditLog(
        audit_engine,
        clock,
        redactor,
        anchor,
        expected_log_id=remembered,
        witness=witness,
        witness_every=witness_every if witness is not None else None,
    )
    if problems or key_ref is None or not key_usable:
        return audit, anchor, tuple(problems)
    try:
        created: str | None = None
        if remembered is None and audit.log_id is None:
            # A new log, or one whose first initialise() was interrupted after the anchor
            # was written (AuditLog.initialise completes it). Any other existing anchor is
            # refused there; open() below then reports the precise reason.
            try:
                created = audit.initialise()
            except Conflict:
                logger.warning("start-up: audit anchor exists for an empty log; not initialising")
            else:
                _remember(operational, created, clock)
        log_id = audit.open()
        if remembered is None and created is None:
            logger.warning("start-up: adopting an existing audit log the database did not know")
            _remember(operational, log_id, clock)
    except CisoError as exc:
        logger.error("start-up: audit log refused to open (%s)", type(exc).__name__)
        problems.append(f"audit_log_unusable ({type(exc).__name__})")
    return audit, anchor, tuple(problems)
