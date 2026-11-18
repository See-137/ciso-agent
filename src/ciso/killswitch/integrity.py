"""Row MACs and the single "does this capability read as blocked?" check. Review H2, H3.

Anyone who can write the operational database could otherwise release the switch with a
plain UPDATE, or plant an outbox row that turns into an audit record. Each flag row and
each outbox row therefore carries an HMAC-SHA256 over its content, keyed by a secret the
kill switch resolves through `SecretResolver` and that agents do not hold.

Reading rule (fail closed): a capability reads as blocked when its row is missing, has no
MAC, has a MAC that does not verify, when the key is not configured or cannot be
resolved, or when the row cannot be read at all. Only a verified row that says
`engaged = false` reads as clear.

Residual: a writer who saved an older verified clear row can put it back (rollback).
The MAC cannot see that; `KillSwitch.reconcile()` against the audit log can.
"""

from __future__ import annotations

import hashlib
import hmac
import logging
from collections.abc import Sequence
from datetime import datetime
from typing import Any

from sqlalchemy import Engine, select

from ciso.common.clock import ensure_utc
from ciso.common.db import read_connection
from ciso.common.enums import KillCapability
from ciso.common.protocols import SecretResolver
from ciso.common.schemas import canonical_json
from ciso.killswitch.tables import killswitch_flag
from ciso.vault import resolve_key_bytes

logger = logging.getLogger(__name__)

FLAG_DOMAIN = "ciso.killswitch.flag.v2"
OUTBOX_DOMAIN = "ciso.killswitch.outbox.v2"


def resolve_key(secrets: SecretResolver | None, key_ref: str | None) -> bytes | None:
    """The MAC key, or None when it is not configured or cannot be resolved.

    Never raises and never logs the value. None makes every row read as blocked.
    """
    if key_ref is None or secrets is None:
        return None
    try:
        return resolve_key_bytes(secrets, key_ref)
    except Exception as exc:
        # Unresolvable, empty, or shorter than MIN_KEY_BYTES: the message names the
        # reference only, never the value.
        logger.warning("kill switch: MAC key %s unusable (%s)", key_ref, type(exc).__name__)
        return None


def _mac(key: bytes, parts: Sequence[Any]) -> str:
    return hmac.new(key, canonical_json(list(parts)).encode("utf-8"), hashlib.sha256).hexdigest()


def _when(value: datetime) -> str:
    return ensure_utc(value).isoformat()


def flag_mac(
    key: bytes,
    *,
    capability: str,
    engaged: bool,
    version: int,
    changed_by: str,
    changed_at: datetime,
    reason: str,
    via: str,
    operator: str,
) -> str:
    return _mac(
        key,
        [FLAG_DOMAIN, capability, engaged, version, changed_by, _when(changed_at), reason,
         via, operator],
    )  # fmt: skip


def flag_row_verifies(key: bytes | None, row: Any) -> bool:
    if key is None or row is None or not row.mac:
        return False
    expected = flag_mac(
        key,
        capability=row.capability,
        engaged=bool(row.engaged),
        version=int(row.version),
        changed_by=row.changed_by,
        changed_at=row.changed_at,
        reason=row.reason,
        via=row.via,
        operator=row.operator or "",
    )
    return hmac.compare_digest(expected, str(row.mac))


def outbox_mac(
    key: bytes,
    *,
    entry_id: str,
    actor_id: str,
    capabilities: str,
    reason: str,
    via: str,
    operator: str,
    recorded_at: datetime,
) -> str:
    return _mac(
        key,
        [OUTBOX_DOMAIN, entry_id, actor_id, capabilities, reason, via, operator,
         _when(recorded_at)],
    )  # fmt: skip


def outbox_row_verifies(key: bytes, row: Any) -> bool:
    expected = outbox_mac(
        key,
        entry_id=row.entry_id,
        actor_id=row.actor_id,
        capabilities=row.capabilities,
        reason=row.reason,
        via=row.via,
        operator=row.operator or "",
        recorded_at=row.recorded_at,
    )
    return hmac.compare_digest(expected, str(row.mac or ""))


def row_reads_blocked(key: bytes | None, row: Any) -> bool:
    """The reading rule for one fetched row (None = missing)."""
    if row is None or not flag_row_verifies(key, row):
        return True
    return bool(row.engaged)


def capability_reads_blocked(engine: Engine, key: bytes | None, capability: object) -> bool:
    """The check `KillSwitch.is_blocked` and the break-glass read-back both use.

    Any failure (unknown capability, unreadable database, missing table) reads as blocked
    and is logged.
    """
    try:
        cap = KillCapability(str(capability))
        with read_connection(engine) as conn:
            row = conn.execute(
                select(killswitch_flag).where(killswitch_flag.c.capability == cap.value)
            ).first()
    except Exception:
        logger.exception("kill switch: cannot read state for %r; treating as blocked", capability)
        return True
    return row_reads_blocked(key, row)
