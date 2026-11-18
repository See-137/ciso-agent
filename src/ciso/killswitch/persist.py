"""Writes shared by the service and the break-glass entry point. Review H4.

Every write here runs inside a short `BEGIN IMMEDIATE` transaction through `run_write`,
which retries a busy or locked database a bounded number of times and turns any final
failure into `FailClosed`, so no driver error leaks to the caller.
"""

from __future__ import annotations

import json
import logging
from collections.abc import Callable, Sequence
from datetime import datetime

from sqlalchemy import Connection, Engine, select, update
from sqlalchemy.exc import OperationalError

from ciso.common.enums import ActorType, KillCapability
from ciso.common.errors import CisoError, FailClosed
from ciso.common.ids import new_id
from ciso.killswitch.integrity import flag_mac, outbox_mac
from ciso.killswitch.tables import killswitch_flag, killswitch_pending_audit

logger = logging.getLogger(__name__)

#: Implementation retry for a busy/locked database, not a safety parameter. Each attempt
#: also waits up to the engine's own busy timeout before failing.
WRITE_ATTEMPTS = 5
WRITE_RETRY_PAUSE_SECONDS = 0.05


def _is_busy(exc: OperationalError) -> bool:
    text = str(exc.orig if exc.orig is not None else exc).lower()
    return "locked" in text or "busy" in text


def run_write[T](
    engine: Engine,
    work: Callable[[Connection], T],
    *,
    what: str,
    sleep: Callable[[float], None],
    attempts: int = WRITE_ATTEMPTS,
) -> T:
    """Run `work` in one write transaction. Platform errors raised by `work` pass through;
    anything else, or a database that stays locked, becomes `FailClosed`."""
    last: Exception | None = None
    for attempt in range(1, attempts + 1):
        try:
            with engine.begin() as conn:
                return work(conn)
        except CisoError:
            raise
        except OperationalError as exc:
            if not _is_busy(exc):
                raise FailClosed(f"{what} failed: database error") from exc
            last = exc
            logger.warning("kill switch: %s found the database busy (attempt %d)", what, attempt)
            if attempt < attempts:
                sleep(WRITE_RETRY_PAUSE_SECONDS)
        except Exception as exc:
            raise FailClosed(f"{what} failed: {type(exc).__name__}") from exc
    raise FailClosed(f"{what} failed: database stayed locked after {attempts} attempts") from last


def current_versions(conn: Connection) -> dict[str, int]:
    rows = conn.execute(select(killswitch_flag.c.capability, killswitch_flag.c.version))
    return {row.capability: int(row.version) for row in rows}


def write_flag(
    conn: Connection,
    cap: KillCapability,
    *,
    engaged: bool,
    changed_by: str,
    actor_type: ActorType,
    reason: str,
    via: str,
    operator: str,
    now: datetime,
    key: bytes | None,
) -> int:
    """Upsert one flag row with the next version and its MAC (None without a key).

    Returns the new version. Without a key the row is stored but reads as blocked.
    """
    version = current_versions(conn).get(cap.value, 0) + 1
    values = {
        "engaged": engaged,
        "version": version,
        "changed_by": changed_by,
        "actor_type": actor_type.value,
        "changed_at": now,
        "reason": reason,
        "via": via,
        "operator": operator,
        "mac": None
        if key is None
        else flag_mac(
            key,
            capability=cap.value,
            engaged=engaged,
            version=version,
            changed_by=changed_by,
            changed_at=now,
            reason=reason,
            via=via,
            operator=operator,
        ),
    }
    done = conn.execute(
        update(killswitch_flag).where(killswitch_flag.c.capability == cap.value).values(values)
    )
    if done.rowcount == 0:
        conn.execute(killswitch_flag.insert().values(capability=cap.value, **values))
    return version


def queue_engage_audit(
    conn: Connection,
    caps: Sequence[KillCapability],
    *,
    actor_id: str,
    reason: str,
    via: str,
    operator: str,
    now: datetime,
    key: bytes | None,
) -> int:
    """Insert the outbox row for an engage. Returns its seq."""
    entry_id = new_id("ksaudit")
    capabilities = json.dumps([cap.value for cap in caps])
    mac = None
    if key is not None:
        mac = outbox_mac(
            key, entry_id=entry_id, actor_id=actor_id, capabilities=capabilities,
            reason=reason, via=via, operator=operator, recorded_at=now,
        )  # fmt: skip
    result = conn.execute(
        killswitch_pending_audit.insert().values(
            entry_id=entry_id, actor_id=actor_id, capabilities=capabilities, reason=reason,
            via=via, operator=operator, recorded_at=now, mac=mac, quarantined=False,
            last_error="",
        )
    )  # fmt: skip
    seq = result.inserted_primary_key[0] if result.inserted_primary_key else None
    if not isinstance(seq, int):
        raise FailClosed("kill-switch outbox row was not written")
    return seq


def engage_rows(
    conn: Connection,
    caps: Sequence[KillCapability],
    *,
    actor_id: str,
    actor_type: ActorType,
    reason: str,
    via: str,
    operator: str,
    now: datetime,
    key: bytes | None,
) -> int:
    """Engage the flags and queue the audit record in one transaction. Returns the seq."""
    for cap in caps:
        write_flag(
            conn, cap, engaged=True, changed_by=actor_id, actor_type=actor_type,
            reason=reason, via=via, operator=operator, now=now, key=key,
        )  # fmt: skip
    return queue_engage_audit(
        conn, caps, actor_id=actor_id, reason=reason, via=via, operator=operator, now=now,
        key=key,
    )  # fmt: skip
