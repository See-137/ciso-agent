"""Pure helpers for the kill-switch service: validation, refusal rules, state views."""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from datetime import datetime
from typing import Any

from sqlalchemy import Connection, select

from ciso.common.enums import ActorType, AuditOutcome, KillCapability, Role
from ciso.common.errors import ValidationFailed
from ciso.common.principal import Principal
from ciso.common.protocols import AuditEvent
from ciso.killswitch.integrity import flag_row_verifies, row_reads_blocked
from ciso.killswitch.models import CapabilityState
from ciso.killswitch.tables import killswitch_flag


def normalise_capabilities(capabilities: Iterable[KillCapability]) -> tuple[KillCapability, ...]:
    """Validate and sort. An empty list or an unknown name raises ValidationFailed."""
    try:
        caps = sorted({KillCapability(cap) for cap in capabilities})
    except ValueError as exc:
        raise ValidationFailed(f"unknown kill-switch capability: {exc}") from exc
    if not caps:
        raise ValidationFailed("name at least one capability")
    return tuple(caps)


def require_text(value: str, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValidationFailed(f"{field} must not be blank")
    return value.strip()


def refusal(claimed: str, resolved: Principal | None) -> str | None:
    if resolved is None:
        return "unknown or disabled actor"
    if resolved.actor_id != claimed:
        return "identity store returned a different actor"
    if resolved.actor_type is not ActorType.HUMAN:
        return "only a human may change the kill switch"
    if not resolved.has_role(Role.SECURITY_ADMIN):
        return "security_admin role required"
    return None


def fetch_flag(conn: Connection, cap: KillCapability) -> Any:
    return conn.execute(
        select(killswitch_flag).where(killswitch_flag.c.capability == cap.value)
    ).first()


def state_of(cap: KillCapability, row: Any, key: bytes | None) -> CapabilityState:
    if row is None:
        return CapabilityState(capability=cap, engaged=True, recorded=False, verified=False)
    return CapabilityState(
        capability=cap,
        engaged=row_reads_blocked(key, row),
        recorded=True,
        verified=flag_row_verifies(key, row),
        stored_engaged=bool(row.engaged),
        version=int(row.version),
        changed_by=row.changed_by,
        changed_at=row.changed_at,
        reason=row.reason,
        via=row.via,
        operator=row.operator or None,
    )


def written_state(
    cap: KillCapability,
    *,
    engaged: bool,
    actor_id: str,
    reason: str,
    via: str,
    now: datetime,
    verified: bool,
) -> CapabilityState:
    """What was just committed, built without another read (which could fail)."""
    return CapabilityState(
        capability=cap, engaged=engaged or not verified, recorded=True, verified=verified,
        stored_engaged=engaged, changed_by=actor_id, changed_at=now, reason=reason, via=via,
    )  # fmt: skip


def target_of(caps: Sequence[KillCapability]) -> str:
    return "killswitch:" + ",".join(cap.value for cap in caps)


def denial_event(
    actor_id: str,
    actor_type: ActorType,
    action: str,
    caps: Sequence[KillCapability],
    reason: str,
    outcome: AuditOutcome = AuditOutcome.SUCCESS,
) -> AuditEvent:
    return AuditEvent(
        actor_id=actor_id,
        actor_type=actor_type,
        action=action,
        target=target_of(caps),
        outcome=outcome,
        details={"capabilities": [c.value for c in caps], "reason": reason},
    )
