"""Managed machines and their tokens (docs/skill/decision-api.md, "Authentication").

A device is an identity actor of type `service`, named for the machine, plus a row in
`app_devices`. Only an actor with an active row holds `governance.report`, the one
permission the decide and activity routes accept; no role template grants it, so no
person can report activity with their own token.

- `register`: a current human `security_admin` (re-resolved by the identity service, not
  taken from the caller object) creates the actor and gets its bearer token exactly once.
  The token is stored hashed and expires within `safety.max_token_ttl_seconds` (unset:
  the authenticator refuses to mint, and registration fails).
- `revoke`: disables the actor, which revokes every token it holds, and marks the row.

Audit order: ATTEMPT, then the identity service's own audited steps, then a short write
transaction on `app_devices` (no audit call inside it), then the RESULT.
"""

from __future__ import annotations

import logging
import re
from datetime import datetime
from typing import Any, Final

from sqlalchemy import Engine, select

from ciso.app.tables import devices
from ciso.common.clock import Clock
from ciso.common.db import read_connection
from ciso.common.enums import ActorType, AuditOutcome
from ciso.common.errors import Conflict, FailClosed, NotFound, ValidationFailed
from ciso.common.principal import Principal
from ciso.common.protocols import AuditEvent, AuditSink
from ciso.common.schemas import Model, UtcDatetime
from ciso.identity import Authenticator, IdentityService, IssuedToken

logger = logging.getLogger(__name__)

#: Same grammar as the decision API's `device` field.
DEVICE_NAME_RE: Final = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}")
REGISTER_ACTION: Final = "governance.device.register"
REVOKE_ACTION: Final = "governance.device.revoke"


class Device(Model):
    device_id: str
    name: str
    created_at: UtcDatetime
    created_by: str
    revoked_at: UtcDatetime | None = None
    revoked_by: str | None = None


class DeviceRegistration(Model):
    """Returned once by `register`. `token.token` is the only copy of the secret."""

    device: Device
    token: IssuedToken


def check_device_name(name: str) -> str:
    if not isinstance(name, str) or not DEVICE_NAME_RE.fullmatch(name):
        raise ValidationFailed("a device name is 1-64 characters of [A-Za-z0-9._-]")
    return name


class DeviceDirectory:
    def __init__(
        self,
        engine: Engine,
        *,
        clock: Clock,
        audit: AuditSink,
        identity: IdentityService,
        authenticator: Authenticator,
    ) -> None:
        self._engine = engine
        self._clock = clock
        self._audit = audit
        self._identity = identity
        self._authn = authenticator

    # -- reads -------------------------------------------------------------------------

    def is_device(self, actor_id: str) -> bool:
        """True when `actor_id` is a registered device that is not revoked. Raises when the
        table cannot be read; callers refuse."""
        with read_connection(self._engine) as conn:
            row = conn.execute(
                select(devices.c.actor_id)
                .where(devices.c.actor_id == actor_id)
                .where(devices.c.revoked_at.is_(None))
            ).first()
        return row is not None

    def active_name(self, actor_id: str) -> str | None:
        """The registered name of an active device actor; None for anything else (reviews
        H4, Q8: the decision uses this name, never the request's). Raises when the table
        cannot be read; callers refuse."""
        with read_connection(self._engine) as conn:
            row = conn.execute(
                select(devices.c.name)
                .where(devices.c.actor_id == actor_id)
                .where(devices.c.revoked_at.is_(None))
            ).first()
        return None if row is None else str(row.name)

    def get(self, device_id: str) -> Device:
        with read_connection(self._engine) as conn:
            row = conn.execute(select(devices).where(devices.c.actor_id == device_id)).first()
        if row is None:
            raise NotFound("no such device")
        return _device(row)

    # -- changes -----------------------------------------------------------------------

    def register(self, by: Principal, name: str) -> DeviceRegistration:
        """Create the device actor and issue its token. See the module docstring."""
        name = check_device_name(name)
        if self._active_named(name):
            raise Conflict("a device with this name is already registered")
        self._emit(by, REGISTER_ACTION, name, AuditOutcome.ATTEMPT, {"name": name})
        actor = self._identity.create_actor(by, ActorType.SERVICE, f"Device {name}")
        try:
            device = self._insert(actor.id, name, by.actor_id)
            issued = self._authn.issue_token(actor.id, by)
        except Exception as exc:
            self._emit(by, REGISTER_ACTION, actor.id, AuditOutcome.FAILED,
                       {"name": name, "error": type(exc).__name__})  # fmt: skip
            self._disable_quietly(by, actor.id)
            raise
        self._emit(by, REGISTER_ACTION, actor.id, AuditOutcome.SUCCESS,
                   {"name": name, "token_id": issued.token_id,
                    "expires_at": issued.expires_at.isoformat()})  # fmt: skip
        return DeviceRegistration(device=device, token=issued)

    def revoke(self, by: Principal, device_id: str) -> Device:
        """Disable the device actor (every token revoked) and mark the row revoked."""
        current = self.get(device_id)
        if current.revoked_at is not None:
            raise Conflict("the device is already revoked")
        self._emit(by, REVOKE_ACTION, device_id, AuditOutcome.ATTEMPT, {"name": current.name})
        self._identity.disable_actor(by, device_id)
        now = self._clock.now()
        with self._engine.begin() as conn:
            conn.execute(
                devices.update()
                .where(devices.c.actor_id == device_id)
                .where(devices.c.revoked_at.is_(None))
                .values(revoked_at=now, revoked_by=by.actor_id)
            )
        self._emit(by, REVOKE_ACTION, device_id, AuditOutcome.SUCCESS, {"name": current.name})
        return current.model_copy(update={"revoked_at": now, "revoked_by": by.actor_id})

    # -- helpers -----------------------------------------------------------------------

    def _active_named(self, name: str) -> bool:
        with read_connection(self._engine) as conn:
            row = conn.execute(
                select(devices.c.actor_id)
                .where(devices.c.name == name)
                .where(devices.c.revoked_at.is_(None))
            ).first()
        return row is not None

    def _insert(self, actor_id: str, name: str, created_by: str) -> Device:
        now = self._clock.now()
        device = Device(device_id=actor_id, name=name, created_at=now, created_by=created_by)
        with self._engine.begin() as conn:
            taken = conn.execute(
                select(devices.c.actor_id)
                .where(devices.c.name == name)
                .where(devices.c.revoked_at.is_(None))
            ).first()
            if taken is not None:
                raise Conflict("a device with this name is already registered")
            conn.execute(
                devices.insert().values(
                    actor_id=actor_id, name=name, created_at=now, created_by=created_by
                )
            )
        return device

    def _disable_quietly(self, by: Principal, actor_id: str) -> None:
        """A half-made device must not keep a usable actor. A failure here is logged; the
        actor then has no device row, so it can never report activity anyway."""
        try:
            self._identity.disable_actor(by, actor_id)
        except Exception as exc:
            logger.error("devices: could not disable half-made device actor (%s)",
                         type(exc).__name__)  # fmt: skip

    def _emit(
        self,
        by: Principal,
        action: str,
        target: str,
        outcome: AuditOutcome,
        details: dict[str, Any],
    ) -> None:
        event = AuditEvent(
            actor_id=by.actor_id,
            actor_type=by.actor_type,
            action=action,
            target=target,
            outcome=outcome,
            details=details,
        )
        try:
            self._audit.append(event)
        except Exception as exc:
            raise FailClosed("device change could not be audited") from exc


def _device(row: Any) -> Device:
    revoked_at: datetime | None = row.revoked_at
    return Device(
        device_id=row.actor_id,
        name=row.name,
        created_at=row.created_at,
        created_by=row.created_by,
        revoked_at=revoked_at,
        revoked_by=row.revoked_by,
    )
