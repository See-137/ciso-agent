"""Bootstrap authentication: one-time bearer tokens (NFR-004, FR-003; blueprint 9.3).

The identity provider is undecided (OD-03), so this is a local fallback: a security_admin
issues a token to exactly one actor, the token string is returned once, and only a scrypt
hash of its secret is stored. MFA and SSO belong to the provider OD-03 picks;
`ExternalIdentityAdapter` says what such an integration must supply.

Known limit of this bootstrap model (review M4): an administrator can mint a token for
another human, including an approver, and then act as that person. Each credential
records who issued it, and `authenticate` sets `Principal.credential_issued_by`; the
approvals module refuses an approver whose credential the requester issued.

Authentication rules:
- Every rejection raises `AuthenticationError` with one message, whatever the cause.
- A malformed token or an unknown token id writes no audit record; it is logged and
  counted (review F8). Failures against a real token id are audited, as
  `actor_id="unauthenticated"`, `ActorType.ANONYMOUS` until the secret has matched.
- The credential is read and scrypt runs outside any write transaction; a short write
  transaction then records `last_used_at` (no write lock is held across an audit append).
- A successful authentication whose audit write fails still returns the principal, so
  people can sign in to investigate while the log refuses appends (review F7). It is
  logged as an error and counted; state changes are still stopped because they audit
  before acting.
"""

from __future__ import annotations

import logging
import threading
from datetime import datetime, timedelta
from typing import Any, NoReturn, Protocol

from sqlalchemy import Connection, Engine, select

from ciso.common.clock import Clock
from ciso.common.db import read_connection
from ciso.common.enums import ActorType, AuditOutcome
from ciso.common.errors import AuthenticationError, Conflict, FailClosed, NotFound
from ciso.common.principal import Principal
from ciso.common.protocols import AuditSink
from ciso.common.schemas import Model
from ciso.identity import tables as t
from ciso.identity.gate import AdminGate, Caller
from ciso.identity.service import IdentityService
from ciso.identity.store import (
    UNAUTHENTICATED,
    Actor,
    ActorStatus,
    admin_refusal,
    find_actor,
    load_actor,
    write_audit,
)
from ciso.identity.tokens import (
    PRODUCTION_SCRYPT,
    IssuedToken,
    ScryptParams,
    TokenMinter,
    parse_token,
)

__all__ = [
    "PRODUCTION_SCRYPT",
    "Authenticator",
    "ExternalIdentityAdapter",
    "ExternalSubject",
    "IssuedToken",
    "ScryptParams",
]

logger = logging.getLogger(__name__)

_FAILURE_MESSAGE = "authentication failed"
_ACTION = "identity.authenticate"


class ExternalSubject(Model):
    """What an external identity provider asserts about a signed-in person or workload."""

    issuer: str
    subject: str
    display_name: str
    groups: frozenset[str] = frozenset()
    #: Authentication methods the provider says were used (for example a second factor).
    methods: frozenset[str] = frozenset()


class ExternalIdentityAdapter(Protocol):
    """Interface only (OD-03): what an SSO integration must provide. No implementation.

    The platform keeps its own Actor rows and role assignments; the provider proves who
    someone is, and the security_admin maps provider subjects to actors and roles.
    """

    def verify(self, assertion: str) -> ExternalSubject:
        """Validate a provider assertion (signature, issuer, audience, expiry, replay).

        Raises `AuthenticationError` for anything invalid.
        """
        ...

    def is_active(self, subject: ExternalSubject) -> bool:
        """True while the provider still considers the subject enabled."""
        ...

    def actor_ref(self, subject: ExternalSubject) -> str | None:
        """The local actor id this subject is mapped to, or None if unmapped."""
        ...


class Authenticator:
    """Issues, revokes and checks bootstrap tokens.

    `max_token_ttl` is the longest lifetime a token may have. With `None` nothing is issued
    (fail closed, no invented default). `scrypt` sets the hashing cost for new tokens.
    """

    def __init__(
        self,
        engine: Engine,
        clock: Clock,
        audit: AuditSink,
        identity: IdentityService,
        *,
        max_token_ttl: timedelta | None = None,
        scrypt: ScryptParams = PRODUCTION_SCRYPT,
    ) -> None:
        self._engine = engine
        self._clock = clock
        self._audit = audit
        self._identity = identity
        self._minter = TokenMinter(max_token_ttl, scrypt)
        self._gate = AdminGate(engine, clock, audit)
        self._lock = threading.Lock()
        self._counters = {
            "rejected_unaudited": 0,
            "success_audit_failures": 0,
            "failure_audit_failures": 0,
        }

    @property
    def minter(self) -> TokenMinter:
        """For the host-local operations, which mint without an authenticated caller."""
        return self._minter

    def counters(self) -> dict[str, int]:
        """A copy of the authentication counters (for metrics and health)."""
        with self._lock:
            return dict(self._counters)

    def _count(self, name: str) -> None:
        with self._lock:
            self._counters[name] += 1

    # -- issuing and revoking ---------------------------------------------------------

    def issue_token(
        self, actor_id: str, issued_by: Caller, ttl: timedelta | None = None
    ) -> IssuedToken:
        """Issue a token for one active actor. `ttl=None` means `max_token_ttl`.

        Only a current human security_admin (re-resolved by actor id) may issue. The
        returned token is the only copy; the issuer is stored with the credential.
        """
        lifetime = self._minter.lifetime(ttl)

        def change(conn: Connection, now: datetime) -> tuple[IssuedToken, dict[str, Any]]:
            if load_actor(conn, actor_id).status is not ActorStatus.ACTIVE:
                raise Conflict(f"actor {actor_id} is disabled")
            issuer = issued_by if isinstance(issued_by, str) else issued_by.actor_id
            issued = self._minter.mint(conn, actor_id, issuer, now, now + lifetime)
            return issued, {
                "token_id": issued.token_id,
                "expires_at": issued.expires_at.isoformat(),
            }

        details = {"lifetime_seconds": int(lifetime.total_seconds())}
        result: IssuedToken = self._gate.run(
            issued_by, "identity.token.issue", actor_id, details, change
        )
        return result

    def revoke_token(self, token_id: str, revoked_by: Caller) -> None:
        """Revoke a token. A current human security_admin or the token's own actor may."""

        def authorize(conn: Connection, caller: str, now: datetime) -> str | None:
            row = conn.execute(
                select(t.credentials.c.actor_id).where(t.credentials.c.token_id == token_id)
            ).first()
            if row is not None and row.actor_id == caller:
                owner = find_actor(conn, caller)
                if owner is not None and owner.status is ActorStatus.ACTIVE:
                    return None
            return admin_refusal(conn, caller, now)

        def change(conn: Connection, now: datetime) -> tuple[None, dict[str, Any]]:
            row = conn.execute(
                select(t.credentials).where(t.credentials.c.token_id == token_id)
            ).first()
            if row is None:
                raise NotFound(f"no such token: {token_id}")
            if row.revoked_at is not None:
                raise Conflict(f"token {token_id} is already revoked")
            by = revoked_by if isinstance(revoked_by, str) else revoked_by.actor_id
            conn.execute(
                t.credentials.update()
                .where(t.credentials.c.token_id == token_id)
                .values(revoked_at=now, revoked_by=by)
            )
            return None, {"actor": row.actor_id}

        self._gate.run(revoked_by, "identity.token.revoke", token_id, {}, change, authorize)

    # -- authentication ---------------------------------------------------------------

    def _unaudited(self, reason: str) -> NoReturn:
        self._count("rejected_unaudited")
        logger.info("identity: authentication refused (%s)", reason)
        raise AuthenticationError(_FAILURE_MESSAGE)

    def _refuse(self, reason: str, token_id: str, actor: Actor | None) -> NoReturn:
        try:
            write_audit(
                self._audit,
                actor_id=actor.id if actor else UNAUTHENTICATED,
                actor_type=actor.actor_type if actor else ActorType.ANONYMOUS,
                action=_ACTION,
                target=token_id,
                outcome=AuditOutcome.DENIED,
                details={"reason": reason},
            )
        except FailClosed:
            self._count("failure_audit_failures")
            logger.error("identity: refused authentication (%s) could not be audited", reason)
        logger.info("identity: authentication refused (%s)", reason)
        raise AuthenticationError(_FAILURE_MESSAGE)

    def authenticate(self, token: str) -> Principal:
        """Return the principal of the token's actor or raise `AuthenticationError`.

        Rejects a malformed token, an unknown token id, a wrong secret, an expired or
        revoked token, and a disabled actor, all with one message.
        """
        parsed = parse_token(token)
        if parsed is None:
            self._minter.burn("x")  # keep timing uniform
            self._unaudited("malformed")
        token_id, secret = parsed
        with read_connection(self._engine) as conn:
            row = conn.execute(
                select(t.credentials).where(t.credentials.c.token_id == token_id)
            ).first()
            actor = find_actor(conn, row.actor_id) if row is not None else None
        if row is None:
            self._minter.burn(secret)
            self._unaudited("unknown_token")
        if not self._minter.verify(secret, row):
            self._refuse("wrong_secret", token_id, None)
        now = self._clock.now()
        if row.revoked_at is not None:
            self._refuse("revoked", token_id, actor)
        if now >= row.expires_at:
            self._refuse("expired", token_id, actor)
        resolved = self._identity.resolve(row.actor_id)
        if resolved is None:
            self._refuse("actor_disabled", token_id, actor)
        principal = resolved.model_copy(update={"credential_issued_by": row.created_by})
        self._touch(token_id, now, actor)
        self._audit_success(principal, token_id)
        return principal

    def _touch(self, token_id: str, now: datetime, actor: Actor | None) -> None:
        with self._engine.begin() as conn:
            touched = conn.execute(
                t.credentials.update()
                .where(t.credentials.c.token_id == token_id)
                .where(t.credentials.c.revoked_at.is_(None))
                .values(last_used_at=now)
            ).rowcount
        if touched != 1:  # revoked between the read and this write
            self._refuse("revoked", token_id, actor)

    def _audit_success(self, principal: Principal, token_id: str) -> None:
        try:
            write_audit(
                self._audit,
                actor_id=principal.actor_id,
                actor_type=principal.actor_type,
                action=_ACTION,
                target=token_id,
                outcome=AuditOutcome.SUCCESS,
                details={"roles": sorted(r.value for r in principal.roles)},
            )
        except FailClosed:
            self._count("success_audit_failures")
            logger.error(
                "identity: actor %s authenticated but the audit write failed", principal.actor_id
            )
        else:
            logger.info("identity: actor %s authenticated", principal.actor_id)
