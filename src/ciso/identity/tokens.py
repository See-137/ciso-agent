"""Bearer token minting and verification. Internal to `ciso.identity`.

Token format: `<token_id>.<secret>`. Only a scrypt hash of the secret is stored, with its
salt and cost parameters. Parsing is exact (`re.fullmatch`): trailing whitespace or a
newline makes a token malformed (review L3).
"""

from __future__ import annotations

import hashlib
import hmac
import re
import secrets
from datetime import datetime, timedelta
from typing import Any

from pydantic import Field, field_validator
from sqlalchemy import Connection

from ciso.common.errors import FailClosed, ValidationFailed
from ciso.common.ids import new_id
from ciso.common.schemas import Model, UtcDatetime
from ciso.identity import tables as t

_TOKEN_RE = re.compile(r"(tok_[0-9A-HJKMNP-TV-Z]{26})\.([A-Za-z0-9_-]{32,128})")
_SECRET_BYTES = 32
_SALT_BYTES = 16
_DIGEST_BYTES = 32


class ScryptParams(Model):
    """scrypt cost: `n` (CPU/memory, power of two), `r` (block size), `p` (parallelism)."""

    n: int
    r: int
    p: int

    @field_validator("n")
    @classmethod
    def _power_of_two(cls, n: int) -> int:
        if n < 2 or n & (n - 1):
            raise ValueError("scrypt n must be a power of two greater than 1")
        return n

    @field_validator("r", "p")
    @classmethod
    def _positive(cls, value: int) -> int:
        if value < 1:
            raise ValueError("scrypt r and p must be at least 1")
        return value


#: Production-leaning default: n=2**14, r=8, p=1 (16 MiB, tens of ms per hash). These
#: are the scrypt paper's interactive-login parameters. The secrets hashed here are 256
#: random bits, so brute force is already infeasible; the cost guards against a leaked
#: table being cheap to test at scale while keeping per-request authentication tolerable.
#: Each credential row stores its own parameters, so raising them later breaks nothing.
PRODUCTION_SCRYPT = ScryptParams(n=2**14, r=8, p=1)


def _scrypt(secret: str, salt: bytes, params: ScryptParams) -> bytes:
    return hashlib.scrypt(
        secret.encode("utf-8"),
        salt=salt,
        n=params.n,
        r=params.r,
        p=params.p,
        maxmem=256 * params.n * params.r * params.p + (1 << 20),
        dklen=_DIGEST_BYTES,
    )


def parse_token(token: object) -> tuple[str, str] | None:
    """(token_id, secret) for an exactly well-formed token, else None."""
    if not isinstance(token, str):
        return None
    match = _TOKEN_RE.fullmatch(token)
    return None if match is None else (match.group(1), match.group(2))


class IssuedToken(Model):
    """Returned once. `token` is hidden from repr and is never stored."""

    token_id: str
    actor_id: str
    expires_at: UtcDatetime
    token: str = Field(repr=False)


class TokenMinter:
    """Creates and checks token hashes. `max_token_ttl=None` refuses to mint (fail closed)."""

    def __init__(self, max_token_ttl: timedelta | None, scrypt: ScryptParams) -> None:
        self._max_ttl = max_token_ttl
        self._scrypt = scrypt

    def lifetime(self, ttl: timedelta | None) -> timedelta:
        """`ttl`, or `max_token_ttl` if `ttl` is None. Raises if unconfigured or out of range."""
        if self._max_ttl is None:
            raise FailClosed("max_token_ttl is not configured; refusing to issue tokens")
        lifetime = self._max_ttl if ttl is None else ttl
        if lifetime <= timedelta(0) or lifetime > self._max_ttl:
            raise ValidationFailed("token lifetime must be positive and within max_token_ttl")
        return lifetime

    def mint(
        self, conn: Connection, actor_id: str, issued_by: str, now: datetime, expires_at: datetime
    ) -> IssuedToken:
        """Insert a credential row for exactly one actor and return the only copy of the token."""
        token_id = new_id("tok")
        secret = secrets.token_urlsafe(_SECRET_BYTES)
        salt = secrets.token_bytes(_SALT_BYTES)
        conn.execute(
            t.credentials.insert().values(
                token_id=token_id,
                actor_id=actor_id,
                secret_hash=_scrypt(secret, salt, self._scrypt).hex(),
                salt=salt.hex(),
                scrypt_n=self._scrypt.n,
                scrypt_r=self._scrypt.r,
                scrypt_p=self._scrypt.p,
                created_at=now,
                created_by=issued_by,
                expires_at=expires_at,
            )
        )
        return IssuedToken(
            token_id=token_id,
            actor_id=actor_id,
            expires_at=expires_at,
            token=f"{token_id}.{secret}",
        )

    def verify(self, secret: str, row: Any) -> bool:
        """Constant-time comparison of `secret` against a stored credential row."""
        params = ScryptParams(n=row.scrypt_n, r=row.scrypt_r, p=row.scrypt_p)
        computed = _scrypt(secret, bytes.fromhex(row.salt), params)
        return hmac.compare_digest(computed, bytes.fromhex(row.secret_hash))

    def burn(self, secret: str) -> None:
        """Spend one hash on a token that cannot match, so timing does not reveal why."""
        _scrypt(secret, bytes(_SALT_BYTES), self._scrypt)
