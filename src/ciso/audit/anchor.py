"""HMAC-keyed head anchor for the audit chain (gap G4, blueprint §11 audit tampering, NFR-006).

An unkeyed hash chain cannot show that rows were cut off the end, and anyone who can write
the database file can drop the triggers and recompute every hash. The anchor closes both
holes. It is a small JSON file kept OUTSIDE the audit database:

    {"version": 2, "key_id": ..., "log_id": ..., "final": {"seq", "head_hash"},
     "pending": {"seq", "head_hash"} | null, "hmac": ...}

`hmac` is HMAC-SHA256 over every other field plus a domain label, with a key resolved from
the injected `SecretResolver` by reference (`secret://...`). `key_id` is a hash of the key
(never the key), so an anchor written under a different key reports `key_mismatch`
instead of a bad MAC: a key rotation is told apart from tampering (rotation itself is not
built). Without the key nobody can produce a matching anchor for a rewritten, shortened or
swapped chain. The anchor alone cannot detect the database and the anchor being rolled
back together to an older, validly signed pair: that needs a `HeadWitness` (witness.py).

Two-phase protocol (used by `AuditLog`): before COMMIT the writer records `pending` (the
head the transaction will create); after COMMIT it promotes `pending` to `final`. A crash
or failed COMMIT in between leaves a state that is recognisable and repaired
automatically (see `ciso.audit.reconcile`).

Caller duties: keep the anchor path on storage the audit database's attacker cannot reach
(location provisional, ADR-0014 / OD-01) and back it up with the database. A restored
database must be restored with its anchor.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import tempfile
import threading
import time
from collections.abc import Callable
from enum import StrEnum
from pathlib import Path
from typing import Any, TypeGuard

from ciso.common.errors import FailClosed, NotFound, ValidationFailed
from ciso.common.protocols import SecretResolver
from ciso.common.schemas import Model, canonical_json
from ciso.vault import resolve_key_bytes

logger = logging.getLogger(__name__)

ANCHOR_FORMAT_VERSION = 2
_SECRET_PREFIX = "secret://"  # noqa: S105 - a URI scheme, not a secret
_DOMAIN = "ciso.audit.anchor"
_HEX64 = frozenset("0123456789abcdef")

#: Windows refuses to replace or open a file while another handle (a reader in another
#: process, an antivirus scan) has it open. These bound an implementation retry; they are
#: not a safety parameter. Total wait is at most attempts x pause.
FILE_RETRY_ATTEMPTS = 20
FILE_RETRY_PAUSE_SECONDS = 0.025


class AnchorState(StrEnum):
    PRESENT = "present"  # MAC checked and valid
    MISSING = "missing"
    UNREADABLE = "unreadable"
    INVALID_MAC = "invalid_mac"
    KEY_MISMATCH = "key_mismatch"  # signed with another key: rotation or a foreign anchor


class AnchorEntry(Model):
    seq: int
    head_hash: str


class AnchorReading(Model):
    state: AnchorState
    log_id: str | None = None
    final: AnchorEntry | None = None
    pending: AnchorEntry | None = None


class AnchorKey:
    """A resolved HMAC key. Hidden from repr; never log or serialise it.

    `key_id` is the first 16 hex characters of SHA-256 over a label and the key: it names
    the key without revealing it.
    """

    __slots__ = ("_raw",)

    def __init__(self, raw: bytes) -> None:
        self._raw = raw

    @property
    def key_id(self) -> str:
        return hashlib.sha256(b"ciso.audit.key-id:" + self._raw).hexdigest()[:16]

    def mac(self, fields: dict[str, Any]) -> str:
        message = canonical_json(fields).encode("utf-8")
        return hmac.new(self._raw, message, hashlib.sha256).hexdigest()

    def sign(self, log_id: str, final: AnchorEntry, pending: AnchorEntry | None) -> str:
        return self.mac(_signed_fields(self.key_id, log_id, final, pending))

    def __repr__(self) -> str:
        return "AnchorKey(***)"


def resolve_key(secrets: SecretResolver, key_ref: str) -> AnchorKey:
    """Resolve an HMAC key by `secret://` reference. Raises FailClosed if it cannot be had,
    is empty or is shorter than `ciso.vault.MIN_KEY_BYTES`."""
    try:
        raw = resolve_key_bytes(secrets, key_ref)
    except FailClosed as exc:
        raise FailClosed(f"audit {exc}") from exc
    except NotFound as exc:
        raise FailClosed(f"audit key unavailable: {key_ref}") from exc
    except Exception as exc:
        raise FailClosed(f"audit key could not be resolved: {key_ref}") from exc
    return AnchorKey(raw)


def require_secret_ref(key_ref: str) -> str:
    if not key_ref.startswith(_SECRET_PREFIX) or len(key_ref) == len(_SECRET_PREFIX):
        raise ValidationFailed("an audit key must be a secret:// reference")
    return key_ref


def _signed_fields(
    key_id: str, log_id: str, final: AnchorEntry, pending: AnchorEntry | None
) -> dict[str, Any]:
    return {
        "domain": _DOMAIN,
        "version": ANCHOR_FORMAT_VERSION,
        "key_id": key_id,
        "log_id": log_id,
        "final": final.model_dump(),
        "pending": pending.model_dump() if pending is not None else None,
    }


class HeadAnchor:
    """Reads and writes the anchor file at `path` with the key behind `key_ref`."""

    def __init__(self, path: Path, secrets: SecretResolver, key_ref: str) -> None:
        self._key_ref = require_secret_ref(key_ref)
        self._path = Path(path)
        self._secrets = secrets
        self._lock = threading.Lock()

    @property
    def path(self) -> Path:
        return self._path

    def exists(self) -> bool:
        return self._path.exists()

    def load_key(self) -> AnchorKey:
        """Resolve the key now. Raises FailClosed if it cannot be had."""
        return resolve_key(self._secrets, self._key_ref)

    def write(
        self, key: AnchorKey, log_id: str, final: AnchorEntry, pending: AnchorEntry | None = None
    ) -> None:
        """Atomically replace the anchor. Raises FailClosed on any I/O error.

        Temp file in the same directory, flushed, fsynced and closed, then renamed over the
        target with a bounded retry while another handle holds the target open.
        """
        if pending is not None and pending.seq <= final.seq:
            raise ValidationFailed("a pending anchor entry must be ahead of the final one")
        document = {
            **_signed_fields(key.key_id, log_id, final, pending),
            "hmac": key.sign(log_id, final, pending),
        }
        del document["domain"]
        payload = canonical_json(document).encode("utf-8")
        with self._lock:
            tmp = self._write_temp(payload)
            try:
                _retry(lambda: tmp.replace(self._path))
            except OSError as exc:
                tmp.unlink(missing_ok=True)
                raise FailClosed("audit anchor could not be written") from exc
            fsync_directory(self._path.parent)

    def _write_temp(self, payload: bytes) -> Path:
        try:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            fd, name = tempfile.mkstemp(
                prefix=f".{self._path.name}.", suffix=".tmp", dir=self._path.parent
            )
        except OSError as exc:
            raise FailClosed("audit anchor could not be written") from exc
        tmp = Path(name)
        try:
            with os.fdopen(fd, "wb") as handle:
                handle.write(payload)
                handle.flush()
                os.fsync(handle.fileno())
        except OSError as exc:
            tmp.unlink(missing_ok=True)
            raise FailClosed("audit anchor could not be written") from exc
        return tmp

    def read(self, key: AnchorKey) -> AnchorReading:
        """Read and authenticate the anchor. Never raises for a bad or absent file.

        The file is read in one call and closed at once, so the reader's handle is open
        for as short a time as possible; a read that collides with a replace is retried.
        """
        with self._lock:
            try:
                raw = _retry(self._path.read_bytes)
            except FileNotFoundError:
                return AnchorReading(state=AnchorState.MISSING)
            except OSError:
                logger.warning("audit anchor exists but cannot be read")
                return AnchorReading(state=AnchorState.UNREADABLE)
        parsed = _parse(raw)
        if parsed is None:
            return AnchorReading(state=AnchorState.UNREADABLE)
        key_id, log_id, final, pending, mac = parsed
        if key_id != key.key_id:
            return AnchorReading(state=AnchorState.KEY_MISMATCH, log_id=log_id)
        state = (
            AnchorState.PRESENT
            if hmac.compare_digest(key.sign(log_id, final, pending), mac)
            else AnchorState.INVALID_MAC
        )
        return AnchorReading(state=state, log_id=log_id, final=final, pending=pending)


def _retry[T](operation: Callable[[], T]) -> T:
    """Run `operation`, retrying PermissionError (a Windows sharing violation)."""
    for attempt in range(1, FILE_RETRY_ATTEMPTS + 1):
        try:
            return operation()
        except PermissionError:
            if attempt == FILE_RETRY_ATTEMPTS:
                raise
            logger.warning("audit anchor busy (attempt %d), retrying", attempt)
            time.sleep(FILE_RETRY_PAUSE_SECONDS)
    raise AssertionError("unreachable")  # pragma: no cover


def fsync_directory(directory: Path) -> None:
    """Make a rename durable where the platform allows it (POSIX). Windows offers no
    directory handle to fsync; NTFS journals the rename itself."""
    if os.name == "nt":
        return
    try:
        fd = os.open(directory, os.O_RDONLY)
    except OSError as exc:
        raise FailClosed("audit directory could not be synced") from exc
    try:
        os.fsync(fd)
    except OSError as exc:
        raise FailClosed("audit directory could not be synced") from exc
    finally:
        os.close(fd)


def _parse(raw: bytes) -> tuple[str, str, AnchorEntry, AnchorEntry | None, str] | None:
    try:
        data = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        return None
    if not isinstance(data, dict) or data.get("version") != ANCHOR_FORMAT_VERSION:
        return None
    key_id, log_id, mac = data.get("key_id"), data.get("log_id"), data.get("hmac")
    if not isinstance(key_id, str) or not key_id:
        return None
    final = _entry(data.get("final"))
    pending = _entry(data.get("pending")) if data.get("pending") is not None else None
    if not isinstance(log_id, str) or not log_id or not _is_hex64(mac) or final is None:
        return None
    if data.get("pending") is not None and (pending is None or pending.seq <= final.seq):
        return None
    return key_id, log_id, final, pending, mac


def _entry(value: object) -> AnchorEntry | None:
    if not isinstance(value, dict):
        return None
    seq, head_hash = value.get("seq"), value.get("head_hash")
    if type(seq) is not int or seq < 0 or not _is_hex64(head_hash):
        return None
    return AnchorEntry(seq=seq, head_hash=head_hash)


def _is_hex64(value: object) -> TypeGuard[str]:
    return isinstance(value, str) and len(value) == 64 and set(value) <= _HEX64
