"""Head witness: a record of past heads kept where the data-directory writer cannot reach
(review C1, blueprint §11 audit tampering, NFR-006).

The anchor proves the database matches a head that was signed with the key, but an old
database restored together with its old anchor is still a validly signed pair. A witness
remembers every head it was shown, so `verify()` can tell that the chain no longer
contains a head it once had: status `failed`, reason `rolled_back`. `AuditLog` also checks
the witness before every append, so its own writer never grows a rolled-back chain past the
witnessed head (which would hide the rollback); two different heads recorded for one seq
are reported as `witness_invalid`.

`FileHeadWitness` is an append-only file of HMAC-signed lines. It only protects anything
if its path is on storage the audit database's writer cannot change (another host, a
WORM share, a different OS identity); the path comes from settings
(`Settings.audit_witness_path`) and is unset by default, in which case the log reports
`witnessed=False`. Where that storage lives is open (OD-01, ADR-0013).

Torn writes. A crash in the middle of `publish` can leave a cut-short last line. Reading
ignores it only under the rules in `ciso.audit.witness_lines` (last line, every earlier
line verified) and `read()` reports it as `torn_tail`, which `AuditLog.verify()` turns
into the warning `witness_torn_tail`. The next `publish` starts on a fresh line and signs
the fragment's digest into its `repairs` field, so the fragment stays in the file (nothing
is ever cut away, which also suits append-only storage) and is accepted from then on. A
bad line anywhere else is still `witness_invalid`.

Cost, stated plainly: `latest()` reads and checks the whole file, and `AuditLog` calls it
before every append (and `publish` reads it again to find a torn tail), so append time
grows with the file. There is no index and no
rotation. `size_bytes()` exposes the file size so a health check can flag growth; the
threshold is not configured anywhere yet (a settings value is a pending contract change),
so no such check is registered.
"""

from __future__ import annotations

import logging
import os
import threading
from datetime import datetime
from pathlib import Path
from typing import Protocol, runtime_checkable

from ciso.audit.anchor import fsync_directory, require_secret_ref, resolve_key
from ciso.audit.witness_lines import (
    WitnessedHead,
    encode,
    fields,
    fragment_digest,
    last_fragment,
    scan,
)
from ciso.common.clock import ensure_utc
from ciso.common.errors import FailClosed, IntegrityFailure
from ciso.common.protocols import SecretResolver
from ciso.common.schemas import Model

logger = logging.getLogger(__name__)

NEWLINE = b"\n"

__all__ = ["FileHeadWitness", "HeadWitness", "ReadingWitness", "WitnessReading", "WitnessedHead"]


@runtime_checkable
class HeadWitness(Protocol):
    def publish(self, log_id: str, seq: int, head_hash: str, at: datetime) -> None:
        """Record a head. Raise on any failure; the caller then fails closed."""
        ...

    def latest(self, log_id: str) -> WitnessedHead | None:
        """Highest head recorded for `log_id`, or None if there is none.

        Raise IntegrityFailure for a record that fails its signature, FailClosed if the
        store cannot be read.
        """
        ...


class WitnessReading(Model):
    """`head`: as `HeadWitness.latest`. `torn_tail`: the store ends in a torn write that
    was ignored for reading and not yet stepped over by a publish."""

    head: WitnessedHead | None
    torn_tail: bool = False


@runtime_checkable
class ReadingWitness(HeadWitness, Protocol):
    """A witness that can also say whether it ignored a torn tail."""

    def read(self, log_id: str) -> WitnessReading: ...


class FileHeadWitness:
    """Append-only JSON-lines file, one HMAC-signed head per line."""

    def __init__(self, path: Path, secrets: SecretResolver, key_ref: str) -> None:
        self._path = Path(path)
        self._secrets = secrets
        self._key_ref = require_secret_ref(key_ref)
        self._lock = threading.Lock()

    @property
    def path(self) -> Path:
        return self._path

    def size_bytes(self) -> int:
        """Current size of the witness file; 0 when it does not exist yet.

        Raises FailClosed if the file exists but cannot be inspected.
        """
        try:
            return self._path.stat().st_size
        except FileNotFoundError:
            return 0
        except OSError as exc:
            raise FailClosed("audit head witness size could not be read") from exc

    def publish(self, log_id: str, seq: int, head_hash: str, at: datetime) -> None:
        """Append one signed head. Over a torn tail the line starts on a fresh line and
        signs the fragment's digest (`repairs`). Raises FailClosed on any I/O error and
        IntegrityFailure if the last line parses but fails its signature."""
        key = resolve_key(self._secrets, self._key_ref)
        with self._lock:
            raw = self._read_raw()
            fragment = last_fragment(key, raw) if raw else None
            repairs = fragment_digest(fragment) if fragment is not None else None
            values = fields(key.key_id, log_id, seq, head_hash, ensure_utc(at), repairs)
            prefix = NEWLINE if raw and not raw.endswith(NEWLINE) else b""
            if fragment is not None:
                logger.warning("audit head witness: stepping over a torn last line")
            try:
                self._path.parent.mkdir(parents=True, exist_ok=True)
                is_new = not self._path.exists()
                with self._path.open("ab") as handle:
                    handle.write(prefix + encode(key, values) + NEWLINE)
                    handle.flush()
                    os.fsync(handle.fileno())
            except OSError as exc:
                raise FailClosed("audit head witness could not be written") from exc
            if is_new:
                fsync_directory(self._path.parent)

    def latest(self, log_id: str) -> WitnessedHead | None:
        return self.read(log_id).head

    def read(self, log_id: str) -> WitnessReading:
        """Highest head for `log_id` and whether a torn tail was ignored. Raises as
        `HeadWitness.latest` does; a torn line anywhere but the end is IntegrityFailure."""
        key = resolve_key(self._secrets, self._key_ref)
        with self._lock:
            raw = self._read_raw()
        result = scan(key, raw)
        best: WitnessedHead | None = None
        seen: dict[int, str] = {}
        for head in result.heads:
            if head.log_id != log_id:
                continue
            if seen.setdefault(head.seq, head.head_hash) != head.head_hash:
                # One log never has two heads at one seq: the log was rolled back and
                # grown again by a witnessed writer (second review R1).
                raise IntegrityFailure(f"audit head witness has conflicting heads at {head.seq}")
            if best is None or head.seq > best.seq:
                best = head
        return WitnessReading(head=best, torn_tail=result.torn_tail is not None)

    def _read_raw(self) -> bytes:
        try:
            return self._path.read_bytes()
        except FileNotFoundError:
            return b""
        except OSError as exc:
            raise FailClosed("audit head witness could not be read") from exc
