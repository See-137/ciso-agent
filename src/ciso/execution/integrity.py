"""The MAC on `execution_run` rows (review finding M7; same threat as ADR-0018's
kill-switch rows).

`succeeded`, the idempotency answer, the rate count and recovery are all read from rows
in the operational database, which is not tamper-evident. Each row therefore carries an
HMAC-SHA256 over every field of its `ExecutionRecord` (state, envelope hash, stored
envelope hash, idempotency key, actor, approval reference, both audit references, the
run token, the tool's claim and the verification result, the timestamps), keyed with a
secret resolved through the `SecretResolver` from `key_ref`.

What this gives: a writer without the key cannot turn a failed run into `verified`, move
a row to another key or actor, or swap the stored request, without the row becoming
unreadable. A row whose MAC does not verify is `ExecutionStoreError` (a `FailClosed`)
for replay, the rate limiter and recovery alike.

What it does not give, stated plainly:

- A DELETED row cannot be detected. A MAC authenticates a row that exists; nothing in
  this table shows that a row is missing. After a delete the same envelope runs again
  and the rate window is empty. The audit log (ATTEMPT and result records, hash-chained
  in its own database) is the record that survives; nothing here cross-checks it.
- A row copied back from an older state of the same row (a replay of the row itself)
  verifies, because the old row was genuine when it was written.
- A writer who holds the key is not stopped. In one process (ADR-0010) the key is
  reachable by any code in it.

No key reference means no key: the store refuses every read and write and the broker
refuses every execution. A key is never generated here.
"""

from __future__ import annotations

import hashlib
import hmac
import re

from ciso.common.protocols import SecretResolver
from ciso.common.schemas import canonical_json
from ciso.execution.records import ExecutionRecord, ExecutionStoreError

#: Shortest key accepted, in UTF-8 bytes: the SHA-256 output size, as for every other
#: keyed MAC in the platform. Structural, not an operator setting.
MIN_ROW_KEY_BYTES = 32

_REF_RE = re.compile(r"secret://[a-z0-9_]+")
_DOMAIN = b"ciso.execution.execution_run.v1\n"


class RowKeyUnset(ExecutionStoreError):
    """No key reference was configured, so no row can be authenticated."""


class RowKeyUnavailable(ExecutionStoreError):
    """The key reference did not resolve to a usable key."""


class RowSeal:
    """Computes and checks the row MAC. Holds the reference, never the key: the key is
    resolved for each use and not kept."""

    def __init__(self, secrets: SecretResolver, key_ref: str | None) -> None:
        if key_ref is not None and (not isinstance(key_ref, str) or not _REF_RE.fullmatch(key_ref)):
            raise ValueError("row_key_ref must look like secret://<name>")
        self._secrets = secrets
        self._key_ref = key_ref

    @property
    def configured(self) -> bool:
        return self._key_ref is not None

    def key(self) -> bytes:
        """The key, resolved now. Call it BEFORE opening a write transaction. Raises
        `RowKeyUnset` or `RowKeyUnavailable`; the message never holds the key."""
        if self._key_ref is None:
            raise RowKeyUnset("row_key_ref is not set; execution rows cannot be authenticated")
        try:
            revealed = self._secrets.get(self._key_ref).reveal()
        except Exception as exc:
            raise RowKeyUnavailable(
                f"the execution row key could not be resolved ({type(exc).__name__})"
            ) from None
        raw = revealed.encode("utf-8") if isinstance(revealed, str) else b""
        if len(raw) < MIN_ROW_KEY_BYTES:
            raise RowKeyUnavailable(
                f"the execution row key is shorter than {MIN_ROW_KEY_BYTES} bytes"
            )
        return raw

    @staticmethod
    def mac(key: bytes, record: ExecutionRecord) -> str:
        body = canonical_json(record.model_dump(mode="json")).encode("utf-8")
        return hmac.new(key, _DOMAIN + body, hashlib.sha256).hexdigest()

    def matches(self, key: bytes, record: ExecutionRecord, stored: object) -> bool:
        if not isinstance(stored, str):
            return False
        return hmac.compare_digest(stored.encode("utf-8"), self.mac(key, record).encode("utf-8"))

    def __repr__(self) -> str:
        return "RowSeal()"
