"""Resolving a secret that is used as a cryptographic key, with a length floor.

An HMAC or key-derivation key of a few characters can be guessed by brute force, so a
resolved value shorter than `MIN_KEY_BYTES` UTF-8 bytes is refused (`FailClosed`). The
floor matches the SHA-256 output size used by every keyed MAC in the platform (audit
anchor and witness, kill-switch flags, backup key derivation, inference output digests).
Messages name the `secret://` reference, never the value.
"""

from __future__ import annotations

from typing import Final

from ciso.common.errors import FailClosed
from ciso.common.protocols import SecretResolver

#: Shortest key accepted, in UTF-8 bytes.
MIN_KEY_BYTES: Final = 32


def resolve_key_bytes(secrets: SecretResolver, ref: str) -> bytes:
    """Resolve `ref` and return its value as UTF-8 bytes.

    Raises `FailClosed` when the value is empty or shorter than `MIN_KEY_BYTES` bytes.
    Whatever the resolver raises (an unknown reference, an expired secret) propagates
    unchanged, so a caller keeps its own mapping of those errors.
    """
    raw = secrets.get(ref).reveal()
    if not raw:
        raise FailClosed(f"key is empty: {ref}")
    key = raw.encode("utf-8")
    if len(key) < MIN_KEY_BYTES:
        raise FailClosed(f"key is shorter than {MIN_KEY_BYTES} bytes: {ref}")
    return key
