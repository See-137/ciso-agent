"""Encryption at rest for uploaded changes (spec D1: content kept only encrypted).

AES-256-GCM. The 32-byte key is derived with HKDF-SHA256 from the secret named by
`governance.change_key_ref` (at least `ciso.vault.MIN_KEY_BYTES` bytes), so the stored
secret is never used as a cipher key directly. Each file gets a fresh 96-bit nonce, and
the change id is the associated data: a file renamed to another change's id does not
decrypt. Layout of a sealed blob: `MAGIC | nonce | ciphertext+tag`.
"""

from __future__ import annotations

import os
from typing import Final

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from ciso.common.errors import IntegrityFailure, ValidationFailed
from ciso.common.protocols import SecretResolver
from ciso.vault import resolve_key_bytes

MAGIC: Final = b"CISOCHG1"
NONCE_BYTES: Final = 12
_INFO: Final = b"ciso.app.changes.v1"


class ChangeCipher:
    """Seals and opens one change file. Holds the derived key only; `repr` hides it."""

    def __init__(self, key_material: bytes) -> None:
        if len(key_material) < 32:
            raise ValidationFailed("change key material is too short")
        key = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=_INFO).derive(key_material)
        self._aead = AESGCM(key)

    @classmethod
    def from_secret(cls, secrets: SecretResolver, ref: str) -> ChangeCipher:
        """Resolve `ref` now (raises `FailClosed` or `NotFound` when it cannot be used)."""
        return cls(resolve_key_bytes(secrets, ref))

    def __repr__(self) -> str:
        return "ChangeCipher(<key hidden>)"

    def seal(self, change_id: str, plaintext: bytes) -> bytes:
        nonce = os.urandom(NONCE_BYTES)
        return MAGIC + nonce + self._aead.encrypt(nonce, plaintext, change_id.encode())

    def open(self, change_id: str, blob: bytes) -> bytes:
        """The plaintext, or `IntegrityFailure` for a file that is not ours or was changed."""
        head = len(MAGIC) + NONCE_BYTES
        if len(blob) <= head or not blob.startswith(MAGIC):
            raise IntegrityFailure("stored change has an unknown format")
        nonce = blob[len(MAGIC) : head]
        try:
            return self._aead.decrypt(nonce, blob[head:], change_id.encode())
        except InvalidTag as exc:
            raise IntegrityFailure("stored change does not decrypt") from exc


def frame(diff: bytes, bundle: bytes) -> bytes:
    """Diff and bundle in one plaintext: an 8-byte diff length, the diff, the bundle."""
    return len(diff).to_bytes(8, "big") + diff + bundle


def unframe(plaintext: bytes) -> tuple[bytes, bytes]:
    if len(plaintext) < 8:
        raise IntegrityFailure("stored change is truncated")
    size = int.from_bytes(plaintext[:8], "big")
    if size > len(plaintext) - 8:
        raise IntegrityFailure("stored change is truncated")
    return plaintext[8 : 8 + size], plaintext[8 + size :]
