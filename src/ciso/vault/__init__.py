"""Secret references, masked secret values and redaction. Holds no secret material.

Named `vault` rather than `secrets` so the package does not shadow the standard library
module of that name and does not collide with tooling rules that protect directories
called `secrets`.
"""

from ciso.vault.keys import MIN_KEY_BYTES, resolve_key_bytes
from ciso.vault.redact import (
    MIN_REGISTERED_LENGTH,
    REDACTION_MARKER,
    RedactingLogFilter,
    SecretRedactor,
)
from ciso.vault.store import ENV_PREFIX, SECRET_SCHEME, EnvSecretStore, SecretValue, parse_ref

__all__ = [
    "ENV_PREFIX",
    "MIN_KEY_BYTES",
    "MIN_REGISTERED_LENGTH",
    "REDACTION_MARKER",
    "SECRET_SCHEME",
    "EnvSecretStore",
    "RedactingLogFilter",
    "SecretRedactor",
    "SecretValue",
    "parse_ref",
    "resolve_key_bytes",
]
