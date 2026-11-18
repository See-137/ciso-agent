"""Stable identifiers.

Ids are `<prefix>_<26 chars>`: 48 bits of milliseconds then 80 random bits, Crockford
base32, so they sort by creation time. An EntityRef is `<kind>:<id>` and is how one record
points at another across modules. Exactly one colon is allowed and the id half is limited
to letters, digits, `_`, `.` and `-`, so a reference cannot smuggle a second reference or a
path. External identifiers (a source system's own ids) are not EntityRefs; they are stored
as `source_record_id` values.
"""

from __future__ import annotations

import re
import secrets
import time
from typing import NamedTuple

from ciso.common.errors import ValidationFailed

_ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
_PREFIX_RE = re.compile(r"^[a-z][a-z0-9]{1,11}$")
_ID_RE = re.compile(r"^[a-z][a-z0-9]{1,11}_[0-9A-HJKMNP-TV-Z]{26}$")
_KIND_RE = re.compile(r"^[a-z][a-z0-9_]{1,31}$")
_REF_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")


def _encode(value: int, length: int) -> str:
    chars = []
    for _ in range(length):
        chars.append(_ALPHABET[value & 0x1F])
        value >>= 5
    return "".join(reversed(chars))


def new_id(prefix: str, *, at_ms: int | None = None) -> str:
    if not _PREFIX_RE.fullmatch(prefix):
        raise ValidationFailed(f"bad id prefix: {prefix!r}")
    millis = time.time_ns() // 1_000_000 if at_ms is None else at_ms
    return f"{prefix}_{_encode(millis, 10)}{_encode(secrets.randbits(80), 16)}"


def is_id(value: str, prefix: str | None = None) -> bool:
    if not _ID_RE.fullmatch(value):
        return False
    return prefix is None or value.startswith(prefix + "_")


class EntityRef(NamedTuple):
    kind: str
    id: str

    def __str__(self) -> str:
        return f"{self.kind}:{self.id}"

    @classmethod
    def parse(cls, value: str) -> EntityRef:
        parts = value.split(":")
        if (
            len(parts) != 2
            or not _KIND_RE.fullmatch(parts[0])
            or not _REF_ID_RE.fullmatch(parts[1])
        ):
            raise ValidationFailed(f"bad entity ref: {value!r}")
        kind, ident = parts
        return cls(kind, ident)


def entity_ref(kind: str, ident: str) -> str:
    """Build and validate the string form of a reference."""
    return str(EntityRef.parse(f"{kind}:{ident}"))
