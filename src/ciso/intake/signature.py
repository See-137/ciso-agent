"""Standard Webhooks symmetric signature verification (version `v1`), as the central gate
uses it.

Scheme (Standard Webhooks specification; the platform's endpoint documentation):

- headers `webhook-id`, `webhook-timestamp` (Unix seconds, decimal) and
  `webhook-signature` (space-separated `v1,<base64>` entries), looked up case-insensitively;
- signed content `"{webhook-id}.{webhook-timestamp}." + raw body bytes`;
- signature `base64(HMAC-SHA256(key, signed content))`, standard base64 alphabet;
- secret `whsec_` + standard base64 of 24 to 64 random bytes;
- accept when any `v1` entry matches, compared in constant time; reject a timestamp more
  than the tolerance away from now in either direction.

The tolerance is a parameter with no default here: `None` refuses every delivery.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import re
from collections.abc import Iterable, Mapping
from datetime import UTC, datetime
from typing import NamedTuple

from ciso.intake.errors import RefusalCode, SignatureRefused

SECRET_PREFIX = "whsec_"  # noqa: S105 (the scheme prefix, not a secret)
#: Key length bounds from the Standard Webhooks specification, in bytes.
MIN_SECRET_BYTES = 24
MAX_SECRET_BYTES = 64
#: Most entries accepted in one `webhook-signature` header.
MAX_SIGNATURE_ENTRIES = 16
#: Longest accepted `webhook-id`.
MAX_MESSAGE_ID_CHARS = 256

HEADER_ID = "webhook-id"
HEADER_TIMESTAMP = "webhook-timestamp"
HEADER_SIGNATURE = "webhook-signature"
_HEADERS = (HEADER_ID, HEADER_TIMESTAMP, HEADER_SIGNATURE)
_TIMESTAMP = re.compile(r"[0-9]{1,12}")
_MESSAGE_ID = re.compile(r"[A-Za-z0-9._:-]{1,256}")
_STD_B64 = re.compile(r"[A-Za-z0-9+/]+={0,2}")


class VerifiedDelivery(NamedTuple):
    message_id: str
    signed_at: datetime


def _refuse(code: RefusalCode) -> SignatureRefused:
    return SignatureRefused(code)


def signature_headers(headers: Mapping[str, str]) -> dict[str, str]:
    """The three signature headers by lowercase name. Two spellings of one header with
    different values are refused: which one a proxy kept is unknowable."""
    found: dict[str, str] = {}
    for name, value in headers.items():
        lowered = name.lower()
        if lowered not in _HEADERS:
            continue
        if lowered in found and found[lowered] != value:
            raise _refuse(RefusalCode.AMBIGUOUS_HEADER)
        found[lowered] = value
    if any(name not in found for name in _HEADERS):
        raise _refuse(RefusalCode.UNSIGNED_REQUEST)
    return found


def decode_secret(secret: str) -> bytes:
    """Key bytes from `whsec_<standard base64>`; anything else is a configuration fault."""
    encoded = secret.removeprefix(SECRET_PREFIX)
    if encoded == secret or not _STD_B64.fullmatch(encoded):
        raise _refuse(RefusalCode.SIGNING_SECRET_INVALID)
    try:
        key = base64.b64decode(encoded, validate=True)
    except (binascii.Error, ValueError):
        raise _refuse(RefusalCode.SIGNING_SECRET_INVALID) from None
    if not MIN_SECRET_BYTES <= len(key) <= MAX_SECRET_BYTES:
        raise _refuse(RefusalCode.SIGNING_SECRET_INVALID)
    return key


def _candidates(header: str) -> list[bytes]:
    entries = header.split()
    if not entries or len(entries) > MAX_SIGNATURE_ENTRIES:
        raise _refuse(RefusalCode.INVALID_SIGNATURE_HEADER)
    found = [
        entry.encode("utf-8", errors="replace") for entry in entries if entry.startswith("v1,")
    ]
    if not found:
        raise _refuse(RefusalCode.NO_SUPPORTED_SIGNATURE)
    return found


def _check_time(stamp: str, now: datetime, tolerance_seconds: int | None) -> datetime:
    if tolerance_seconds is None:
        raise _refuse(RefusalCode.TOLERANCE_UNSET)
    if not _TIMESTAMP.fullmatch(stamp):
        raise _refuse(RefusalCode.TIMESTAMP_INVALID)
    signed_at = datetime.fromtimestamp(int(stamp), tz=UTC)
    if abs((now - signed_at).total_seconds()) > tolerance_seconds:
        raise _refuse(RefusalCode.TIMESTAMP_OUT_OF_TOLERANCE)
    return signed_at


def verify_standard_webhook(
    headers: Mapping[str, str],
    body: bytes,
    *,
    secrets: Iterable[str],
    now: datetime,
    tolerance_seconds: int | None,
) -> VerifiedDelivery:
    """Verify one delivery against each secret in `secrets` (the current one, and the
    previous one during a rotation). Raises `SignatureRefused` with a reason code."""
    found = signature_headers(headers)
    message_id = found[HEADER_ID]
    if not _MESSAGE_ID.fullmatch(message_id):
        raise _refuse(RefusalCode.INVALID_SIGNATURE_HEADER)
    signed_at = _check_time(found[HEADER_TIMESTAMP], now, tolerance_seconds)
    candidates = _candidates(found[HEADER_SIGNATURE])
    content = f"{message_id}.{found[HEADER_TIMESTAMP]}.".encode() + body
    keys = [decode_secret(secret) for secret in secrets]
    if not keys:
        raise _refuse(RefusalCode.SIGNING_SECRET_UNAVAILABLE)
    matched = False
    for key in keys:
        mac = hmac.new(key, content, hashlib.sha256).digest()
        expected = b"v1," + base64.b64encode(mac)
        for candidate in candidates:
            # Evaluate every comparison: no early exit that would time the match.
            matched = hmac.compare_digest(expected, candidate) or matched
    if not matched:
        raise _refuse(RefusalCode.BAD_SIGNATURE)
    return VerifiedDelivery(message_id, signed_at)
