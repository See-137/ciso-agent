"""Shapes of the values callers hand to the approval service. Pure: no database, no audit.

One strict pattern per kind of value, always applied with `fullmatch` (review finding
M5). Ids are compared as raw strings by the requester/approver rule, so a padded or
look-alike id for the same person is refused here instead of being stored.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping
from datetime import timedelta

from ciso.approvals.models import ApprovalInputInvalid, ApprovalReason
from ciso.common.enums import APPROVER_ROLES, ActorType, Role

MAX_ACTOR = 128
MAX_CORRELATION = 128
MAX_BINDING_FIELDS = 32
MAX_KEY = 64
MAX_FIELD = 512
MAX_NOTE = 2000
MAX_PARTIES = 16

_KIND_RE = re.compile(r"[a-z][a-z0-9_.]{1,63}")
_HASH_RE = re.compile(r"[0-9a-f]{64}")
#: Actor ids and correlation ids: an identifier, nothing a terminal or a log could act on.
_IDENT_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:@-]*")
#: Names of binding fields and target attributes.
_KEY_RE = re.compile(r"[A-Za-z][A-Za-z0-9_.-]*")
#: Free text (binding and target values, notes): no control characters, no invisible or
#: direction-changing characters, no line or paragraph separators.
_BANNED_IN_TEXT = (
    (0x00, 0x1F), (0x7F, 0x9F), (0xAD, 0xAD), (0x61C, 0x61C), (0x200B, 0x200F),
    (0x2028, 0x202F), (0x2060, 0x206F), (0xFEFF, 0xFEFF), (0xFFF9, 0xFFFB),
)  # fmt: skip
_TEXT_RE = re.compile(
    "[^" + "".join(f"{re.escape(chr(a))}-{re.escape(chr(b))}" for a, b in _BANNED_IN_TEXT) + "]*"
)


def is_ident(value: object, limit: int) -> bool:
    return isinstance(value, str) and len(value) <= limit and bool(_IDENT_RE.fullmatch(value))


def is_text(value: object, limit: int) -> bool:
    """Clean text within `limit`: no control characters, no leading or trailing space."""
    return (
        isinstance(value, str)
        and len(value) <= limit
        and value == value.strip()
        and bool(_TEXT_RE.fullmatch(value))
    )


def check_ttl(ttl: timedelta | None) -> timedelta | None:
    """`None` is allowed and means "refuse"; a set value must be a positive duration."""
    if ttl is None:
        return None
    if not isinstance(ttl, timedelta) or ttl <= timedelta(0):
        raise ApprovalInputInvalid(
            ApprovalReason.INVALID_SETTING, "approval_ttl must be a positive duration or None"
        )
    return ttl


def check_subject(subject_kind: object, subject_hash: object) -> tuple[str, str]:
    """A subject is a kind (`action_envelope`, `external_inference`, ...) and the
    SHA-256 hex of the canonical form of what is being approved."""
    if not isinstance(subject_kind, str) or not _KIND_RE.fullmatch(subject_kind):
        raise ApprovalInputInvalid(ApprovalReason.INVALID_SUBJECT, "bad subject kind")
    if not isinstance(subject_hash, str) or not _HASH_RE.fullmatch(subject_hash):
        raise ApprovalInputInvalid(
            ApprovalReason.INVALID_SUBJECT, "subject hash must be 64 lowercase hex characters"
        )
    return subject_kind, subject_hash


def _text_map(
    value: object, reason: ApprovalReason, what: str, *, drop_none: bool
) -> dict[str, str]:
    if not isinstance(value, Mapping):
        raise ApprovalInputInvalid(reason, f"{what} must be a mapping")
    if len(value) > MAX_BINDING_FIELDS:
        raise ApprovalInputInvalid(reason, f"{what} has too many fields")
    out: dict[str, str] = {}
    for key, item in value.items():
        if drop_none and item is None:
            continue
        if not isinstance(key, str) or len(key) > MAX_KEY or not _KEY_RE.fullmatch(key):
            raise ApprovalInputInvalid(reason, f"{what} keys must be short field names")
        if not isinstance(item, str) or not is_text(item, MAX_FIELD):
            raise ApprovalInputInvalid(
                reason, f"{what} values must be short text without control characters"
            )
        out[key] = item
    return out


def check_binding(binding: object) -> dict[str, str]:
    """Binding fields are strings on both sides, so equality is exact."""
    return _text_map(binding, ApprovalReason.INVALID_BINDING, "binding", drop_none=False)


def check_target(target: object) -> dict[str, str]:
    """Target attributes as `Principal.covering_roles` takes them. A `None` value means
    "not known" and is dropped: a scoped grant never reaches an unknown attribute."""
    return _text_map(target, ApprovalReason.INVALID_TARGET, "target", drop_none=True)


def check_actor(actor_id: object, reason: ApprovalReason, what: str) -> str:
    if not isinstance(actor_id, str) or not is_ident(actor_id, MAX_ACTOR):
        raise ApprovalInputInvalid(reason, f"{what} must be an actor id")
    return actor_id


def check_issuer(issuer: object) -> str:
    """The credential issuer a principal carries: an actor id, or empty for unknown."""
    if isinstance(issuer, str) and issuer == "":
        return ""
    return check_actor(issuer, ApprovalReason.INVALID_ACTOR, "credential issuer")


def check_requester(actor_id: object, actor_type: object) -> tuple[str, ActorType]:
    ident = check_actor(actor_id, ApprovalReason.INVALID_REQUESTER, "requester")
    if not isinstance(actor_type, ActorType) or actor_type is ActorType.ANONYMOUS:
        raise ApprovalInputInvalid(
            ApprovalReason.INVALID_REQUESTER, "requester must be a human, service or agent"
        )
    return ident, actor_type


def check_parties(parties: object, requested_by: str) -> tuple[str, ...]:
    """Actor ids, besides the requester, who may not decide. Sorted, no repeats."""
    reason = ApprovalReason.INVALID_PARTIES
    if isinstance(parties, str | bytes) or not isinstance(parties, Iterable):
        raise ApprovalInputInvalid(reason, "parties must be a collection of actor ids")
    found = {check_actor(item, reason, "party") for item in parties}
    found.discard(requested_by)
    if len(found) > MAX_PARTIES:
        raise ApprovalInputInvalid(reason, "too many parties")
    return tuple(sorted(found))


def check_roles(roles: object) -> tuple[Role, ...]:
    """Non-empty and inside `APPROVER_ROLES` (ADR-0021). Anything else is refused."""
    if isinstance(roles, str) or not isinstance(roles, Iterable):
        raise ApprovalInputInvalid(ApprovalReason.INVALID_ROLES, "roles must be a collection")
    found: set[Role] = set()
    for item in roles:
        try:
            role = Role(item)
        except ValueError:
            raise ApprovalInputInvalid(ApprovalReason.INVALID_ROLES, "unknown role") from None
        if role not in APPROVER_ROLES:
            raise ApprovalInputInvalid(
                ApprovalReason.INVALID_ROLES, f"{role.value} is not an approver role"
            )
        found.add(role)
    if not found:
        raise ApprovalInputInvalid(ApprovalReason.INVALID_ROLES, "no approver role named")
    return tuple(sorted(found))


def check_note(value: object) -> str:
    if not isinstance(value, str) or not is_text(value, MAX_NOTE):
        raise ApprovalInputInvalid(
            ApprovalReason.INVALID_TEXT, "note must be short text without control characters"
        )
    return value


def check_correlation(value: object) -> str:
    """Empty, or an identifier. Too long is refused, never cut."""
    if isinstance(value, str) and value == "":
        return ""
    if not isinstance(value, str) or not is_ident(value, MAX_CORRELATION):
        raise ApprovalInputInvalid(
            ApprovalReason.INVALID_TEXT, "correlation id must be a short identifier"
        )
    return value
