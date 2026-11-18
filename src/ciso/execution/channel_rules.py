"""What a channel name, an outbox name and a line of administrator-facing text may be,
and the record and refusal types of the channel registry (plan gap G13; OD-13).

`ciso.execution.channels` holds the registry that applies these rules.
"""

from __future__ import annotations

import re
import unicodedata
from enum import StrEnum

from ciso.common.errors import AuthorizationError, ValidationFailed
from ciso.common.schemas import Model, UtcDatetime, sha256_hex

_NAME_RE = re.compile(r"[a-z][a-z0-9_]{1,62}")
#: Digits a port device name may end in: the platform also reserves the superscript
#: forms of 1, 2 and 3.
_PORT_DIGITS = "0123456789\xb9\xb2\xb3"
#: Names an operating system treats as devices rather than directories, case-folded.
_DEVICE_NAMES = frozenset(
    {"con", "prn", "aux", "nul"}
    | {f"{port}{digit}" for port in ("com", "lpt") for digit in _PORT_DIGITS}
)
#: Longest purpose or reason, in characters.
MAX_TEXT = 500
#: Unicode categories refused in a purpose or reason: control characters, format
#: characters (which include the direction overrides and zero-width characters), and
#: the line and paragraph separators. The text is shown to the approving administrator
#: and copied into audit details, so it must not be able to redraw either.
_REFUSED_CATEGORIES = frozenset({"Cc", "Cf", "Zl", "Zp"})
#: How many channels one actor may have waiting for a decision at once. A structural
#: bound on a table an agent can write to, not a tunable: a proposed name blocks everyone
#: else from proposing it until an administrator revokes it.
MAX_OPEN_PROPOSALS_PER_PROPOSER = 20


class ChannelStatus(StrEnum):
    PROPOSED = "proposed"
    #: An administrator decided to approve; the approval's audit record id is not on the
    #: row yet. Not usable. Left behind only by a crash; approve again or revoke.
    APPROVING = "approving"
    APPROVED = "approved"
    REVOKED = "revoked"


#: States that count as waiting for a decision.
OPEN_STATES = (ChannelStatus.PROPOSED.value, ChannelStatus.APPROVING.value)


class ChannelRefusal(StrEnum):
    """Why a channel request was refused before or instead of a change. A wire format:
    these values are written to audit details."""

    BAD_CHANNEL_NAME = "bad_channel_name"
    BAD_TARGET = "bad_target"
    BAD_TEXT = "bad_text"
    SELF_APPROVAL = "self_approval"
    TOO_MANY_OPEN_PROPOSALS = "too_many_open_proposals"


class ChannelInvalid(ValidationFailed):
    """A channel name, target, purpose or reason is not acceptable."""

    def __init__(self, code: ChannelRefusal, detail: str) -> None:
        super().__init__(detail)
        self.code = code


class ChannelDenied(AuthorizationError):
    """A known, authorised actor may still not do this: approve their own proposal, or
    hold more open proposals than the bound."""

    def __init__(self, code: ChannelRefusal, detail: str) -> None:
        super().__init__(detail)
        self.code = code


def purpose_digest(purpose: str) -> str:
    """The digest an approval must carry: SHA-256 of the purpose exactly as shown."""
    return sha256_hex(purpose)


class ChannelRecord(Model):
    """One channel as stored. To approve it, pass back `target`, `version` and
    `purpose_digest` of the record the administrator was shown."""

    channel: str
    target: str
    status: ChannelStatus
    purpose: str
    proposed_by: str
    proposed_at: UtcDatetime
    decided_by: str = ""
    decided_at: UtcDatetime | None = None
    approval_audit_ref: str = ""
    revoked_by: str = ""
    revoked_at: UtcDatetime | None = None
    revoke_reason: str = ""
    version: int

    @property
    def purpose_digest(self) -> str:
        return purpose_digest(self.purpose)


def is_device_name(value: str) -> bool:
    """True for a reserved device name in any letter case, with plain or superscript
    port digits."""
    return value.casefold() in _DEVICE_NAMES


def is_outbox_name(value: object) -> bool:
    """True for a plain local outbox name: lower-case letters, digits and `_`, starting
    with a letter, 2 to 63 characters, and not a device name. Dots, slashes, colons, `@`
    and whitespace are all outside the pattern, which is what keeps URLs, hosts, e-mail
    addresses and paths out. A channel name follows the same rule."""
    return (
        isinstance(value, str)
        and _NAME_RE.fullmatch(value) is not None
        and not is_device_name(value)
    )


def clean_text(value: object) -> str | None:
    """The text with surrounding whitespace removed, or None when it is not acceptable:
    not a string, blank, longer than `MAX_TEXT`, or holding a refused character."""
    if not isinstance(value, str) or len(value) > MAX_TEXT:
        return None
    text = value.strip()
    if not text or any(unicodedata.category(char) in _REFUSED_CATEGORIES for char in text):
        return None
    return text


def value_digest(value: object) -> str:
    """What an audit record carries in place of a refused value."""
    return sha256_hex(value if isinstance(value, str) else repr(value))
