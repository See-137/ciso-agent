"""The line format of `FileHeadWitness` and the rules for reading a file of such lines.

Each line is a JSON object of signed fields plus `hmac` (HMAC-SHA256 over the fields and a
domain label). A line may also carry `repairs`: the SHA-256 of a torn fragment that the
writer found at the end of the file and stepped over (see below); it is signed like every
other field, so only the key holder can acknowledge a fragment.

Reading rules (`scan`), applied to the whole file in order:

- a line that parses but fails its signature, or is signed with another key, is fatal
  wherever it is (`IntegrityFailure` / `FailClosed`);
- a line that does not parse (a torn write: bytes cut short, or zero fill left by a crash)
  is tolerated in exactly two places: as the LAST line of the file, where it is ignored and
  reported as a torn tail; or directly before a valid line whose `repairs` names its
  digest, where it is a torn tail the writer has already acknowledged. Anywhere else it is
  fatal (`IntegrityFailure`). Because lines are checked in order, every line before a
  tolerated tail has verified;
- a last line without a trailing newline that parses and verifies is a valid head.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from ciso.audit.anchor import AnchorKey
from ciso.common.errors import FailClosed, IntegrityFailure
from ciso.common.schemas import Model, UtcDatetime

DOMAIN = "ciso.audit.witness"
VERSION = 1


class WitnessedHead(Model):
    log_id: str
    seq: int
    head_hash: str
    at: UtcDatetime


@dataclass(frozen=True)
class _Line:
    head: WitnessedHead
    repairs: str | None


@dataclass(frozen=True)
class Scan:
    """Every verified head in file order, and the torn tail if one is unacknowledged."""

    heads: tuple[WitnessedHead, ...]
    torn_tail: bytes | None


def fragment_digest(fragment: bytes) -> str:
    return hashlib.sha256(fragment).hexdigest()


def fields(
    key_id: str,
    log_id: str,
    seq: int,
    head_hash: str,
    at: datetime,
    repairs: str | None = None,
) -> dict[str, Any]:
    out: dict[str, Any] = {
        "version": VERSION,
        "key_id": key_id,
        "log_id": log_id,
        "seq": seq,
        "head_hash": head_hash,
        "at": at.isoformat(),
    }
    if repairs is not None:
        out["repairs"] = repairs
    return out


def signed(values: dict[str, Any]) -> dict[str, Any]:
    return {"domain": DOMAIN, **values}


def encode(key: AnchorKey, values: dict[str, Any]) -> bytes:
    return json.dumps({**values, "hmac": key.mac(signed(values))}, sort_keys=True).encode()


def _parse(key: AnchorKey, line: bytes, number: int) -> _Line | None:
    """None when the line does not parse (a torn write); raises when it parses but does not
    verify."""
    try:
        data = json.loads(line.decode("utf-8"))
        mac = data.pop("hmac")
        repairs = data.get("repairs")
        if repairs is not None and not isinstance(repairs, str):
            raise TypeError("repairs")
        values = fields(
            data["key_id"],
            data["log_id"],
            data["seq"],
            data["head_hash"],
            datetime.fromisoformat(data["at"]),
            repairs,
        )
    except (UnicodeDecodeError, ValueError, KeyError, TypeError, AttributeError):
        return None
    if values["key_id"] != key.key_id:
        raise FailClosed(f"audit head witness line {number} is signed with another key")
    if not isinstance(mac, str) or not hmac.compare_digest(key.mac(signed(values)), mac):
        raise IntegrityFailure(f"audit head witness line {number} fails its signature")
    head = WitnessedHead(
        log_id=values["log_id"],
        seq=values["seq"],
        head_hash=values["head_hash"],
        at=datetime.fromisoformat(values["at"]),
    )
    return _Line(head=head, repairs=repairs)


def scan(key: AnchorKey, raw: bytes) -> Scan:
    """Apply the reading rules in the module docstring to the whole file."""
    numbered = [
        (number, line) for number, line in enumerate(raw.split(b"\n"), start=1) if line.strip()
    ]
    parsed = [(number, line, _parse(key, line, number)) for number, line in numbered]
    heads: list[WitnessedHead] = []
    torn: bytes | None = None
    for index, (number, line, result) in enumerate(parsed):
        if result is not None:
            heads.append(result.head)
            continue
        following = parsed[index + 1][2] if index + 1 < len(parsed) else None
        if index + 1 == len(parsed):
            torn = line  # the last line: a torn write, ignored for reading
        elif following is None or following.repairs != fragment_digest(line):
            raise IntegrityFailure(f"audit head witness line {number} is malformed")
    return Scan(heads=tuple(heads), torn_tail=torn)


def last_fragment(key: AnchorKey, raw: bytes) -> bytes | None:
    """The unparseable last line a new publish must acknowledge, or None. Raises when the
    last line parses but does not verify."""
    lines = [line for line in raw.split(b"\n") if line.strip()]
    if not lines:
        return None
    return lines[-1] if _parse(key, lines[-1], len(lines)) is None else None
