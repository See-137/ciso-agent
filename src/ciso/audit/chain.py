"""Audit records and the hash chain: building, hashing, storing and walking records.

`hash` = SHA-256 of the canonical JSON of every record field except `hash` (so it covers
`prev_hash`). The first record's `prev_hash` is `GENESIS_HASH` (NFR-006, ADR-0013).

What is stored is exactly what is hashed: `details` is stored as strict canonical JSON
(JSON-native values only, no NaN, no duplicate keys) and `occurred_at` in one fixed text
format, and the verify walk rejects any row whose stored text differs (review M2).
"""

from __future__ import annotations

import json
import math
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from pydantic import ValidationError
from sqlalchemy import Connection, Row, String, select, type_coerce

from ciso.audit.anchor import AnchorEntry
from ciso.audit.tables import GENESIS_HASH, audit_meta, audit_record
from ciso.common.enums import ActorType, AuditOutcome
from ciso.common.errors import IntegrityFailure, ValidationFailed
from ciso.common.ids import new_id
from ciso.common.protocols import AuditEvent
from ciso.common.schemas import FrozenMap, Model, UtcDatetime, canonical_json, sha256_hex, thaw

GENESIS = AnchorEntry(seq=0, head_hash=GENESIS_HASH)

#: The text SQLAlchemy writes for `UtcDateTime` on SQLite. Any other spelling is refused.
STORED_TIME_FORMAT = "%Y-%m-%d %H:%M:%S.%f"


def strict_canonical(value: Any) -> str:
    """Canonical JSON with no fallbacks: a non-JSON value raises instead of being
    stringified (review M1). Raises TypeError or ValueError."""
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    )


def require_utf8(value: str, what: str) -> str:
    """Refuse strings that cannot be stored as UTF-8, such as lone surrogates (review L1)."""
    try:
        value.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise ValidationFailed(f"{what} is not valid UTF-8") from exc
    return value


def require_json_native(value: Any, path: str = "details") -> None:
    """Allow only dict (str keys), list, tuple, str, int, float (finite), bool and None.

    Bytes, sets, datetimes and arbitrary objects are refused, so nothing reaches storage
    through an implicit `str()` that the redactor never saw (review M1).
    """
    if value is None or isinstance(value, bool | int):
        return
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ValidationFailed(f"{path} holds a non-finite number")
        return
    if isinstance(value, str):
        require_utf8(value, path)
        return
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise ValidationFailed(f"{path} has a non-string key")
            require_utf8(key, f"{path} key")
            require_json_native(item, f"{path}.{key}")
        return
    if isinstance(value, list | tuple):
        for index, item in enumerate(value):
            require_json_native(item, f"{path}[{index}]")
        return
    raise ValidationFailed(f"{path} holds a {type(value).__name__}, which is not JSON")


def _no_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    keys = [key for key, _ in pairs]
    if len(set(keys)) != len(keys):
        raise ValueError("duplicate key in stored details")
    return dict(pairs)


def parse_stored_details(text: str) -> dict[str, Any]:
    """Parse stored details and insist the text is exactly its canonical form."""
    parsed = json.loads(text, object_pairs_hook=_no_duplicate_keys)
    if not isinstance(parsed, dict) or strict_canonical(parsed) != text:
        raise ValueError("stored details are not in canonical form")
    return parsed


class AuditRecord(Model):
    id: str
    seq: int
    occurred_at: UtcDatetime
    actor_id: str
    actor_type: ActorType
    action: str
    target: str
    outcome: AuditOutcome
    correlation_id: str
    details: FrozenMap[str, Any]
    prev_hash: str
    hash: str


def record_hash(record: AuditRecord) -> str:
    """The chain hash of a record: every field except `hash`, canonical JSON, SHA-256."""
    return sha256_hex(canonical_json(record.model_dump(mode="json", exclude={"hash"})))


def entry_of(record: AuditRecord) -> AnchorEntry:
    return AnchorEntry(seq=record.seq, head_hash=record.hash)


@dataclass(frozen=True)
class PreparedEvent:
    """An event whose details are already redacted, ready to be chained."""

    event: AuditEvent
    details: dict[str, Any]
    occurred_at: datetime


def build_records(head: AnchorEntry, batch: list[PreparedEvent]) -> list[AuditRecord]:
    records: list[AuditRecord] = []
    prev = head
    for item in batch:
        draft = AuditRecord(
            id=new_id("aud"),
            seq=prev.seq + 1,
            occurred_at=item.occurred_at,
            actor_id=item.event.actor_id,
            actor_type=item.event.actor_type,
            action=item.event.action,
            target=item.event.target,
            outcome=item.event.outcome,
            correlation_id=item.event.correlation_id,
            details=item.details,
            prev_hash=prev.head_hash,
            hash="",
        )
        record = draft.model_copy(update={"hash": record_hash(draft)})
        records.append(record)
        prev = entry_of(record)
    return records


def row_values(record: AuditRecord) -> dict[str, Any]:
    values = record.model_dump(mode="python")
    values["actor_type"] = record.actor_type.value
    values["outcome"] = record.outcome.value
    values["details"] = strict_canonical(thaw(record.details))
    return values


def _parse_stored_time(raw: object) -> datetime:
    """Parse the stored time text ourselves, so a value that is not a timestamp at all is
    a parse failure of this row, not an exception out of the driver (second review R2)."""
    if not isinstance(raw, str):
        raise TypeError("stored occurred_at is not text")
    return datetime.strptime(raw, STORED_TIME_FORMAT).replace(tzinfo=UTC)


def row_to_record(row: Row[Any]) -> AuditRecord:
    """Parse a stored row. With an `occurred_at_raw` column (the verify walk) the time is
    parsed from the stored text, which must be in the one format this module writes."""
    try:
        values = dict(row._mapping)
        has_raw = "occurred_at_raw" in values
        raw_time = values.pop("occurred_at_raw", None)
        if has_raw:
            values["occurred_at"] = _parse_stored_time(raw_time)
        values["details"] = parse_stored_details(values["details"])
        record = AuditRecord.model_validate(values)
    except (ValueError, TypeError, ValidationError) as exc:
        raise IntegrityFailure(f"audit row seq {row.seq} cannot be parsed") from exc
    if has_raw and raw_time != record.occurred_at.strftime(STORED_TIME_FORMAT):
        raise IntegrityFailure(f"audit row seq {row.seq} has a non-canonical timestamp")
    return record


def read_log_id(conn: Connection) -> str | None:
    value = conn.execute(select(audit_meta.c.log_id)).scalar_one_or_none()
    return None if value is None else str(value)


def read_head(conn: Connection) -> AnchorEntry:
    t = audit_record.c
    row = conn.execute(select(t.seq, t.hash).order_by(t.seq.desc()).limit(1)).first()
    if row is None:
        return GENESIS
    return AnchorEntry(seq=int(row.seq), head_hash=str(row.hash))


def hash_at(conn: Connection, seq: int) -> str | None:
    """The stored hash of record `seq`; `GENESIS_HASH` for 0; None if absent."""
    if seq == 0:
        return GENESIS_HASH
    value = conn.execute(
        select(audit_record.c.hash).where(audit_record.c.seq == seq)
    ).scalar_one_or_none()
    return None if value is None else str(value)


@dataclass
class Walk:
    """Outcome of walking part of the chain. `broken_seq`/`reason` set on the first fault."""

    head: AnchorEntry
    checked: int = 0
    broken_seq: int | None = None
    reason: str | None = None


def check_row(row: Row[Any], head: AnchorEntry) -> tuple[AuditRecord | None, str | None]:
    """Check one row against the head before it. Returns (record, None) or (None, reason)."""
    if row.seq != head.seq + 1:
        return None, "seq_gap"
    try:
        record = row_to_record(row)
    except IntegrityFailure:
        return None, "row_invalid"
    if record.prev_hash != head.head_hash:
        return None, "prev_hash_mismatch"
    if record_hash(record) != record.hash:
        return None, "hash_mismatch"
    return record, None


def walk_chain(conn: Connection, start: AnchorEntry) -> Walk:
    """Check every record after `start`, in seq order, stopping at the first fault."""
    walk = Walk(head=start)
    t = audit_record.c
    raw_time = type_coerce(t.occurred_at, String).label("occurred_at_raw")
    columns = [c for c in audit_record.c if c.name != "occurred_at"]
    rows = conn.execute(select(*columns, raw_time).where(t.seq > start.seq).order_by(t.seq))
    for row in rows:
        record, reason = check_row(row, walk.head)
        if record is None:
            walk.broken_seq, walk.reason = walk.head.seq + 1, reason
            return walk
        walk.checked += 1
        walk.head = entry_of(record)
    return walk
