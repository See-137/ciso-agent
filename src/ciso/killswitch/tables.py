"""Kill-switch tables on the shared operational metadata. Blueprint 11.2; ADR-0018.

`killswitch_flag` holds one row per `KillCapability`. Each row carries a per-row
`version` counter and an HMAC (`mac`) over its content, made with a key that only the
kill switch resolves. A row that is missing, has no MAC, or whose MAC does not verify
reads as blocked (see `ciso.killswitch.integrity`).

`killswitch_pending_audit` is an outbox for engage records. Every engage writes its row
in the same transaction as the flag change; the row is claimed, delivered to the audit
sink and marked delivered. A row whose MAC fails is quarantined: kept, never delivered,
reported. The action is not stored: an outbox row can only ever become an engage record.

Version 2: v1 had no MACs, no claim columns and stored the action (review H2, H3).
"""

from __future__ import annotations

from sqlalchemy import Boolean, Column, Integer, String, Table, Text

from ciso.common.db import UtcDateTime, operational_metadata, register_schema

register_schema("killswitch", 2)

killswitch_flag = Table(
    "killswitch_flag",
    operational_metadata,
    Column("capability", String(32), primary_key=True),
    Column("engaged", Boolean, nullable=False),
    Column("version", Integer, nullable=False),
    Column("changed_by", String(128), nullable=False),
    Column("actor_type", String(16), nullable=False),
    Column("changed_at", UtcDateTime, nullable=False),
    Column("reason", Text, nullable=False),
    Column("via", String(16), nullable=False),
    Column("operator", String(128), nullable=False, default=""),
    Column("mac", String(64), nullable=True),
)

killswitch_pending_audit = Table(
    "killswitch_pending_audit",
    operational_metadata,
    Column("seq", Integer, primary_key=True, autoincrement=True),
    Column("entry_id", String(40), nullable=False, unique=True),
    Column("actor_id", String(128), nullable=False),
    Column("capabilities", Text, nullable=False),
    Column("reason", Text, nullable=False),
    Column("via", String(16), nullable=False),
    Column("operator", String(128), nullable=False, default=""),
    Column("recorded_at", UtcDateTime, nullable=False),
    Column("mac", String(64), nullable=True),
    Column("claimed_by", String(40), nullable=True),
    Column("claimed_at", UtcDateTime, nullable=True),
    Column("delivered_at", UtcDateTime, nullable=True),
    Column("quarantined", Boolean, nullable=False, default=False),
    Column("last_error", Text, nullable=False, default=""),
)
