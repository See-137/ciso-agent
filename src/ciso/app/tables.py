"""The composition root's own state on the operational database.

`app_state` remembers the audit log's id, so a later start can tell a new audit log from
a wiped one (ADR-0013): an id remembered here with no audit database next to it is a
deleted log, never a fresh start.
"""

from __future__ import annotations

from sqlalchemy import Column, String, Table, Text

from ciso.common.db import UtcDateTime, operational_metadata, register_schema

register_schema("app", 1)

app_state = Table(
    "app_state",
    operational_metadata,
    Column("key", String(64), primary_key=True),
    Column("value", Text, nullable=False),
    Column("recorded_at", UtcDateTime, nullable=False),
)

AUDIT_LOG_ID_KEY = "audit_log_id"
