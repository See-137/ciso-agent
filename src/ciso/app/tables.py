"""The composition root's own state on the operational database.

`app_state` remembers the audit log's id, so a later start can tell a new audit log from
a wiped one (ADR-0013): an id remembered here with no audit database next to it is a
deleted log, never a fresh start.
"""

from __future__ import annotations

from sqlalchemy import Column, Index, String, Table, Text

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

#: Managed machines that report AI activity (docs/skill/decision-api.md). Each device is
#: an identity actor of type `service`; this row is what makes that actor a device, so
#: only these actors hold `governance.report`. A revoked device keeps its row.
devices = Table(
    "app_devices",
    operational_metadata,
    Column("actor_id", String(40), primary_key=True),
    Column("name", String(64), nullable=False),
    Column("created_at", UtcDateTime, nullable=False),
    Column("created_by", String(64), nullable=False),
    Column("revoked_at", UtcDateTime, nullable=True),
    Column("revoked_by", String(64), nullable=True),
    Index("ix_app_devices_name", "name"),
)
