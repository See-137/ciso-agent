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

#: Changes uploaded for their pre-push scan (`ciso.app.changes`). The change itself (diff
#: and bundle) is a file under `data_dir/changes`, encrypted; this row holds what the
#: decision needs (who sent it, what it covers, the inspection results, which hold no
#: content). `deleted_at` is set when the file is removed; the row stays as the record.
changes = Table(
    "app_changes",
    operational_metadata,
    Column("change_id", String(40), primary_key=True),
    Column("device_actor_id", String(64), nullable=False),
    Column("session_id", String(128), nullable=False),
    Column("kind", String(16), nullable=False),
    Column("remote", String(64), nullable=True),
    Column("branch", String(200), nullable=True),
    Column("source", String(200), nullable=True),
    Column("head", String(64), nullable=False),
    Column("base", String(64), nullable=True),
    Column("commits", Text, nullable=False),
    Column("fingerprint", String(64), nullable=False),
    Column("state", String(16), nullable=False),
    Column("diff_result", Text, nullable=False),
    Column("sandbox_result", Text, nullable=True),
    Column("created_at", UtcDateTime, nullable=False),
    Column("expires_at", UtcDateTime, nullable=False),
    Column("report_at", UtcDateTime, nullable=True),
    Column("deleted_at", UtcDateTime, nullable=True),
    Index("ix_app_changes_fingerprint", "fingerprint"),
)
