"""Approval table on the shared operational metadata. Blueprint 9.5; gaps G2, G3, G12.

One row per approval request. `status` is pending, approved, rejected, consumed or void;
"valid" and "expired" are never stored. `binding`, `parties`, `required_roles`,
`decided_roles` and `target` hold canonical JSON. `decision_audit_ref` is the audit
record id of the grant and is written only after that record exists: an approved row
without it cannot be used. `parties` lists actor ids besides the requester who may not
decide. Actors are plain ids, never foreign keys into another module's tables.
"""

from __future__ import annotations

from sqlalchemy import Boolean, Column, Index, String, Table, Text

from ciso.common.db import UtcDateTime, operational_metadata, register_schema

register_schema("approvals", 1)

approval = Table(
    "approval",
    operational_metadata,
    Column("approval_id", String(40), primary_key=True),
    Column("subject_kind", String(64), nullable=False),
    Column("subject_hash", String(64), nullable=False),
    Column("binding", Text, nullable=False),
    Column("requested_by", String(128), nullable=False),
    Column("requested_by_type", String(16), nullable=False),
    Column("parties", Text, nullable=False, default="[]"),
    Column("required_roles", Text, nullable=False),
    Column("target", Text, nullable=False),
    Column("status", String(16), nullable=False),
    Column("requested_at", UtcDateTime, nullable=False),
    Column("expires_at", UtcDateTime, nullable=False),
    Column("correlation_id", String(128), nullable=False, default=""),
    Column("decided_by", String(128), nullable=True),
    Column("decided_at", UtcDateTime, nullable=True),
    Column("decided_roles", Text, nullable=False, default="[]"),
    Column("decision_note", Text, nullable=False, default=""),
    Column("self_approved", Boolean, nullable=False, default=False),
    Column("approver_credential_issuer", String(128), nullable=True),
    Column("decision_audit_ref", String(64), nullable=True),
    Column("consumed_at", UtcDateTime, nullable=True),
    Column("consumed_by", String(128), nullable=True),
    Index("ix_approval_status_requested_at", "status", "requested_at"),
)
