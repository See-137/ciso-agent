"""Identity tables on the operational database (blueprint 9.3, gap G30, G32).

An actor is a user of the CISO platform. It is not a company person record: `person_ref`
optionally points at a registry Person by `EntityRef` string, never by foreign key.
"""

from __future__ import annotations

from sqlalchemy import CheckConstraint, Column, ForeignKey, Index, Integer, String, Table, Text

from ciso.common.db import UtcDateTime, operational_metadata, register_schema

register_schema("identity", 1)

actors = Table(
    "identity_actors",
    operational_metadata,
    Column("id", String(40), primary_key=True),
    Column("actor_type", String(16), nullable=False),
    Column("display_name", String(200), nullable=False),
    Column("status", String(16), nullable=False),
    Column("person_ref", String(200), nullable=True),
    Column("created_at", UtcDateTime(), nullable=False),
    Column("created_by", String(64), nullable=False),
)

role_assignments = Table(
    "identity_role_assignments",
    operational_metadata,
    Column("id", String(40), primary_key=True),
    Column("actor_id", String(40), ForeignKey("identity_actors.id"), nullable=False),
    Column("role", String(32), nullable=False),
    #: JSON object: {"system": [...], "environment": [...], "classification": [...]}.
    Column("scope_json", Text(), nullable=False),
    Column("valid_from", UtcDateTime(), nullable=False),
    Column("valid_until", UtcDateTime(), nullable=True),
    Column("assigned_by", String(64), nullable=False),
    Column("assigned_at", UtcDateTime(), nullable=False),
    Column("revoked_at", UtcDateTime(), nullable=True),
    Column("revoked_by", String(64), nullable=True),
    Index("ix_identity_role_assignments_actor", "actor_id"),
)

credentials = Table(
    "identity_credentials",
    operational_metadata,
    Column("token_id", String(40), primary_key=True),
    Column("actor_id", String(40), ForeignKey("identity_actors.id"), nullable=False),
    #: Hex scrypt digest of the secret part. The secret itself is never stored.
    Column("secret_hash", String(128), nullable=False),
    Column("salt", String(64), nullable=False),
    #: Cost parameters used for this row, so a later change of defaults keeps old tokens.
    Column("scrypt_n", Integer(), nullable=False),
    Column("scrypt_r", Integer(), nullable=False),
    Column("scrypt_p", Integer(), nullable=False),
    Column("created_at", UtcDateTime(), nullable=False),
    #: Who issued it: an admin actor id, or `host_local` for bootstrap and recovery (M4).
    Column("created_by", String(64), nullable=False),
    Column("expires_at", UtcDateTime(), nullable=False),
    Column("revoked_at", UtcDateTime(), nullable=True),
    Column("revoked_by", String(64), nullable=True),
    Column("last_used_at", UtcDateTime(), nullable=True),
    Index("ix_identity_credentials_actor", "actor_id"),
)

#: At most one row, ever (the primary key is a constant). Bootstrap inserts it in the same
#: transaction as the first admin, so two bootstraps cannot both succeed on any database
#: (review L5). Nothing deletes it.
bootstrap_marker = Table(
    "identity_bootstrap_marker",
    operational_metadata,
    Column("id", String(16), primary_key=True),
    Column("actor_id", String(40), nullable=False),
    Column("created_at", UtcDateTime(), nullable=False),
    CheckConstraint("id = 'bootstrap'", name="single_row"),
)

BOOTSTRAP_MARKER_ID = "bootstrap"
