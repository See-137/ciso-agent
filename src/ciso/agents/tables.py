"""Agent registry tables on the operational database (docs/skill/spec-draft.md, S1).

Person and agent references are `EntityRef` strings, never foreign keys into another
module's tables.
"""

from __future__ import annotations

from sqlalchemy import (
    Boolean,
    Column,
    ForeignKey,
    Index,
    Integer,
    PrimaryKeyConstraint,
    String,
    Table,
)

from ciso.common.db import UtcDateTime, operational_metadata, register_schema

register_schema("agents", 1)

_TEXT = 512
_REF = 200

agents = Table(
    "agents_agents",
    operational_metadata,
    Column("id", String(40), primary_key=True),
    Column("display_name", String(_REF), nullable=False),
    Column("agent_class", String(32), nullable=False),
    Column("status", String(16), nullable=False),
    Column("surface", String(32), nullable=False),
    Column("owner_ref", String(_REF), nullable=True),
    Column("operator_ref", String(_REF), nullable=True),
    #: Set only on records attribution created. Unique: one observed record per session.
    Column("observed_session_id", String(_TEXT), nullable=True, unique=True),
    Column("status_before_suspension", String(16), nullable=True),
    Column("created_at", UtcDateTime(), nullable=False),
    Column("updated_at", UtcDateTime(), nullable=False),
    Index("ix_agents_agents_status", "status"),
    Index("ix_agents_agents_operator", "operator_ref"),
)

agent_facts = Table(
    "agents_facts",
    operational_metadata,
    Column("agent_id", String(40), ForeignKey("agents_agents.id"), nullable=False),
    Column("kind", String(32), nullable=False),
    Column("value", String(_TEXT), nullable=False),
    PrimaryKeyConstraint("agent_id", "kind", "value"),
    Index("ix_agents_facts_kind_value", "kind", "value"),
)

bindings = Table(
    "agents_bindings",
    operational_metadata,
    Column("id", String(40), primary_key=True),
    Column("kind", String(32), nullable=False),
    Column("subject", String(_TEXT), nullable=False),
    Column("person_ref", String(_REF), nullable=False),
    Column("bound_at", UtcDateTime(), nullable=False),
    Column("bound_by", String(64), nullable=False),
    Column("unbound_at", UtcDateTime(), nullable=True),
    Column("unbound_by", String(64), nullable=True),
    Index("ix_agents_bindings_person", "person_ref"),
)

#: At most one ACTIVE binding per claim. Unbound rows stay as history.
Index(
    "uq_agents_bindings_active_claim",
    bindings.c.kind,
    bindings.c.subject,
    unique=True,
    sqlite_where=bindings.c.unbound_at.is_(None),
)

sessions = Table(
    "agents_sessions",
    operational_metadata,
    Column("session_id", String(_TEXT), primary_key=True),
    Column("first_seen", UtcDateTime(), nullable=False),
    Column("last_seen", UtcDateTime(), nullable=False),
    Column("device", String(_TEXT), nullable=False),
    Column("surface", String(_TEXT), nullable=False),
    Column("agent_ref", String(_REF), nullable=True),
    Column("person_ref", String(_REF), nullable=True),
    Column("state", String(16), nullable=False),
    Column("claim_overflow", Integer(), nullable=False),
    Index("ix_agents_sessions_person", "person_ref"),
)

session_claims = Table(
    "agents_session_claims",
    operational_metadata,
    Column("session_id", String(_TEXT), ForeignKey("agents_sessions.session_id"), nullable=False),
    Column("kind", String(32), nullable=False),
    Column("subject", String(_TEXT), nullable=False),
    Column("verified", Boolean(), nullable=False),
    Column("first_seen", UtcDateTime(), nullable=False),
    PrimaryKeyConstraint("session_id", "kind", "subject", "verified"),
)
