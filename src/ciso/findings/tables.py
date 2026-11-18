"""Findings tables on the shared operational metadata (milestone S6).

`finding` holds one row per finding; rows are never deleted. A partial unique index keeps
at most one active (open or acknowledged) finding per fingerprint, so two writers cannot
both open the same finding. `finding_transition` is the status history. `alert` holds
each alert and its delivery state. Cross-module references are plain strings.
"""

from __future__ import annotations

from sqlalchemy import Column, Index, Integer, String, Table, Text, text

from ciso.common.db import UtcDateTime, operational_metadata, register_schema

register_schema("findings", 1)

_ID = 40
_REF = 512
_SHORT = 64

finding = Table(
    "findings_finding",
    operational_metadata,
    Column("finding_id", String(_ID), primary_key=True),
    Column("fingerprint", String(64), nullable=False),
    Column("origin", String(16), nullable=False),
    Column("status", String(16), nullable=False),
    Column("severity", String(16), nullable=False),
    Column("category", String(_REF), nullable=False),
    Column("check_key", String(_REF), nullable=False),
    Column("title", String(_REF), nullable=False),
    Column("session_id", String(_REF), nullable=False),
    Column("person_ref", String(_REF), nullable=True),
    Column("agent_ref", String(_REF), nullable=True),
    Column("agent_class", String(_SHORT), nullable=False),
    Column("action_kind", String(_SHORT), nullable=False),
    Column("repository", String(_REF), nullable=False, default=""),
    Column("branch", String(_REF), nullable=False, default=""),
    Column("path", String(_REF), nullable=False, default=""),
    Column("decision_id", String(128), nullable=False),
    Column("verdict", String(16), nullable=False),
    Column("last_decision_id", String(128), nullable=False),
    Column("evidence_refs", Text, nullable=False, default="[]"),
    Column("recommendation", String(_REF), nullable=False),
    Column("occurrences", Integer, nullable=False),
    Column("first_seen", UtcDateTime, nullable=False),
    Column("last_seen", UtcDateTime, nullable=False),
    Column("status_changed_by", String(128), nullable=False, default=""),
    Column("status_changed_at", UtcDateTime, nullable=True),
    Column("approval_ref", String(128), nullable=True),
    Column("status_reason", String(_REF), nullable=False, default=""),
    Column("version", Integer, nullable=False),
    Index("ix_findings_finding_status_severity", "status", "severity"),
    Index("ix_findings_finding_person", "person_ref"),
    Index("ix_findings_finding_last_seen", "last_seen"),
    Index(
        "uq_findings_finding_active_fingerprint",
        "fingerprint",
        unique=True,
        sqlite_where=text("status IN ('open', 'acknowledged')"),
    ),
)

finding_transition = Table(
    "findings_transition",
    operational_metadata,
    Column("transition_id", String(_ID), primary_key=True),
    Column("finding_id", String(_ID), nullable=False),
    Column("from_status", String(16), nullable=False),
    Column("to_status", String(16), nullable=False),
    Column("actor_id", String(128), nullable=False),
    Column("at", UtcDateTime, nullable=False),
    Column("approval_ref", String(128), nullable=True),
    Index("ix_findings_transition_finding", "finding_id"),
)

alert = Table(
    "findings_alert",
    operational_metadata,
    Column("alert_id", String(_ID), primary_key=True),
    Column("trigger", String(32), nullable=False),
    Column("finding_id", String(_ID), nullable=False),
    Column("decision_id", String(128), nullable=False),
    Column("severity", String(16), nullable=False),
    Column("title", String(_REF), nullable=False),
    Column("person_ref", String(_REF), nullable=True),
    Column("agent_ref", String(_REF), nullable=True),
    Column("repository", String(_REF), nullable=False, default=""),
    Column("branch", String(_REF), nullable=False, default=""),
    Column("recommendation", String(_REF), nullable=False),
    Column("created_at", UtcDateTime, nullable=False),
    Column("status", String(16), nullable=False),
    Column("attempts", Integer, nullable=False, default=0),
    Column("last_failure", String(128), nullable=False, default=""),
    Column("delivered_at", UtcDateTime, nullable=True),
    Index("ix_findings_alert_status", "status"),
)
