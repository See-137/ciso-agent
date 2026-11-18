"""Execution tables on the shared operational metadata.

`execution_channel` holds one row per notification or ticket channel (plan gap G13,
blueprint 9.1 L2). A channel is usable only while its status is `approved` AND
`approval_audit_ref` holds the id of the audit record of that approval: the status alone
is written one step earlier as `approving`, so a crash between the two never leaves a
usable row without its record. `target` is the name of a local outbox, never an address
(OD-13). `version` goes up by one on every change, so an undo can tell whether the row
is still the one it wrote, and an approval can tell whether it is the proposal that was
reviewed.

`execution_run` holds one row per requesting actor and idempotency key the broker
accepted for a tool call (plan gap G5, blueprint 9.4 `execution_result / residual_risk`).
The key is unique per actor, not globally: one actor cannot occupy another's key. The row
is inserted as `pending` before the attempt is audited and before the tool is called, and
it is the record of what is known about the side effect. `attempt_audit_ref` is the audit
record id of the attempt: the tool is called only after it is stored, so a `pending` row
without it never reached the tool. `result_audit_ref` is the audit record id of the
closing record: a finished row with an audited attempt and without it still owes that
record.

`run_token` and `claimed_at` say which run holds the row and since when (injected
clock). The broker's state changes are conditional on its own token; start-up recovery
touches only rows claimed before its process started and replaces the token. The rate
limit counts rows per operation by `claimed_at`, so it survives a restart.

`envelope` is the request as canonical JSON AFTER the `Redactor`: a secret pasted into an
argument is not kept here. It is not the request as received, and it is still operational
content (titles, bodies, purposes) that readers of this database and its backups see.
`envelope_hash` is the hash of the request as submitted; `stored_envelope_hash` is the
SHA-256 of the `envelope` text. A later verification rebuilds the call from `envelope`,
which is exact only when the redactor changed nothing.

`row_mac` authenticates every other column that the `ExecutionRecord` carries
(`ciso.execution.integrity`). It makes an edited row unreadable. It cannot show that a
row was deleted: the audit log is the record that survives a delete, and nothing here
cross-checks it. Actors, approvals and targets are plain ids and entity refs, never
foreign keys.

The schema version stays 1: this build has no migration path (ADR-0002) and no deployed
database, so the table is defined as it is now.
"""

from __future__ import annotations

from sqlalchemy import Boolean, Column, Index, Integer, String, Table, Text, UniqueConstraint

from ciso.common.db import UtcDateTime, operational_metadata, register_schema

register_schema("execution", 1)

execution_channel = Table(
    "execution_channel",
    operational_metadata,
    Column("channel", String(64), primary_key=True),
    Column("target", String(64), nullable=False),
    Column("status", String(16), nullable=False),
    Column("purpose", Text, nullable=False),
    Column("proposed_by", String(128), nullable=False),
    Column("proposed_at", UtcDateTime, nullable=False),
    Column("decided_by", String(128), nullable=False, default=""),
    Column("decided_at", UtcDateTime, nullable=True),
    Column("approval_audit_ref", String(64), nullable=False, default=""),
    Column("revoked_by", String(128), nullable=False, default=""),
    Column("revoked_at", UtcDateTime, nullable=True),
    Column("revoke_reason", Text, nullable=False, default=""),
    Column("version", Integer, nullable=False),
)

execution_run = Table(
    "execution_run",
    operational_metadata,
    Column("execution_id", String(40), primary_key=True),
    Column("idempotency_key", String(128), nullable=False),
    Column("envelope_hash", String(64), nullable=False),
    Column("stored_envelope_hash", String(64), nullable=False),
    Column("request_id", String(40), nullable=False),
    Column("operation", String(128), nullable=False),
    Column("authority_level", Integer, nullable=False),
    Column("actor_id", String(128), nullable=False),
    Column("actor_type", String(16), nullable=False),
    Column("target_resource", String(192), nullable=False),
    Column("envelope", Text, nullable=False),
    Column("state", String(24), nullable=False),
    Column("policy_outcome", String(24), nullable=False),
    Column("ruleset_hash", String(64), nullable=False, default=""),
    Column("approval_ref", String(64), nullable=True),
    Column("run_token", String(64), nullable=True),
    Column("claimed_at", UtcDateTime, nullable=True),
    Column("attempt_audit_ref", String(64), nullable=True),
    Column("tool_outcome", String(16), nullable=True),
    Column("result_references", Text, nullable=False, default="[]"),
    Column("tool_detail", Text, nullable=False, default=""),
    Column("verification_matches", Boolean, nullable=True),
    Column("verification_detail", Text, nullable=False, default=""),
    Column("observed", Text, nullable=False, default="[]"),
    Column("residual_risk", Text, nullable=False, default=""),
    Column("error_kind", String(96), nullable=False, default=""),
    Column("result_audit_ref", String(64), nullable=True),
    Column("created_at", UtcDateTime, nullable=False),
    Column("updated_at", UtcDateTime, nullable=False),
    Column("row_mac", String(64), nullable=False),
    UniqueConstraint("actor_id", "idempotency_key"),
    Index("ix_execution_run_operation_claimed_at", "operation", "claimed_at"),
    Index("ix_execution_run_state", "state"),
)
