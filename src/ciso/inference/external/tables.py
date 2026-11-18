"""Operational tables for the external model path (blueprint 8.4 steps 1 and 4 to 6).

`external_inference_proposal`: one row per proposal, holding who proposed what (ids, the
purpose hash and, per item, ref, label and a digest of the text) so that a proposal
presented again later can be recognised and a request id nobody proposed is refused.
`external_inference_authorization`: one row per approval request, holding what was
previewed (ids, hashes, sizes, labels and refs) so that transmit can compare.
`external_inference_record`: one row per transmission attempt, the step-6 record.

No table holds payload bytes, context item text or answer text. `purpose` is the
short, already redacted statement the approver agreed to (step 6 names it). Approvals and
actors are referenced by id or `EntityRef` string, never by foreign key.
"""

from __future__ import annotations

from sqlalchemy import Column, Index, Integer, String, Table, Text

from ciso.common.db import UtcDateTime, operational_metadata, register_schema

register_schema("inference_external", 1)

external_inference_proposal = Table(
    "external_inference_proposal",
    operational_metadata,
    Column("request_id", String(40), primary_key=True),
    Column("requester_actor_id", String(128), nullable=False),
    Column("provider_name", String(128), nullable=False),
    Column("model_name", String(128), nullable=False),
    Column("purpose_sha256", String(64), nullable=False),
    Column("items", Text, nullable=False),
    Column("created_at", UtcDateTime, nullable=False),
    Column("correlation_id", String(128), nullable=False, default=""),
)

external_inference_authorization = Table(
    "external_inference_authorization",
    operational_metadata,
    Column("approval_id", String(40), primary_key=True),
    Column("request_id", String(40), nullable=False),
    Column("subject_hash", String(64), nullable=False),
    Column("provider_name", String(128), nullable=False),
    Column("model_name", String(128), nullable=False),
    Column("purpose", Text, nullable=False),
    Column("purpose_sha256", String(64), nullable=False),
    Column("payload_sha256", String(64), nullable=False),
    Column("payload_bytes", Integer, nullable=False),
    Column("payload_classification", String(32), nullable=False),
    Column("kept", Text, nullable=False),
    Column("dropped", Text, nullable=False),
    Column("requested_by", String(128), nullable=False),
    Column("required_role", String(32), nullable=False),
    Column("created_at", UtcDateTime, nullable=False),
    Column("correlation_id", String(128), nullable=False, default=""),
    Index("ix_external_inference_authorization_request", "request_id"),
)

external_inference_record = Table(
    "external_inference_record",
    operational_metadata,
    Column("id", String(40), primary_key=True),
    Column("request_id", String(40), nullable=False),
    Column("approval_ref", String(64), nullable=False, unique=True),
    Column("requested_by", String(128), nullable=False),
    Column("transmitted_by", String(128), nullable=False),
    Column("approver", String(128), nullable=False),
    Column("approver_roles", Text, nullable=False),
    Column("approved_at", UtcDateTime, nullable=False),
    Column("provider_name", String(128), nullable=False),
    Column("model_name", String(128), nullable=False),
    Column("purpose", Text, nullable=False),
    Column("purpose_sha256", String(64), nullable=False),
    Column("payload_sha256", String(64), nullable=False),
    Column("payload_bytes", Integer, nullable=False),
    Column("payload_classification", String(32), nullable=False),
    Column("kept", Text, nullable=False),
    Column("policy_decision", Text, nullable=False),
    Column("attempted_at", UtcDateTime, nullable=False),
    Column("completed_at", UtcDateTime, nullable=True),
    Column("outcome", String(24), nullable=False),
    Column("error_type", String(100), nullable=True),
    Column("response_bytes", Integer, nullable=True),
    Column("response_digest", String(64), nullable=True),
    Column("response_metadata", Text, nullable=False, default="{}"),
    Column("result_ref", String(64), nullable=True),
    Column("correlation_id", String(128), nullable=False, default=""),
    Index("ix_external_inference_record_request", "request_id"),
    Index("ix_external_inference_record_attempted", "attempted_at"),
)
