"""Operational table for the inference invocation log (blueprint 8.3, gap G31).

The row holds metadata only. The prompt body and the model output are never stored; the
output is represented by its size and, when a key is configured, a keyed digest.
"""

from __future__ import annotations

from sqlalchemy import Column, Float, Index, Integer, String, Table, Text

from ciso.common.db import UtcDateTime, operational_metadata, register_schema

register_schema("inference", 1)

inference_invocation = Table(
    "inference_invocation",
    operational_metadata,
    Column("id", String(40), primary_key=True),
    Column("occurred_at", UtcDateTime, nullable=False),
    Column("provider_name", String(100), nullable=False),
    Column("model_id", String(200), nullable=False),
    Column("model_version", String(100), nullable=False),
    Column("prompt_template_id", String(100), nullable=False),
    Column("prompt_template_version", Integer, nullable=False),
    Column("prompt_template_sha256", String(64), nullable=False),
    Column("task_category", String(100), nullable=False),
    Column("context_refs", Text, nullable=False),
    Column("latency_seconds", Float, nullable=True),
    Column("provider_reported_seconds", Float, nullable=True),
    Column("input_tokens", Integer, nullable=True),
    Column("output_tokens", Integer, nullable=True),
    Column("status", String(24), nullable=False),
    Column("error_type", String(100), nullable=True),
    Column("output_size", Integer, nullable=False),
    Column("output_digest", String(64), nullable=True),
    Column("correlation_id", String(100), nullable=False),
    Index("ix_inference_invocation_correlation", "correlation_id"),
    Index("ix_inference_invocation_occurred", "occurred_at"),
)
