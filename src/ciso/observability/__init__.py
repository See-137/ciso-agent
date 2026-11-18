"""Redacted structured logs, in-process metrics and health aggregation (NFR-012, NFR-018)."""

from __future__ import annotations

from ciso.observability.health import (
    CheckResult,
    ComponentHealth,
    HealthCheck,
    HealthRegistry,
    HealthReport,
    HealthState,
)
from ciso.observability.logs import (
    RedactingJsonHandler,
    configure_logging,
    dropped_records_check,
    remove_logging,
)
from ciso.observability.metrics import PREDEFINED_COUNTERS, MetricNames, MetricsRegistry

__all__ = [
    "PREDEFINED_COUNTERS",
    "CheckResult",
    "ComponentHealth",
    "HealthCheck",
    "HealthRegistry",
    "HealthReport",
    "HealthState",
    "MetricNames",
    "MetricsRegistry",
    "RedactingJsonHandler",
    "configure_logging",
    "dropped_records_check",
    "remove_logging",
]
