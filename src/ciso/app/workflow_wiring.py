"""How the composition root builds the job queue (plan T1.14; gap G14, ADR-0019)."""

from __future__ import annotations

from sqlalchemy import Engine

from ciso.app.settings import Settings
from ciso.common.clock import Clock
from ciso.common.protocols import AuditSink, PrincipalResolver
from ciso.observability.metrics import MetricNames, MetricsRegistry
from ciso.workflows import JobQueue


def build_queue(
    settings: Settings,
    engine: Engine,
    clock: Clock,
    audit: AuditSink,
    principals: PrincipalResolver,
    metrics: MetricsRegistry,
) -> JobQueue:
    """The one `JobQueue`. Every number comes from `Settings.safety`; an unset one reaches
    the queue as `None` and the queue refuses."""
    safety = settings.safety

    def on_dead_letter(kind: str, reason: str) -> None:
        # The reason is free text: it stays in the queue's log line, never in a label.
        metrics.inc(MetricNames.QUEUE_DEAD_LETTERS, labels={"kind": kind})

    return JobQueue(
        engine,
        clock,
        audit,
        principals,
        lease_seconds=safety.queue_lease_seconds,
        max_attempts=safety.queue_max_attempts,
        backoff_base_seconds=safety.queue_backoff_base_seconds,
        backoff_max_seconds=safety.queue_backoff_max_seconds,
        on_dead_letter=on_dead_letter,
    )
