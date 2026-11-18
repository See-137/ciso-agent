"""In-process counters and gauges with label sets. No exporter, no network (ADR-0020).

Counter names are fixed in `MetricNames`; incrementing an undeclared name raises, so a typo
cannot create a silent second series. Labels are passed as a mapping, so a label may be
called anything (`name`, `value`, `amount`) without clashing with a parameter.

Each metric holds at most `max_series_per_metric` distinct label sets. A new label set
beyond that is refused: nothing is recorded, `rejected_series` goes up and one warning is
logged per metric. A metric whose labels carry user-controlled text cannot grow memory
without bound. `None` allows one series per metric (the unlabelled one) and nothing more.
"""

from __future__ import annotations

import logging
import threading
from collections.abc import Mapping
from typing import Any

from ciso.common.errors import ValidationFailed

log = logging.getLogger(__name__)

LabelKey = tuple[tuple[str, str], ...]


class MetricNames:
    POLICY_DECISIONS = "ciso_policy_decisions_total"  # label: outcome
    BROKER_EXECUTIONS = "ciso_broker_executions_total"  # label: state
    INFERENCE_CALLS = "ciso_inference_calls_total"  # label: result
    CONNECTOR_SYNCS = "ciso_connector_syncs_total"  # label: result
    AUDIT_APPENDS = "ciso_audit_appends_total"
    KILLSWITCH_BLOCKED_READS = "ciso_killswitch_blocked_reads_total"
    LOG_RECORDS_DROPPED = "ciso_log_records_dropped_total"
    QUEUE_DEAD_LETTERS = "ciso_queue_dead_letters_total"  # label: kind (never the reason)


PREDEFINED_COUNTERS: tuple[str, ...] = (
    MetricNames.POLICY_DECISIONS,
    MetricNames.BROKER_EXECUTIONS,
    MetricNames.INFERENCE_CALLS,
    MetricNames.CONNECTOR_SYNCS,
    MetricNames.AUDIT_APPENDS,
    MetricNames.KILLSWITCH_BLOCKED_READS,
    MetricNames.LOG_RECORDS_DROPPED,
    MetricNames.QUEUE_DEAD_LETTERS,
)


def _key(labels: Mapping[str, str] | None) -> LabelKey:
    if not labels:
        return ()
    for k, v in labels.items():
        if not isinstance(k, str) or not isinstance(v, str):
            raise ValidationFailed("label names and values must be strings")
    return tuple(sorted(labels.items()))


class MetricsRegistry:
    """Counters and gauges. Safe to share between threads."""

    def __init__(self, *, max_series_per_metric: int | None) -> None:
        if max_series_per_metric is not None and (
            isinstance(max_series_per_metric, bool)
            or not isinstance(max_series_per_metric, int)
            or max_series_per_metric < 1
        ):
            raise ValidationFailed("max_series_per_metric must be a positive integer or None")
        self._cap = 1 if max_series_per_metric is None else max_series_per_metric
        self._lock = threading.Lock()
        self._counters: dict[str, dict[LabelKey, int]] = {n: {} for n in PREDEFINED_COUNTERS}
        self._gauges: dict[str, dict[LabelKey, float]] = {}
        self._rejected = 0
        self._warned: set[str] = set()

    @property
    def rejected_series(self) -> int:
        """How many increments or sets were refused because of the series cap."""
        with self._lock:
            return self._rejected

    def declare_counter(self, name: str) -> None:
        with self._lock:
            self._counters.setdefault(name, {})

    def declare_gauge(self, name: str) -> None:
        with self._lock:
            self._gauges.setdefault(name, {})

    def inc(self, name: str, amount: int = 1, labels: Mapping[str, str] | None = None) -> None:
        if isinstance(amount, bool) or not isinstance(amount, int) or amount < 0:
            raise ValidationFailed("counters only go up, by an integer")
        key = _key(labels)
        with self._lock:
            series = self._counters.get(name)
            if series is None:
                raise ValidationFailed(f"undeclared counter: {name}")
            if self._admit(name, series, key):
                series[key] = series.get(key, 0) + amount

    def value(self, name: str, labels: Mapping[str, str] | None = None) -> int:
        with self._lock:
            series = self._counters.get(name)
            if series is None:
                raise ValidationFailed(f"undeclared counter: {name}")
            return series.get(_key(labels), 0)

    def set_gauge(self, name: str, value: float, labels: Mapping[str, str] | None = None) -> None:
        key = _key(labels)
        with self._lock:
            series = self._gauges.get(name)
            if series is None:
                raise ValidationFailed(f"undeclared gauge: {name}")
            if self._admit(name, series, key):
                series[key] = value

    def gauge(self, name: str, labels: Mapping[str, str] | None = None) -> float | None:
        with self._lock:
            series = self._gauges.get(name)
            if series is None:
                raise ValidationFailed(f"undeclared gauge: {name}")
            return series.get(_key(labels))

    def snapshot(self) -> dict[str, Any]:
        """Plain JSON-serialisable data: each metric is a list of `{labels, value}`."""
        with self._lock:

            def rows(table: Mapping[LabelKey, Any]) -> list[dict[str, Any]]:
                return [{"labels": dict(k), "value": v} for k, v in sorted(table.items())]

            return {
                "counters": {n: rows(s) for n, s in self._counters.items()},
                "gauges": {n: rows(s) for n, s in self._gauges.items()},
                "rejected_series": self._rejected,
            }

    def _admit(self, name: str, series: Mapping[LabelKey, Any], key: LabelKey) -> bool:
        """Caller holds the lock. True if `key` exists or may be added."""
        if key in series or len(series) < self._cap:
            return True
        self._rejected += 1
        if name not in self._warned:
            self._warned.add(name)
            log.warning(
                "metric %s reached its series cap (%d); new label sets refused", name, self._cap
            )
        return False
