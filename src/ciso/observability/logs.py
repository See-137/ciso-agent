"""Structured (JSON lines) logging where every record passes the redactor first.

Message, arguments, extra fields and exception text are all redacted, and the finished
line is redacted once more. If the redactor raises, the record is dropped and counted:
losing a log line is better than emitting an unredacted one (NFR-012). The count is
available as `handler.dropped`, as a metric (when a registry is given) and through
`dropped_records_check`, which reports `unhealthy` once anything was dropped.

One handler serves the whole process. Each `configure_logging` call adds its redactor to
that handler, so several components (two live containers, say) each get their own
secrets scrubbed from every line; `remove_redactor` drops one that was added, and the
handler's first redactor stays for its lifetime. Exception text is printed from
`exc_info`, or, when an upstream filter has already rendered and redacted it and cleared
`exc_info` (`ciso.vault.RedactingLogFilter`), from `exc_text`; either way it passes every
redactor again.

Loggers that do not propagate to the root logger (a server's own access and error
loggers, for example) never reach the root handler. Pass their names as `logger_names`:
foreign handlers on them are removed and the redacting handler is attached instead.
"""

from __future__ import annotations

import contextlib
import json
import logging
import math
import sys
import threading
from collections.abc import Sequence
from typing import IO, Any

from ciso.common.protocols import Redactor
from ciso.observability.health import CheckResult, HealthCheck, HealthState
from ciso.observability.metrics import MetricNames, MetricsRegistry

_STANDARD_ATTRS = frozenset(logging.LogRecord("", 0, "", 0, "", None, None).__dict__.keys()) | {
    "message",
    "asctime",
    "taskName",
}


class RedactingJsonHandler(logging.StreamHandler):  # type: ignore[type-arg]
    """Writes one JSON object per record. `dropped` counts records that could not be made safe.

    Every redactor in `redactors` is applied to every text and value, in order.
    """

    def __init__(
        self, redactor: Redactor, stream: IO[str], metrics: MetricsRegistry | None = None
    ) -> None:
        super().__init__(stream)
        self._redactors: tuple[Redactor, ...] = (redactor,)
        self._redactor_lock = threading.Lock()
        self.metrics = metrics
        self.dropped = 0

    @property
    def redactors(self) -> tuple[Redactor, ...]:
        return self._redactors

    def add_redactor(self, redactor: Redactor) -> bool:
        """Apply `redactor` too from now on. False if it is already applied."""
        with self._redactor_lock:
            if any(r is redactor for r in self._redactors):
                return False
            self._redactors = (*self._redactors, redactor)
            return True

    def remove_redactor(self, redactor: Redactor) -> bool:
        """Stop applying a redactor added with `add_redactor`. The first (constructor)
        redactor is never removed, so the handler is never left without one. Returns
        whether anything was removed."""
        with self._redactor_lock:
            base, *added = self._redactors
            kept = [r for r in added if r is not redactor]
            if len(kept) == len(added):
                return False
            self._redactors = (base, *kept)
            return True

    def _redact(self, text: str, redactors: tuple[Redactor, ...]) -> str:
        for red in redactors:
            text = red.redact(text)
        return text

    def _redact_value(self, value: Any, redactors: tuple[Redactor, ...]) -> Any:
        for red in redactors:
            value = red.redact_value(value)
        return value

    def format(self, record: logging.LogRecord) -> str:
        redactors = self._redactors  # one atomic read: a consistent snapshot
        body: dict[str, Any] = {
            "level": record.levelname,
            "logger": record.name,
            "message": self._redact(record.getMessage(), redactors),
        }
        if record.exc_info:
            text = logging.Formatter().formatException(record.exc_info)
            body["exc_info"] = self._redact(text, redactors)
        elif record.exc_text:
            body["exc_info"] = self._redact(record.exc_text, redactors)
        for key, value in record.__dict__.items():
            if key in _STANDARD_ATTRS or key in body:
                continue
            body[key] = self._redact_value(_jsonable(value), redactors)
        line = json.dumps(body, sort_keys=True, default=str, allow_nan=False)
        return self._redact(line, redactors)

    def handleError(self, record: logging.LogRecord) -> None:
        # The default prints a traceback to stderr, which is another unredacted channel.
        # Nothing here may log: that could recurse into this handler.
        self.dropped += 1
        metrics = self.metrics
        if metrics is not None:
            # A broken metric must not break logging; `dropped` still counts.
            with contextlib.suppress(Exception):
                metrics.inc(MetricNames.LOG_RECORDS_DROPPED)


def _jsonable(value: Any) -> Any:
    if isinstance(value, dict):
        return {str(k): _jsonable(v) for k, v in value.items()}
    if isinstance(value, list | tuple | set | frozenset):
        return [_jsonable(v) for v in value]
    if isinstance(value, float) and not math.isfinite(value):
        return repr(value)  # 'nan', 'inf': bare NaN is not valid JSON
    if value is None or isinstance(value, str | int | float | bool):
        return value
    return repr(value)


def _find(logger: logging.Logger) -> RedactingJsonHandler | None:
    for existing in logger.handlers:
        if isinstance(existing, RedactingJsonHandler):
            return existing
    return None


def configure_logging(
    redactor: Redactor,
    level: int | str,
    *,
    stream: IO[str] | None = None,
    metrics: MetricsRegistry | None = None,
    logger_names: Sequence[str] = (),
) -> RedactingJsonHandler:
    """Attach the redacting JSON handler to the root logger and set the root level.

    Idempotent: if the root logger already has the handler, that one is returned (with
    the level updated and `metrics` filled in if it had none) and no second handler is
    added. A second call's `redactor` is added to the existing handler (`add_redactor`),
    so its secrets are scrubbed too; its `stream` is ignored: every caller writes to the
    first handler's stream.

    `logger_names` lists loggers that do not propagate. Their other handlers are removed
    and the same handler is attached, so they cannot bypass redaction. Returns the handler
    so a caller or test can undo everything with `remove_logging`. The root level is
    changed and not restored; callers that need that keep the old value themselves.
    """
    root = logging.getLogger()
    handler = _find(root)
    if handler is None:
        handler = RedactingJsonHandler(redactor, stream if stream is not None else sys.stderr)
        root.addHandler(handler)
    else:
        handler.add_redactor(redactor)
    if handler.metrics is None:
        handler.metrics = metrics
    handler.setLevel(level)
    root.setLevel(level)
    for name in logger_names:
        named = logging.getLogger(name)
        for foreign in [h for h in named.handlers if h is not handler]:
            named.removeHandler(foreign)
        if not named.propagate and handler not in named.handlers:
            named.addHandler(handler)
    return handler


def remove_logging(handler: logging.Handler, logger_names: Sequence[str] = ()) -> None:
    """Detach `handler` from the root logger and the named loggers, and close it."""
    for logger in (logging.getLogger(), *(logging.getLogger(n) for n in logger_names)):
        logger.removeHandler(handler)
    handler.close()


def dropped_records_check(handler: RedactingJsonHandler) -> HealthCheck:
    """A health check that is `unhealthy` once the handler has dropped any record."""

    def check() -> CheckResult:
        if handler.dropped:
            return CheckResult(
                state=HealthState.UNHEALTHY, reason=f"{handler.dropped} log records dropped"
            )
        return CheckResult(state=HealthState.HEALTHY, reason="no log records dropped")

    return check
