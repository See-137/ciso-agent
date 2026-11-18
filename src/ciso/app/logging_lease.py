"""Sharing the process's one redacting log handler between live containers (NFR-012).

`configure_logging` keeps a single redacting handler on the root logger and hands the
same one to every caller, adding each caller's redactor to it. A container therefore must
not remove that handler on `close()` while another container still logs through it.

Each container takes a `LogLease`, recorded on the shared handler as a `ContainerLogFilter`
(a filter that passes every record unchanged):

- while it is held, the handler applies this container's redactor to every line, so a
  secret one container resolved is redacted from every line the process writes;
  releasing it removes that redactor again, unless it is the handler's first one (the
  container that installed the handler), which stays for the handler's lifetime;
- it counts as a holder: the handler is removed only when the last lease is released,
  and only if a container put it there. A handler someone else installed (a test
  harness, a server's own start-up) is left in place.

No module-level state: the leases live on the handler itself, as its filters.
"""

from __future__ import annotations

import logging
from collections.abc import Sequence
from typing import IO

from ciso.common.protocols import Redactor
from ciso.observability import (
    MetricsRegistry,
    RedactingJsonHandler,
    configure_logging,
    remove_logging,
)


class ContainerLogFilter(logging.Filter):
    """One live container's hold on the shared handler. Records pass unchanged: the
    handler itself applies every holder's redactor."""

    def __init__(
        self,
        redactor: Redactor,
        *,
        added_redactor: bool,
        owns_handler: bool,
        root_level: int,
        logger_names: tuple[str, ...],
    ) -> None:
        super().__init__()
        self.redactor = redactor
        #: True when this lease added its redactor to an existing handler (release removes it).
        self.added_redactor = added_redactor
        #: True when a container installed the handler, so the last lease removes it.
        self.owns_handler = owns_handler
        #: The root level before the first container changed it.
        self.root_level = root_level
        #: Every non-propagating logger the handler was attached to by any container.
        self.logger_names = logger_names

    def filter(self, record: logging.LogRecord) -> bool:
        return True


def _holders(handler: logging.Handler) -> list[ContainerLogFilter]:
    return [f for f in handler.filters if isinstance(f, ContainerLogFilter)]


def _existing_handler() -> RedactingJsonHandler | None:
    for existing in logging.getLogger().handlers:
        if isinstance(existing, RedactingJsonHandler):
            return existing
    return None


class LogLease:
    """Returned by `acquire_logging`; `release()` is idempotent."""

    def __init__(self, handler: RedactingJsonHandler, hold: ContainerLogFilter) -> None:
        self.handler = handler
        self._hold = hold
        self._released = False

    def release(self) -> None:
        """Drop this container's hold and the redactor it added. The last holder removes a
        container-installed handler from every logger it was attached to and restores the
        root level."""
        if self._released:
            return
        self._released = True
        self.handler.removeFilter(self._hold)
        if self._hold.added_redactor:
            self.handler.remove_redactor(self._hold.redactor)
        if _holders(self.handler) or not self._hold.owns_handler:
            return
        remove_logging(self.handler, self._hold.logger_names)
        logging.getLogger().setLevel(self._hold.root_level)


def acquire_logging(
    redactor: Redactor,
    level: int | str,
    *,
    stream: IO[str] | None,
    metrics: MetricsRegistry | None,
    logger_names: Sequence[str],
) -> LogLease:
    """Configure (or join) the redacting root handler and take a lease on it.

    When a handler is already installed, `stream` is ignored (see `configure_logging`):
    every container in the process writes to the first handler's stream.
    """
    root_level = logging.getLogger().level
    existing = _existing_handler()
    holders = _holders(existing) if existing is not None else []
    already = existing is not None and any(r is redactor for r in existing.redactors)
    handler = configure_logging(
        redactor, level, stream=stream, metrics=metrics, logger_names=logger_names
    )
    names = tuple(dict.fromkeys((*logger_names, *(n for h in holders for n in h.logger_names))))
    if existing is None:
        owns, original_level = True, root_level
    elif holders:
        owns, original_level = any(h.owns_handler for h in holders), holders[0].root_level
    else:
        owns, original_level = False, root_level
    hold = ContainerLogFilter(
        redactor,
        added_redactor=existing is not None and not already,
        owns_handler=owns,
        root_level=original_level,
        logger_names=names,
    )
    handler.addFilter(hold)
    for other in holders:
        other.logger_names = names
    return LogLease(handler, hold)
