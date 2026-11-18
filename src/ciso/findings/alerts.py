"""Alert delivery: the `AlertSink` protocol and two sinks (spec section 4 step 7).

A sink receives an `Alert` and sends only `Alert.payload()`: ids, severity, a short title,
person and agent references, repository and branch, and the fixed recommendation. Never
command text, content or a secret. A sink raises on failure; the service records the
failure on the alert and keeps it pending for `deliver_pending()`.
"""

from __future__ import annotations

import json
import logging
import os
import secrets
from pathlib import Path
from typing import Protocol, runtime_checkable

from ciso.common.errors import ValidationFailed
from ciso.common.ids import is_id
from ciso.findings.models import ALERT_PREFIX, Alert

logger = logging.getLogger(__name__)


@runtime_checkable
class AlertSink(Protocol):
    def deliver(self, alert: Alert) -> None:
        """Deliver the alert or raise. Called outside any database transaction."""
        ...


class InMemoryAlertSink:
    """For tests. `fail = True` makes every delivery raise `OSError`."""

    def __init__(self) -> None:
        self.delivered: list[Alert] = []
        self.fail = False

    def deliver(self, alert: Alert) -> None:
        if self.fail:
            raise OSError("in-memory alert sink set to fail")
        self.delivered.append(alert)


class DirectoryAlertSink:
    """Writes one JSON file per alert, `<alert_id>.json`, into an existing directory.

    The write is atomic: a temporary file in the same directory is written, flushed and
    fsynced, then hard-linked to its final name, which fails if that name exists (never
    an overwrite), and the temporary name is removed. Redelivering an alert whose file
    already holds the same content succeeds; a different file under that name raises
    `FileExistsError`. Alert ids must be platform ids (`alt_` + 26 characters), so a name
    cannot carry a path; the final path is also checked to sit directly in the directory.
    The directory itself is not fsynced (not possible on Windows).
    """

    def __init__(self, directory: Path) -> None:
        root = Path(directory)
        if not root.is_dir():
            raise ValidationFailed("alert directory must be an existing directory")
        self._root = root.resolve(strict=True)

    def _target(self, alert_id: str) -> Path:
        if not is_id(alert_id, ALERT_PREFIX):
            raise ValidationFailed("alert id is not a platform alert id")
        target = (self._root / f"{alert_id}.json").resolve()
        if target.parent != self._root:
            raise ValidationFailed("alert file would escape the alert directory")
        return target

    def deliver(self, alert: Alert) -> None:
        target = self._target(alert.alert_id)
        body = json.dumps(alert.payload(), sort_keys=True, ensure_ascii=True).encode("ascii")
        temp = self._root / f".{alert.alert_id}.{secrets.token_hex(8)}.tmp"
        try:
            with temp.open("xb") as handle:
                handle.write(body)
                handle.flush()
                os.fsync(handle.fileno())
            try:
                os.link(temp, target)
            except FileExistsError:
                if target.is_symlink() or target.read_bytes() != body:
                    raise
                logger.info("findings: alert %s was already delivered", alert.alert_id)
        finally:
            temp.unlink(missing_ok=True)
