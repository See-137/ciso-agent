"""verify() reads a snapshot and does not block appends (coordinator item 2, review M5)."""

from __future__ import annotations

import threading
import time
from typing import Any

import pytest
from tests.audit.helpers import make_event

from ciso.audit import AuditLog, VerifyStatus
from ciso.audit import chain as chain_module

pytestmark = pytest.mark.resilience


class _Appender:
    """Appends until stopped; records when each append finished (monotonic seconds)."""

    def __init__(self, log: AuditLog) -> None:
        self._log = log
        self._stop = threading.Event()
        self.finished_at: list[float] = []
        self.errors: list[BaseException] = []
        self._thread = threading.Thread(target=self._run)

    def _run(self) -> None:
        n = 1000
        while not self._stop.is_set():
            try:
                self._log.append(make_event(n))
            except BaseException as exc:
                self.errors.append(exc)
                return
            self.finished_at.append(time.monotonic())
            n += 1

    def __enter__(self) -> _Appender:
        self._thread.start()
        return self

    def __exit__(self, *exc: object) -> None:
        self._stop.set()
        self._thread.join()


def test_verify_during_continuous_appends_is_always_ok(audit_log: AuditLog) -> None:
    for n in range(20):
        audit_log.append(make_event(n))

    with _Appender(audit_log) as appender:
        results = [audit_log.verify() for _ in range(8)]

    assert appender.errors == []
    assert len(appender.finished_at) > 0
    assert [r.status for r in results] == [VerifyStatus.OK] * 8
    assert [r.reason for r in results] == [None] * 8
    final = audit_log.verify()
    assert final.status is VerifyStatus.OK
    assert final.checked == 20 + len(appender.finished_at)


def test_appends_complete_while_a_slow_verify_walks(
    audit_log: AuditLog, monkeypatch: pytest.MonkeyPatch
) -> None:
    for n in range(40):
        audit_log.append(make_event(n))
    real_check = chain_module.check_row
    walking = threading.Event()

    def slow_check(row: Any, head: Any) -> Any:
        walking.set()
        time.sleep(0.01)
        return real_check(row, head)

    monkeypatch.setattr(chain_module, "check_row", slow_check)

    with _Appender(audit_log) as appender:
        start = time.monotonic()
        result = audit_log.verify()
        end = time.monotonic()

    assert walking.is_set()  # the slowed walk really ran
    assert end - start >= 0.4
    assert appender.errors == []
    during = [t for t in appender.finished_at if start < t < end]
    assert len(during) >= 1, "appends were blocked for the whole walk"
    assert result.status is VerifyStatus.OK
    assert result.checked >= 40
