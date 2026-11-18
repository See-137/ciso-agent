"""A crash inside the audit log's first `initialise()` no longer leaves the platform stuck
at `log_missing`: the next start-up completes it (M1 fix pass item 6b)."""

from __future__ import annotations

from pathlib import Path

import pytest
from tests.app.helpers import AUDIT_KEY, SECRET_ENV, build, event, provisional
from tests.fakes.core import FakeRedactor, FakeSecrets

from ciso.audit import AnchorEntry, AuditLog, HeadAnchor, VerifyStatus, init_audit_schema
from ciso.audit.anchor import AnchorKey
from ciso.common.clock import FixedClock
from ciso.common.db import create_db_engine

pytestmark = pytest.mark.resilience

REF = "secret://audit_hmac_key"


class CrashAfterAnchor(HeadAnchor):
    def write(
        self, key: AnchorKey, log_id: str, final: AnchorEntry, pending: AnchorEntry | None = None
    ) -> None:
        super().write(key, log_id, final, pending)
        raise RuntimeError("process killed (test)")


def crash_first_initialise(audit_db: Path, anchor_path: Path) -> str:
    engine = create_db_engine(audit_db)
    try:
        init_audit_schema(engine)
        anchor = CrashAfterAnchor(anchor_path, FakeSecrets({REF: AUDIT_KEY}), REF)
        log = AuditLog(engine, FixedClock(), FakeRedactor(), anchor)
        with pytest.raises(RuntimeError):
            log.initialise()
        assert log.log_id is None
        reading = anchor.read(anchor.load_key())
        assert reading.log_id is not None
        return reading.log_id
    finally:
        engine.dispose()


def test_start_up_after_an_interrupted_initialise_is_ready(tmp_path: Path) -> None:
    settings = provisional(tmp_path / "d")
    anchored = crash_first_initialise(settings.audit_db, settings.audit_anchor)
    with build(settings, SECRET_ENV) as c:
        assert c.readiness().missing == ()
        assert c.audit.log_id == anchored
        c.audit.append(event())
        assert c.audit.verify().status is VerifyStatus.OK
    with build(settings, SECRET_ENV) as again:  # and the id is remembered from now on
        assert again.readiness().ready is True
        assert again.audit.log_id == anchored
