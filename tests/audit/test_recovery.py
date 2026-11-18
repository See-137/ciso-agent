"""Two-phase anchor: crashes are repaired automatically and recorded; tampering is not
(coordinator item 3, review H1)."""

from __future__ import annotations

import json
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

import pytest
from sqlalchemy import Engine, event
from sqlalchemy.exc import OperationalError
from tests.audit.helpers import (
    ANCHOR_KEY_REF,
    drop_triggers,
    make_event,
    raw_exec,
)
from tests.fakes.core import FakeSecrets

from ciso.audit import (
    RECOVERY_ACTION,
    AnchorEntry,
    AuditLog,
    HeadAnchor,
    RecoveryCase,
    VerifyStatus,
    record_hash,
)
from ciso.audit.anchor import AnchorKey
from ciso.common.errors import FailClosed, IntegrityFailure

pytestmark = pytest.mark.resilience


class SimulatedCrash(Exception):
    """Stands in for the process dying at this point."""


class CrashingAnchor(HeadAnchor):
    """Crashes once: right after the pending write, or instead of the promotion."""

    def __init__(self, path: Path, secrets: FakeSecrets, at: str) -> None:
        super().__init__(path, secrets, ANCHOR_KEY_REF)
        self.at = at
        self.armed = False

    def write(
        self, key: AnchorKey, log_id: str, final: AnchorEntry, pending: AnchorEntry | None = None
    ) -> None:
        if self.armed and self.at == "promotion" and pending is None:
            self.armed = False
            raise SimulatedCrash
        super().write(key, log_id, final, pending)
        if self.armed and self.at == "pending" and pending is not None:
            self.armed = False
            raise SimulatedCrash


class FailingPromotionAnchor(HeadAnchor):
    def __init__(self, path: Path, secrets: FakeSecrets) -> None:
        super().__init__(path, secrets, ANCHOR_KEY_REF)
        self.armed = False

    def write(
        self, key: AnchorKey, log_id: str, final: AnchorEntry, pending: AnchorEntry | None = None
    ) -> None:
        if self.armed and pending is None:
            self.armed = False
            raise FailClosed("disk full")
        super().write(key, log_id, final, pending)


def _anchor_json(path: Path) -> dict[str, Any]:
    return dict(json.loads(path.read_text(encoding="utf-8")))


def _recoveries(log: AuditLog) -> list[str]:
    return [r.details["case"] for r in log.query(limit=100, action_prefix=RECOVERY_ACTION)]


@pytest.fixture
def crashing(
    make_log: Callable[..., AuditLog], anchor_path: Path, anchor_secrets: FakeSecrets
) -> Callable[[str], tuple[AuditLog, CrashingAnchor]]:
    def build(at: str) -> tuple[AuditLog, CrashingAnchor]:
        anchor = CrashingAnchor(anchor_path, anchor_secrets, at)
        log = make_log(anchor=anchor)
        log.initialise()
        for n in range(3):
            log.append(make_event(n))
        anchor.armed = True
        return log, anchor

    return build


def test_crash_after_pending_before_commit_is_recovered_on_next_append(
    crashing: Callable[[str], tuple[AuditLog, CrashingAnchor]],
    make_log: Callable[..., AuditLog],
    anchor_path: Path,
) -> None:
    log, _ = crashing("pending")
    with pytest.raises(SimulatedCrash):
        log.append(make_event(99))
    state = _anchor_json(anchor_path)
    assert state["final"]["seq"] == 3
    assert state["pending"]["seq"] == 4  # the crash signature really is on disk

    restarted = make_log()
    receipt = restarted.append(make_event(4))

    assert _recoveries(restarted) == [RecoveryCase.COMMIT_NOT_APPLIED.value]
    assert receipt.seq == 5  # 4 is the recovery record
    assert restarted.query(limit=10, target="asset:99") == []  # the crashed event is gone
    assert restarted.verify().status is VerifyStatus.OK


def test_crash_after_commit_before_promotion_is_recovered_on_next_append(
    crashing: Callable[[str], tuple[AuditLog, CrashingAnchor]],
    make_log: Callable[..., AuditLog],
    anchor_path: Path,
) -> None:
    log, _ = crashing("promotion")
    with pytest.raises(SimulatedCrash):
        log.append(make_event(99))
    assert _anchor_json(anchor_path)["pending"]["seq"] == 4

    restarted = make_log()
    receipt = restarted.append(make_event(5))

    assert _recoveries(restarted) == [RecoveryCase.PROMOTION_MISSING.value]
    assert [r.seq for r in restarted.query(limit=10, target="asset:99")] == [4]  # kept
    assert receipt.seq == 6
    assert restarted.verify().status is VerifyStatus.OK
    assert _anchor_json(anchor_path)["pending"] is None


@pytest.fixture
def failing_commit(audit_engine: Engine) -> Iterator[list[bool]]:
    armed = [False]

    def on_commit(conn: Any) -> None:
        if armed[0]:
            armed[0] = False
            raise OperationalError("COMMIT", {}, Exception("disk I/O error"))

    event.listen(audit_engine, "commit", on_commit)
    yield armed
    event.remove(audit_engine, "commit", on_commit)


def test_a_commit_that_raises_is_recovered_on_next_append(
    audit_log: AuditLog, failing_commit: list[bool], anchor_path: Path
) -> None:
    for n in range(3):
        audit_log.append(make_event(n))
    failing_commit[0] = True

    with pytest.raises(FailClosed):
        audit_log.append(make_event(99))
    assert _anchor_json(anchor_path)["pending"]["seq"] == 4
    assert len(audit_log.query(limit=10)) == 3

    receipt = audit_log.append(make_event(4))

    assert _recoveries(audit_log) == [RecoveryCase.COMMIT_NOT_APPLIED.value]
    assert receipt.seq == 5
    assert audit_log.verify().status is VerifyStatus.OK


def test_verify_and_open_repair_a_crash_too(
    crashing: Callable[[str], tuple[AuditLog, CrashingAnchor]],
    make_log: Callable[..., AuditLog],
) -> None:
    log, _ = crashing("pending")
    with pytest.raises(SimulatedCrash):
        log.append(make_event(99))

    restarted = make_log()
    result = restarted.verify()

    assert result.status is VerifyStatus.OK
    assert _recoveries(restarted) == [RecoveryCase.COMMIT_NOT_APPLIED.value]
    assert restarted.open() == restarted.log_id  # nothing left to repair
    assert len(_recoveries(restarted)) == 1


def test_a_failed_promotion_still_returns_the_receipt_and_is_repaired(
    audit_log: AuditLog,
    make_log: Callable[..., AuditLog],
    anchor_path: Path,
    anchor_secrets: FakeSecrets,
) -> None:
    anchor = FailingPromotionAnchor(anchor_path, anchor_secrets)
    log = make_log(anchor=anchor)
    log.append(make_event(1))
    anchor.armed = True

    receipt = log.append(make_event(2))  # committed and covered by the signed pending entry

    assert receipt.seq == 2
    assert _anchor_json(anchor_path)["pending"]["seq"] == 2
    assert log.append(make_event(3)).seq == 4
    assert _recoveries(log) == [RecoveryCase.PROMOTION_MISSING.value]


# Not crash signatures: reported, never repaired.


def test_a_different_record_at_the_pending_seq_is_refused(
    crashing: Callable[[str], tuple[AuditLog, CrashingAnchor]],
    make_log: Callable[..., AuditLog],
    audit_engine: Engine,
) -> None:
    log, _ = crashing("pending")
    with pytest.raises(SimulatedCrash):
        log.append(make_event(99))
    [*_, head] = log.query(limit=10)
    substitute = head.model_copy(
        update={"id": "aud_sub", "seq": 4, "prev_hash": head.hash, "details": {"n": 7}}
    )
    raw_exec(
        audit_engine,
        "INSERT INTO audit_record (id, seq, occurred_at, actor_id, actor_type, action, target,"
        " outcome, correlation_id, details, prev_hash, hash) VALUES ('aud_sub', 4, :at, :actor,"
        " 'human', 'test.event', :target, 'success', :corr, :details, :prev, :hash)",
        at=head.occurred_at.strftime("%Y-%m-%d %H:%M:%S.%f"),
        actor=head.actor_id,
        target=head.target,
        corr=head.correlation_id,
        details='{"n":7}',
        prev=head.hash,
        hash=record_hash(substitute),
    )

    restarted = make_log()
    result = restarted.verify()

    assert result.status is VerifyStatus.FAILED
    assert result.reason == "anchor_hash_mismatch"
    assert result.first_broken_seq == 4
    with pytest.raises(IntegrityFailure):
        restarted.append(make_event(5))
    assert _recoveries(restarted) == []


def test_truncation_below_final_with_a_pending_entry_is_refused(
    crashing: Callable[[str], tuple[AuditLog, CrashingAnchor]],
    make_log: Callable[..., AuditLog],
    audit_engine: Engine,
) -> None:
    log, _ = crashing("pending")
    with pytest.raises(SimulatedCrash):
        log.append(make_event(99))
    drop_triggers(audit_engine)
    raw_exec(audit_engine, "DELETE FROM audit_record WHERE seq = 3")

    restarted = make_log()

    assert restarted.verify().reason == "truncated"
    with pytest.raises(IntegrityFailure):
        restarted.open()
    assert _recoveries(restarted) == []


def test_recovery_state_written_by_another_key_is_not_repaired(
    crashing: Callable[[str], tuple[AuditLog, CrashingAnchor]],
    make_log: Callable[..., AuditLog],
    anchor_path: Path,
) -> None:
    log, _ = crashing("pending")
    with pytest.raises(SimulatedCrash):
        log.append(make_event(99))
    other = make_log(
        anchor=HeadAnchor(
            anchor_path,
            FakeSecrets({ANCHOR_KEY_REF: "other-anchor-key-for-the-recovery-test"}),
            ANCHOR_KEY_REF,
        )
    )
    with pytest.raises(FailClosed):
        other.append(make_event(5))
    assert _anchor_json(anchor_path)["pending"]["seq"] == 4  # untouched
