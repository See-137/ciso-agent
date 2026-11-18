"""HMAC head anchor: truncation, recompute, forgery and file handling (T1.2, G4, NFR-006)."""

from __future__ import annotations

import json
import logging
import sys
import threading
from collections.abc import Callable
from pathlib import Path

import pytest
from sqlalchemy import Engine
from tests.audit.helpers import (
    ANCHOR_KEY_REF,
    ANCHOR_KEY_VALUE,
    drop_triggers,
    make_event,
    raw_exec,
    raw_sql,
)
from tests.fakes.core import FakeRedactor, FakeSecrets

from ciso.audit import AuditLog, HeadAnchor, VerifyStatus, init_audit_schema, record_hash
from ciso.audit import anchor as anchor_module
from ciso.common.clock import FixedClock
from ciso.common.db import create_db_engine
from ciso.common.errors import FailClosed, IntegrityFailure, ValidationFailed
from ciso.common.schemas import thaw

pytestmark = pytest.mark.resilience


def _fill(log: AuditLog, count: int) -> None:
    for n in range(count):
        log.append(make_event(n))


def test_anchor_file_tracks_the_head_and_holds_no_key(
    audit_log: AuditLog, anchor_path: Path
) -> None:
    _fill(audit_log, 3)

    data = json.loads(anchor_path.read_text(encoding="utf-8"))
    [*_, head] = audit_log.query(limit=10)
    assert data["final"] == {"seq": 3, "head_hash": head.hash}
    assert data["pending"] is None
    assert data["log_id"] == audit_log.log_id
    assert len(data["key_id"]) == 16
    assert len(data["hmac"]) == 64
    assert ANCHOR_KEY_VALUE not in anchor_path.read_text(encoding="utf-8")
    leftovers = [p.name for p in anchor_path.parent.iterdir() if p != anchor_path]
    assert leftovers == []  # temp files are replaced or removed


@pytest.mark.parametrize("where", ["beside", "below"])
def test_an_anchor_inside_the_database_directory_is_refused(
    make_log: Callable[..., AuditLog],
    audit_db_path: Path,
    anchor_secrets: FakeSecrets,
    where: str,
) -> None:
    path = (
        audit_db_path.parent / "anchor.json"
        if where == "beside"
        else audit_db_path.parent / "sub" / "anchor.json"
    )
    with pytest.raises(ValidationFailed):
        make_log(anchor=HeadAnchor(path, anchor_secrets, ANCHOR_KEY_REF))


def test_an_anchor_elsewhere_is_accepted(
    make_log: Callable[..., AuditLog], tmp_path: Path, anchor_secrets: FakeSecrets
) -> None:
    log = make_log(anchor=HeadAnchor(tmp_path / "other" / "a.json", anchor_secrets, ANCHOR_KEY_REF))
    assert log.initialise()


@pytest.mark.parametrize("removed", [1, 2])
def test_tail_truncation_is_detected_and_appends_refused(
    audit_log: AuditLog, audit_engine: Engine, removed: int
) -> None:
    _fill(audit_log, 4)
    drop_triggers(audit_engine)
    raw_exec(audit_engine, "DELETE FROM audit_record WHERE seq > :keep", keep=4 - removed)

    result = audit_log.verify()

    assert result.status is VerifyStatus.FAILED
    assert result.reason == "truncated"
    assert result.first_broken_seq == 5 - removed
    assert result.head_seq == 4 - removed
    with pytest.raises(IntegrityFailure):
        audit_log.append(make_event(9))


def test_full_chain_recompute_without_the_key_is_detected(
    audit_log: AuditLog, audit_engine: Engine
) -> None:
    _fill(audit_log, 3)
    records = audit_log.query(limit=10)
    drop_triggers(audit_engine)
    prev = records[0].prev_hash
    for record in records:  # rewrite record 1, then re-chain everything after it
        details = {"n": 666} if record.seq == 1 else thaw(record.details)
        forged = record.model_copy(update={"details": details, "prev_hash": prev})
        new_hash = record_hash(forged)
        raw_exec(
            audit_engine,
            "UPDATE audit_record SET details = :details, prev_hash = :prev, hash = :hash"
            " WHERE seq = :seq",
            details=json.dumps(details, separators=(",", ":"), sort_keys=True),
            prev=prev,
            hash=new_hash,
            seq=record.seq,
        )
        prev = new_hash

    result = audit_log.verify()

    assert result.checked == 3  # the chain itself is internally consistent again
    assert result.status is VerifyStatus.FAILED
    assert result.reason == "anchor_hash_mismatch"
    assert result.first_broken_seq == 3


def test_record_forged_onto_the_end_without_the_key_fails(
    audit_log: AuditLog, audit_engine: Engine
) -> None:
    """Review M8: with the two-phase anchor, a head beyond the anchor is tampering."""
    _fill(audit_log, 2)
    [_, head] = audit_log.query(limit=10)
    forged = head.model_copy(update={"seq": 3, "id": "aud_forged", "prev_hash": head.hash})
    raw_exec(
        audit_engine,
        "INSERT INTO audit_record (id, seq, occurred_at, actor_id, actor_type, action, target,"
        " outcome, correlation_id, details, prev_hash, hash) VALUES (:id, 3, :at, :actor,"
        " 'human', 'test.event', '', 'success', '', :details, :prev, :hash)",
        id="aud_forged",
        at=head.occurred_at.strftime("%Y-%m-%d %H:%M:%S.%f"),
        actor=head.actor_id,
        details='{"n":1}',
        prev=head.hash,
        hash=record_hash(
            forged.model_copy(update={"target": "", "correlation_id": "", "details": {"n": 1}})
        ),
    )

    result = audit_log.verify()

    assert result.checked == 3
    assert result.status is VerifyStatus.FAILED
    assert result.reason == "anchor_behind_head"
    assert result.first_broken_seq == 3


def test_missing_anchor_is_unverifiable_not_ok(audit_log: AuditLog, anchor_path: Path) -> None:
    _fill(audit_log, 2)
    anchor_path.unlink()

    result = audit_log.verify()

    assert result.status is VerifyStatus.UNVERIFIABLE
    assert result.reason == "anchor_missing"
    with pytest.raises(IntegrityFailure):
        audit_log.append(make_event(9))
    assert len(audit_log.query(limit=10)) == 2


def test_unreadable_anchor_is_unverifiable(audit_log: AuditLog, anchor_path: Path) -> None:
    _fill(audit_log, 2)
    anchor_path.write_bytes(b"\x00not json")

    result = audit_log.verify()

    assert result.status is VerifyStatus.UNVERIFIABLE
    assert result.reason == "anchor_unreadable"
    with pytest.raises(FailClosed):
        audit_log.append(make_event(9))


def test_anchor_key_unavailable_at_verify_is_unverifiable(
    audit_log: AuditLog, make_log: Callable[..., AuditLog], anchor_path: Path
) -> None:
    _fill(audit_log, 2)
    keyless = make_log(anchor=HeadAnchor(anchor_path, FakeSecrets(), ANCHOR_KEY_REF))

    result = keyless.verify()

    assert result.status is VerifyStatus.UNVERIFIABLE
    assert result.reason == "anchor_key_unavailable"


def test_anchor_signed_with_another_key_is_a_key_mismatch_not_bad_mac(
    audit_log: AuditLog, make_log: Callable[..., AuditLog], anchor_path: Path
) -> None:
    """Review L6: a rotated key is told apart from tampering."""
    _fill(audit_log, 2)
    rotated = FakeSecrets({ANCHOR_KEY_REF: "a-different-anchor-key-0000-0000-0000"})
    other = make_log(anchor=HeadAnchor(anchor_path, rotated, ANCHOR_KEY_REF))

    result = other.verify()

    assert result.status is VerifyStatus.UNVERIFIABLE
    assert result.reason == "anchor_key_mismatch"
    with pytest.raises(FailClosed):
        other.append(make_event(9))


def test_forged_anchor_without_the_key_fails(
    audit_log: AuditLog, audit_engine: Engine, anchor_path: Path
) -> None:
    _fill(audit_log, 3)
    drop_triggers(audit_engine)
    raw_sql(audit_engine, "DELETE FROM audit_record WHERE seq = 3")
    data = json.loads(anchor_path.read_text(encoding="utf-8"))
    [*_, head] = audit_log.query(limit=10)
    forged = {**data, "final": {"seq": 2, "head_hash": head.hash}}  # hmac left as it was
    anchor_path.write_text(json.dumps(forged), encoding="utf-8")

    result = audit_log.verify()

    assert result.status is VerifyStatus.FAILED
    assert result.reason == "anchor_hmac_invalid"


def test_a_replayed_older_anchor_alone_fails(audit_log: AuditLog, anchor_path: Path) -> None:
    _fill(audit_log, 2)
    old = anchor_path.read_bytes()
    _fill(audit_log, 1)
    anchor_path.write_bytes(old)

    result = audit_log.verify()

    assert result.status is VerifyStatus.FAILED
    assert result.reason == "anchor_behind_head"
    with pytest.raises(IntegrityFailure):
        audit_log.append(make_event(9))


@pytest.mark.parametrize("ref", ["", "audit_anchor_key", "file://x", "secret://"])
def test_anchor_key_must_be_a_secret_reference(tmp_path: Path, ref: str) -> None:
    with pytest.raises(ValidationFailed):
        HeadAnchor(tmp_path / "a.json", FakeSecrets(), ref)


def test_anchor_key_is_requested_by_reference(
    audit_log: AuditLog, anchor_secrets: FakeSecrets
) -> None:
    _fill(audit_log, 1)
    assert anchor_secrets.requested
    assert set(anchor_secrets.requested) == {ANCHOR_KEY_REF}


def test_an_anchor_with_a_one_bit_different_mac_fails(
    audit_log: AuditLog, anchor_path: Path
) -> None:
    _fill(audit_log, 1)
    data = json.loads(anchor_path.read_text(encoding="utf-8"))
    last = data["hmac"][-1]
    data["hmac"] = data["hmac"][:-1] + ("0" if last != "0" else "1")
    anchor_path.write_text(json.dumps(data), encoding="utf-8")

    assert audit_log.verify().reason == "anchor_hmac_invalid"


# Windows sharing violations (coordinator item 5).


@pytest.mark.skipif(sys.platform != "win32", reason="open handles block replace only on Windows")
def test_append_retries_while_another_handle_holds_the_anchor(
    audit_log: AuditLog, anchor_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    _fill(audit_log, 1)
    handle = anchor_path.open("rb")
    releaser = threading.Timer(0.15, handle.close)
    releaser.start()
    try:
        with caplog.at_level(logging.WARNING, logger="ciso.audit.anchor"):
            receipt = audit_log.append(make_event(2))
    finally:
        releaser.join()
        handle.close()

    assert receipt.seq == 2
    assert any("busy" in r.getMessage() for r in caplog.records)  # the hold really bit
    assert audit_log.verify().status is VerifyStatus.OK


@pytest.mark.skipif(sys.platform != "win32", reason="open handles block replace only on Windows")
def test_append_fails_and_rolls_back_when_the_anchor_stays_locked(
    audit_log: AuditLog, anchor_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _fill(audit_log, 1)
    monkeypatch.setattr(anchor_module, "FILE_RETRY_ATTEMPTS", 3)
    before = anchor_path.read_bytes()
    with anchor_path.open("rb"), pytest.raises(FailClosed):
        audit_log.append(make_event(2))

    assert anchor_path.read_bytes() == before
    assert [r.seq for r in audit_log.query(limit=10)] == [1]
    assert audit_log.verify().status is VerifyStatus.OK
    assert audit_log.append(make_event(3)).seq == 2


def test_in_memory_engine_skips_the_directory_check(
    clock: FixedClock, anchor_secrets: FakeSecrets, tmp_path: Path
) -> None:
    engine = create_db_engine(None)
    try:
        init_audit_schema(engine)
        anchor = HeadAnchor(tmp_path / "a.json", anchor_secrets, ANCHOR_KEY_REF)
        log = AuditLog(engine, clock, FakeRedactor(), anchor)
        log.initialise()
        assert log.append(make_event(1)).seq == 1
    finally:
        engine.dispose()
