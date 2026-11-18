"""Tests for guards that the 2026-11-18 mutation run found uncaught.

Each test names the mutant it kills (labels as in the builder report).
"""

from __future__ import annotations

import json
import math
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
from sqlalchemy import Engine
from sqlalchemy.exc import IntegrityError
from tests.audit.helpers import (
    ANCHOR_KEY_REF,
    ANCHOR_KEY_VALUE,
    WITNESS_KEY_REF,
    drop_triggers,
    make_event,
    raw_exec,
)
from tests.audit.test_recovery import CrashingAnchor, SimulatedCrash
from tests.fakes.core import FakeSecrets

from ciso.audit import (
    AnchorEntry,
    AuditLog,
    FileHeadWitness,
    HeadAnchor,
    VerifyStatus,
    audit_record,
)
from ciso.audit.anchor import AnchorKey, resolve_key
from ciso.audit.chain import (
    GENESIS,
    PreparedEvent,
    build_records,
    require_json_native,
    row_values,
    strict_canonical,
)
from ciso.common.db import create_db_engine
from ciso.common.errors import FailClosed, IntegrityFailure, ValidationFailed

pytestmark = pytest.mark.resilience

_INSERT = (
    "INSERT INTO audit_record (id, seq, occurred_at, actor_id, actor_type, action, target,"
    " outcome, correlation_id, details, prev_hash, hash) VALUES (:id, :seq,"
    " '2026-11-17 12:00:00.000000', 'a', 'human', 'x', '', 'success', '', '{}', :prev, :hash)"
)


def _anchor_doc(path: Path) -> dict[str, Any]:
    return dict(json.loads(path.read_text(encoding="utf-8")))


# -- log.py -------------------------------------------------------------------------


def test_append_refuses_something_that_is_not_an_audit_event(audit_log: AuditLog) -> None:
    """L08."""
    fake = {"actor_id": "a", "action": "x", "target": "", "correlation_id": "", "details": {}}
    with pytest.raises(ValidationFailed):
        audit_log.append(fake)  # type: ignore[arg-type]
    assert audit_log.query(limit=10) == []


def test_a_late_promotion_never_moves_the_anchor_back(
    audit_log: AuditLog, make_log: Callable[..., AuditLog], audit_db_path: Path
) -> None:
    """L20: another writer promotes (and moves on) between our COMMIT and our promotion."""
    audit_log.append(make_event(1))
    other_engine = create_db_engine(audit_db_path)
    try:
        other = make_log(engine=other_engine)
        real_promote = audit_log._promote

        def promote_late(*args: Any) -> None:
            other.append(make_event(2))  # sees our pending entry and repairs it first
            real_promote(*args)

        audit_log._promote = promote_late  # type: ignore[method-assign]
        audit_log.append(make_event(3))
    finally:
        other_engine.dispose()

    result = audit_log.verify()
    assert result.status is VerifyStatus.OK
    assert result.head_seq == 4  # 1, ours (2), the other's recovery record (3) and event (4)


def test_verify_gives_up_as_unverifiable_while_a_crash_state_keeps_appearing(
    make_log: Callable[..., AuditLog], anchor_path: Path, anchor_secrets: FakeSecrets
) -> None:
    """L28 and V03: a crash state that is not repaired is never reported as ok."""
    anchor = CrashingAnchor(anchor_path, anchor_secrets, "pending")
    log = make_log(anchor=anchor)
    log.initialise()
    log.append(make_event(1))
    anchor.armed = True
    with pytest.raises(SimulatedCrash):
        log.append(make_event(2))
    log._settle = lambda key: None  # type: ignore[method-assign]  # repair keeps losing

    result = log.verify()

    assert result.status is VerifyStatus.UNVERIFIABLE
    assert result.reason == "anchor_recovery_pending"


def test_a_fault_added_after_the_snapshot_is_found_by_the_tail_walk(
    audit_log: AuditLog, audit_engine: Engine, monkeypatch: pytest.MonkeyPatch
) -> None:
    """V01: the record appears between the lock-free walk and the locked tail walk."""
    from ciso.audit import log as log_module

    for n in range(2):
        audit_log.append(make_event(n))
    [_, head] = audit_log.query(limit=10)
    real_walk = log_module.walk_chain

    def walk_then_insert(conn: Any, start: AnchorEntry) -> Any:
        snap = real_walk(conn, start)
        raw_exec(audit_engine, _INSERT, id="aud_late", seq=3, prev=head.hash, hash="f" * 64)
        return snap

    monkeypatch.setattr(log_module, "walk_chain", walk_then_insert)

    result = audit_log.verify()

    assert result.status is VerifyStatus.FAILED
    assert result.reason == "hash_mismatch"
    assert result.first_broken_seq == 3


def test_an_ok_verify_with_a_witness_says_it_was_witnessed(
    make_log: Callable[..., AuditLog], witness_path: Path, anchor_secrets: FakeSecrets
) -> None:
    """V08."""
    witness = FileHeadWitness(witness_path, anchor_secrets, WITNESS_KEY_REF)
    log = make_log(witness=witness, witness_every=1)
    log.initialise()
    log.append(make_event(1))

    result = log.verify()

    assert result.status is VerifyStatus.OK
    assert result.witnessed is True


# -- chain.py -----------------------------------------------------------------------


@pytest.mark.parametrize(
    "value",
    [{"x": math.nan}, {"x": math.inf}, {"x": {1: "a"}}, {"x": b"b"}, {"x": object()}],
    ids=["nan", "inf", "int-key", "bytes", "object"],
)
def test_require_json_native_refuses_on_its_own(value: Any) -> None:
    """C02, C03, C04: the check is tested without the serialiser behind it."""
    with pytest.raises(ValidationFailed):
        require_json_native(value)


def test_strict_canonical_refuses_non_finite_numbers_on_its_own() -> None:
    """C15."""
    with pytest.raises(ValueError, match="JSON compliant"):
        strict_canonical({"x": math.nan})


def test_a_nested_non_string_key_is_refused_by_append(audit_log: AuditLog) -> None:
    """C03 through the public path: json would silently turn the key into "1"."""
    with pytest.raises(ValidationFailed):
        audit_log.append(make_event(1, details={"x": {1: "a"}}))
    assert audit_log.query(limit=10) == []


# -- anchor.py ----------------------------------------------------------------------


def test_an_empty_key_is_refused() -> None:
    """A02."""
    with pytest.raises(FailClosed):
        resolve_key(FakeSecrets({ANCHOR_KEY_REF: ""}), ANCHOR_KEY_REF)


def test_writing_a_pending_entry_not_ahead_of_final_is_refused(head_anchor: HeadAnchor) -> None:
    """A03."""
    key = head_anchor.load_key()
    entry = AnchorEntry(seq=3, head_hash="a" * 64)
    with pytest.raises(ValidationFailed):
        head_anchor.write(key, "alog_X", entry, pending=entry)
    assert not head_anchor.exists()


def test_a_failed_replace_leaves_no_temp_file(
    audit_log: AuditLog, anchor_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A04."""
    audit_log.append(make_event(1))

    def refuse(self: Path, target: Any) -> Path:
        raise PermissionError("held open")

    monkeypatch.setattr("ciso.audit.anchor.FILE_RETRY_ATTEMPTS", 1)
    monkeypatch.setattr(Path, "replace", refuse)
    with pytest.raises(FailClosed):
        audit_log.append(make_event(2))
    monkeypatch.undo()

    assert [p.name for p in anchor_path.parent.iterdir()] == [anchor_path.name]


def _resign(doc: dict[str, Any]) -> dict[str, Any]:
    """Re-sign a document as the key holder would, so only the parse rule can refuse it."""
    key = AnchorKey(ANCHOR_KEY_VALUE.encode("utf-8"))
    final = AnchorEntry.model_validate(doc["final"])
    pending = AnchorEntry.model_validate(doc["pending"]) if doc["pending"] else None
    return {**doc, "hmac": key.sign(doc["log_id"], final, pending)}


@pytest.mark.parametrize(
    "corrupt",
    [
        lambda d: {**d, "version": 1},
        lambda d: {**d, "key_id": ""},
        lambda d: {**d, "hmac": d["hmac"].upper()},
        lambda d: {**d, "log_id": ""},
        lambda d: {**d, "final": {**d["final"], "seq": str(d["final"]["seq"])}},
        lambda d: {**d, "final": {**d["final"], "seq": -1}},
        lambda d: {**d, "final": {**d["final"], "head_hash": d["final"]["head_hash"].upper()}},
        lambda d: _resign({**d, "pending": dict(d["final"])}),
    ],
    ids=[
        "old-version",
        "empty-key-id",
        "hmac-not-lower-hex",
        "empty-log-id",
        "seq-as-text",
        "negative-seq",
        "hash-not-lower-hex",
        "signed-pending-not-ahead",
    ],
)
def test_a_malformed_anchor_is_unreadable_not_trusted(
    audit_log: AuditLog, anchor_path: Path, corrupt: Callable[[dict[str, Any]], Any]
) -> None:
    """A11 to A16: the strict parser, not the MAC, refuses these."""
    audit_log.append(make_event(1))
    anchor_path.write_text(json.dumps(corrupt(_anchor_doc(anchor_path))), encoding="utf-8")

    result = audit_log.verify()

    assert result.status is VerifyStatus.UNVERIFIABLE
    assert result.reason == "anchor_unreadable"


# -- reconcile.py -------------------------------------------------------------------


def test_records_without_an_identity_row_are_meta_missing(
    make_log: Callable[..., AuditLog], audit_engine: Engine
) -> None:
    """R01: a correctly chained record, so only the missing identity is wrong."""
    event = make_event(1)
    [record] = build_records(
        GENESIS, [PreparedEvent(event, dict(event.details), datetime(2026, 1, 1, tzinfo=UTC))]
    )
    with audit_engine.begin() as conn:
        conn.execute(audit_record.insert(), [row_values(record)])

    result = make_log().verify()

    assert result.status is VerifyStatus.FAILED
    assert result.reason == "meta_missing"


def test_promotion_is_not_repaired_when_the_final_record_was_altered(
    make_log: Callable[..., AuditLog],
    anchor_path: Path,
    anchor_secrets: FakeSecrets,
    audit_engine: Engine,
) -> None:
    """R11: append does not walk the chain, so the final-hash check is its only guard."""
    anchor = CrashingAnchor(anchor_path, anchor_secrets, "promotion")
    log = make_log(anchor=anchor)
    log.initialise()
    for n in range(3):
        log.append(make_event(n))
    anchor.armed = True
    with pytest.raises(SimulatedCrash):
        log.append(make_event(99))
    drop_triggers(audit_engine)
    raw_exec(audit_engine, "UPDATE audit_record SET hash = :h WHERE seq = 3", h="e" * 64)

    with pytest.raises(IntegrityFailure, match="anchor_hash_mismatch"):
        make_log().append(make_event(5))


# -- witness.py ---------------------------------------------------------------------


@pytest.mark.parametrize("ref", ["", "witness_key", "secret://"])
def test_witness_key_must_be_a_secret_reference(tmp_path: Path, ref: str) -> None:
    """W01."""
    with pytest.raises(ValidationFailed):
        FileHeadWitness(tmp_path / "w.jsonl", FakeSecrets(), ref)


def test_witness_lines_under_another_key_are_fail_closed_not_forged(
    witness_path: Path, anchor_secrets: FakeSecrets
) -> None:
    """W06: a rotated key is told apart from a forged line."""
    FileHeadWitness(witness_path, anchor_secrets, WITNESS_KEY_REF).publish(
        "alog_X", 1, "a" * 64, datetime(2026, 1, 1, tzinfo=UTC)
    )
    rotated = FileHeadWitness(
        witness_path,
        FakeSecrets({WITNESS_KEY_REF: "k2-rotated-witness-key-for-the-test"}),
        WITNESS_KEY_REF,
    )

    with pytest.raises(FailClosed):
        rotated.latest("alog_X")


def test_a_malformed_witness_line_is_an_integrity_failure(
    witness_path: Path, anchor_secrets: FakeSecrets
) -> None:
    """W07. A malformed line before a valid one is fatal. (The same line as the only, hence
    last, line is a torn write: `test_stuck_states.py`.)"""
    witness = FileHeadWitness(witness_path, anchor_secrets, WITNESS_KEY_REF)
    witness.publish("alog_X", 1, "a" * 64, datetime(2026, 1, 1, tzinfo=UTC))
    witness_path.write_bytes(b"not json\n" + witness_path.read_bytes())

    with pytest.raises(IntegrityFailure, match="malformed"):
        witness.latest("alog_X")


def test_a_witness_write_error_is_fail_closed(
    witness_path: Path, anchor_secrets: FakeSecrets
) -> None:
    """W08: the witness's own contract, not only the log's wrapper."""
    witness_path.mkdir(parents=True)  # a directory where the file should be
    witness = FileHeadWitness(witness_path, anchor_secrets, WITNESS_KEY_REF)

    with pytest.raises(FailClosed):
        witness.publish("alog_X", 1, "a" * 64, datetime(2026, 1, 1, tzinfo=UTC))


# -- tables.py ----------------------------------------------------------------------


def test_an_insert_with_the_wrong_prev_hash_is_aborted(
    audit_log: AuditLog, audit_engine: Engine
) -> None:
    """T06."""
    audit_log.append(make_event(1))

    with pytest.raises(IntegrityError, match="audit chain"):
        raw_exec(audit_engine, _INSERT, id="aud_x", seq=2, prev="c" * 64, hash="f" * 64)


def test_a_second_identity_row_is_refused(audit_log: AuditLog, audit_engine: Engine) -> None:
    """T08."""
    with pytest.raises(IntegrityError):
        raw_exec(
            audit_engine,
            "INSERT INTO audit_meta (id, log_id, created_at)"
            " VALUES (2, 'alog_other', '2026-11-17 12:00:00.000000')",
        )
    assert audit_log.verify().status is VerifyStatus.OK
