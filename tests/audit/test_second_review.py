"""Findings of the second, independent read of the audit package (2026-11-18).

Each test names the finding it pins. They sit beside the first review's tests rather than
inside them, so that file history shows what the second read added.
"""

from __future__ import annotations

import json
import shutil
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
from sqlalchemy import Engine
from tests.audit.helpers import (
    WITNESS_KEY_REF,
    WITNESS_KEY_VALUE,
    copy_db,
    drop_triggers,
    make_event,
    raw_exec,
    raw_sql,
    restore_db,
)
from tests.fakes.core import FakeSecrets

from ciso.audit import AuditLog, FileHeadWitness, VerifyStatus, WitnessedHead
from ciso.audit import anchor as anchor_module
from ciso.common.errors import FailClosed, IntegrityFailure, ValidationFailed

pytestmark = pytest.mark.resilience


@pytest.fixture
def witness(witness_path: Path, anchor_secrets: FakeSecrets) -> FileHeadWitness:
    return FileHeadWitness(witness_path, anchor_secrets, WITNESS_KEY_REF)


@pytest.fixture
def witnessed_log(make_log: Callable[..., AuditLog], witness: FileHeadWitness) -> AuditLog:
    log = make_log(witness=witness, witness_every=1)
    log.initialise()
    return log


def _rollback_pair(
    log: AuditLog, engine: Engine, db_path: Path, anchor_path: Path, scratch: Path
) -> None:
    for n in range(3):
        log.append(make_event(n))
    engine.dispose()
    copy_db(db_path, scratch / "db")
    shutil.copy2(anchor_path, scratch / "anchor.json")
    for n in range(3, 6):
        log.append(make_event(n, action="secret.exfiltrate"))
    engine.dispose()
    restore_db(scratch / "db", db_path)
    shutil.copy2(scratch / "anchor.json", anchor_path)


# Finding R1: the honest writer itself used to grow a rolled-back log past the witnessed
# head, after which verify() reported ok and the rollback was gone from view.


def test_append_is_refused_on_a_log_rolled_back_behind_the_witness(
    witnessed_log: AuditLog,
    audit_engine: Engine,
    audit_db_path: Path,
    anchor_path: Path,
    tmp_path: Path,
) -> None:
    _rollback_pair(witnessed_log, audit_engine, audit_db_path, anchor_path, tmp_path / "s")

    with pytest.raises(IntegrityFailure, match="rolled_back"):
        witnessed_log.append(make_event(50))

    assert [r.seq for r in witnessed_log.query(limit=20)] == [1, 2, 3]


def test_regrowth_by_the_witnessed_writer_never_turns_verify_ok(
    witnessed_log: AuditLog,
    audit_engine: Engine,
    audit_db_path: Path,
    anchor_path: Path,
    tmp_path: Path,
) -> None:
    _rollback_pair(witnessed_log, audit_engine, audit_db_path, anchor_path, tmp_path / "s")
    for n in range(4):
        with pytest.raises(IntegrityFailure):
            witnessed_log.append(make_event(50 + n))

    result = witnessed_log.verify()

    assert result.status is VerifyStatus.FAILED
    assert result.reason == "rolled_back"


def test_an_unreadable_witness_refuses_appends_fail_closed(
    witnessed_log: AuditLog, witness_path: Path
) -> None:
    witnessed_log.append(make_event(1))
    witness_path.unlink()
    witness_path.mkdir()

    with pytest.raises(FailClosed):
        witnessed_log.append(make_event(2))
    assert [r.seq for r in witnessed_log.query(limit=10)] == [1]


class _PublishFailsWitness:
    """Readable, but every publish fails: isolates the publish guard from the read gate."""

    def __init__(self) -> None:
        self.published: list[int] = []

    def publish(self, log_id: str, seq: int, head_hash: str, at: datetime) -> None:
        self.published.append(seq)
        raise OSError("witness host down")

    def latest(self, log_id: str) -> WitnessedHead | None:
        return None


def test_a_failed_publish_raises_after_the_record_is_committed(
    make_log: Callable[..., AuditLog],
) -> None:
    """The append raises, so the caller does not act; the ATTEMPT record stays."""
    witness = _PublishFailsWitness()
    log = make_log(witness=witness, witness_every=1)
    log.initialise()

    with pytest.raises(FailClosed, match="witness"):
        log.append(make_event(1))

    assert witness.published == [1]
    assert [r.seq for r in log.query(limit=10)] == [1]


def test_conflicting_witness_entries_for_one_seq_are_invalid(
    witness: FileHeadWitness, witnessed_log: AuditLog
) -> None:
    log_id = witnessed_log.log_id
    assert log_id is not None
    at = datetime(2026, 1, 1, tzinfo=UTC)
    witness.publish(log_id, 7, "a" * 64, at)
    witness.publish(log_id, 7, "b" * 64, at)

    with pytest.raises(IntegrityFailure, match="conflicting"):
        witness.latest(log_id)


def test_the_same_head_published_twice_is_not_a_conflict(witness: FileHeadWitness) -> None:
    at = datetime(2026, 1, 1, tzinfo=UTC)
    witness.publish("alog_X", 7, "a" * 64, at)
    witness.publish("alog_X", 7, "a" * 64, at)
    latest = witness.latest("alog_X")
    assert latest is not None
    assert latest.seq == 7


# Finding R2: a stored timestamp that is not a timestamp escaped verify() and query() as a
# raw ValueError or TypeError.


@pytest.mark.parametrize("value", ["garbage", 12345, "2026-01-01 00:00:00.5"])
def test_an_unparseable_stored_timestamp_is_row_invalid(
    audit_log: AuditLog, audit_engine: Engine, value: object
) -> None:
    for n in range(3):
        audit_log.append(make_event(n))
    drop_triggers(audit_engine)
    raw_exec(audit_engine, "UPDATE audit_record SET occurred_at = :v WHERE seq = 2", v=value)

    result = audit_log.verify()

    assert result.status is VerifyStatus.FAILED
    assert result.reason == "row_invalid"
    assert result.first_broken_seq == 2


def test_query_over_an_unparseable_timestamp_raises_integrity_failure(
    audit_log: AuditLog, audit_engine: Engine
) -> None:
    audit_log.append(make_event(1))
    drop_triggers(audit_engine)
    raw_sql(audit_engine, "UPDATE audit_record SET occurred_at = 'garbage' WHERE seq = 1")

    with pytest.raises(IntegrityFailure):
        audit_log.query(limit=10)


# Finding R3: input that is too deep or too large escaped append() as RecursionError or was
# reported as a redactor fault (FailClosed) instead of bad input (ValidationFailed).


def _deep(levels: int) -> dict[str, Any]:
    root: dict[str, Any] = {}
    cursor = root
    for _ in range(levels):
        cursor["a"] = {}
        cursor = cursor["a"]
    return root


@pytest.mark.parametrize(
    "details",
    [_deep(5000), {"x": 10**5000}],
    ids=["too-deep", "int-too-long-for-json"],
)
def test_details_json_cannot_serialise_are_refused_as_invalid(
    audit_log: AuditLog, details: dict[str, Any]
) -> None:
    with pytest.raises(ValidationFailed):
        audit_log.append(make_event(1, details=details))
    assert audit_log.query(limit=10) == []


def test_moderately_nested_details_are_accepted(audit_log: AuditLog) -> None:
    assert audit_log.append(make_event(1, details=_deep(50))).seq == 1


# Review H1 fix list: the rename is followed by a directory fsync on POSIX.


def test_anchor_write_syncs_its_directory(
    audit_log: AuditLog, anchor_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    synced: list[Path] = []
    monkeypatch.setattr(anchor_module, "fsync_directory", synced.append)

    audit_log.append(make_event(1))

    assert synced
    assert set(synced) == {anchor_path.parent}


def test_fsync_directory_on_posix_opens_syncs_and_closes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: list[tuple[str, object]] = []
    monkeypatch.setattr(anchor_module.os, "name", "posix")
    monkeypatch.setattr(anchor_module.os, "open", lambda p, flags: calls.append(("open", p)) or 7)
    monkeypatch.setattr(anchor_module.os, "fsync", lambda fd: calls.append(("fsync", fd)))
    monkeypatch.setattr(anchor_module.os, "close", lambda fd: calls.append(("close", fd)))

    anchor_module.fsync_directory(tmp_path)

    assert calls == [("open", tmp_path), ("fsync", 7), ("close", 7)]


def test_fsync_directory_failure_is_fail_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def broken(fd: int) -> None:
        raise OSError("io")

    closed: list[int] = []
    monkeypatch.setattr(anchor_module.os, "name", "posix")
    monkeypatch.setattr(anchor_module.os, "open", lambda p, flags: 7)
    monkeypatch.setattr(anchor_module.os, "fsync", broken)
    monkeypatch.setattr(anchor_module.os, "close", closed.append)

    with pytest.raises(FailClosed):
        anchor_module.fsync_directory(tmp_path)
    assert closed == [7]


def test_fsync_directory_is_skipped_on_windows(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    opened: list[object] = []
    monkeypatch.setattr(anchor_module.os, "name", "nt")
    monkeypatch.setattr(anchor_module.os, "open", lambda p, flags: opened.append(p) or 7)

    anchor_module.fsync_directory(tmp_path)

    assert opened == []


def test_witness_lines_are_signed_and_hold_no_key(
    witnessed_log: AuditLog, witness_path: Path
) -> None:
    witnessed_log.append(make_event(1))
    [line] = witness_path.read_text(encoding="utf-8").splitlines()
    data = json.loads(line)
    assert data["seq"] == 1
    assert len(data["hmac"]) == 64
    assert WITNESS_KEY_VALUE not in line
