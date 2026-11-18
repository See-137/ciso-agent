"""Head witness: rolling the database back together with its anchor is caught (review C1)."""

from __future__ import annotations

import json
import shutil
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path

import pytest
from sqlalchemy import Engine
from tests.audit.helpers import WITNESS_KEY_REF, copy_db, make_event, restore_db
from tests.fakes.core import FakeSecrets

from ciso.audit import AuditLog, FileHeadWitness, VerifyStatus, WitnessedHead
from ciso.common.errors import FailClosed, IntegrityFailure, ValidationFailed

pytestmark = pytest.mark.resilience


@pytest.fixture
def witness(witness_path: Path, anchor_secrets: FakeSecrets) -> FileHeadWitness:
    return FileHeadWitness(witness_path, anchor_secrets, WITNESS_KEY_REF)


def _pair_rollback(
    log: AuditLog, engine: Engine, db_path: Path, anchor_path: Path, scratch: Path
) -> None:
    """The reviewer's sequence: snapshot both files at seq 3, write 4-6, put both back."""
    for n in range(3):
        log.append(make_event(n))
    engine.dispose()
    copy_db(db_path, scratch / "db")
    shutil.copy2(anchor_path, scratch / "anchor.json")
    for n in range(3, 6):
        log.append(make_event(n, action="secret.exfiltrate"))
    assert log.verify().status is VerifyStatus.OK
    engine.dispose()
    restore_db(scratch / "db", db_path)
    shutil.copy2(scratch / "anchor.json", anchor_path)


def test_pair_rollback_fails_with_a_witness(
    make_log: Callable[..., AuditLog],
    witness: FileHeadWitness,
    audit_engine: Engine,
    audit_db_path: Path,
    anchor_path: Path,
    tmp_path: Path,
) -> None:
    log = make_log(witness=witness, witness_every=1)
    log.initialise()
    _pair_rollback(log, audit_engine, audit_db_path, anchor_path, tmp_path / "snap")

    result = log.verify()

    assert result.status is VerifyStatus.FAILED
    assert result.reason == "rolled_back"
    assert result.first_broken_seq == 4
    assert result.witnessed is True
    with pytest.raises(IntegrityFailure, match="rolled_back"):
        log.open()


def test_pair_rollback_is_ok_but_unwitnessed_without_a_witness(
    audit_log: AuditLog,
    audit_engine: Engine,
    audit_db_path: Path,
    anchor_path: Path,
    tmp_path: Path,
) -> None:
    """Documents the limit: without a witness the rollback is invisible, and the result
    says so through `witnessed=False`."""
    _pair_rollback(audit_log, audit_engine, audit_db_path, anchor_path, tmp_path / "snap")

    result = audit_log.verify()

    assert result.status is VerifyStatus.OK
    assert result.head_seq == 3
    assert result.witnessed is False


def test_rollback_then_regrowth_is_caught_by_hash(
    make_log: Callable[..., AuditLog],
    witness: FileHeadWitness,
    audit_engine: Engine,
    audit_db_path: Path,
    anchor_path: Path,
    tmp_path: Path,
) -> None:
    """After the rollback, the attacker appends until the head passes the witness again."""
    log = make_log(witness=witness, witness_every=1)
    log.initialise()
    _pair_rollback(log, audit_engine, audit_db_path, anchor_path, tmp_path / "snap")
    unwitnessed = make_log()  # an attacker's writer that does not publish
    for n in range(10, 14):
        unwitnessed.append(make_event(n))

    result = log.verify()

    assert result.status is VerifyStatus.FAILED
    assert result.reason == "rolled_back"
    assert result.first_broken_seq == 6


def test_cadence_publishes_every_nth_record(
    make_log: Callable[..., AuditLog], witness: FileHeadWitness, witness_path: Path
) -> None:
    log = make_log(witness=witness, witness_every=3)
    log_id = log.initialise()
    for n in range(7):
        log.append(make_event(n))

    seqs = [json.loads(line)["seq"] for line in witness_path.read_text().splitlines()]
    assert seqs == [3, 6]
    latest = witness.latest(log_id)
    assert latest is not None
    assert latest.seq == 6
    assert log.verify().status is VerifyStatus.OK


@pytest.mark.parametrize("every", [None, 0, -1])
def test_a_witness_needs_a_positive_cadence(
    make_log: Callable[..., AuditLog], witness: FileHeadWitness, every: int | None
) -> None:
    with pytest.raises(ValidationFailed):
        make_log(witness=witness, witness_every=every)


def test_a_witness_inside_the_database_directory_is_refused(
    make_log: Callable[..., AuditLog], audit_db_path: Path, anchor_secrets: FakeSecrets
) -> None:
    inside = FileHeadWitness(audit_db_path.parent / "w.jsonl", anchor_secrets, WITNESS_KEY_REF)
    with pytest.raises(ValidationFailed):
        make_log(witness=inside, witness_every=1)


class _BrokenWitness:
    def publish(self, log_id: str, seq: int, head_hash: str, at: datetime) -> None:
        raise OSError("witness host down")

    def latest(self, log_id: str) -> WitnessedHead | None:
        raise OSError("witness host down")


def test_a_publish_failure_fails_the_append(make_log: Callable[..., AuditLog]) -> None:
    log = make_log(witness=_BrokenWitness(), witness_every=1)
    log.initialise()

    with pytest.raises(FailClosed):
        log.append(make_event(1))


def test_an_unreadable_witness_is_unverifiable(
    make_log: Callable[..., AuditLog], witness: FileHeadWitness, witness_path: Path
) -> None:
    log = make_log(witness=witness, witness_every=1)
    log.initialise()
    log.append(make_event(1))
    witness_path.unlink()
    witness_path.mkdir()  # a directory where the file should be: unreadable

    result = log.verify()

    assert result.status is VerifyStatus.UNVERIFIABLE
    assert result.reason == "witness_unreadable"


def test_a_tampered_witness_line_fails(
    make_log: Callable[..., AuditLog], witness: FileHeadWitness, witness_path: Path
) -> None:
    log = make_log(witness=witness, witness_every=1)
    log.initialise()
    log.append(make_event(1))
    line = json.loads(witness_path.read_text())
    line["seq"] = 99
    witness_path.write_text(json.dumps(line) + "\n")

    result = log.verify()

    assert result.status is VerifyStatus.FAILED
    assert result.reason == "witness_invalid"


def test_witness_entries_of_other_logs_are_ignored(
    make_log: Callable[..., AuditLog], witness: FileHeadWitness
) -> None:
    witness.publish("alog_OTHER", 50, "a" * 64, datetime(2026, 1, 1, tzinfo=UTC))
    log = make_log(witness=witness, witness_every=1)
    log.initialise()
    log.append(make_event(1))

    assert log.verify().status is VerifyStatus.OK
