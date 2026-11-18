"""Log identity and explicit initialisation: a wiped or swapped log is not a fresh one
(coordinator item 4, review C1)."""

from __future__ import annotations

import shutil
from collections.abc import Callable
from pathlib import Path

import pytest
from sqlalchemy import Engine
from sqlalchemy.exc import IntegrityError
from tests.audit.helpers import ANCHOR_KEY_REF, db_files, make_event, raw_exec, raw_sql
from tests.fakes.core import FakeRedactor, FakeSecrets

from ciso.audit import GENESIS_HASH, AuditLog, HeadAnchor, VerifyStatus, init_audit_schema
from ciso.common.clock import FixedClock
from ciso.common.db import create_db_engine
from ciso.common.errors import Conflict, FailClosed, IntegrityFailure

pytestmark = pytest.mark.resilience


def test_an_uninitialised_log_refuses_appends(
    make_log: Callable[..., AuditLog], anchor_path: Path
) -> None:
    log = make_log()

    with pytest.raises(FailClosed):
        log.append(make_event(1))

    assert log.log_id is None
    assert log.query(limit=10) == []
    assert not anchor_path.exists()
    result = log.verify()
    assert result.status is VerifyStatus.UNVERIFIABLE
    assert result.reason == "uninitialised"


def test_initialise_creates_an_identity_shared_by_database_and_anchor(
    make_log: Callable[..., AuditLog], anchor_path: Path
) -> None:
    log = make_log()

    log_id = log.initialise()

    assert log.log_id == log_id
    assert log_id.startswith("alog_")
    assert f'"log_id":"{log_id}"' in anchor_path.read_text(encoding="utf-8")
    assert log.open() == log_id
    assert log.append(make_event(1)).seq == 1


def test_initialise_twice_is_refused(audit_log: AuditLog) -> None:
    log_id = audit_log.log_id
    with pytest.raises(Conflict):
        audit_log.initialise()
    assert audit_log.log_id == log_id


def test_initialise_over_existing_records_is_refused(
    make_log: Callable[..., AuditLog], audit_engine: Engine, anchor_path: Path
) -> None:
    raw_exec(
        audit_engine,
        "INSERT INTO audit_record (id, seq, occurred_at, actor_id, actor_type, action, target,"
        " outcome, correlation_id, details, prev_hash, hash) VALUES ('aud_x', 1,"
        " '2026-11-17 12:00:00.000000', 'a', 'human', 'x', '', 'success', '', '{}', :g, :h)",
        g=GENESIS_HASH,
        h="a" * 64,
    )
    log = make_log()

    with pytest.raises(Conflict):
        log.initialise()

    assert log.log_id is None
    assert not anchor_path.exists()


def test_initialise_is_refused_when_an_anchor_file_exists(
    make_log: Callable[..., AuditLog], anchor_path: Path
) -> None:
    anchor_path.parent.mkdir(parents=True)
    anchor_path.write_text("{}", encoding="utf-8")
    log = make_log()

    with pytest.raises(Conflict):
        log.initialise()
    assert log.log_id is None


def test_initialise_is_refused_when_an_existing_log_is_expected(
    make_log: Callable[..., AuditLog],
) -> None:
    with pytest.raises(Conflict):
        make_log(expected_log_id="alog_SOMETHING").initialise()


def test_the_identity_row_cannot_be_changed_or_removed(
    audit_log: AuditLog, audit_engine: Engine
) -> None:
    with pytest.raises(IntegrityError, match="write-once"):
        raw_sql(audit_engine, "UPDATE audit_meta SET log_id = 'alog_other'")
    with pytest.raises(IntegrityError, match="write-once"):
        raw_sql(audit_engine, "DELETE FROM audit_meta")
    assert audit_log.verify().status is VerifyStatus.OK


def test_expected_log_id_matches(audit_log: AuditLog, make_log: Callable[..., AuditLog]) -> None:
    log = make_log(expected_log_id=audit_log.log_id)
    assert log.open() == audit_log.log_id
    assert log.verify().status is VerifyStatus.OK


def test_an_unexpected_log_id_fails(audit_log: AuditLog, make_log: Callable[..., AuditLog]) -> None:
    audit_log.append(make_event(1))
    log = make_log(expected_log_id="alog_REMEMBERED")

    result = log.verify()

    assert result.status is VerifyStatus.FAILED
    assert result.reason == "log_id_unexpected"
    with pytest.raises(IntegrityFailure):
        log.append(make_event(2))
    with pytest.raises(IntegrityFailure):
        log.open()


def test_an_anchor_from_another_log_fails(
    audit_log: AuditLog,
    tmp_path: Path,
    clock: FixedClock,
    anchor_secrets: FakeSecrets,
    anchor_path: Path,
) -> None:
    audit_log.append(make_event(1))
    other_engine = create_db_engine(tmp_path / "db2" / "audit.db")
    try:
        init_audit_schema(other_engine)
        other_anchor = tmp_path / "anchor2" / "a.json"
        other = AuditLog(
            other_engine,
            clock,
            FakeRedactor(),
            HeadAnchor(other_anchor, anchor_secrets, ANCHOR_KEY_REF),
        )
        other.initialise()
        other.append(make_event(1))
        shutil.copy2(other_anchor, anchor_path)  # same key, different log
    finally:
        other_engine.dispose()

    result = audit_log.verify()

    assert result.status is VerifyStatus.FAILED
    assert result.reason == "log_id_mismatch"
    with pytest.raises(IntegrityFailure):
        audit_log.append(make_event(2))


def _wipe(audit_engine: Engine, audit_db_path: Path, anchor_path: Path) -> None:
    audit_engine.dispose()
    for path in db_files(audit_db_path):
        path.unlink()
    anchor_path.unlink()


def test_wipe_and_reinitialise_is_refused_through_expected_log_id(
    audit_log: AuditLog,
    make_log: Callable[..., AuditLog],
    audit_engine: Engine,
    audit_db_path: Path,
    anchor_path: Path,
) -> None:
    """Review C1 wipe: delete both files and start again. The remembered id catches it."""
    remembered = audit_log.log_id
    for n in range(3):
        audit_log.append(make_event(n))
    _wipe(audit_engine, audit_db_path, anchor_path)
    init_audit_schema(audit_engine)
    make_log().initialise()  # the attacker's fresh log
    make_log().append(make_event(1))

    app = make_log(expected_log_id=remembered)

    result = app.verify()
    assert result.status is VerifyStatus.FAILED
    assert result.reason == "log_id_unexpected"
    with pytest.raises(IntegrityFailure):
        app.open()


def test_wipe_without_reinitialising_is_log_missing(
    audit_log: AuditLog,
    make_log: Callable[..., AuditLog],
    audit_engine: Engine,
    audit_db_path: Path,
    anchor_path: Path,
) -> None:
    remembered = audit_log.log_id
    audit_log.append(make_event(1))
    _wipe(audit_engine, audit_db_path, anchor_path)
    init_audit_schema(audit_engine)

    app = make_log(expected_log_id=remembered)

    result = app.verify()
    assert result.status is VerifyStatus.FAILED
    assert result.reason == "log_missing"
    with pytest.raises(IntegrityFailure):
        app.append(make_event(2))


def test_database_wiped_but_anchor_kept_is_log_missing(
    audit_log: AuditLog,
    make_log: Callable[..., AuditLog],
    audit_engine: Engine,
    audit_db_path: Path,
) -> None:
    audit_log.append(make_event(1))
    audit_engine.dispose()
    for path in db_files(audit_db_path):
        path.unlink()
    init_audit_schema(audit_engine)

    result = make_log().verify()

    assert result.status is VerifyStatus.FAILED
    assert result.reason == "log_missing"
