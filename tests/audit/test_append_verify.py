"""Append, chain, query and fail-closed behaviour of the audit log (T1.1, FR-028, NFR-006)."""

from __future__ import annotations

import itertools
import math
import threading
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from sqlalchemy import Engine
from tests.audit.helpers import (
    ANCHOR_KEY_REF,
    REDACTED_SECRET,
    db_files,
    make_event,
    raw_sql,
)
from tests.fakes.core import FakeRedactor, FakeSecrets

from ciso.audit import (
    GENESIS_HASH,
    RECOVERY_ACTION,
    AuditLog,
    HeadAnchor,
    VerifyStatus,
    init_audit_schema,
    record_hash,
)
from ciso.common.clock import FixedClock
from ciso.common.db import create_db_engine
from ciso.common.enums import ActorType, AuditOutcome
from ciso.common.errors import Conflict, FailClosed, ValidationFailed
from ciso.common.ids import is_id
from ciso.common.protocols import AuditSink

pytestmark = pytest.mark.unit


def _raw_rows(engine: Engine) -> list[tuple[Any, ...]]:
    with engine.begin() as conn:
        return [tuple(r) for r in conn.exec_driver_sql("SELECT * FROM audit_record ORDER BY seq")]


def test_audit_log_satisfies_the_audit_sink_protocol(audit_log: AuditLog) -> None:
    assert isinstance(audit_log, AuditSink)


def test_audit_log_has_no_mutating_method() -> None:
    """Required by the T1.1 brief. The behaviour test below is the real guard."""
    forbidden = ("delete", "update", "remove", "purge")
    names = [name for name in dir(AuditLog) if not name.startswith("__")]
    assert [n for n in names if n.lstrip("_").startswith(forbidden)] == []


def test_no_public_operation_changes_an_existing_record(
    audit_log: AuditLog, audit_engine: Engine
) -> None:
    for n in range(3):
        audit_log.append(make_event(n))
    before = _raw_rows(audit_engine)

    audit_log.open()
    audit_log.verify()
    audit_log.query(limit=10, action_prefix="test.")
    _ = audit_log.log_id
    with pytest.raises(Conflict):
        audit_log.initialise()
    audit_log.append(make_event(9))

    after = _raw_rows(audit_engine)
    assert after[:3] == before
    assert len(after) == 4


def test_first_record_starts_at_seq_one_from_genesis(
    audit_log: AuditLog, clock: FixedClock
) -> None:
    receipt = audit_log.append(make_event(1))

    assert receipt.seq == 1
    assert is_id(receipt.record_id, "aud")
    assert receipt.occurred_at == clock.now()
    [record] = audit_log.query(limit=10)
    assert record.prev_hash == GENESIS_HASH
    assert record.hash == receipt.hash == record_hash(record)


def test_prev_hash_links_each_record_to_the_one_before(
    audit_log: AuditLog, clock: FixedClock
) -> None:
    receipts = []
    for n in range(5):
        receipts.append(audit_log.append(make_event(n)))
        clock.advance(seconds=1)

    records = audit_log.query(limit=10)
    assert [r.seq for r in records] == [1, 2, 3, 4, 5]
    assert [r.hash for r in records] == [r.hash for r in receipts]
    for before, after in itertools.pairwise(records):
        assert after.prev_hash == before.hash
    assert len({r.hash for r in records}) == 5


def test_record_details_cannot_be_changed_in_place(audit_log: AuditLog) -> None:
    audit_log.append(make_event(1, details={"a": {"b": [1, 2]}}))
    [record] = audit_log.query(limit=1)
    with pytest.raises(TypeError):
        record.details["a"]["b"] = 3  # type: ignore[index]


def test_verify_reports_ok_with_counts_for_an_intact_log(audit_log: AuditLog) -> None:
    for n in range(3):
        audit_log.append(make_event(n))

    result = audit_log.verify()

    assert result.status is VerifyStatus.OK
    assert result.checked == 3
    assert result.head_seq == 3
    assert result.log_id == audit_log.log_id
    assert result.witnessed is False
    assert result.first_broken_seq is None
    assert result.reason is None


def test_verify_of_an_initialised_empty_log_is_ok(audit_log: AuditLog) -> None:
    result = audit_log.verify()
    assert result.status is VerifyStatus.OK
    assert result.checked == 0


def test_seq_is_gapless_under_four_concurrent_appenders(audit_log: AuditLog) -> None:
    per_thread = 15
    errors: list[BaseException] = []
    seqs: list[int] = []
    guard = threading.Lock()
    start = threading.Barrier(4)

    def worker(index: int) -> None:
        try:
            start.wait()
            for n in range(per_thread):
                receipt = audit_log.append(make_event(index * 100 + n))
                with guard:
                    seqs.append(receipt.seq)
        except BaseException as exc:  # recorded, then asserted below
            errors.append(exc)

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(4)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert errors == []
    assert sorted(seqs) == list(range(1, 4 * per_thread + 1))
    assert audit_log.query(limit=100, action_prefix=RECOVERY_ACTION) == []
    result = audit_log.verify()
    assert result.status is VerifyStatus.OK
    assert result.checked == 4 * per_thread


def test_seq_is_gapless_across_two_engines_on_one_file(
    audit_db_path: Path,
    audit_log: AuditLog,
    make_log: Callable[..., AuditLog],
) -> None:
    """Two writers that share only the file: BEGIN IMMEDIATE serialises them."""
    other_engine = create_db_engine(audit_db_path)
    try:
        logs = [audit_log, make_log(engine=other_engine, redactor=FakeRedactor())]
        errors: list[BaseException] = []

        def worker(log: AuditLog, base: int) -> None:
            try:
                for n in range(10):
                    log.append(make_event(base + n))
            except BaseException as exc:
                errors.append(exc)

        threads = [threading.Thread(target=worker, args=(logs[i % 2], i * 100)) for i in range(4)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        assert errors == []
        seqs = [r.seq for r in logs[0].query(limit=100)]
        assert seqs == list(range(1, len(seqs) + 1))
        user = logs[0].query(limit=100, action_prefix="test.")
        assert len(user) == 40
        assert logs[1].verify().status is VerifyStatus.OK
    finally:
        other_engine.dispose()


def test_details_pass_through_the_redactor_and_secret_never_reaches_the_file(
    audit_log: AuditLog, audit_redactor: FakeRedactor, audit_db_path: Path
) -> None:
    marker = "visible-marker-31415"
    event = make_event(
        1, details={"note": marker, "nested": {"token": f"Bearer {REDACTED_SECRET}"}}
    )

    audit_log.append(event)

    assert audit_redactor.calls > 0
    [record] = audit_log.query(limit=1)
    assert record.details["nested"]["token"] == "Bearer [REDACTED]"
    raw = b"".join(path.read_bytes() for path in db_files(audit_db_path))
    assert marker.encode() in raw  # positive evidence that the bytes were read
    assert REDACTED_SECRET.encode() not in raw


@pytest.mark.parametrize(
    "details",
    [
        {"b": REDACTED_SECRET.encode()},
        {"s": {REDACTED_SECRET}},
        {"when": datetime(2026, 1, 1, tzinfo=UTC)},
        {"x": math.nan},
        {"x": math.inf},
        {"o": object()},
        {"nested": [{"b": bytearray(b"x")}]},
    ],
    ids=["bytes", "set", "datetime", "nan", "inf", "object", "nested-bytearray"],
)
def test_non_json_details_are_refused_not_stringified(
    audit_log: AuditLog, audit_db_path: Path, details: dict[str, Any]
) -> None:
    with pytest.raises(ValidationFailed):
        audit_log.append(make_event(1, details=details))

    assert audit_log.query(limit=10) == []
    raw = b"".join(path.read_bytes() for path in db_files(audit_db_path))
    assert REDACTED_SECRET.encode() not in raw


@pytest.mark.parametrize(
    "overrides",
    [
        {"target": "asset:\ud800"},
        {"action": "bad.\udfff"},
        {"details": {"k": "v\ud800"}},
        {"details": {"k\udc00": "v"}},
    ],
    ids=["target", "action", "details-value", "details-key"],
)
def test_strings_that_are_not_utf8_are_refused(
    audit_log: AuditLog, overrides: dict[str, Any]
) -> None:
    with pytest.raises(ValidationFailed):
        audit_log.append(make_event(1, **overrides))
    assert audit_log.query(limit=10) == []


def test_query_filters(audit_log: AuditLog, clock: FixedClock) -> None:
    start = clock.now()
    audit_log.append(
        make_event(1, action="policy.evaluate", actor_id="agent_ciso", actor_type=ActorType.AGENT)
    )
    clock.advance(minutes=1)
    audit_log.append(make_event(2, action="policy.reload", outcome=AuditOutcome.DENIED))
    clock.advance(minutes=1)
    audit_log.append(make_event(3, action="killswitch.engage", correlation_id="corr_x"))
    clock.advance(minutes=1)
    audit_log.append(make_event(4, action="policyXevaluate"))

    def seqs(**kwargs: Any) -> list[int]:
        return [r.seq for r in audit_log.query(limit=10, **kwargs)]

    assert seqs(actor_id="agent_ciso") == [1]
    assert seqs(action_prefix="policy.") == [1, 2]
    assert seqs(action_prefix="policy_") == []  # LIKE wildcards are escaped
    assert seqs(target="asset:3") == [3]
    assert seqs(outcome=AuditOutcome.DENIED) == [2]
    assert seqs(correlation_id="corr_x") == [3]
    assert seqs(since=start + timedelta(minutes=1), until=start + timedelta(minutes=3)) == [2, 3]
    assert seqs(after_seq=2) == [3, 4]
    assert [r.seq for r in audit_log.query(limit=2)] == [1, 2]


@pytest.mark.parametrize("limit", [0, -1])
def test_query_refuses_a_non_positive_limit(audit_log: AuditLog, limit: int) -> None:
    with pytest.raises(ValidationFailed):
        audit_log.query(limit=limit)


def test_append_raises_when_the_schema_is_missing(
    tmp_path: Path, clock: FixedClock, head_anchor: HeadAnchor
) -> None:
    engine = create_db_engine(tmp_path / "empty" / "audit.db")
    try:
        log = AuditLog(engine, clock, FakeRedactor(), head_anchor)
        with pytest.raises(FailClosed):
            log.append(make_event(1))
    finally:
        engine.dispose()


class _BrokenRedactor(FakeRedactor):
    def redact_value(self, value: Any) -> Any:
        raise RuntimeError("redactor down")


class _ListRedactor(FakeRedactor):
    def redact_value(self, value: Any) -> Any:
        return ["not", "a", "mapping"]


class _BytesRedactor(FakeRedactor):
    def redact_value(self, value: Any) -> Any:
        return {"b": b"raw"}


@pytest.mark.parametrize("redactor", [_BrokenRedactor(), _ListRedactor(), _BytesRedactor()])
def test_append_raises_and_writes_nothing_when_redaction_fails(
    audit_log: AuditLog, make_log: Callable[..., AuditLog], redactor: FakeRedactor
) -> None:
    log = make_log(redactor=redactor)

    with pytest.raises(FailClosed):
        log.append(make_event(1))

    assert audit_log.query(limit=10) == []


def test_append_raises_and_writes_nothing_when_the_anchor_key_is_missing(
    audit_log: AuditLog, make_log: Callable[..., AuditLog], anchor_path: Path
) -> None:
    before = anchor_path.read_bytes()
    keyless = make_log(anchor=HeadAnchor(anchor_path, FakeSecrets({}), ANCHOR_KEY_REF))

    with pytest.raises(FailClosed):
        keyless.append(make_event(1))

    assert audit_log.query(limit=10) == []
    assert anchor_path.read_bytes() == before


def test_init_audit_schema_is_idempotent(audit_engine: Engine, audit_log: AuditLog) -> None:
    audit_log.append(make_event(1))
    init_audit_schema(audit_engine)
    assert audit_log.verify().status is VerifyStatus.OK


def test_triggers_survive_reinitialising_the_schema(
    audit_engine: Engine, audit_log: AuditLog
) -> None:
    audit_log.append(make_event(1))
    init_audit_schema(audit_engine)
    with pytest.raises(Exception, match="append-only"):
        raw_sql(audit_engine, "DELETE FROM audit_record")
