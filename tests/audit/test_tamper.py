"""Storage-level tampering: triggers refuse it, verify() finds it (T1.1, NFR-006, §11)."""

from __future__ import annotations

import pytest
from sqlalchemy import Engine
from sqlalchemy.exc import IntegrityError
from tests.audit.helpers import drop_triggers, make_event, raw_exec, raw_scalar, raw_sql

from ciso.audit import AuditLog, VerifyStatus
from ciso.common.errors import IntegrityFailure

pytestmark = pytest.mark.resilience


def _fill(log: AuditLog, count: int) -> None:
    for n in range(count):
        log.append(make_event(n))


def test_update_is_aborted_by_the_trigger(audit_log: AuditLog, audit_engine: Engine) -> None:
    _fill(audit_log, 2)
    before = raw_scalar(audit_engine, "SELECT details FROM audit_record WHERE seq = 1")

    with pytest.raises(IntegrityError, match="append-only: update refused"):
        raw_sql(audit_engine, "UPDATE audit_record SET details = '{}' WHERE seq = 1")

    assert raw_scalar(audit_engine, "SELECT details FROM audit_record WHERE seq = 1") == before


def test_delete_is_aborted_by_the_trigger(audit_log: AuditLog, audit_engine: Engine) -> None:
    _fill(audit_log, 2)

    with pytest.raises(IntegrityError, match="append-only: delete refused"):
        raw_sql(audit_engine, "DELETE FROM audit_record WHERE seq = 2")

    assert len(audit_log.query(limit=10)) == 2


def test_an_insert_that_skips_a_seq_is_aborted(audit_log: AuditLog, audit_engine: Engine) -> None:
    _fill(audit_log, 1)
    [head] = audit_log.query(limit=1)

    with pytest.raises(IntegrityError, match="audit chain"):
        raw_exec(
            audit_engine,
            "INSERT INTO audit_record (id, seq, occurred_at, actor_id, actor_type, action,"
            " target, outcome, correlation_id, details, prev_hash, hash) VALUES"
            " ('aud_x', 5, '2026-11-17 12:00:00.000000', 'a', 'human', 'x', '', 'success',"
            " '', '{}', :prev, :hash)",
            prev=head.hash,
            hash="f" * 64,
        )


def test_verify_flags_an_edited_row(audit_log: AuditLog, audit_engine: Engine) -> None:
    _fill(audit_log, 4)
    drop_triggers(audit_engine)
    raw_sql(audit_engine, """UPDATE audit_record SET details = '{"n":999}' WHERE seq = 2""")

    result = audit_log.verify()

    assert result.status is VerifyStatus.FAILED
    assert result.first_broken_seq == 2
    assert result.reason == "hash_mismatch"


def test_verify_flags_a_deleted_middle_row(audit_log: AuditLog, audit_engine: Engine) -> None:
    _fill(audit_log, 4)
    drop_triggers(audit_engine)
    raw_sql(audit_engine, "DELETE FROM audit_record WHERE seq = 2")

    result = audit_log.verify()

    assert result.status is VerifyStatus.FAILED
    assert result.first_broken_seq == 2
    assert result.reason == "seq_gap"


def test_verify_flags_a_deleted_row_hidden_by_renumbering(
    audit_log: AuditLog, audit_engine: Engine
) -> None:
    _fill(audit_log, 4)
    drop_triggers(audit_engine)
    raw_sql(
        audit_engine,
        "DELETE FROM audit_record WHERE seq = 2",
        "UPDATE audit_record SET seq = 2 WHERE seq = 3",
        "UPDATE audit_record SET seq = 3 WHERE seq = 4",
    )

    result = audit_log.verify()

    assert result.status is VerifyStatus.FAILED
    assert result.first_broken_seq == 2
    assert result.reason == "prev_hash_mismatch"


def test_append_is_refused_after_tampering(audit_log: AuditLog, audit_engine: Engine) -> None:
    _fill(audit_log, 3)
    drop_triggers(audit_engine)
    raw_sql(audit_engine, "DELETE FROM audit_record WHERE seq = 3")

    with pytest.raises(IntegrityFailure):
        audit_log.append(make_event(9))

    assert [r.seq for r in audit_log.query(limit=10)] == [1, 2]


# Review M2: what is stored must be exactly what was hashed.


def test_duplicate_keys_in_stored_details_are_row_invalid(
    audit_log: AuditLog, audit_engine: Engine
) -> None:
    _fill(audit_log, 3)  # seq 2 holds {"n":1}
    drop_triggers(audit_engine)
    # Python keeps the last value, so the hash still matches; SQL json_extract sees 999.
    raw_sql(audit_engine, """UPDATE audit_record SET details = '{"n":999,"n":1}' WHERE seq = 2""")

    result = audit_log.verify()

    assert result.status is VerifyStatus.FAILED
    assert result.reason == "row_invalid"
    assert result.first_broken_seq == 2


def test_non_canonical_details_text_is_row_invalid(
    audit_log: AuditLog, audit_engine: Engine
) -> None:
    _fill(audit_log, 3)
    drop_triggers(audit_engine)
    raw_sql(audit_engine, """UPDATE audit_record SET details = '{ "n": 1 }' WHERE seq = 2""")

    result = audit_log.verify()

    assert result.status is VerifyStatus.FAILED
    assert result.reason == "row_invalid"
    assert result.first_broken_seq == 2


def test_respelled_timestamp_is_row_invalid(audit_log: AuditLog, audit_engine: Engine) -> None:
    _fill(audit_log, 3)
    drop_triggers(audit_engine)
    raw_sql(
        audit_engine,
        "UPDATE audit_record SET occurred_at = replace(occurred_at, ' ', 'T') WHERE seq = 2",
    )

    result = audit_log.verify()

    assert result.status is VerifyStatus.FAILED
    assert result.reason == "row_invalid"
    assert result.first_broken_seq == 2
