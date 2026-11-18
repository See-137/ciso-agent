"""Crash states that used to need a hand repair (M1 fix pass item 6).

(a) A crash in the middle of a witness publish leaves a torn last line. It is ignored for
    reading only when it is the last line and every earlier line verifies; `verify()`
    names it (`witness_torn_tail`), and the next publish starts on a fresh line with a
    signed note of the fragment it steps over. A bad line anywhere else stays fatal.
(b) A crash inside `initialise()` after the anchor is written and before the identity row
    commits leaves an anchor at genesis and an empty database. The next `initialise()`
    completes it with the anchor's log id; anything else is still refused.
"""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

import pytest
from sqlalchemy import Engine
from tests.audit.helpers import ANCHOR_KEY_REF, WITNESS_KEY_REF, db_files, make_event
from tests.fakes.core import FakeSecrets

from ciso.audit import AnchorEntry, AuditLog, FileHeadWitness, HeadAnchor, VerifyStatus
from ciso.audit.anchor import AnchorKey
from ciso.audit.tables import init_audit_schema
from ciso.common.errors import Conflict, IntegrityFailure

pytestmark = pytest.mark.resilience

TORN = "witness_torn_tail"


@pytest.fixture
def witness(witness_path: Path, anchor_secrets: FakeSecrets) -> FileHeadWitness:
    return FileHeadWitness(witness_path, anchor_secrets, WITNESS_KEY_REF)


@pytest.fixture
def witnessed_log(make_log: Callable[..., AuditLog], witness: FileHeadWitness) -> AuditLog:
    log = make_log(witness=witness, witness_every=1)
    log.initialise()
    log.append(make_event(1))
    log.append(make_event(2))
    return log


def lines_of(path: Path) -> list[bytes]:
    return path.read_bytes().split(b"\n")


# -- (a) torn witness tail -------------------------------------------------------------


class TestTornWitnessTail:
    def test_a_torn_last_line_without_newline_is_a_named_warning(
        self, witnessed_log: AuditLog, witness_path: Path
    ) -> None:
        good = witness_path.read_bytes()
        with witness_path.open("ab") as handle:
            handle.write(good.split(b"\n")[0][:25])  # half of a line, no newline
        result = witnessed_log.verify()
        assert result.status is VerifyStatus.OK
        assert result.witnessed is True
        assert result.warnings == (TORN,)
        assert result.head_seq == 2

    def test_a_torn_last_line_with_newline_but_unparseable_is_a_warning(
        self, witnessed_log: AuditLog, witness_path: Path
    ) -> None:
        with witness_path.open("ab") as handle:
            handle.write(b"\x00\x00\x00\x00\n")  # zero fill left by a crash
        result = witnessed_log.verify()
        assert result.status is VerifyStatus.OK
        assert result.warnings == (TORN,)

    @pytest.mark.parametrize("fragment", [b'{"at": "2026-', b"\x00\x00\n"])
    def test_the_next_publish_writes_a_fresh_line_and_clears_the_warning(
        self, witnessed_log: AuditLog, witness: FileHeadWitness, witness_path: Path, fragment: bytes
    ) -> None:
        with witness_path.open("ab") as handle:
            handle.write(fragment)
        receipt = witnessed_log.append(make_event(3))
        result = witnessed_log.verify()
        assert result.status is VerifyStatus.OK
        assert result.warnings == ()
        latest = witness.latest(witnessed_log.log_id or "")
        assert latest is not None
        assert latest.seq == receipt.seq == 3
        assert fragment.rstrip(b"\n") in lines_of(witness_path)  # kept, never cut away
        witnessed_log.append(make_event(4))
        assert witnessed_log.verify().status is VerifyStatus.OK

    def test_a_valid_last_line_without_newline_still_counts(
        self, witnessed_log: AuditLog, witness: FileHeadWitness, witness_path: Path
    ) -> None:
        witness_path.write_bytes(witness_path.read_bytes().rstrip(b"\n"))
        latest = witness.latest(witnessed_log.log_id or "")
        assert latest is not None
        assert latest.seq == 2
        assert witnessed_log.verify().warnings == ()
        witnessed_log.append(make_event(3))
        assert witnessed_log.verify().status is VerifyStatus.OK

    def test_a_bad_line_in_the_middle_stays_fatal(
        self, witnessed_log: AuditLog, witness_path: Path
    ) -> None:
        first, *rest = lines_of(witness_path)
        witness_path.write_bytes(b"\n".join([first, b"\x00garbage", *rest]))
        result = witnessed_log.verify()
        assert result.status is VerifyStatus.FAILED
        assert result.reason == "witness_invalid"
        with pytest.raises(IntegrityFailure):
            witnessed_log.append(make_event(3))

    def test_a_torn_tail_after_a_bad_signature_stays_fatal(
        self, witnessed_log: AuditLog, witness_path: Path
    ) -> None:
        first, *rest = lines_of(witness_path)
        forged = first.replace(b'"seq": 1', b'"seq": 7')
        assert forged != first
        witness_path.write_bytes(b"\n".join([forged, *rest]) + b'{"at": "2026-')
        result = witnessed_log.verify()
        assert result.status is VerifyStatus.FAILED
        assert result.reason == "witness_invalid"

    def test_a_last_line_that_parses_but_fails_its_signature_is_fatal(
        self, witnessed_log: AuditLog, witness_path: Path
    ) -> None:
        *rest, last, _ = lines_of(witness_path)
        forged = last.replace(b'"seq": 2', b'"seq": 9')
        assert forged != last
        witness_path.write_bytes(b"\n".join([*rest, forged]))  # no trailing newline
        result = witnessed_log.verify()
        assert result.status is VerifyStatus.FAILED
        assert result.reason == "witness_invalid"

    def test_changing_a_stepped_over_fragment_is_fatal(
        self, witnessed_log: AuditLog, witness_path: Path
    ) -> None:
        with witness_path.open("ab") as handle:
            handle.write(b'{"at": "2026-')
        witnessed_log.append(make_event(3))
        raw = witness_path.read_bytes()
        witness_path.write_bytes(raw.replace(b'{"at": "2026-\n', b'{"at": "2027-\n'))
        result = witnessed_log.verify()
        assert result.status is VerifyStatus.FAILED
        assert result.reason == "witness_invalid"


# -- (b) half-done initialise ----------------------------------------------------------


class CrashAfterAnchor(HeadAnchor):
    """Writes the anchor, then dies before the identity transaction commits."""

    def write(
        self, key: AnchorKey, log_id: str, final: AnchorEntry, pending: AnchorEntry | None = None
    ) -> None:
        super().write(key, log_id, final, pending)
        raise RuntimeError("process killed (test)")


def crash_in_initialise(make_log: Callable[..., AuditLog], anchor_path: Path) -> str:
    secrets = FakeSecrets({ANCHOR_KEY_REF: "anchor-key-for-audit-tests-7f3a9c0b5e"})
    crashing = make_log(anchor=CrashAfterAnchor(anchor_path, secrets, ANCHOR_KEY_REF))
    with pytest.raises(RuntimeError):
        crashing.initialise()
    assert anchor_path.exists()
    assert crashing.log_id is None
    reading = crashing._anchor.read(crashing._anchor.load_key())
    assert reading.log_id is not None
    return reading.log_id


class TestHalfDoneInitialise:
    def test_was_log_missing_before_the_fix(
        self, make_log: Callable[..., AuditLog], anchor_path: Path
    ) -> None:
        crash_in_initialise(make_log, anchor_path)
        result = make_log().verify()
        assert result.status is VerifyStatus.FAILED
        assert result.reason == "log_missing"  # what the next initialise() repairs

    def test_the_next_initialise_completes_with_the_same_log_id(
        self, make_log: Callable[..., AuditLog], anchor_path: Path
    ) -> None:
        anchored = crash_in_initialise(make_log, anchor_path)
        log = make_log()
        assert log.initialise() == anchored
        assert log.log_id == anchored
        assert log.open() == anchored
        assert log.append(make_event(1)).seq == 1
        assert log.verify().status is VerifyStatus.OK

    def test_completion_is_refused_when_an_existing_log_is_expected(
        self, make_log: Callable[..., AuditLog], anchor_path: Path
    ) -> None:
        anchored = crash_in_initialise(make_log, anchor_path)
        with pytest.raises(Conflict):
            make_log(expected_log_id=anchored).initialise()

    def test_an_anchor_past_genesis_over_an_empty_database_is_still_refused(
        self,
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
        with pytest.raises(Conflict):
            make_log().initialise()
        assert make_log().verify().reason == "log_missing"

    def test_an_anchor_under_another_key_is_still_refused(
        self, make_log: Callable[..., AuditLog], anchor_path: Path
    ) -> None:
        crash_in_initialise(make_log, anchor_path)
        other = FakeSecrets({ANCHOR_KEY_REF: "a-completely-different-anchor-key-000"})
        with pytest.raises(Conflict):
            make_log(anchor=HeadAnchor(anchor_path, other, ANCHOR_KEY_REF)).initialise()
