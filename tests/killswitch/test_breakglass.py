"""Break-glass entry point. Gap G20; review M4, H2."""

from __future__ import annotations

import io
from collections.abc import Callable
from pathlib import Path

import pytest
from sqlalchemy import Engine, inspect
from tests.fakes.core import FakeSecrets
from tests.killswitch.conftest import KEY_REF, KEY_VALUE, ScriptedAudit

import ciso.killswitch.breakglass as breakglass
from ciso.common.clock import FixedClock
from ciso.common.db import create_db_engine
from ciso.common.enums import ActorType, KillCapability
from ciso.common.principal import Principal
from ciso.killswitch import KillSwitch
from ciso.killswitch.models import ENGAGE_ACTION

pytestmark = pytest.mark.broker

ALL = tuple(KillCapability)
MakeSwitch = Callable[..., KillSwitch]


def run(
    argv: list[str], clock: FixedClock, secrets: FakeSecrets | None = None
) -> tuple[int, str, str]:
    out, err = io.StringIO(), io.StringIO()
    code = breakglass.main(
        argv, clock=clock, secrets=secrets or FakeSecrets(), stdout=out, stderr=err
    )
    return code, out.getvalue(), err.getvalue()


def args(path: Path, *extra: str) -> list[str]:
    return ["--db", str(path), "--reason", "api down", "--operator", "night shift", *extra]


@pytest.fixture
def ops_db(file_db: tuple[Path, Engine], make_switch: MakeSwitch) -> Path:
    path, eng = file_db
    make_switch(eng).initialise()
    eng.dispose()
    return path


def reopen(path: Path, make_switch: MakeSwitch) -> tuple[Engine, KillSwitch]:
    eng = create_db_engine(path)
    return eng, make_switch(eng)


def test_engages_all_four_with_the_key(
    ops_db: Path, clock: FixedClock, make_switch: MakeSwitch, audit: ScriptedAudit
) -> None:
    code, out, _ = run(args(ops_db, "--key-ref", KEY_REF), clock, FakeSecrets({KEY_REF: KEY_VALUE}))
    assert code == 0
    assert "rows MAC'd" in out
    eng, ks = reopen(ops_db, make_switch)
    try:
        assert [ks.is_blocked(c) for c in ALL] == [True] * 4
        states = ks.status()
        assert all(s.verified and s.stored_engaged for s in states)
        assert {(s.via, s.changed_by, s.operator) for s in states} == {
            ("breakglass", "breakglass", "night shift")
        }
        [owed] = ks.pending_audit()
        assert (owed.via, owed.actor_id, owed.operator) == (
            "breakglass",
            "breakglass",
            "night shift",
        )
        assert ks.retry_pending_audit() == 1
    finally:
        eng.dispose()
    [event_] = audit.find(ENGAGE_ACTION)
    assert (event_.actor_id, event_.actor_type) == ("breakglass", ActorType.ANONYMOUS)
    assert event_.details["origin"] == "breakglass"
    assert event_.details["unverified_operator"] == "night shift"
    assert event_.details["mac_verified"] is True


def test_without_the_key_rows_are_unsigned_and_read_blocked(
    ops_db: Path, clock: FixedClock, make_switch: MakeSwitch, admin: Principal
) -> None:
    code, out, _ = run(args(ops_db), clock)
    assert code == 0
    assert "without a MAC" in out
    eng, ks = reopen(ops_db, make_switch)
    try:
        assert [ks.is_blocked(c) for c in ALL] == [True] * 4
        assert not any(s.verified for s in ks.status())
        ks.engage_all(admin, "re-establish with the key")
        ks.release(admin, [KillCapability.WRITES], "checked")
        assert not ks.is_blocked(KillCapability.WRITES)
    finally:
        eng.dispose()


def test_refuses_a_database_that_is_not_the_operational_one(
    tmp_path: Path, clock: FixedClock
) -> None:
    path = tmp_path / "audit.db"
    other = create_db_engine(path)
    with other.begin() as conn:
        conn.exec_driver_sql("CREATE TABLE audit_record (x INTEGER)")
    other.dispose()
    code, out, err = run(args(path), clock)
    assert code == 1
    assert "not the operational database" in err
    assert out == ""
    check = create_db_engine(path)
    try:
        assert inspect(check).get_table_names() == ["audit_record"]
    finally:
        check.dispose()


def test_refuses_a_missing_database_file(tmp_path: Path, clock: FixedClock) -> None:
    missing = tmp_path / "typo.db"
    code, out, err = run(args(missing), clock)
    assert code == 1
    assert "does not exist" in err
    assert out == ""
    assert not missing.exists()


def test_reports_failure_when_the_read_back_is_not_blocked(
    ops_db: Path, clock: FixedClock, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(breakglass, "capability_reads_blocked", lambda *_a: False)
    code, out, err = run(args(ops_db), clock)
    assert code == 1
    assert "still reads clear" in err
    assert out == ""


@pytest.mark.parametrize(
    "argv",
    [
        ["--reason", "r", "--operator", "op"],
        ["--db", "x.db", "--operator", "op"],
        ["--db", "x.db", "--reason", "r"],
        ["--db", "x.db", "--reason", "r", "--operator", "op", "--release"],
    ],
)
def test_argument_errors_exit_2(argv: list[str], clock: FixedClock) -> None:
    with pytest.raises(SystemExit) as caught:
        run(argv, clock)
    assert caught.value.code == 2


@pytest.mark.parametrize("field", ["--reason", "--operator"])
def test_blank_reason_or_operator_is_refused(ops_db: Path, clock: FixedClock, field: str) -> None:
    argv = args(ops_db)
    argv[argv.index(field) + 1] = "  "
    code, _, err = run(argv, clock)
    assert code == 1
    assert field.lstrip("-") in err


def test_running_it_on_a_released_switch_only_ever_engages(
    ops_db: Path, clock: FixedClock, make_switch: MakeSwitch
) -> None:
    for _ in range(2):
        assert run(args(ops_db), clock)[0] == 0
    eng, ks = reopen(ops_db, make_switch)
    try:
        assert all(s.stored_engaged for s in ks.status())
    finally:
        eng.dispose()


def test_garbage_file_reports_failure(tmp_path: Path, clock: FixedClock) -> None:
    not_a_db = tmp_path / "garbage.db"
    not_a_db.write_bytes(b"this is not a sqlite file at all" * 10)
    code, out, err = run(args(not_a_db), clock)
    assert code == 1
    assert "break-glass" in err
    assert out == ""
