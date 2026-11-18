"""Kill switch service. Blueprint 11.2; FR-030; gap G20; ADR-0018; review H3, H4, L4, L5."""

from __future__ import annotations

import sqlite3
import threading
from collections.abc import Callable
from pathlib import Path

import pytest
from sqlalchemy import Engine, delete, event, select, update
from tests.fakes.core import FakePrincipals, FakeSecrets, make_principal
from tests.killswitch.conftest import AuditHistory, ScriptedAudit, SleepRecorder

from ciso.common.clock import FixedClock
from ciso.common.db import create_db_engine
from ciso.common.enums import ActorType, AuditOutcome, KillCapability, Role
from ciso.common.errors import (
    AuthorizationError,
    FailClosed,
    KillSwitchEngaged,
    ValidationFailed,
)
from ciso.common.principal import Principal
from ciso.common.protocols import AuditEvent, KillSwitchReader
from ciso.killswitch import DEEP_TESTS_CAPABILITY, KillSwitch, KillSwitchRecord
from ciso.killswitch.models import ENGAGE_ACTION, INITIALISE_ACTION, RELEASE_ACTION
from ciso.killswitch.persist import WRITE_ATTEMPTS
from ciso.killswitch.tables import killswitch_flag, killswitch_pending_audit

pytestmark = pytest.mark.broker

ALL = tuple(KillCapability)
W = KillCapability.WRITES
MakeSwitch = Callable[..., KillSwitch]


def blocked(ks: KillSwitch) -> list[bool]:
    return [ks.is_blocked(cap) for cap in ALL]


# --- reading and initial state -----------------------------------------------------------


def test_switch_is_a_kill_switch_reader(switch: KillSwitch) -> None:
    assert isinstance(switch, KillSwitchReader)


def test_initialised_switch_is_clear_and_audited(switch: KillSwitch, audit: ScriptedAudit) -> None:
    assert blocked(switch) == [False] * 4
    for cap in ALL:
        switch.require_clear(cap)
    assert audit.outcomes(INITIALISE_ACTION) == [AuditOutcome.SUCCESS]
    assert all(s.verified and s.recorded for s in switch.status())


def test_missing_rows_read_blocked_before_initialise(
    engine: Engine, make_switch: MakeSwitch
) -> None:
    ks = make_switch(engine)
    assert blocked(ks) == [True] * 4
    ks.initialise()
    assert blocked(ks) == [False] * 4


def test_unknown_capability_reads_blocked(switch: KillSwitch) -> None:
    assert switch.is_blocked("not_a_capability") is True  # type: ignore[arg-type]


def test_engaging_active_scans_blocks_deep_tests(switch: KillSwitch, admin: Principal) -> None:
    assert not switch.is_blocked(DEEP_TESTS_CAPABILITY)
    switch.engage(admin, [KillCapability.ACTIVE_SCANS], "scan storm")
    assert switch.is_blocked(DEEP_TESTS_CAPABILITY)
    with pytest.raises(KillSwitchEngaged):
        switch.require_clear(DEEP_TESTS_CAPABILITY)


# --- engage / release --------------------------------------------------------------------


def test_engage_blocks_only_the_named_capability(
    switch: KillSwitch, admin: Principal, audit: ScriptedAudit
) -> None:
    states = switch.engage(admin, [W], "suspicious change")
    assert switch.is_blocked(W)
    assert not switch.is_blocked(KillCapability.L3_RUNS)
    with pytest.raises(KillSwitchEngaged, match="writes"):
        switch.require_clear(W)
    assert [(s.capability, s.engaged, s.verified) for s in states] == [(W, True, True)]
    [event_] = audit.find(ENGAGE_ACTION)
    assert event_.actor_id == admin.actor_id
    assert event_.actor_type is ActorType.HUMAN
    assert event_.details["capabilities"] == ["writes"]
    assert event_.details["reason"] == "suspicious change"
    assert event_.details["outbox_entry"].startswith("ksaudit_")
    assert switch.pending_audit() == ()


def test_release_audits_attempt_then_success(
    switch: KillSwitch, admin: Principal, audit: ScriptedAudit
) -> None:
    switch.engage_all(admin, "drill")
    switch.release(admin, [KillCapability.ACTIVE_SCANS], "drill over")
    assert not switch.is_blocked(KillCapability.ACTIVE_SCANS)
    assert switch.is_blocked(W)
    assert audit.outcomes(RELEASE_ACTION) == [AuditOutcome.ATTEMPT, AuditOutcome.SUCCESS]
    assert audit.find(RELEASE_ACTION)[0].details["versions"] == {"active_scans": 2}


def test_engage_all_blocks_all_four(switch: KillSwitch, admin: Principal) -> None:
    switch.engage_all(admin, "drill")
    assert blocked(switch) == [True] * 4


def test_flags_persist_across_a_new_service_instance(
    engine: Engine, switch: KillSwitch, make_switch: MakeSwitch, admin: Principal
) -> None:
    switch.engage(admin, [KillCapability.EXTERNAL_INFERENCE, KillCapability.L3_RUNS], "x")
    second = make_switch(engine)
    assert second.is_blocked(KillCapability.EXTERNAL_INFERENCE)
    assert second.is_blocked(KillCapability.L3_RUNS)
    assert not second.is_blocked(W)


def test_flags_persist_on_a_file_database(
    file_db: tuple[Path, Engine], make_switch: MakeSwitch, admin: Principal
) -> None:
    path, eng = file_db
    first = make_switch(eng)
    first.initialise()
    first.engage(admin, [W], "x")
    eng.dispose()
    reopened = create_db_engine(path)
    try:
        assert make_switch(reopened).is_blocked(W)
        assert not make_switch(reopened).is_blocked(KillCapability.L3_RUNS)
    finally:
        reopened.dispose()


@pytest.mark.parametrize("reason", ["", "   "])
def test_blank_reason_is_refused(switch: KillSwitch, admin: Principal, reason: str) -> None:
    with pytest.raises(ValidationFailed):
        switch.engage(admin, [W], reason)


def test_empty_or_unknown_capability_list_is_refused(switch: KillSwitch, admin: Principal) -> None:
    with pytest.raises(ValidationFailed):
        switch.engage(admin, [], "x")
    with pytest.raises(ValidationFailed):
        switch.engage(admin, ["bogus"], "x")  # type: ignore[list-item]


# --- who may (L5) ------------------------------------------------------------------------


@pytest.mark.parametrize("who", ["agent", "service", "employee", "auditor"])
@pytest.mark.parametrize("operation", ["engage", "release"])
def test_non_admins_are_refused_and_audited(
    request: pytest.FixtureRequest,
    switch: KillSwitch,
    admin: Principal,
    audit: ScriptedAudit,
    who: str,
    operation: str,
) -> None:
    if operation == "release":
        switch.engage(admin, [W], "set up")
    before = switch.is_blocked(W)
    principal: Principal = request.getfixturevalue(who)
    with pytest.raises(AuthorizationError):
        getattr(switch, operation)(principal, [W], "try")
    assert switch.is_blocked(W) is before
    denied = [e for e in audit.find(f"killswitch.{operation}") if e.actor_id == principal.actor_id]
    assert [e.outcome for e in denied] == [AuditOutcome.DENIED]


def test_decision_uses_the_resolver_not_the_object_handed_in(
    switch: KillSwitch, principals: FakePrincipals, employee: Principal
) -> None:
    forged = make_principal(employee.actor_id, ActorType.HUMAN, Role.SECURITY_ADMIN)
    assert forged.has_role(Role.SECURITY_ADMIN)
    with pytest.raises(AuthorizationError, match="security_admin"):
        switch.engage(forged, [W], "x")
    assert employee.actor_id in principals.lookups
    assert not switch.is_blocked(W)


def test_unknown_actor_with_admin_object_is_refused(switch: KillSwitch) -> None:
    stranger = make_principal("human_nobody", ActorType.HUMAN, Role.SECURITY_ADMIN)
    with pytest.raises(AuthorizationError, match="unknown"):
        switch.engage(stranger, [W], "x")


def test_disabled_admin_is_refused(
    switch: KillSwitch, admin: Principal, principals: FakePrincipals
) -> None:
    switch.engage(admin, [W], "x")
    principals.remove(admin.actor_id)
    with pytest.raises(AuthorizationError):
        switch.release(admin, [W], "y")
    assert switch.is_blocked(W)


def test_smuggled_role_on_an_agent_is_refused(switch: KillSwitch, agent: Principal) -> None:
    forged = Principal.model_construct(
        actor_id=agent.actor_id, actor_type=ActorType.AGENT,
        roles=frozenset({Role.SECURITY_ADMIN}), grants=(), scopes={}, display_name="",
        credential_issued_by="",
    )  # fmt: skip
    with pytest.raises(AuthorizationError, match="human"):
        switch.engage(forged, [W], "x")
    assert not switch.is_blocked(W)


@pytest.mark.parametrize("operation", ["engage", "release"])
def test_resolver_failure_is_a_refusal(
    switch: KillSwitch, admin: Principal, principals: FakePrincipals, operation: str
) -> None:
    if operation == "release":
        switch.engage(admin, [W], "set up")
    before = switch.is_blocked(W)
    principals.broken = True
    with pytest.raises(AuthorizationError, match="identity"):
        getattr(switch, operation)(admin, [W], "x")
    assert switch.is_blocked(W) is before


def test_refusal_still_raises_when_the_audit_is_down(
    switch: KillSwitch, audit: ScriptedAudit, agent: Principal
) -> None:
    audit.fail = True
    with pytest.raises(AuthorizationError, match="could not be audited"):
        switch.engage(agent, [W], "x")


# --- flag integrity (H3) -----------------------------------------------------------------


def test_direct_update_to_clear_reads_blocked(
    switch: KillSwitch, engine: Engine, admin: Principal
) -> None:
    switch.engage(admin, [W], "incident")
    with engine.begin() as conn:
        conn.execute(update(killswitch_flag).where(killswitch_flag.c.capability == "writes")
                     .values(engaged=False, changed_by="human_admin"))  # fmt: skip
    assert switch.is_blocked(W)
    state = next(s for s in switch.status() if s.capability is W)
    assert state.stored_engaged is False
    assert not state.verified
    assert state.engaged


def test_forged_mac_reads_blocked(switch: KillSwitch, engine: Engine) -> None:
    with engine.begin() as conn:
        conn.execute(update(killswitch_flag).where(killswitch_flag.c.capability == "writes")
                     .values(mac="0" * 64))  # fmt: skip
    assert switch.is_blocked(W)
    assert not switch.is_blocked(KillCapability.L3_RUNS)


def test_wrong_key_reads_blocked(
    engine: Engine, switch: KillSwitch, make_switch: MakeSwitch
) -> None:
    other = make_switch(
        engine,
        secrets=FakeSecrets({"secret://killswitch_key": "a-different-killswitch-key-0000-0000"}),
    )
    assert blocked(other) == [True] * 4


@pytest.mark.parametrize("variant", ["no_ref", "unresolvable"])
def test_missing_key_reads_blocked(
    engine: Engine, switch: KillSwitch, make_switch: MakeSwitch, variant: str
) -> None:
    overrides: dict[str, object] = (
        {"key_ref": None} if variant == "no_ref" else {"secrets": FakeSecrets()}
    )
    keyless = make_switch(engine, **overrides)
    assert blocked(keyless) == [True] * 4
    assert blocked(switch) == [False] * 4


def test_engage_without_key_stores_intent_and_reads_blocked(
    engine: Engine, switch: KillSwitch, make_switch: MakeSwitch, admin: Principal,
    audit: ScriptedAudit,
) -> None:  # fmt: skip
    keyless = make_switch(engine, key_ref=None)
    states = keyless.engage(admin, [W], "key store down")
    assert states[0].engaged
    assert not states[0].verified
    raw = next(s for s in switch.status() if s.capability is W)
    assert raw.stored_engaged is True
    assert not raw.verified
    assert switch.is_blocked(W)
    [event_] = audit.find(ENGAGE_ACTION)
    assert event_.actor_type is ActorType.ANONYMOUS
    assert event_.details["mac_verified"] is False
    assert event_.details["unverified_actor"] == admin.actor_id


def test_release_needs_the_key(
    engine: Engine, switch: KillSwitch, make_switch: MakeSwitch, admin: Principal
) -> None:
    switch.engage(admin, [W], "x")
    with pytest.raises(FailClosed, match="key"):
        make_switch(engine, key_ref=None).release(admin, [W], "y")
    assert switch.is_blocked(W)


def test_release_of_an_unverifiable_row_is_refused_until_engaged_again(
    switch: KillSwitch, engine: Engine, admin: Principal, audit: ScriptedAudit
) -> None:
    with engine.begin() as conn:
        conn.execute(update(killswitch_flag).where(killswitch_flag.c.capability == "writes")
                     .values(reason="edited"))  # fmt: skip
    with pytest.raises(FailClosed, match="cannot verify"):
        switch.release(admin, [W], "y")
    assert audit.find(RELEASE_ACTION) == []
    switch.engage(admin, [W], "re-establish")
    switch.release(admin, [W], "y")
    assert not switch.is_blocked(W)


def test_deleted_row_stays_blocked_after_restart_and_initialise(
    engine: Engine, switch: KillSwitch, make_switch: MakeSwitch, admin: Principal
) -> None:
    switch.engage_all(admin, "incident")
    with engine.begin() as conn:
        conn.execute(delete(killswitch_flag).where(killswitch_flag.c.capability == "writes"))
    restarted = make_switch(engine)
    restarted.initialise()
    assert restarted.is_blocked(W)
    state = next(s for s in restarted.status() if s.capability is W)
    assert not state.recorded
    assert state.engaged


def test_initialise_creates_nothing_when_history_exists_after_a_wipe(
    engine: Engine, switch: KillSwitch, make_switch: MakeSwitch, admin: Principal
) -> None:
    switch.engage(admin, [W], "incident")
    with engine.begin() as conn:
        conn.execute(delete(killswitch_flag))
        conn.execute(delete(killswitch_pending_audit))
    restarted = make_switch(engine)
    restarted.initialise()
    assert blocked(restarted) == [True] * 4
    with engine.connect() as conn:
        assert conn.execute(select(killswitch_flag)).all() == []


def test_initialise_creates_nothing_when_an_outbox_row_exists(
    engine: Engine, make_switch: MakeSwitch, history: AuditHistory, admin: Principal,
    audit: ScriptedAudit,
) -> None:  # fmt: skip
    ks = make_switch(engine, history=None)
    audit.fail = True
    ks.engage(admin, [W], "before initialise")
    audit.fail = False
    with engine.begin() as conn:
        conn.execute(delete(killswitch_flag))
    ks.initialise()
    assert blocked(ks) == [True] * 4


def test_initialise_needs_the_key(engine: Engine, make_switch: MakeSwitch) -> None:
    with pytest.raises(FailClosed, match="key"):
        make_switch(engine, key_ref=None).initialise()


def test_initialise_refuses_when_history_is_unreadable(
    engine: Engine, make_switch: MakeSwitch, history: AuditHistory
) -> None:
    history.broken = True
    with pytest.raises(FailClosed, match="history"):
        make_switch(engine).initialise()
    assert blocked(make_switch(engine)) == [True] * 4


def test_concurrent_initialise_creates_once_without_raw_errors(
    file_db: tuple[Path, Engine], make_switch: MakeSwitch, audit: ScriptedAudit
) -> None:
    path, _ = file_db
    errors: list[BaseException] = []
    start = threading.Barrier(6)

    def run() -> None:
        eng = create_db_engine(path)
        try:
            start.wait()
            make_switch(eng).initialise()
        except BaseException as exc:
            errors.append(exc)
        finally:
            eng.dispose()

    threads = [threading.Thread(target=run) for _ in range(6)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=60)
    assert errors == []
    assert audit.outcomes(INITIALISE_ACTION) == [AuditOutcome.SUCCESS]
    eng = create_db_engine(path)
    try:
        with eng.connect() as conn:
            assert len(conn.execute(select(killswitch_flag)).all()) == 4
        assert blocked(make_switch(eng)) == [False] * 4
    finally:
        eng.dispose()


# --- reconcile ---------------------------------------------------------------------------


def test_reconcile_forces_blocked_when_history_says_engaged(
    switch: KillSwitch, history: AuditHistory, admin: Principal, audit: ScriptedAudit
) -> None:
    history.extra.append(KillSwitchRecord(action=ENGAGE_ACTION, capabilities=(W,)))
    found = switch.reconcile()
    assert [(m.capability, m.forced_blocked) for m in found] == [(W, True)]
    assert switch.is_blocked(W)
    assert not switch.is_blocked(KillCapability.L3_RUNS)
    [event_] = audit.find(ENGAGE_ACTION)
    assert event_.actor_type is ActorType.SERVICE
    history.extra.clear()
    switch.release(admin, [W], "checked")
    assert not switch.is_blocked(W)


def test_reconcile_catches_a_rolled_back_row(
    switch: KillSwitch, engine: Engine, admin: Principal
) -> None:
    with engine.connect() as conn:
        saved = dict(conn.execute(select(killswitch_flag).where(
            killswitch_flag.c.capability == "writes")).one()._mapping)  # fmt: skip
    switch.engage(admin, [W], "incident")
    with engine.begin() as conn:
        conn.execute(update(killswitch_flag).where(killswitch_flag.c.capability == "writes")
                     .values(**{k: v for k, v in saved.items() if k != "capability"}))  # fmt: skip
    assert not switch.is_blocked(W)  # the MAC alone cannot see a rollback
    found = switch.reconcile()
    assert [m.capability for m in found if m.forced_blocked] == [W]
    assert switch.is_blocked(W)


def test_reconcile_reports_blocked_after_release_without_forcing(
    switch: KillSwitch, engine: Engine
) -> None:
    with engine.begin() as conn:
        conn.execute(update(killswitch_flag).where(killswitch_flag.c.capability == "writes")
                     .values(mac=None))  # fmt: skip
    found = switch.reconcile()
    assert [(m.capability, m.flag_reads_blocked, m.forced_blocked) for m in found] == [
        (W, True, False)
    ]


def test_reconcile_on_a_consistent_switch_finds_nothing(
    switch: KillSwitch, admin: Principal
) -> None:
    switch.engage(admin, [W], "x")
    assert switch.reconcile() == ()


def test_reconcile_needs_history(
    engine: Engine, make_switch: MakeSwitch, switch: KillSwitch
) -> None:
    with pytest.raises(FailClosed):
        make_switch(engine, history=None).reconcile()


# --- audit asymmetry and locks (H4, L4, M3) ----------------------------------------------


def test_engage_persists_when_the_audit_write_fails(
    switch: KillSwitch, admin: Principal, audit: ScriptedAudit
) -> None:
    audit.fail = True
    switch.engage(admin, [W, KillCapability.L3_RUNS], "outage")
    assert switch.is_blocked(W)
    assert switch.is_blocked(KillCapability.L3_RUNS)
    [owed] = switch.pending_audit()
    assert owed.capabilities == ("l3_runs", "writes")
    assert "audit append failed" in owed.last_error
    audit.fail = False
    assert switch.retry_pending_audit() == 1
    assert switch.pending_audit() == ()
    assert audit.outcomes(ENGAGE_ACTION) == [AuditOutcome.SUCCESS]


def test_release_attempt_audit_failure_changes_nothing(
    switch: KillSwitch, admin: Principal, audit: ScriptedAudit
) -> None:
    switch.engage_all(admin, "incident")
    audit.fail_if = lambda e: e.action == RELEASE_ACTION and e.outcome is AuditOutcome.ATTEMPT
    with pytest.raises(FailClosed, match="attempt"):
        switch.release(admin, [W], "all clear")
    assert switch.is_blocked(W)
    assert audit.find(RELEASE_ACTION) == []


def test_release_result_audit_failure_re_engages(
    switch: KillSwitch, admin: Principal, audit: ScriptedAudit
) -> None:
    switch.engage_all(admin, "incident")
    audit.fail_if = lambda e: e.action == RELEASE_ACTION and e.outcome is AuditOutcome.SUCCESS
    with pytest.raises(FailClosed, match="re-engaged"):
        switch.release(admin, [W], "all clear")
    assert switch.is_blocked(W)
    assert audit.outcomes(RELEASE_ACTION) == [AuditOutcome.ATTEMPT]
    assert len(audit.find(ENGAGE_ACTION)) == 2


def test_release_refuses_while_an_engage_audit_is_owed(
    switch: KillSwitch, admin: Principal, audit: ScriptedAudit
) -> None:
    audit.fail_if = lambda e: e.action == ENGAGE_ACTION
    switch.engage(admin, [W], "incident")
    with pytest.raises(FailClosed, match="owed"):
        switch.release(admin, [W], "all clear")
    assert switch.is_blocked(W)
    assert audit.find(RELEASE_ACTION) == []


def test_release_delivers_the_owed_engage_first(
    switch: KillSwitch, admin: Principal, audit: ScriptedAudit
) -> None:
    audit.fail = True
    switch.engage(admin, [W], "incident")
    audit.fail = False
    switch.release(admin, [W], "all clear")
    order = [(e.action, e.outcome) for e in audit.events if e.action != INITIALISE_ACTION]
    assert order == [
        (ENGAGE_ACTION, AuditOutcome.SUCCESS),
        (RELEASE_ACTION, AuditOutcome.ATTEMPT),
        (RELEASE_ACTION, AuditOutcome.SUCCESS),
    ]


def _no_lock_probe(path: Path, seen: list[str]) -> Callable[[AuditEvent], None]:
    def probe(event_: AuditEvent) -> None:
        raw = sqlite3.connect(path, timeout=0, isolation_level=None)
        try:
            raw.execute("BEGIN IMMEDIATE")
            raw.execute("COMMIT")
            seen.append(f"{event_.action}:{event_.outcome.value}:free")
        except sqlite3.OperationalError:
            seen.append(f"{event_.action}:{event_.outcome.value}:LOCKED")
        finally:
            raw.close()

    return probe


def test_audit_sink_is_never_called_under_the_write_lock(
    file_db: tuple[Path, Engine], make_switch: MakeSwitch, admin: Principal,
    audit: ScriptedAudit,
) -> None:  # fmt: skip
    path, eng = file_db
    ks = make_switch(eng)
    ks.initialise()
    seen: list[str] = []
    audit.during = _no_lock_probe(path, seen)
    ks.engage(admin, [W], "x")
    ks.release(admin, [W], "y")
    assert seen == [
        "killswitch.engage:success:free",
        "killswitch.release:attempt:free",
        "killswitch.release:success:free",
    ]


def _fast_fail_engine(path: Path) -> Engine:
    eng = create_db_engine(path)

    @event.listens_for(eng, "connect")
    def _no_wait(dbapi_connection: object, _record: object) -> None:
        dbapi_connection.execute("PRAGMA busy_timeout=0")  # type: ignore[attr-defined]

    return eng


def test_engage_retries_a_locked_database(
    file_db: tuple[Path, Engine], make_switch: MakeSwitch, admin: Principal,
    sleeper: SleepRecorder,
) -> None:  # fmt: skip
    path, eng = file_db
    make_switch(eng).initialise()
    fast = _fast_fail_engine(path)
    holder = sqlite3.connect(path, isolation_level=None)
    try:
        holder.execute("BEGIN IMMEDIATE")
        sleeper.hook = lambda n: holder.execute("COMMIT") if n == 2 else None
        make_switch(fast).engage(admin, [W], "under load")
        assert len(sleeper.calls) == 2
        assert make_switch(eng).is_blocked(W)
    finally:
        holder.close()
        fast.dispose()


def test_engage_on_a_database_that_stays_locked_raises_fail_closed(
    file_db: tuple[Path, Engine], make_switch: MakeSwitch, admin: Principal,
    sleeper: SleepRecorder,
) -> None:  # fmt: skip
    path, eng = file_db
    make_switch(eng).initialise()
    fast = _fast_fail_engine(path)
    holder = sqlite3.connect(path, isolation_level=None)
    try:
        holder.execute("BEGIN IMMEDIATE")
        with pytest.raises(FailClosed, match="locked") as caught:
            make_switch(fast).engage(admin, [W], "under load")
        assert type(caught.value) is FailClosed
        assert len(sleeper.calls) == WRITE_ATTEMPTS - 1
    finally:
        holder.execute("ROLLBACK")
        holder.close()
        fast.dispose()


def test_nothing_after_the_commit_turns_engage_into_an_error(
    switch: KillSwitch, engine: Engine, admin: Principal, audit: ScriptedAudit
) -> None:
    def break_outbox(_: AuditEvent) -> None:
        killswitch_pending_audit.drop(engine)

    audit.during = break_outbox
    states = switch.engage(admin, [W], "incident")
    assert states[0].engaged
    assert switch.is_blocked(W)


# --- read failures and status ------------------------------------------------------------


def test_dropped_table_means_blocked(switch: KillSwitch, engine: Engine) -> None:
    assert not switch.is_blocked(W)
    killswitch_flag.drop(engine)
    assert blocked(switch) == [True] * 4
    with pytest.raises(KillSwitchEngaged):
        switch.require_clear(W)


def test_broken_engine_means_blocked(make_switch: MakeSwitch, tmp_path: Path) -> None:
    blocker = tmp_path / "not_a_dir"
    blocker.write_text("x", encoding="utf-8")
    from sqlalchemy import create_engine

    broken = create_engine(f"sqlite:///{(blocker / 'db.sqlite').as_posix()}")
    try:
        ks = make_switch(broken)
        assert blocked(ks) == [True] * 4
        with pytest.raises(FailClosed):
            ks.status()
    finally:
        broken.dispose()


def test_status_reports_every_capability(
    switch: KillSwitch, admin: Principal, clock: FixedClock
) -> None:
    switch.engage(admin, [KillCapability.ACTIVE_SCANS], "scan storm")
    states = {s.capability: s for s in switch.status()}
    assert set(states) == set(ALL)
    scans = states[KillCapability.ACTIVE_SCANS]
    assert (scans.engaged, scans.recorded, scans.verified) == (True, True, True)
    assert scans.changed_by == admin.actor_id
    assert scans.changed_at == clock.now()
    assert scans.reason == "scan storm"
    assert scans.via == "api"
    assert scans.version == 2
    assert not states[W].engaged
