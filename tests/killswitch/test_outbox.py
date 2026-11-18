"""Kill-switch audit outbox. Review H2 (forgery) and M3 (poison, duplicates, order)."""

from __future__ import annotations

import json
from collections.abc import Callable
from datetime import timedelta

import pytest
from sqlalchemy import Engine, select, update
from tests.killswitch.conftest import KEY_VALUE, ScriptedAudit

from ciso.common.clock import FixedClock
from ciso.common.enums import ActorType, AuditOutcome, KillCapability
from ciso.common.principal import Principal
from ciso.common.protocols import AuditEvent
from ciso.killswitch import KillSwitch
from ciso.killswitch.integrity import outbox_mac
from ciso.killswitch.models import ENGAGE_ACTION
from ciso.killswitch.tables import killswitch_pending_audit as outbox

pytestmark = pytest.mark.broker

W = KillCapability.WRITES
MakeSwitch = Callable[..., KillSwitch]


def plant(engine: Engine, clock: FixedClock, *, sign: bool = False, **values: object) -> None:
    """Insert an outbox row the way a hostile database writer would."""
    row: dict[str, object] = {
        "entry_id": f"ksaudit_planted{len(str(values))}",
        "actor_id": "exec_cfo",
        "capabilities": json.dumps(["writes"]),
        "reason": "planted",
        "via": "api",
        "operator": "",
        "recorded_at": clock.now(),
        "mac": None,
        "quarantined": False,
        "last_error": "",
    }
    row.update(values)
    if sign:
        row["mac"] = outbox_mac(
            KEY_VALUE.encode(), entry_id=str(row["entry_id"]), actor_id=str(row["actor_id"]),
            capabilities=str(row["capabilities"]), reason=str(row["reason"]),
            via=str(row["via"]), operator=str(row["operator"]), recorded_at=clock.now(),
        )  # fmt: skip
    with engine.begin() as conn:
        conn.execute(outbox.insert().values(**row))


def test_planted_unsigned_row_never_becomes_a_named_human_record(
    switch: KillSwitch, engine: Engine, clock: FixedClock, audit: ScriptedAudit
) -> None:
    plant(engine, clock)
    assert switch.retry_pending_audit() == 1
    assert {e.action for e in audit.events} <= {ENGAGE_ACTION, "killswitch.initialise"}
    assert [e for e in audit.events if e.actor_id == "exec_cfo"] == []
    [event_] = audit.find(ENGAGE_ACTION)
    assert event_.actor_type is ActorType.ANONYMOUS
    assert event_.actor_id == "unverified"
    assert event_.details["unverified_actor"] == "exec_cfo"
    assert event_.details["mac_verified"] is False


def test_row_with_a_bad_mac_is_quarantined(
    switch: KillSwitch, engine: Engine, clock: FixedClock, audit: ScriptedAudit
) -> None:
    plant(engine, clock, mac="f" * 64)
    assert switch.retry_pending_audit() == 0
    assert audit.find(ENGAGE_ACTION) == []
    assert switch.pending_audit() == ()
    [held] = switch.quarantined_audit()
    assert held.quarantined
    assert "MAC" in held.last_error
    assert switch.retry_pending_audit() == 0


@pytest.mark.parametrize(
    "tamper", [{"actor_id": "exec_cfo"}, {"via": "reconcile"}, {"reason": "edited"}]
)
def test_signed_row_edited_afterwards_is_quarantined(
    switch: KillSwitch, engine: Engine, clock: FixedClock, audit: ScriptedAudit,
    tamper: dict[str, str],
) -> None:  # fmt: skip
    plant(engine, clock, sign=True, actor_id="human_admin")
    with engine.begin() as conn:
        conn.execute(update(outbox).values(**tamper))
    assert switch.retry_pending_audit() == 0
    assert audit.find(ENGAGE_ACTION) == []
    assert len(switch.quarantined_audit()) == 1


def test_signed_api_row_names_its_human(
    switch: KillSwitch, engine: Engine, clock: FixedClock, audit: ScriptedAudit
) -> None:
    plant(engine, clock, sign=True, actor_id="human_admin")
    assert switch.retry_pending_audit() == 1
    [event_] = audit.find(ENGAGE_ACTION)
    assert (event_.actor_id, event_.actor_type) == ("human_admin", ActorType.HUMAN)
    assert event_.details["mac_verified"] is True


@pytest.mark.parametrize(
    "bad", [{"capabilities": '["bogus"]'}, {"capabilities": "not json"}, {"capabilities": "[]"},
            {"via": "approval"}],
)  # fmt: skip
def test_poisoned_row_does_not_block_the_others(
    switch: KillSwitch, engine: Engine, clock: FixedClock, audit: ScriptedAudit,
    admin: Principal, bad: dict[str, str],
) -> None:  # fmt: skip
    plant(engine, clock, **bad)
    audit.fail = True
    switch.engage(admin, [W], "real engage")
    audit.fail = False
    assert len(switch.pending_audit()) == 2
    assert switch.retry_pending_audit() == 1
    assert switch.pending_audit() == ()
    assert len(switch.quarantined_audit()) == 1
    [event_] = audit.find(ENGAGE_ACTION)
    assert event_.actor_id == admin.actor_id


def test_signed_row_waits_for_the_key(
    engine: Engine, switch: KillSwitch, make_switch: MakeSwitch, admin: Principal,
    audit: ScriptedAudit,
) -> None:  # fmt: skip
    audit.fail = True
    switch.engage(admin, [W], "x")
    audit.fail = False
    keyless = make_switch(engine, key_ref=None)
    assert keyless.retry_pending_audit() == 0
    [owed] = keyless.pending_audit()
    assert "key" in owed.last_error
    assert keyless.quarantined_audit() == ()
    assert switch.retry_pending_audit() == 1


def test_two_delivery_loops_deliver_once(
    engine: Engine, switch: KillSwitch, make_switch: MakeSwitch, admin: Principal,
    audit: ScriptedAudit,
) -> None:  # fmt: skip
    audit.fail = True
    switch.engage(admin, [W], "x")
    audit.fail = False
    other = make_switch(engine)
    raced: list[int] = []

    def race(event_: AuditEvent) -> None:
        if event_.action == ENGAGE_ACTION and not raced:
            raced.append(other.retry_pending_audit())

    audit.during = race
    assert switch.retry_pending_audit() == 1
    assert raced == [0]
    [event_] = audit.find(ENGAGE_ACTION)
    assert event_.details["outbox_entry"].startswith("ksaudit_")


def test_failed_mark_after_append_does_not_cause_a_duplicate(
    switch: KillSwitch, engine: Engine, admin: Principal, audit: ScriptedAudit
) -> None:
    with engine.begin() as conn:
        conn.exec_driver_sql(
            "CREATE TRIGGER no_mark BEFORE UPDATE OF delivered_at ON killswitch_pending_audit "
            "BEGIN SELECT RAISE(ABORT, 'mark refused'); END"
        )
    switch.engage(admin, [W], "x")
    assert switch.retry_pending_audit() == 0
    assert len(audit.find(ENGAGE_ACTION)) == 1
    [owed] = switch.pending_audit()
    assert owed.claimed


def test_stale_claim_is_taken_over_only_with_a_timeout(
    engine: Engine, switch: KillSwitch, make_switch: MakeSwitch, admin: Principal,
    audit: ScriptedAudit, clock: FixedClock,
) -> None:  # fmt: skip
    audit.fail = True
    switch.engage(admin, [W], "x")
    audit.fail = False
    with engine.begin() as conn:
        conn.execute(update(outbox).values(claimed_by="claim_dead", claimed_at=clock.now()))
    clock.advance(minutes=10)
    assert switch.retry_pending_audit() == 0
    patient = make_switch(engine, claim_timeout=timedelta(minutes=5))
    assert patient.retry_pending_audit() == 1
    [event_] = audit.find(ENGAGE_ACTION)
    with engine.connect() as conn:
        entry = conn.execute(select(outbox.c.entry_id)).scalar_one()
    assert event_.details["outbox_entry"] == entry
    assert audit.outcomes(ENGAGE_ACTION) == [AuditOutcome.SUCCESS]
