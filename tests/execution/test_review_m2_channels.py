"""Regression tests for the M2 review of the channel registry
(`docs/reviews/m2-tools-channels-write-adapters.md`): M5, M6, M9, L1, L2, L3, L4.

Each test is named after the finding it reproduces and follows the reviewer's sequence.
"""

from __future__ import annotations

from collections.abc import Callable, Iterator
from typing import Any

import pytest
from sqlalchemy import Engine, select
from tests.execution.conftest import FlakyAudit
from tests.fakes.core import FakeAudit, FakePrincipals, make_principal

from ciso.common.clock import FixedClock
from ciso.common.db import create_db_engine
from ciso.common.enums import ActorType, AuditOutcome, Role
from ciso.common.errors import (
    AuthorizationError,
    Conflict,
    FailClosed,
    NotFound,
    ValidationFailed,
)
from ciso.common.protocols import AuditEvent, AuditReceipt
from ciso.common.schemas import canonical_json, sha256_hex
from ciso.execution import ChannelRecord, ChannelRegistry, ChannelStatus, is_outbox_name
from ciso.execution import channels as channels_module
from ciso.execution.tables import execution_channel

pytestmark = pytest.mark.broker

ADMIN = "human_admin"
ADMIN2 = "human_admin2"
AGENT = "agent_ciso"
PROPOSE = "execution.channel.propose"
APPROVE = "execution.channel.approve"
REVOKE = "execution.channel.revoke"


@pytest.fixture
def principals(principals: FakePrincipals) -> FakePrincipals:
    """The standard actors plus a second administrator."""
    principals.register(make_principal(ADMIN2, ActorType.HUMAN, Role.SECURITY_ADMIN))
    return principals


def approve(channels: ChannelRegistry, name: str = "sec_ops", actor: str = ADMIN) -> ChannelRecord:
    """Approve the proposal as it stands now: its target, version and purpose."""
    seen = channels.get(name)
    return channels.approve(
        actor, name, seen.target, version=seen.version, purpose_digest=seen.purpose_digest
    )


def row(engine: Engine, name: str = "sec_ops") -> Any:
    with engine.connect() as conn:
        found = conn.execute(
            select(execution_channel).where(execution_channel.c.channel == name)
        ).first()
        conn.rollback()
    return found


def outcomes(audit: FakeAudit, action: str) -> list[AuditOutcome]:
    return [event.outcome for event in audit.find(action)]


class HookedAudit(FakeAudit):
    """Runs `on(event)` inside `append`, before the event is recorded."""

    def __init__(self, clock: FixedClock) -> None:
        super().__init__(clock)
        self.on: Callable[[AuditEvent], None] | None = None

    def append(self, event: AuditEvent) -> AuditReceipt:
        if self.on is not None:
            self.on(event)
        return super().append(event)


@pytest.fixture
def hooked(clock: FixedClock) -> HookedAudit:
    return HookedAudit(clock)


@pytest.fixture
def hooked_channels(
    engine: Engine, clock: FixedClock, hooked: HookedAudit, principals: FakePrincipals
) -> ChannelRegistry:
    return ChannelRegistry(engine, clock, hooked, principals)


def is_result(event: AuditEvent, action: str) -> bool:
    return event.action == action and event.outcome is AuditOutcome.SUCCESS


# --- M5: an approval is for the proposal the administrator saw ---------------------------


def test_m5_approving_what_was_seen_before_a_reproposal_is_refused(
    channels: ChannelRegistry, audit: FakeAudit
) -> None:
    """The reviewer's sequence: A reviews v1, B revokes, the agent re-proposes the same
    name and target with another purpose, A approves what he reviewed."""
    seen = channels.propose(AGENT, "sec_ops", "tickets", "weekly ticket drafts")
    channels.revoke(ADMIN2, "sec_ops", "tidy up")
    channels.propose(AGENT, "sec_ops", "tickets", "all raw findings incl. restricted data")
    with pytest.raises(Conflict, match="version"):
        channels.approve(
            ADMIN, "sec_ops", "tickets", version=seen.version, purpose_digest=seen.purpose_digest
        )
    assert channels.is_approved("sec_ops") is False
    assert channels.get("sec_ops").status is ChannelStatus.PROPOSED
    assert outcomes(audit, APPROVE) == [AuditOutcome.ATTEMPT, AuditOutcome.FAILED]


def test_m5_approval_must_carry_the_digest_of_the_purpose_shown(
    channels: ChannelRegistry,
) -> None:
    seen = channels.propose(AGENT, "sec_ops", "tickets", "weekly ticket drafts")
    other = channels_module.purpose_digest("some other purpose")
    for digest in (other, "", "not-a-digest", seen.purpose):
        with pytest.raises(Conflict, match="purpose"):
            channels.approve(
                ADMIN, "sec_ops", "tickets", version=seen.version, purpose_digest=digest
            )
    assert channels.is_approved("sec_ops") is False
    assert seen.purpose_digest == sha256_hex("weekly ticket drafts")
    assert channels_module.purpose_digest("weekly ticket drafts") == seen.purpose_digest


@pytest.mark.parametrize("version", [True, "1", 1.0, None])
def test_m5_a_version_must_be_a_real_integer(channels: ChannelRegistry, version: Any) -> None:
    seen = channels.propose(AGENT, "sec_ops", "tickets", "weekly ticket drafts")
    assert seen.version == 1
    with pytest.raises(Conflict, match="version"):
        channels.approve(
            ADMIN, "sec_ops", "tickets", version=version, purpose_digest=seen.purpose_digest
        )
    assert channels.is_approved("sec_ops") is False


def test_m5_approval_must_carry_the_target_shown(channels: ChannelRegistry) -> None:
    seen = channels.propose(AGENT, "sec_ops", "tickets", "weekly ticket drafts")
    with pytest.raises(Conflict, match="target"):
        channels.approve(
            ADMIN,
            "sec_ops",
            "elsewhere",
            version=seen.version,
            purpose_digest=seen.purpose_digest,
        )
    assert channels.is_approved("sec_ops") is False


def test_m5_a_matching_approval_succeeds_and_the_audit_record_says_what_was_approved(
    channels: ChannelRegistry, audit: FakeAudit
) -> None:
    seen = channels.propose(AGENT, "sec_ops", "tickets", "weekly ticket drafts")
    record = approve(channels)
    assert record.status is ChannelStatus.APPROVED
    assert channels.is_approved("sec_ops") is True
    done = audit.find(APPROVE)[-1]
    assert done.outcome is AuditOutcome.SUCCESS
    assert done.details["approved_version"] == seen.version
    assert done.details["purpose_sha256"] == seen.purpose_digest
    assert done.details["target"] == "tickets"


def test_m5_every_reproposal_has_a_new_version(channels: ChannelRegistry) -> None:
    first = channels.propose(AGENT, "sec_ops", "tickets", "weekly ticket drafts")
    channels.revoke(ADMIN, "sec_ops", "no")
    second = channels.propose(AGENT, "sec_ops", "tickets", "weekly ticket drafts")
    assert second.version > first.version


# --- M6: not usable before the approval is on the audit log --------------------------------


def test_m6_a_channel_is_not_usable_while_its_approval_is_being_audited(
    hooked_channels: ChannelRegistry, hooked: HookedAudit, engine: Engine
) -> None:
    during: list[Any] = []

    def peek(event: AuditEvent) -> None:
        if is_result(event, APPROVE):
            during.append((hooked_channels.is_approved("sec_ops"), str(row(engine).status)))
            with pytest.raises(AuthorizationError):
                hooked_channels.approved_target("sec_ops")

    hooked_channels.propose(AGENT, "sec_ops", "tickets", "ticket drafts")
    hooked.on = peek
    record = approve(hooked_channels)
    assert during == [(False, "approving")]
    assert record.status is ChannelStatus.APPROVED
    assert hooked_channels.is_approved("sec_ops") is True
    receipt_ids = {str(row(engine).approval_audit_ref)}
    assert record.approval_audit_ref in receipt_ids
    assert record.approval_audit_ref.startswith("aud_")


def test_m6_a_crash_before_the_audit_id_is_stored_leaves_the_channel_not_approved(
    hooked_channels: ChannelRegistry, hooked: HookedAudit, engine: Engine
) -> None:
    def die(event: AuditEvent) -> None:
        if is_result(event, APPROVE):
            raise SystemExit("the process ends here")

    hooked_channels.propose(AGENT, "sec_ops", "tickets", "ticket drafts")
    hooked.on = die
    with pytest.raises(SystemExit):
        approve(hooked_channels)
    hooked.on = None
    assert hooked_channels.is_approved("sec_ops") is False
    with pytest.raises(AuthorizationError):
        hooked_channels.approved_target("sec_ops")
    left = hooked_channels.get("sec_ops")
    assert left.status is ChannelStatus.APPROVING
    assert left.approval_audit_ref == ""
    assert outcomes(hooked, APPROVE) == [AuditOutcome.ATTEMPT]
    # nothing is stuck: an administrator can decide again, or withdraw it
    assert approve(hooked_channels).status is ChannelStatus.APPROVED
    assert hooked_channels.is_approved("sec_ops") is True


def test_m6_an_interrupted_approval_can_be_revoked(
    hooked_channels: ChannelRegistry, hooked: HookedAudit
) -> None:
    def die(event: AuditEvent) -> None:
        if is_result(event, APPROVE):
            raise SystemExit("the process ends here")

    hooked_channels.propose(AGENT, "sec_ops", "tickets", "ticket drafts")
    hooked.on = die
    with pytest.raises(SystemExit):
        approve(hooked_channels)
    hooked.on = None
    assert hooked_channels.revoke(ADMIN, "sec_ops", "never mind").status is ChannelStatus.REVOKED
    assert hooked_channels.is_approved("sec_ops") is False


def test_m6_an_approved_row_without_an_audit_id_is_not_approved(
    channels: ChannelRegistry, engine: Engine
) -> None:
    """`is_approved` needs both the status and the stored id of the approval's record."""
    channels.propose(AGENT, "sec_ops", "tickets", "ticket drafts")
    approve(channels)
    assert channels.is_approved("sec_ops") is True
    with engine.begin() as conn:
        conn.execute(execution_channel.update().values(approval_audit_ref=""))
    assert channels.is_approved("sec_ops") is False
    with pytest.raises(AuthorizationError):
        channels.approved_target("sec_ops")


def test_m6_an_approving_row_with_an_audit_id_is_not_approved(
    channels: ChannelRegistry, engine: Engine
) -> None:
    channels.propose(AGENT, "sec_ops", "tickets", "ticket drafts")
    approve(channels)
    with engine.begin() as conn:
        conn.execute(execution_channel.update().values(status="approving"))
    assert channels.is_approved("sec_ops") is False


def test_m6_an_undo_that_changed_nothing_says_so(
    engine: Engine, clock: FixedClock, hooked: HookedAudit, principals: FakePrincipals
) -> None:
    """The reviewer's sequence: the proposal's result cannot be audited, and before the
    undo runs another session has approved the row. Nothing was undone; say that."""
    channels = ChannelRegistry(engine, clock, hooked, principals)
    other = ChannelRegistry(engine, clock, FakeAudit(clock), principals)

    def race(event: AuditEvent) -> None:
        if is_result(event, PROPOSE):
            approve(other)
            raise FailClosed("audit path unavailable")

    hooked.on = race
    with pytest.raises(FailClosed, match="could NOT be undone") as caught:
        channels.propose(AGENT, "sec_ops", "tickets", "ticket drafts")
    assert "was undone" not in str(caught.value)
    hooked.on = None
    assert channels.is_approved("sec_ops") is True  # the other session's approval stands
    assert channels.get("sec_ops").decided_by == ADMIN


def test_m6_an_undo_that_did_put_the_row_back_says_that(
    engine: Engine, clock: FixedClock, flaky_audit: FlakyAudit, principals: FakePrincipals
) -> None:
    channels = ChannelRegistry(engine, clock, flaky_audit, principals)
    flaky_audit.fail_outcomes = {AuditOutcome.SUCCESS}
    with pytest.raises(FailClosed, match="the change was undone"):
        channels.propose(AGENT, "sec_ops", "tickets", "ticket drafts")
    assert row(engine) is None
    flaky_audit.fail_outcomes = set()
    channels.propose(AGENT, "sec_ops", "tickets", "ticket drafts")
    before = channels.get("sec_ops")
    flaky_audit.fail_outcomes = {AuditOutcome.SUCCESS}
    with pytest.raises(FailClosed, match="the change was undone"):
        approve(channels)
    after = channels.get("sec_ops")
    assert after.status is ChannelStatus.PROPOSED
    assert after.decided_by == ""
    assert after.version > before.version
    assert channels.is_approved("sec_ops") is False


def test_m6_an_approval_whose_row_changed_before_it_was_finished_is_not_reported_as_done(
    engine: Engine, clock: FixedClock, hooked: HookedAudit, principals: FakePrincipals
) -> None:
    channels = ChannelRegistry(engine, clock, hooked, principals)
    other = ChannelRegistry(engine, clock, FakeAudit(clock), principals)

    def race(event: AuditEvent) -> None:
        if is_result(event, APPROVE):
            other.revoke(ADMIN2, "sec_ops", "withdrawn meanwhile")

    channels.propose(AGENT, "sec_ops", "tickets", "ticket drafts")
    hooked.on = race
    with pytest.raises(Conflict, match="NOT approved"):
        approve(channels)
    hooked.on = None
    assert channels.is_approved("sec_ops") is False
    assert channels.get("sec_ops").status is ChannelStatus.REVOKED
    assert outcomes(hooked, APPROVE) == [
        AuditOutcome.ATTEMPT,
        AuditOutcome.SUCCESS,
        AuditOutcome.FAILED,
    ]
    assert hooked.find(APPROVE)[-1].details["problem"] == "approval_not_completed"


@pytest.mark.parametrize(
    ("tamper", "left"),
    [
        pytest.param({"version": 99}, "approving", id="another_version"),
        pytest.param({"status": "proposed"}, "proposed", id="another_status"),
    ],
)
def test_m6_the_second_step_touches_only_the_approving_row_this_call_wrote(
    hooked_channels: ChannelRegistry,
    hooked: HookedAudit,
    engine: Engine,
    tamper: dict[str, Any],
    left: str,
) -> None:
    """Each condition of the second step on its own: the row keeps its version but is no
    longer `approving`, or is still `approving` at another version."""

    def change(event: AuditEvent) -> None:
        if is_result(event, APPROVE):
            with engine.begin() as conn:
                conn.execute(execution_channel.update().values(**tamper))

    hooked_channels.propose(AGENT, "sec_ops", "tickets", "ticket drafts")
    hooked.on = change
    with pytest.raises(Conflict, match="NOT approved"):
        approve(hooked_channels)
    hooked.on = None
    assert str(row(engine).status) == left
    assert str(row(engine).approval_audit_ref) == ""
    assert hooked_channels.is_approved("sec_ops") is False


class NoIdAudit(FakeAudit):
    """An audit sink that accepts a record and hands back a receipt with no id."""

    def append(self, event: AuditEvent) -> AuditReceipt:
        receipt = super().append(event)
        if event.action == APPROVE and event.outcome is AuditOutcome.SUCCESS:
            return receipt.model_copy(update={"record_id": ""})
        return receipt


def test_m6_an_approval_without_an_audit_record_id_is_not_approved(
    engine: Engine, clock: FixedClock, principals: FakePrincipals
) -> None:
    channels = ChannelRegistry(engine, clock, NoIdAudit(clock), principals)
    channels.propose(AGENT, "sec_ops", "tickets", "ticket drafts")
    with pytest.raises(FailClosed, match="NOT approved"):
        approve(channels)
    assert channels.is_approved("sec_ops") is False
    assert channels.get("sec_ops").status is ChannelStatus.APPROVING


def test_m6_an_approval_that_cannot_be_finished_fails_closed(
    channels: ChannelRegistry, audit: FakeAudit, monkeypatch: pytest.MonkeyPatch
) -> None:
    def broken(self: ChannelRegistry, *args: Any) -> bool:
        raise RuntimeError("database went away")

    channels.propose(AGENT, "sec_ops", "tickets", "ticket drafts")
    monkeypatch.setattr(ChannelRegistry, "_complete_approval", broken)
    with pytest.raises(FailClosed, match="NOT approved"):
        approve(channels)
    assert channels.is_approved("sec_ops") is False
    assert channels.get("sec_ops").status is ChannelStatus.APPROVING
    assert outcomes(audit, APPROVE)[-1] is AuditOutcome.FAILED


# --- M9: guards that had no test able to fail ---------------------------------------------


def test_m9_the_undo_touches_only_the_row_this_call_wrote(
    engine: Engine, clock: FixedClock, hooked: HookedAudit, principals: FakePrincipals
) -> None:
    """The version condition in `_restore`: without it the undo would delete a row that
    somebody else has changed since."""
    channels = ChannelRegistry(engine, clock, hooked, principals)

    def touch(event: AuditEvent) -> None:
        if is_result(event, PROPOSE):
            with engine.begin() as conn:
                conn.execute(execution_channel.update().values(version=7, purpose="changed"))
            raise FailClosed("audit path unavailable")

    hooked.on = touch
    with pytest.raises(FailClosed, match="could NOT be undone"):
        channels.propose(AGENT, "sec_ops", "tickets", "ticket drafts")
    left = row(engine)
    assert left is not None
    assert (left.version, left.purpose) == (7, "changed")


def test_m9_an_update_refuses_a_row_that_changed_since_it_was_read(
    channels: ChannelRegistry, engine: Engine
) -> None:
    """The version condition in `_update`, and that a write matching no row is an error."""
    channels.propose(AGENT, "sec_ops", "tickets", "ticket drafts")
    stale = row(engine)
    with engine.begin() as conn:
        conn.execute(execution_channel.update().values(version=stale.version + 1))
    with pytest.raises(Conflict, match="changed"), engine.begin() as conn:
        ChannelRegistry._update(conn, stale, {"purpose": "overwritten"})
    assert row(engine).purpose == "ticket drafts"
    fresh = row(engine)
    with engine.begin() as conn:
        ChannelRegistry._update(conn, fresh, {"purpose": "written"})
    assert (row(engine).purpose, row(engine).version) == ("written", fresh.version + 1)


def test_m9_text_longer_than_the_bound_is_refused(channels: ChannelRegistry) -> None:
    limit = channels_module.MAX_TEXT
    assert limit == 500
    with pytest.raises(ValidationFailed):
        channels.propose(AGENT, "sec_ops", "tickets", "p" * (limit + 1))
    assert channels.records() == ()
    assert channels.propose(AGENT, "sec_ops", "tickets", "p" * limit).purpose == "p" * limit
    with pytest.raises(ValidationFailed):
        channels.revoke(ADMIN, "sec_ops", "r" * (limit + 1))
    assert channels.get("sec_ops").status is ChannelStatus.PROPOSED


def test_m9_an_undo_that_raises_is_reported_as_not_undone(
    engine: Engine,
    clock: FixedClock,
    flaky_audit: FlakyAudit,
    principals: FakePrincipals,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def broken(self: ChannelRegistry, *args: Any) -> bool:
        raise RuntimeError("database went away")

    channels = ChannelRegistry(engine, clock, flaky_audit, principals)
    monkeypatch.setattr(ChannelRegistry, "_restore", broken)
    flaky_audit.fail_outcomes = {AuditOutcome.SUCCESS}
    with pytest.raises(FailClosed, match="could NOT be undone"):
        channels.propose(AGENT, "sec_ops", "tickets", "ticket drafts")
    assert row(engine) is not None


def test_m9_a_database_failure_during_the_change_is_audited_and_fails_closed(
    channels: ChannelRegistry, audit: FakeAudit, monkeypatch: pytest.MonkeyPatch
) -> None:
    def broken(self: ChannelRegistry, *args: Any) -> Any:
        raise RuntimeError("database went away")

    monkeypatch.setattr(ChannelRegistry, "_transact", broken)
    with pytest.raises(FailClosed, match="could not be changed"):
        channels.propose(AGENT, "sec_ops", "tickets", "ticket drafts")
    assert outcomes(audit, PROPOSE) == [AuditOutcome.ATTEMPT, AuditOutcome.FAILED]
    assert audit.find(PROPOSE)[-1].details["error"] == "RuntimeError"


@pytest.fixture
def bare_engine() -> Iterator[Engine]:
    """A database with no tables: every read fails."""
    eng = create_db_engine(None)
    yield eng
    eng.dispose()


def test_m9_reading_records_fails_closed_when_the_database_cannot_be_read(
    bare_engine: Engine, clock: FixedClock, audit: FakeAudit, principals: FakePrincipals
) -> None:
    channels = ChannelRegistry(bare_engine, clock, audit, principals)
    with pytest.raises(FailClosed):
        channels.records()
    with pytest.raises(FailClosed):
        channels.get("sec_ops")


# --- L1: device names ------------------------------------------------------------------------


@pytest.mark.parametrize("name", ["com0", "lpt0", "com9", "lpt5", "nul", "con", "prn", "aux"])
def test_l1_a_device_name_is_not_an_outbox_name(channels: ChannelRegistry, name: str) -> None:
    assert is_outbox_name(name) is False
    with pytest.raises(ValidationFailed):
        channels.propose(AGENT, "sec_ops", name, "ticket drafts")
    assert channels.records() == ()


@pytest.mark.parametrize("name", ["nul", "con", "com1", "lpt0", "com0", "aux"])
def test_l1_a_device_name_is_not_a_channel_name(channels: ChannelRegistry, name: str) -> None:
    with pytest.raises(ValidationFailed):
        channels.propose(AGENT, name, "tickets", "ticket drafts")
    assert channels.records() == ()
    assert channels.is_approved(name) is False


@pytest.mark.parametrize(
    "name", ["NUL", "Con", "COM1", "LPT0", "com\xb9", "COM\xb2", "lpt\xb3", "Lpt\xb9"]
)
def test_l1_device_names_are_matched_whatever_the_case_or_digit_form(name: str) -> None:
    assert channels_module.is_device_name(name) is True


@pytest.mark.parametrize("name", ["tickets", "com", "com10", "console", "null", "lpt_1", "aux1"])
def test_l1_ordinary_names_are_not_device_names(name: str) -> None:
    assert channels_module.is_device_name(name) is False
    assert is_outbox_name(name) is True


# --- L2: separation of duties, and a bound on open proposals -----------------------------------


def test_l2_the_proposer_may_not_approve_their_own_channel(
    channels: ChannelRegistry, audit: FakeAudit
) -> None:
    channels.propose(ADMIN, "sec_ops", "tickets", "mine")
    with pytest.raises(channels_module.ChannelDenied) as caught:
        approve(channels, actor=ADMIN)
    assert caught.value.code is channels_module.ChannelRefusal.SELF_APPROVAL
    assert isinstance(caught.value, AuthorizationError)
    assert channels.is_approved("sec_ops") is False
    assert channels.get("sec_ops").status is ChannelStatus.PROPOSED
    assert outcomes(audit, APPROVE) == [AuditOutcome.ATTEMPT, AuditOutcome.DENIED]
    assert audit.find(APPROVE)[-1].details["reason"] == "self_approval"
    # another administrator may
    record = approve(channels, actor=ADMIN2)
    assert (record.proposed_by, record.decided_by) == (ADMIN, ADMIN2)
    assert channels.is_approved("sec_ops") is True


def test_l2_open_proposals_per_proposer_are_capped(
    channels: ChannelRegistry, audit: FakeAudit
) -> None:
    cap = channels_module.MAX_OPEN_PROPOSALS_PER_PROPOSER
    assert cap == 20
    for index in range(cap):
        channels.propose(AGENT, f"ch_{index}", "tickets", "p")
    with pytest.raises(channels_module.ChannelDenied) as caught:
        channels.propose(AGENT, "one_more", "tickets", "p")
    assert caught.value.code is channels_module.ChannelRefusal.TOO_MANY_OPEN_PROPOSALS
    assert len(channels.records()) == cap
    assert audit.find(PROPOSE)[-1].outcome is AuditOutcome.DENIED
    assert audit.find(PROPOSE)[-1].details["reason"] == "too_many_open_proposals"
    # the bound is per proposer, and a decided proposal no longer counts
    assert channels.propose("human_emp", "one_more", "tickets", "p").proposed_by == "human_emp"
    approve(channels, "ch_0")
    channels.revoke(ADMIN, "ch_1", "no")
    assert channels.propose(AGENT, "after_approve", "tickets", "p").version == 1
    assert channels.propose(AGENT, "after_revoke", "tickets", "p").version == 1
    with pytest.raises(channels_module.ChannelDenied):
        channels.propose(AGENT, "over_again", "tickets", "p")


def test_l2_reproposing_a_revoked_name_counts_against_the_cap(channels: ChannelRegistry) -> None:
    cap = channels_module.MAX_OPEN_PROPOSALS_PER_PROPOSER
    channels.propose("human_emp", "old", "tickets", "p")
    channels.revoke(ADMIN, "old", "no")
    for index in range(cap):
        channels.propose(AGENT, f"ch_{index}", "tickets", "p")
    with pytest.raises(channels_module.ChannelDenied):
        channels.propose(AGENT, "old", "tickets", "p")
    assert channels.get("old").status is ChannelStatus.REVOKED


# --- L3: a refused name or target leaves a trace -------------------------------------------------


@pytest.mark.parametrize(
    "target", ["https://evil.example.test/hook", "soc@example.test", "../../x", "nul", ""]
)
def test_l3_a_refused_target_is_audited_without_the_value(
    channels: ChannelRegistry, audit: FakeAudit, target: str
) -> None:
    with pytest.raises(channels_module.ChannelInvalid) as caught:
        channels.propose(AGENT, "sec_ops", target, "ticket drafts")
    assert caught.value.code is channels_module.ChannelRefusal.BAD_TARGET
    assert isinstance(caught.value, ValidationFailed)
    assert channels.records() == ()
    assert len(audit.events) == 1
    event = audit.events[0]
    assert (event.action, event.outcome, event.actor_id) == (PROPOSE, AuditOutcome.DENIED, AGENT)
    assert event.target == "channel:sec_ops"
    assert event.details == {"reason": "bad_target", "value_sha256": sha256_hex(target)}
    if target:
        assert target not in canonical_json(event)


@pytest.mark.parametrize("name", ["Sec Ops", "a/b", "../x", "sec_ops\n", "nul"])
def test_l3_a_refused_channel_name_is_audited_without_the_value(
    channels: ChannelRegistry, audit: FakeAudit, name: str
) -> None:
    attempts: list[tuple[str, Callable[[], Any]]] = [
        (PROPOSE, lambda: channels.propose(AGENT, name, "tickets", "ticket drafts")),
        (
            APPROVE,
            lambda: channels.approve(ADMIN, name, "tickets", version=1, purpose_digest="0" * 64),
        ),
        (REVOKE, lambda: channels.revoke(ADMIN, name, "reason")),
    ]
    for action, attempt in attempts:
        with pytest.raises(channels_module.ChannelInvalid) as caught:
            attempt()
        assert caught.value.code is channels_module.ChannelRefusal.BAD_CHANNEL_NAME
        event = audit.find(action)[-1]
        assert event.outcome is AuditOutcome.DENIED
        assert event.target == "channel:(invalid)"
        assert event.details == {"reason": "bad_channel_name", "value_sha256": sha256_hex(name)}
        assert name not in canonical_json(event)
    assert len(audit.events) == 3
    assert channels.records() == ()


def test_l3_refused_text_is_audited_without_the_value(
    channels: ChannelRegistry, audit: FakeAudit
) -> None:
    bad = "ok\x1b[2K APPROVED by human_admin"
    with pytest.raises(channels_module.ChannelInvalid) as caught:
        channels.propose(AGENT, "sec_ops", "tickets", bad)
    assert caught.value.code is channels_module.ChannelRefusal.BAD_TEXT
    event = audit.find(PROPOSE)[-1]
    assert event.outcome is AuditOutcome.DENIED
    assert event.details == {"reason": "bad_text", "value_sha256": sha256_hex(bad)}
    assert "APPROVED" not in canonical_json(event)


def test_l3_the_actor_is_resolved_before_the_value_is_judged(
    channels: ChannelRegistry, audit: FakeAudit, principals: FakePrincipals
) -> None:
    """An unknown actor is refused as unknown, in its own name as ANONYMOUS."""
    with pytest.raises(AuthorizationError):
        channels.propose("ghost", "sec_ops", "https://evil.example.test", "p")
    assert principals.lookups == ["ghost"]
    assert [e.actor_type for e in audit.events] == [ActorType.ANONYMOUS]
    assert "bad_target" not in canonical_json(audit.events[0])


def test_l3_a_denial_that_cannot_be_audited_is_still_a_refusal(
    engine: Engine, clock: FixedClock, flaky_audit: FlakyAudit, principals: FakePrincipals
) -> None:
    channels = ChannelRegistry(engine, clock, flaky_audit, principals)
    flaky_audit.fail_outcomes = {AuditOutcome.DENIED}
    with pytest.raises(channels_module.ChannelInvalid):
        channels.propose(AGENT, "sec_ops", "soc@example.test", "p")
    assert channels.records() == ()


# --- L4: text shown to an administrator ---------------------------------------------------------

HOSTILE_TEXT = [
    pytest.param("ok\nAPPROVED by human_admin", id="newline"),
    pytest.param("ok\x1b[2K", id="escape"),
    pytest.param("ok\x00", id="nul"),
    pytest.param("ok\u202eAPPROVED", id="right_to_left_override"),
    pytest.param("ok\u2066x\u2069", id="isolate"),
    pytest.param("ok\u200bhidden", id="zero_width_space"),
    pytest.param("ok\u2028next", id="line_separator"),
    pytest.param("ok\u2029next", id="paragraph_separator"),
    pytest.param("tab\there", id="tab"),
    pytest.param("ok\x7f", id="delete"),
]


@pytest.mark.parametrize("text", HOSTILE_TEXT)
def test_l4_control_and_direction_characters_are_refused_in_a_purpose(
    channels: ChannelRegistry, text: str
) -> None:
    with pytest.raises(ValidationFailed):
        channels.propose(AGENT, "sec_ops", "tickets", text)
    assert channels.records() == ()


@pytest.mark.parametrize("text", HOSTILE_TEXT)
def test_l4_control_and_direction_characters_are_refused_in_a_reason(
    channels: ChannelRegistry, text: str
) -> None:
    channels.propose(AGENT, "sec_ops", "tickets", "ticket drafts")
    with pytest.raises(ValidationFailed):
        channels.revoke(ADMIN, "sec_ops", text)
    assert channels.get("sec_ops").status is ChannelStatus.PROPOSED


def test_l4_ordinary_text_in_any_script_is_kept(channels: ChannelRegistry) -> None:
    purpose = "Tickets f\xfcr das B\xfcro: \u7968 (weekly), caf\xe9 - 100%"
    assert channels.propose(AGENT, "sec_ops", "tickets", f"  {purpose}  ").purpose == purpose
    assert channels.revoke(ADMIN, "sec_ops", purpose).revoke_reason == purpose


def test_m9_a_missing_channel_is_reported_as_missing(channels: ChannelRegistry) -> None:
    with pytest.raises(NotFound):
        channels.approve(ADMIN, "sec_ops", "tickets", version=1, purpose_digest="0" * 64)
