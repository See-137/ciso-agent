"""Channel registry (plan gap G13): who may approve, what a target may be, what is audited.

Blueprint 9.1 L2 "channel-specific authorization"; OD-13: targets are local outboxes only.
"""

from __future__ import annotations

from collections.abc import Iterator

import pytest
from sqlalchemy import Engine, select
from tests.execution.conftest import FlakyAudit, LockSpy
from tests.fakes.core import FakeAudit, FakePrincipals, make_principal

from ciso.common.clock import FixedClock
from ciso.common.db import create_db_engine, registered_schemas
from ciso.common.enums import ActorType, AuditOutcome, Role
from ciso.common.errors import (
    AuthorizationError,
    Conflict,
    FailClosed,
    NotFound,
    ValidationFailed,
)
from ciso.common.principal import Principal, RoleGrant
from ciso.execution import ChannelRecord, ChannelRegistry, ChannelStatus
from ciso.execution.tables import execution_channel

pytestmark = pytest.mark.broker

ADMIN = "human_admin"
APPROVE = "execution.channel.approve"
REVOKE = "execution.channel.revoke"
PROPOSE = "execution.channel.propose"


def approve_as(
    channels: ChannelRegistry, actor_id: str, name: str = "sec_ops", target: str = "tickets"
) -> ChannelRecord:
    """Approve `target` at the version and purpose stored now, as an administrator who
    has just read the record would."""
    try:
        seen = channels.get(name)
    except NotFound:
        return channels.approve(actor_id, name, target, version=1, purpose_digest="0" * 64)
    return channels.approve(
        actor_id, name, target, version=seen.version, purpose_digest=seen.purpose_digest
    )


def approved(channels: ChannelRegistry, name: str = "sec_ops", target: str = "tickets") -> None:
    channels.propose("agent_ciso", name, target, "ticket drafts")
    approve_as(channels, ADMIN, name, target)


def status_in_db(engine: Engine, name: str) -> str | None:
    with engine.connect() as conn:
        row = conn.execute(
            select(execution_channel.c.status).where(execution_channel.c.channel == name)
        ).first()
        conn.rollback()
    return None if row is None else str(row.status)


def outcomes(audit: FakeAudit, action: str) -> list[AuditOutcome]:
    return [event.outcome for event in audit.find(action)]


class TestLifecycle:
    def test_schema_is_registered(self) -> None:
        assert registered_schemas()["execution"] == 1

    def test_proposed_is_not_approved(self, channels: ChannelRegistry) -> None:
        record = channels.propose("agent_ciso", "sec_ops", "tickets", "ticket drafts")
        assert record.status is ChannelStatus.PROPOSED
        assert record.version == 1
        assert channels.is_approved("sec_ops") is False

    def test_admin_approval_makes_it_approved(
        self, channels: ChannelRegistry, clock: FixedClock
    ) -> None:
        channels.propose("agent_ciso", "sec_ops", "tickets", "ticket drafts")
        record = approve_as(channels, ADMIN)
        assert record.status is ChannelStatus.APPROVED
        assert record.decided_by == ADMIN
        assert record.decided_at == clock.now()
        assert channels.is_approved("sec_ops") is True
        assert channels.approved_target("sec_ops") == "tickets"
        assert channels.get("sec_ops") == record
        assert [r.channel for r in channels.records()] == ["sec_ops"]

    def test_revoked_is_not_approved(self, channels: ChannelRegistry) -> None:
        approved(channels)
        record = channels.revoke(ADMIN, "sec_ops", "no longer used")
        assert record.status is ChannelStatus.REVOKED
        assert record.revoked_by == ADMIN
        assert channels.is_approved("sec_ops") is False
        with pytest.raises(AuthorizationError):
            channels.approved_target("sec_ops")

    def test_unknown_channel_is_not_approved(self, channels: ChannelRegistry) -> None:
        approved(channels)
        assert channels.is_approved("other") is False
        assert channels.is_approved("") is False
        assert channels.is_approved("sec_ops\n") is False
        assert channels.is_approved("SEC_OPS") is False
        with pytest.raises(NotFound):
            channels.get("other")

    def test_a_proposal_can_be_rejected_by_revoking_it(self, channels: ChannelRegistry) -> None:
        channels.propose("agent_ciso", "sec_ops", "tickets", "ticket drafts")
        assert channels.revoke(ADMIN, "sec_ops", "not wanted").status is ChannelStatus.REVOKED
        with pytest.raises(Conflict):
            approve_as(channels, ADMIN)
        assert channels.is_approved("sec_ops") is False

    def test_a_live_channel_cannot_be_proposed_again(self, channels: ChannelRegistry) -> None:
        approved(channels)
        with pytest.raises(Conflict):
            channels.propose("agent_ciso", "sec_ops", "elsewhere", "swap the target")
        assert channels.approved_target("sec_ops") == "tickets"

    def test_reproposing_a_revoked_channel_needs_a_fresh_approval(
        self, channels: ChannelRegistry
    ) -> None:
        approved(channels)
        channels.revoke(ADMIN, "sec_ops", "rotate")
        record = channels.propose("agent_ciso", "sec_ops", "elsewhere", "new outbox")
        assert record.status is ChannelStatus.PROPOSED
        assert record.decided_by == ""
        assert record.version == 5  # proposed, approving, approved, revoked, proposed
        assert channels.is_approved("sec_ops") is False

    def test_approval_binds_to_the_target_the_admin_saw(self, channels: ChannelRegistry) -> None:
        channels.propose("agent_ciso", "sec_ops", "tickets", "ticket drafts")
        with pytest.raises(Conflict):
            approve_as(channels, ADMIN, target="elsewhere")
        assert channels.is_approved("sec_ops") is False

    def test_approving_twice_or_approving_nothing_fails(self, channels: ChannelRegistry) -> None:
        with pytest.raises(NotFound):
            approve_as(channels, ADMIN)
        approved(channels)
        with pytest.raises(Conflict):
            approve_as(channels, ADMIN)
        channels.revoke(ADMIN, "sec_ops", "done")
        with pytest.raises(Conflict):
            channels.revoke(ADMIN, "sec_ops", "again")
        with pytest.raises(NotFound):
            channels.revoke(ADMIN, "nothing", "x")


class TestTargets:
    """OD-13: a target is the name of a local outbox and nothing else."""

    @pytest.mark.parametrize(
        "target",
        [
            pytest.param("https://hooks.example.test/T000/B000", id="url"),
            pytest.param("tickets.example.test", id="host"),
            pytest.param("10.0.0.5", id="address"),
            pytest.param("soc@example.test", id="email"),
            pytest.param("/var/spool/outbox", id="posix-path"),
            pytest.param("C:\\outbox", id="windows-path"),
            pytest.param("..\\outbox", id="relative-path"),
            pytest.param("outbox/../../etc", id="traversal"),
            pytest.param("file:outbox", id="scheme"),
            pytest.param("tickets\n", id="trailing-newline"),
            pytest.param("Tickets", id="upper-case"),
            pytest.param("nul", id="device-name"),
            pytest.param("com1", id="device-name-port"),
            pytest.param("", id="empty"),
            pytest.param("t" * 64, id="too-long"),
        ],
    )
    def test_anything_but_an_outbox_name_is_rejected(
        self, channels: ChannelRegistry, audit: FakeAudit, target: str
    ) -> None:
        with pytest.raises(ValidationFailed):
            channels.propose("agent_ciso", "sec_ops", target, "ticket drafts")
        assert channels.records() == ()
        # refused, and (review finding L3) the refusal leaves a trace without the value
        assert [(e.action, e.outcome) for e in audit.events] == [(PROPOSE, AuditOutcome.DENIED)]
        assert audit.events[0].details["reason"] == "bad_target"

    def test_an_outbox_name_is_accepted(self, channels: ChannelRegistry) -> None:
        record = channels.propose("agent_ciso", "sec_ops", "ticket_drafts_2", "ticket drafts")
        assert record.target == "ticket_drafts_2"

    @pytest.mark.parametrize("name", ["", "Sec", "sec ops", "sec.ops", "a/b", "sec_ops\n"])
    def test_channel_names_are_strict(self, channels: ChannelRegistry, name: str) -> None:
        with pytest.raises(ValidationFailed):
            channels.propose("agent_ciso", name, "tickets", "ticket drafts")

    def test_a_blank_purpose_or_reason_is_rejected(self, channels: ChannelRegistry) -> None:
        with pytest.raises(ValidationFailed):
            channels.propose("agent_ciso", "sec_ops", "tickets", "  ")
        approved(channels)
        with pytest.raises(ValidationFailed):
            channels.revoke(ADMIN, "sec_ops", "")
        assert channels.is_approved("sec_ops") is True

    def test_a_stored_target_that_is_not_an_outbox_is_never_approved(
        self, channels: ChannelRegistry, engine: Engine
    ) -> None:
        approved(channels)
        with engine.begin() as conn:
            conn.execute(execution_channel.update().values(target="https://example.test/hook"))
        assert channels.is_approved("sec_ops") is False
        with pytest.raises(AuthorizationError):
            channels.approved_target("sec_ops")

    def test_a_tampered_proposal_cannot_be_approved(
        self, channels: ChannelRegistry, engine: Engine
    ) -> None:
        channels.propose("agent_ciso", "sec_ops", "tickets", "ticket drafts")
        with engine.begin() as conn:
            conn.execute(execution_channel.update().values(target="soc@example.test"))
        with pytest.raises(Conflict):
            approve_as(channels, ADMIN, target="soc@example.test")
        assert channels.is_approved("sec_ops") is False


class TestWhoMayDecide:
    @pytest.mark.parametrize(
        "actor_id",
        ["agent_ciso", "svc_connector", "human_owner", "human_risk", "human_emp", "human_aud"],
    )
    def test_only_a_security_admin_approves(
        self, channels: ChannelRegistry, audit: FakeAudit, actor_id: str
    ) -> None:
        channels.propose("agent_ciso", "sec_ops", "tickets", "ticket drafts")
        with pytest.raises(AuthorizationError):
            approve_as(channels, actor_id)
        assert channels.is_approved("sec_ops") is False
        assert outcomes(audit, APPROVE) == [AuditOutcome.DENIED]
        assert audit.find(APPROVE)[0].actor_id == actor_id

    @pytest.mark.parametrize("actor_id", ["agent_ciso", "human_owner", "nobody"])
    def test_only_a_security_admin_revokes(
        self, channels: ChannelRegistry, audit: FakeAudit, actor_id: str
    ) -> None:
        approved(channels)
        with pytest.raises(AuthorizationError):
            channels.revoke(actor_id, "sec_ops", "because")
        assert channels.is_approved("sec_ops") is True
        assert outcomes(audit, REVOKE) == [AuditOutcome.DENIED]

    def test_unknown_or_disabled_actor_is_refused(
        self, channels: ChannelRegistry, principals: FakePrincipals, audit: FakeAudit
    ) -> None:
        channels.propose("agent_ciso", "sec_ops", "tickets", "ticket drafts")
        with pytest.raises(AuthorizationError):
            approve_as(channels, "ghost")
        principals.remove(ADMIN)  # disabled since the caller last looked
        with pytest.raises(AuthorizationError):
            approve_as(channels, ADMIN)
        assert channels.is_approved("sec_ops") is False
        assert audit.find(APPROVE)[0].actor_type is ActorType.ANONYMOUS

    def test_the_role_is_read_now_not_from_a_snapshot(
        self, channels: ChannelRegistry, principals: FakePrincipals
    ) -> None:
        channels.propose("agent_ciso", "sec_ops", "tickets", "ticket drafts")
        principals.register(make_principal(ADMIN, ActorType.HUMAN, Role.EMPLOYEE))
        with pytest.raises(AuthorizationError):
            approve_as(channels, ADMIN)
        assert principals.lookups[-1] == ADMIN
        principals.register(make_principal(ADMIN, ActorType.HUMAN, Role.SECURITY_ADMIN))
        assert approve_as(channels, ADMIN).status is ChannelStatus.APPROVED

    def test_a_non_human_holding_the_role_is_still_refused(
        self, channels: ChannelRegistry, principals: FakePrincipals
    ) -> None:
        forged = Principal.model_construct(
            actor_id="agent_ciso",
            actor_type=ActorType.AGENT,
            roles=frozenset({Role.SECURITY_ADMIN}),
            grants=(),
            display_name="",
            credential_issued_by="",
        )
        principals._known["agent_ciso"] = forged
        channels.propose("human_emp", "sec_ops", "tickets", "ticket drafts")
        with pytest.raises(AuthorizationError):
            approve_as(channels, "agent_ciso")
        assert channels.is_approved("sec_ops") is False

    def test_a_narrowed_admin_grant_does_not_reach_channels(
        self, channels: ChannelRegistry, principals: FakePrincipals
    ) -> None:
        grant = RoleGrant(role=Role.SECURITY_ADMIN, scope={"environment": frozenset({"staging"})})
        principals.register(
            make_principal(ADMIN, ActorType.HUMAN, Role.SECURITY_ADMIN, grants=(grant,))
        )
        channels.propose("agent_ciso", "sec_ops", "tickets", "ticket drafts")
        with pytest.raises(AuthorizationError):
            approve_as(channels, ADMIN)
        assert channels.is_approved("sec_ops") is False

    def test_a_resolver_answering_for_someone_else_is_refused(
        self, channels: ChannelRegistry, principals: FakePrincipals, admin: Principal
    ) -> None:
        principals._known["human_emp"] = admin
        channels.propose("agent_ciso", "sec_ops", "tickets", "ticket drafts")
        with pytest.raises(AuthorizationError):
            approve_as(channels, "human_emp")
        assert channels.is_approved("sec_ops") is False

    def test_identity_store_down_fails_closed(
        self, channels: ChannelRegistry, principals: FakePrincipals, audit: FakeAudit
    ) -> None:
        channels.propose("agent_ciso", "sec_ops", "tickets", "ticket drafts")
        principals.broken = True
        with pytest.raises(FailClosed):
            approve_as(channels, ADMIN)
        principals.broken = False
        assert channels.is_approved("sec_ops") is False
        assert outcomes(audit, APPROVE) == [AuditOutcome.DENIED]

    def test_an_anonymous_actor_cannot_propose(
        self, channels: ChannelRegistry, principals: FakePrincipals
    ) -> None:
        principals.register(make_principal("visitor", ActorType.ANONYMOUS))
        with pytest.raises(AuthorizationError):
            channels.propose("visitor", "sec_ops", "tickets", "ticket drafts")
        assert channels.records() == ()

    def test_an_unknown_actor_cannot_propose(
        self, channels: ChannelRegistry, audit: FakeAudit
    ) -> None:
        with pytest.raises(AuthorizationError):
            channels.propose("ghost", "sec_ops", "tickets", "ticket drafts")
        assert channels.records() == ()
        assert outcomes(audit, PROPOSE) == [AuditOutcome.DENIED]


class TestAudit:
    def test_every_change_is_attempt_then_result(
        self, channels: ChannelRegistry, audit: FakeAudit
    ) -> None:
        approved(channels)
        channels.revoke(ADMIN, "sec_ops", "rotate")
        assert [(e.action, e.outcome) for e in audit.events] == [
            (PROPOSE, AuditOutcome.ATTEMPT),
            (PROPOSE, AuditOutcome.SUCCESS),
            (APPROVE, AuditOutcome.ATTEMPT),
            (APPROVE, AuditOutcome.SUCCESS),
            (REVOKE, AuditOutcome.ATTEMPT),
            (REVOKE, AuditOutcome.SUCCESS),
        ]
        done = audit.find(APPROVE)[1]
        assert done.target == "channel:sec_ops"
        assert done.actor_id == ADMIN
        assert done.actor_type is ActorType.HUMAN
        assert done.details["target"] == "tickets"
        assert done.details["status"] == "approved"
        assert audit.find(REVOKE)[1].details["reason"] == "rotate"

    def test_the_attempt_is_written_before_the_row_changes(
        self, engine: Engine, clock: FixedClock, principals: FakePrincipals
    ) -> None:
        seen: list[tuple[AuditOutcome, str | None]] = []

        class Peek(FakeAudit):
            def append(self, event):  # type: ignore[no-untyped-def]
                seen.append((event.outcome, status_in_db(engine, "sec_ops")))
                return super().append(event)

        channels = ChannelRegistry(engine, clock, Peek(clock), principals)
        approved(channels)
        assert seen == [
            (AuditOutcome.ATTEMPT, None),
            (AuditOutcome.SUCCESS, "proposed"),
            (AuditOutcome.ATTEMPT, "proposed"),
            # not usable yet: the row turns `approved` only after this record exists
            (AuditOutcome.SUCCESS, "approving"),
        ]
        assert status_in_db(engine, "sec_ops") == "approved"

    def test_a_failed_change_is_audited_as_failed(
        self, channels: ChannelRegistry, audit: FakeAudit
    ) -> None:
        with pytest.raises(NotFound):
            approve_as(channels, ADMIN)
        assert outcomes(audit, APPROVE) == [AuditOutcome.ATTEMPT, AuditOutcome.FAILED]

    def test_no_attempt_record_no_change(
        self,
        engine: Engine,
        clock: FixedClock,
        flaky_audit: FlakyAudit,
        principals: FakePrincipals,
    ) -> None:
        channels = ChannelRegistry(engine, clock, flaky_audit, principals)
        flaky_audit.fail_outcomes = {AuditOutcome.ATTEMPT}
        with pytest.raises(FailClosed):
            channels.propose("agent_ciso", "sec_ops", "tickets", "ticket drafts")
        assert status_in_db(engine, "sec_ops") is None
        flaky_audit.fail_outcomes = set()
        channels.propose("agent_ciso", "sec_ops", "tickets", "ticket drafts")
        flaky_audit.fail_outcomes = {AuditOutcome.ATTEMPT}
        with pytest.raises(FailClosed):
            approve_as(channels, ADMIN)
        assert status_in_db(engine, "sec_ops") == "proposed"
        flaky_audit.fail_outcomes = set()
        approve_as(channels, ADMIN)
        flaky_audit.fail_outcomes = {AuditOutcome.ATTEMPT}
        with pytest.raises(FailClosed):
            channels.revoke(ADMIN, "sec_ops", "rotate")
        assert status_in_db(engine, "sec_ops") == "approved"

    def test_an_approval_whose_result_cannot_be_audited_is_undone(
        self,
        engine: Engine,
        clock: FixedClock,
        flaky_audit: FlakyAudit,
        principals: FakePrincipals,
    ) -> None:
        channels = ChannelRegistry(engine, clock, flaky_audit, principals)
        channels.propose("agent_ciso", "sec_ops", "tickets", "ticket drafts")
        flaky_audit.fail_outcomes = {AuditOutcome.SUCCESS}
        with pytest.raises(FailClosed):
            approve_as(channels, ADMIN)
        assert status_in_db(engine, "sec_ops") == "proposed"
        assert channels.is_approved("sec_ops") is False
        assert channels.get("sec_ops").decided_by == ""

    def test_a_proposal_whose_result_cannot_be_audited_is_undone(
        self,
        engine: Engine,
        clock: FixedClock,
        flaky_audit: FlakyAudit,
        principals: FakePrincipals,
    ) -> None:
        channels = ChannelRegistry(engine, clock, flaky_audit, principals)
        flaky_audit.fail_outcomes = {AuditOutcome.SUCCESS}
        with pytest.raises(FailClosed):
            channels.propose("agent_ciso", "sec_ops", "tickets", "ticket drafts")
        assert status_in_db(engine, "sec_ops") is None

    def test_a_revocation_stands_even_if_its_result_cannot_be_audited(
        self,
        engine: Engine,
        clock: FixedClock,
        flaky_audit: FlakyAudit,
        principals: FakePrincipals,
    ) -> None:
        channels = ChannelRegistry(engine, clock, flaky_audit, principals)
        approved(channels)
        flaky_audit.fail_outcomes = {AuditOutcome.SUCCESS}
        with pytest.raises(FailClosed):
            channels.revoke(ADMIN, "sec_ops", "rotate")
        assert status_in_db(engine, "sec_ops") == "revoked"
        assert channels.is_approved("sec_ops") is False

    def test_a_refusal_that_cannot_be_audited_is_still_a_refusal(
        self,
        engine: Engine,
        clock: FixedClock,
        flaky_audit: FlakyAudit,
        principals: FakePrincipals,
    ) -> None:
        channels = ChannelRegistry(engine, clock, flaky_audit, principals)
        channels.propose("agent_ciso", "sec_ops", "tickets", "ticket drafts")
        flaky_audit.fail_outcomes = {AuditOutcome.DENIED}
        with pytest.raises(AuthorizationError):
            approve_as(channels, "agent_ciso")
        assert status_in_db(engine, "sec_ops") == "proposed"

    def test_audit_is_never_written_inside_the_write_lock(
        self,
        engine: Engine,
        clock: FixedClock,
        lock_spy: LockSpy,
        principals: FakePrincipals,
    ) -> None:
        channels = ChannelRegistry(engine, clock, lock_spy, principals)
        approved(channels)
        channels.revoke(ADMIN, "sec_ops", "rotate")
        with pytest.raises(AuthorizationError):
            approve_as(channels, "agent_ciso")
        with pytest.raises(Conflict):
            approve_as(channels, ADMIN)
        assert lock_spy.appends_checked == 9
        assert lock_spy.writes_seen == 5  # an approval is two short transactions
        assert lock_spy.open_writes == 0


class TestReadFailures:
    @pytest.fixture
    def bare_engine(self) -> Iterator[Engine]:
        """A database with no tables: every read fails."""
        eng = create_db_engine(None)
        yield eng
        eng.dispose()

    def test_a_read_error_is_never_an_approval(
        self,
        bare_engine: Engine,
        clock: FixedClock,
        audit: FakeAudit,
        principals: FakePrincipals,
    ) -> None:
        channels = ChannelRegistry(bare_engine, clock, audit, principals)
        with pytest.raises(FailClosed):
            channels.is_approved("sec_ops")
        with pytest.raises(FailClosed):
            channels.approved_target("sec_ops")

    def test_an_unknown_stored_status_is_not_approved(
        self, channels: ChannelRegistry, engine: Engine
    ) -> None:
        approved(channels)
        with engine.begin() as conn:
            conn.execute(execution_channel.update().values(status="APPROVED "))
        assert channels.is_approved("sec_ops") is False
