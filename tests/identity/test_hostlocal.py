"""Host-local bootstrap and admin token recovery (review H3, L5; ADR writer finding 2)."""

from __future__ import annotations

from datetime import timedelta

import pytest
from sqlalchemy import Engine, delete, select
from tests.identity.conftest import FAST_SCRYPT, MAX_TTL, SelectiveAudit

import ciso.identity.tables as t
from ciso.common.clock import FixedClock
from ciso.common.enums import ActorType, AuditOutcome, Role
from ciso.common.errors import (
    AuthenticationError,
    AuthorizationError,
    Conflict,
    FailClosed,
    ValidationFailed,
)
from ciso.common.principal import Principal
from ciso.identity.authn import Authenticator
from ciso.identity.hostlocal import BootstrapResult, HostLocalAdmin
from ciso.identity.service import IdentityService

pytestmark = pytest.mark.policy

A, S, D = AuditOutcome.ATTEMPT, AuditOutcome.SUCCESS, AuditOutcome.DENIED


def _second_admin(identity: IdentityService, admin: Principal) -> str:
    other = identity.create_actor(admin, ActorType.HUMAN, "Second Admin").id
    identity.assign_role(admin, other, Role.SECURITY_ADMIN)
    return other


class TestBootstrap:
    def test_bootstrap_once_only(
        self,
        hostlocal: HostLocalAdmin,
        authn: Authenticator,
        identity: IdentityService,
        audit: SelectiveAudit,
    ) -> None:
        result = hostlocal.bootstrap_first_admin("First Admin")
        principal = authn.authenticate(result.token.token)
        assert principal.actor_id == result.actor.id
        assert principal.roles == frozenset({Role.SECURITY_ADMIN})
        assert principal.is_human
        assert principal.credential_issued_by == "host_local"
        with pytest.raises(Conflict):
            hostlocal.bootstrap_first_admin("Second Admin")
        assert [e.outcome for e in audit.find("identity.bootstrap")] == [A, S, A, D]
        assert len(identity.list_assignments(role=Role.SECURITY_ADMIN)) == 1

    def test_bootstrap_needs_max_ttl(
        self,
        engine: Engine,
        clock: FixedClock,
        audit: SelectiveAudit,
        identity: IdentityService,
    ) -> None:
        closed = Authenticator(
            engine, clock, audit, identity, max_token_ttl=None, scrypt=FAST_SCRYPT
        )
        with pytest.raises(FailClosed):
            HostLocalAdmin(engine, clock, audit, closed.minter).bootstrap_first_admin("Admin")
        assert identity.list_assignments(role=Role.SECURITY_ADMIN) == ()

    def test_attempt_audit_failure_blocks_bootstrap(
        self, hostlocal: HostLocalAdmin, audit: SelectiveAudit, engine: Engine
    ) -> None:
        audit.fail_outcomes = {A}
        with pytest.raises(FailClosed):
            hostlocal.bootstrap_first_admin("First Admin")
        with engine.connect() as conn:
            for table in (t.actors, t.role_assignments, t.credentials, t.bootstrap_marker):
                assert conn.execute(select(table)).all() == []
        audit.fail_outcomes = set()
        assert hostlocal.bootstrap_first_admin("First Admin").actor.display_name == "First Admin"

    def test_refused_after_the_admin_role_is_revoked(
        self, hostlocal: HostLocalAdmin, identity: IdentityService, root_admin: Principal
    ) -> None:
        second = _second_admin(identity, root_admin)
        (grant,) = identity.list_assignments(actor_id=root_admin.actor_id)
        identity.revoke_role(second, grant.id)
        with pytest.raises(Conflict):
            hostlocal.bootstrap_first_admin("Mallory")

    def test_refused_after_the_admin_is_disabled(
        self, hostlocal: HostLocalAdmin, identity: IdentityService, root_admin: Principal
    ) -> None:
        second = _second_admin(identity, root_admin)
        identity.disable_actor(second, root_admin.actor_id)
        with pytest.raises(Conflict):
            hostlocal.bootstrap_first_admin("Mallory")

    def test_refused_after_an_admin_window_lapses(
        self,
        hostlocal: HostLocalAdmin,
        engine: Engine,
        clock: FixedClock,
        identity: IdentityService,
    ) -> None:
        # Only a hand edit can produce an admin grant with an end; let it lapse.
        with engine.begin() as conn:
            conn.execute(
                t.actors.insert().values(
                    id="act_handmade",
                    actor_type="human",
                    display_name="Temp Admin",
                    status="active",
                    created_at=clock.now(),
                    created_by="hand_edit",
                )
            )
            conn.execute(
                t.role_assignments.insert().values(
                    id="ras_handmade",
                    actor_id="act_handmade",
                    role=Role.SECURITY_ADMIN.value,
                    scope_json="{}",
                    valid_from=clock.now(),
                    valid_until=clock.now() + timedelta(hours=1),
                    assigned_by="hand_edit",
                    assigned_at=clock.now(),
                )
            )
        clock.advance(hours=2)
        assert identity.resolve("act_handmade") is not None
        assert (
            identity.list_assignments(role=Role.SECURITY_ADMIN)[0].is_current(clock.now()) is False
        )
        with pytest.raises(Conflict):
            hostlocal.bootstrap_first_admin("Mallory")

    def test_marker_alone_blocks_a_second_bootstrap(
        self, hostlocal: HostLocalAdmin, root: BootstrapResult, engine: Engine
    ) -> None:
        # Even if every admin assignment row vanished, the single-row marker holds.
        with engine.begin() as conn:
            conn.execute(delete(t.credentials))
            conn.execute(delete(t.role_assignments))
        with pytest.raises(Conflict):
            hostlocal.bootstrap_first_admin("Mallory")


class TestRecovery:
    def test_expired_admin_recovers_a_token(
        self,
        hostlocal: HostLocalAdmin,
        authn: Authenticator,
        root: BootstrapResult,
        clock: FixedClock,
        audit: SelectiveAudit,
    ) -> None:
        clock.advance(MAX_TTL)
        with pytest.raises(AuthenticationError):
            authn.authenticate(root.token.token)
        issued = hostlocal.recover_admin_token(root.actor.id, "Night Operator", "token expired")
        principal = authn.authenticate(issued.token)
        assert principal.actor_id == root.actor.id
        assert principal.credential_issued_by == "host_local"
        events = audit.find("identity.recover_admin_token")
        assert [e.outcome for e in events] == [A, S]
        assert events[1].details["operator"] == "Night Operator"
        assert events[1].details["reason"] == "token expired"
        assert events[1].details["channel"] == "host_local_recovery"
        assert events[1].details["token_id"] == issued.token_id

    @pytest.mark.parametrize("actor_type", [ActorType.AGENT, ActorType.SERVICE])
    def test_agent_or_service_is_never_recovered(
        self,
        hostlocal: HostLocalAdmin,
        identity: IdentityService,
        root_admin: Principal,
        actor_type: ActorType,
        engine: Engine,
    ) -> None:
        bot = identity.create_actor(root_admin, actor_type, "bot").id
        with pytest.raises(AuthorizationError):
            hostlocal.recover_admin_token(bot, "Night Operator", "test")
        with engine.connect() as conn:
            rows = conn.execute(select(t.credentials).where(t.credentials.c.actor_id == bot))
            assert rows.all() == []

    def test_non_admin_or_disabled_admin_is_not_recovered(
        self, hostlocal: HostLocalAdmin, identity: IdentityService, root_admin: Principal
    ) -> None:
        human = identity.create_actor(root_admin, ActorType.HUMAN, "Person A").id
        identity.assign_role(root_admin, human, Role.SYSTEM_OWNER)
        with pytest.raises(AuthorizationError):
            hostlocal.recover_admin_token(human, "Night Operator", "test")
        second = _second_admin(identity, root_admin)
        identity.disable_actor(root_admin, second)
        with pytest.raises(AuthorizationError):
            hostlocal.recover_admin_token(second, "Night Operator", "test")

    def test_operator_and_reason_are_required(
        self, hostlocal: HostLocalAdmin, root: BootstrapResult
    ) -> None:
        with pytest.raises(ValidationFailed):
            hostlocal.recover_admin_token(root.actor.id, " ", "token expired")
        with pytest.raises(ValidationFailed):
            hostlocal.recover_admin_token(root.actor.id, "Night Operator", "")


def test_host_local_operations_say_so() -> None:
    for method in (HostLocalAdmin.bootstrap_first_admin, HostLocalAdmin.recover_admin_token):
        assert "never reachable from the API" in (method.__doc__ or "")
