"""T1.4: role templates, actors, assignments, ABAC scope. Blueprint 9.3; FR-002, FR-024.

Also the M1 review fixes: H2 (callers re-resolved), M3 (unscoped, open-ended admin only),
M7 (closed scope model), F17 (no classification scheme), last-admin protection.
"""

from __future__ import annotations

import json
from datetime import timedelta

import pytest
from sqlalchemy import Engine, Table, func, select
from tests.fakes.core import make_principal
from tests.identity.conftest import SelectiveAudit

import ciso.identity.tables as t
from ciso.common.clock import FixedClock
from ciso.common.enums import HUMAN_ONLY_ROLES, ActorType, AuditOutcome, Environment, Role
from ciso.common.errors import (
    AuthorizationError,
    Conflict,
    FailClosed,
    IntegrityFailure,
    NotFound,
    ValidationFailed,
)
from ciso.common.principal import Principal
from ciso.common.protocols import AuditEvent
from ciso.identity.roles import (
    PERMISSIONS,
    ROLE_TEMPLATES,
    RoleScope,
    permissions_for,
    scope_matches,
    template_for,
)
from ciso.identity.service import ActorStatus, IdentityService

pytestmark = pytest.mark.policy

A, S, D = AuditOutcome.ATTEMPT, AuditOutcome.SUCCESS, AuditOutcome.DENIED


def _human(identity: IdentityService, admin: Principal, name: str = "Person A") -> str:
    return identity.create_actor(admin, ActorType.HUMAN, name).id


def _outcomes(audit: SelectiveAudit, action: str) -> list[AuditOutcome]:
    return [event.outcome for event in audit.find(action)]


def _count(engine: Engine, table: Table) -> int:
    with engine.connect() as conn:
        return int(conn.execute(select(func.count()).select_from(table)).scalar_one())


def _second_admin(identity: IdentityService, admin: Principal) -> Principal:
    other = _human(identity, admin, "Second Admin")
    identity.assign_role(admin, other, Role.SECURITY_ADMIN)
    principal = identity.resolve(other)
    assert principal is not None
    return principal


def _raw_assignment(engine: Engine, clock: FixedClock, actor_id: str, **values: object) -> None:
    row: dict[str, object] = {
        "id": f"ras_raw{_count(engine, t.role_assignments)}",
        "actor_id": actor_id,
        "role": Role.SYSTEM_OWNER.value,
        "scope_json": "{}",
        "valid_from": clock.now(),
        "valid_until": None,
        "assigned_by": "hand_edit",
        "assigned_at": clock.now(),
    }
    row.update(values)
    with engine.begin() as conn:
        conn.execute(t.role_assignments.insert().values(**row))


class TestTemplates:
    def test_five_templates_load_with_zero_assignments(self, identity: IdentityService) -> None:
        assert {tpl.role for tpl in ROLE_TEMPLATES} == set(Role)
        assert len(ROLE_TEMPLATES) == 5
        for tpl in ROLE_TEMPLATES:
            assert tpl.description
            assert tpl.permissions
            assert identity.list_assignments(role=tpl.role) == ()

    def test_every_template_permission_is_documented(self) -> None:
        for tpl in ROLE_TEMPLATES:
            assert tpl.permissions <= set(PERMISSIONS)
        assert all(PERMISSIONS[name] for name in PERMISSIONS)

    def test_permissions_for_is_the_union(self) -> None:
        both = permissions_for([Role.EMPLOYEE, Role.AUDITOR])
        assert (
            both == template_for(Role.EMPLOYEE).permissions | template_for(Role.AUDITOR).permissions
        )
        assert "report.submit" in both
        assert "audit.read" in both
        assert permissions_for([]) == frozenset()

    def test_risk_acceptance_and_killswitch_sit_with_the_right_roles(self) -> None:
        assert "risk.accept" in permissions_for([Role.EXECUTIVE_RISK_OWNER])
        assert "risk.accept" not in permissions_for([Role.SECURITY_ADMIN, Role.SYSTEM_OWNER])
        assert "killswitch.engage" in permissions_for([Role.SECURITY_ADMIN])
        assert "audit.read" in permissions_for([Role.AUDITOR])
        assert not permissions_for([Role.AUDITOR]) & {"finding.update", "approval.decide"}


class TestActors:
    def test_create_actor_audits_attempt_then_result(
        self, identity: IdentityService, root_admin: Principal, audit: SelectiveAudit
    ) -> None:
        actor = identity.create_actor(
            root_admin, ActorType.HUMAN, "Person A", person_ref="person:p_1"
        )
        assert actor.status is ActorStatus.ACTIVE
        assert actor.person_ref == "person:p_1"
        events = audit.find("identity.actor.create")
        assert [e.outcome for e in events] == [A, S]
        assert events[1].target == actor.id
        assert {e.actor_id for e in events} == {root_admin.actor_id}

    def test_person_ref_must_be_an_entity_ref(
        self, identity: IdentityService, root_admin: Principal
    ) -> None:
        with pytest.raises(ValidationFailed):
            identity.create_actor(root_admin, ActorType.HUMAN, "Person A", person_ref="no colon")

    def test_attempt_audit_failure_blocks_creation(
        self,
        identity: IdentityService,
        root_admin: Principal,
        audit: SelectiveAudit,
        engine: Engine,
    ) -> None:
        before = _count(engine, t.actors)
        audit.fail_outcomes = {A}
        with pytest.raises(FailClosed):
            identity.create_actor(root_admin, ActorType.HUMAN, "Person A")
        assert _count(engine, t.actors) == before

    def test_result_audit_failure_raises_but_the_change_stands(
        self,
        identity: IdentityService,
        root_admin: Principal,
        audit: SelectiveAudit,
        engine: Engine,
    ) -> None:
        before = _count(engine, t.actors)
        audit.fail_outcomes = {S}
        with pytest.raises(FailClosed):
            identity.create_actor(root_admin, ActorType.HUMAN, "Person A")
        assert _count(engine, t.actors) == before + 1
        assert _outcomes(audit, "identity.actor.create") == [A]

    def test_disabled_actor_yields_no_principal(
        self, identity: IdentityService, root_admin: Principal, audit: SelectiveAudit
    ) -> None:
        actor_id = _human(identity, root_admin)
        identity.assign_role(root_admin, actor_id, Role.EMPLOYEE)
        assert identity.resolve(actor_id) is not None
        identity.disable_actor(root_admin, actor_id)
        assert identity.resolve(actor_id) is None
        assert identity.principal_for(actor_id) is None
        assert _outcomes(audit, "identity.actor.disable") == [A, S]
        identity.enable_actor(root_admin, actor_id)
        principal = identity.resolve(actor_id)
        assert principal is not None
        assert principal.roles == frozenset({Role.EMPLOYEE})

    def test_attempt_audit_failure_blocks_disable(
        self, identity: IdentityService, root_admin: Principal, audit: SelectiveAudit
    ) -> None:
        actor_id = _human(identity, root_admin)
        audit.fail_outcomes = {A}
        with pytest.raises(FailClosed):
            identity.disable_actor(root_admin, actor_id)
        assert identity.get_actor(actor_id).status is ActorStatus.ACTIVE

    def test_unknown_actor(self, identity: IdentityService) -> None:
        assert identity.resolve("act_00000000000000000000000000") is None
        with pytest.raises(NotFound):
            identity.principal_for("act_00000000000000000000000000")


class TestCallerIsReresolved:
    """H2: only the caller's actor id counts; the Principal object is never trusted."""

    def test_forged_admin_principal_gets_nowhere(
        self,
        identity: IdentityService,
        root_admin: Principal,
        admin: Principal,
        audit: SelectiveAudit,
        engine: Engine,
    ) -> None:
        target = _human(identity, root_admin)
        grant = identity.assign_role(root_admin, target, Role.EMPLOYEE)
        actors_before = _count(engine, t.actors)
        attempts = [
            lambda: identity.create_actor(admin, ActorType.HUMAN, "Mallory"),
            lambda: identity.assign_role(admin, target, Role.SECURITY_ADMIN),
            lambda: identity.revoke_role(admin, grant.id),
            lambda: identity.disable_actor(admin, target),
            lambda: identity.enable_actor(admin, target),
        ]
        for attempt in attempts:
            with pytest.raises(AuthorizationError):
                attempt()
        assert _count(engine, t.actors) == actors_before
        assert identity.get_actor(target).status is ActorStatus.ACTIVE
        assert len(identity.list_assignments(actor_id=target)) == 1
        denied = [e for e in audit.events if e.actor_id == admin.actor_id]
        assert len(denied) == 5
        assert {e.outcome for e in denied} == {D}
        assert {e.details["reason"] for e in denied} == {"unknown_caller"}
        assert {e.actor_type for e in denied} == {ActorType.ANONYMOUS}

    def test_principal_claims_are_ignored_for_a_real_non_admin(
        self, identity: IdentityService, root_admin: Principal
    ) -> None:
        employee = _human(identity, root_admin)
        claimed = make_principal(employee, ActorType.HUMAN, Role.SECURITY_ADMIN)
        with pytest.raises(AuthorizationError):
            identity.create_actor(claimed, ActorType.HUMAN, "Mallory")
        with pytest.raises(AuthorizationError):
            identity.create_actor(employee, ActorType.HUMAN, "Mallory")

    def test_stale_principal_of_a_disabled_admin_is_refused(
        self, identity: IdentityService, root_admin: Principal, audit: SelectiveAudit
    ) -> None:
        second = _second_admin(identity, root_admin)
        identity.disable_actor(root_admin, second.actor_id)
        with pytest.raises(AuthorizationError):
            identity.create_actor(second, ActorType.HUMAN, "Mallory")
        refused = [e for e in audit.events if e.actor_id == second.actor_id and e.outcome is D]
        assert [e.details["reason"] for e in refused] == ["caller_disabled"]

    def test_stale_principal_after_role_revoked_is_refused(
        self, identity: IdentityService, root_admin: Principal
    ) -> None:
        second = _second_admin(identity, root_admin)
        (grant,) = identity.list_assignments(actor_id=second.actor_id)
        identity.revoke_role(root_admin, grant.id)
        with pytest.raises(AuthorizationError):
            identity.create_actor(second, ActorType.HUMAN, "Mallory")

    def test_real_agent_row_cannot_administer(
        self, identity: IdentityService, root_admin: Principal
    ) -> None:
        bot = identity.create_actor(root_admin, ActorType.AGENT, "bot").id
        with pytest.raises(AuthorizationError):
            identity.create_actor(bot, ActorType.HUMAN, "Mallory")

    def test_caller_is_rechecked_inside_the_write_transaction(
        self,
        identity: IdentityService,
        root_admin: Principal,
        audit: SelectiveAudit,
        engine: Engine,
    ) -> None:
        """The caller passes the pre-check, then loses admin before the transaction runs."""
        second = _second_admin(identity, root_admin)
        before = _count(engine, t.actors)

        def concurrent_disable(event: AuditEvent) -> None:
            if event.action == "identity.actor.create" and event.outcome is A:
                with engine.begin() as conn:
                    conn.execute(
                        t.actors.update()
                        .where(t.actors.c.id == second.actor_id)
                        .values(status="disabled")
                    )

        audit.on_append = concurrent_disable
        with pytest.raises(AuthorizationError, match="caller_disabled"):
            identity.create_actor(second, ActorType.HUMAN, "Mallory")
        assert _count(engine, t.actors) == before
        outcomes = [e.outcome for e in audit.find("identity.actor.create")][-2:]
        assert outcomes == [A, D]

    def test_scoped_admin_row_from_a_hand_edit_cannot_administer(
        self,
        identity: IdentityService,
        root_admin: Principal,
        engine: Engine,
        clock: FixedClock,
    ) -> None:
        human = _human(identity, root_admin)
        _raw_assignment(
            engine,
            clock,
            human,
            role=Role.SECURITY_ADMIN.value,
            scope_json=json.dumps({"environment": ["development"]}),
        )
        with pytest.raises(AuthorizationError):
            identity.create_actor(human, ActorType.HUMAN, "Mallory")


class TestAssignments:
    def test_multiple_roles_per_actor(
        self, identity: IdentityService, root_admin: Principal
    ) -> None:
        actor_id = _human(identity, root_admin)
        for role in (Role.SYSTEM_OWNER, Role.EXECUTIVE_RISK_OWNER, Role.AUDITOR):
            identity.assign_role(root_admin, actor_id, role)
        principal = identity.resolve(actor_id)
        assert principal is not None
        assert principal.roles == frozenset(
            {Role.SYSTEM_OWNER, Role.EXECUTIVE_RISK_OWNER, Role.AUDITOR}
        )
        assert len(principal.grants) == 3
        assert {g.role for g in principal.grants} == principal.roles
        assert all(dict(g.scope) == {} for g in principal.grants)
        assert len(identity.list_assignments(actor_id=actor_id)) == 3

    @pytest.mark.parametrize("actor_type", [ActorType.AGENT, ActorType.SERVICE])
    @pytest.mark.parametrize("role", sorted(HUMAN_ONLY_ROLES))
    def test_non_humans_refused_human_only_roles(
        self,
        identity: IdentityService,
        root_admin: Principal,
        audit: SelectiveAudit,
        actor_type: ActorType,
        role: Role,
    ) -> None:
        actor_id = identity.create_actor(root_admin, actor_type, "bot").id
        with pytest.raises(AuthorizationError, match="human_only_role"):
            identity.assign_role(root_admin, actor_id, role)
        assert identity.list_assignments(actor_id=actor_id) == ()
        events = [e for e in audit.find("identity.role.assign") if e.target == actor_id]
        assert [e.outcome for e in events] == [A, D]
        assert "human_only_role" in events[1].details["message"]

    @pytest.mark.parametrize("actor_type", [ActorType.AGENT, ActorType.SERVICE])
    def test_non_humans_may_hold_employee_role(
        self, identity: IdentityService, root_admin: Principal, actor_type: ActorType
    ) -> None:
        actor_id = identity.create_actor(root_admin, actor_type, "bot").id
        identity.assign_role(root_admin, actor_id, Role.EMPLOYEE)
        principal = identity.resolve(actor_id)
        assert principal is not None
        assert principal.roles == frozenset({Role.EMPLOYEE})

    def test_only_a_human_security_admin_assigns(
        self, identity: IdentityService, root_admin: Principal
    ) -> None:
        actor_id = _human(identity, root_admin)
        owner = _human(identity, root_admin, "Owner")
        identity.assign_role(root_admin, owner, Role.SYSTEM_OWNER)
        with pytest.raises(AuthorizationError):
            identity.assign_role(owner, actor_id, Role.EMPLOYEE)
        assert identity.list_assignments(actor_id=actor_id) == ()
        identity.assign_role(root_admin, actor_id, Role.EMPLOYEE)
        assert len(identity.list_assignments(actor_id=actor_id)) == 1

    def test_assign_and_revoke_are_audited(
        self, identity: IdentityService, root_admin: Principal, audit: SelectiveAudit
    ) -> None:
        actor_id = _human(identity, root_admin)
        assignment = identity.assign_role(root_admin, actor_id, Role.SYSTEM_OWNER)
        revoked = identity.revoke_role(root_admin, assignment.id)
        assert revoked.revoked_by == root_admin.actor_id
        assert revoked.revoked_at is not None
        assigns = [e for e in audit.find("identity.role.assign") if e.target == actor_id]
        assert [e.outcome for e in assigns] == [A, S]
        assert assigns[1].details["role"] == "system_owner"
        assert _outcomes(audit, "identity.role.revoke") == [A, S]
        principal = identity.resolve(actor_id)
        assert principal is not None
        assert principal.roles == frozenset()

    def test_attempt_audit_failure_blocks_assignment(
        self, identity: IdentityService, root_admin: Principal, audit: SelectiveAudit
    ) -> None:
        actor_id = _human(identity, root_admin)
        audit.fail_outcomes = {A}
        with pytest.raises(FailClosed):
            identity.assign_role(root_admin, actor_id, Role.SYSTEM_OWNER)
        assert identity.list_assignments(actor_id=actor_id, include_revoked=True) == ()

    def test_attempt_audit_failure_blocks_revocation(
        self, identity: IdentityService, root_admin: Principal, audit: SelectiveAudit
    ) -> None:
        actor_id = _human(identity, root_admin)
        assignment = identity.assign_role(root_admin, actor_id, Role.SYSTEM_OWNER)
        audit.fail_outcomes = {A}
        with pytest.raises(FailClosed):
            identity.revoke_role(root_admin, assignment.id)
        principal = identity.resolve(actor_id)
        assert principal is not None
        assert principal.roles == frozenset({Role.SYSTEM_OWNER})

    def test_bad_window_is_refused(
        self, identity: IdentityService, root_admin: Principal, clock: FixedClock
    ) -> None:
        actor_id = _human(identity, root_admin)
        with pytest.raises(ValidationFailed):
            identity.assign_role(
                root_admin,
                actor_id,
                Role.EMPLOYEE,
                valid_from=clock.now(),
                valid_until=clock.now() - timedelta(minutes=1),
            )

    def test_stored_non_human_with_human_role_fails_closed(
        self,
        identity: IdentityService,
        root_admin: Principal,
        engine: Engine,
        clock: FixedClock,
    ) -> None:
        actor_id = identity.create_actor(root_admin, ActorType.AGENT, "bot").id
        _raw_assignment(engine, clock, actor_id, role=Role.SECURITY_ADMIN.value)
        with pytest.raises(IntegrityFailure):
            identity.resolve(actor_id)


class TestAdminGrantShape:
    """M3: security_admin is unscoped and open-ended."""

    def test_scoped_security_admin_is_refused(
        self, identity: IdentityService, root_admin: Principal
    ) -> None:
        actor_id = _human(identity, root_admin)
        with pytest.raises(ValidationFailed):
            identity.assign_role(
                root_admin,
                actor_id,
                Role.SECURITY_ADMIN,
                scope=RoleScope(environments=frozenset({Environment.DEVELOPMENT})),
            )
        assert identity.list_assignments(actor_id=actor_id) == ()

    def test_security_admin_with_an_end_is_refused(
        self, identity: IdentityService, root_admin: Principal, clock: FixedClock
    ) -> None:
        actor_id = _human(identity, root_admin)
        with pytest.raises(ValidationFailed):
            identity.assign_role(
                root_admin,
                actor_id,
                Role.SECURITY_ADMIN,
                valid_until=clock.now() + timedelta(hours=1),
            )
        identity.assign_role(root_admin, actor_id, Role.SECURITY_ADMIN)
        assert len(identity.list_assignments(actor_id=actor_id)) == 1


class TestLastAdmin:
    def test_last_admin_cannot_be_disabled_or_lose_the_role(
        self, identity: IdentityService, root_admin: Principal
    ) -> None:
        (grant,) = identity.list_assignments(actor_id=root_admin.actor_id)
        with pytest.raises(Conflict):
            identity.disable_actor(root_admin, root_admin.actor_id)
        with pytest.raises(Conflict):
            identity.revoke_role(root_admin, grant.id)
        assert identity.resolve(root_admin.actor_id) is not None

    def test_a_second_admin_makes_it_possible(
        self, identity: IdentityService, root_admin: Principal
    ) -> None:
        second = _second_admin(identity, root_admin)
        identity.disable_actor(second, root_admin.actor_id)
        with pytest.raises(Conflict):
            identity.disable_actor(second, second.actor_id)

    def test_a_scheduled_admin_does_not_count_until_it_starts(
        self, identity: IdentityService, root_admin: Principal, clock: FixedClock
    ) -> None:
        later = _human(identity, root_admin, "Later Admin")
        identity.assign_role(
            root_admin, later, Role.SECURITY_ADMIN, valid_from=clock.now() + timedelta(days=1)
        )
        with pytest.raises(Conflict):
            identity.disable_actor(root_admin, root_admin.actor_id)


class TestScope:
    def test_scope_inside_and_outside(
        self, identity: IdentityService, root_admin: Principal
    ) -> None:
        actor_id = _human(identity, root_admin)
        identity.assign_role(
            root_admin,
            actor_id,
            Role.SYSTEM_OWNER,
            scope=RoleScope(
                systems=frozenset({"app:billing"}),
                environments=frozenset({Environment.STAGING}),
                classifications=frozenset({"internal"}),
            ),
        )
        p = identity.resolve(actor_id)
        assert p is not None
        (grant,) = p.grants
        assert dict(grant.scope) == {
            "system": frozenset({"app:billing"}),
            "environment": frozenset({"staging"}),
            "classification": frozenset({"internal"}),
        }
        full = {"system": "app:billing", "environment": "staging", "classification": "internal"}
        assert p.covers(Role.SYSTEM_OWNER, full)
        assert scope_matches(p, Role.SYSTEM_OWNER, **full)
        for name, wrong in (
            ("system", "app:other"),
            ("environment", "production"),
            ("classification", "restricted"),
        ):
            assert not scope_matches(p, Role.SYSTEM_OWNER, **{**full, name: wrong})
        assert not scope_matches(p, Role.SYSTEM_OWNER, system="app:billing")
        assert not scope_matches(p, Role.AUDITOR)

    def test_unscoped_role_is_not_narrowed(
        self, identity: IdentityService, root_admin: Principal
    ) -> None:
        actor_id = _human(identity, root_admin)
        identity.assign_role(root_admin, actor_id, Role.AUDITOR)
        p = identity.resolve(actor_id)
        assert p is not None
        assert scope_matches(p, Role.AUDITOR)
        assert scope_matches(p, Role.AUDITOR, system="app:any", environment="production")

    def test_two_grants_do_not_mix_attributes(
        self, identity: IdentityService, root_admin: Principal
    ) -> None:
        actor_id = _human(identity, root_admin)
        for system, env in (("app:a", Environment.PRODUCTION), ("app:b", Environment.STAGING)):
            identity.assign_role(
                root_admin,
                actor_id,
                Role.SYSTEM_OWNER,
                scope=RoleScope(systems=frozenset({system}), environments=frozenset({env})),
            )
        p = identity.resolve(actor_id)
        assert p is not None
        assert len(p.grants) == 2
        assert scope_matches(p, Role.SYSTEM_OWNER, system="app:a", environment="production")
        assert scope_matches(p, Role.SYSTEM_OWNER, system="app:b", environment="staging")
        assert not scope_matches(p, Role.SYSTEM_OWNER, system="app:a", environment="staging")
        assert not scope_matches(p, Role.SYSTEM_OWNER, system="app:b", environment="production")

    def test_scope_of_one_role_does_not_narrow_another(
        self, identity: IdentityService, root_admin: Principal
    ) -> None:
        actor_id = _human(identity, root_admin)
        identity.assign_role(
            root_admin, actor_id, Role.SYSTEM_OWNER, scope=RoleScope(systems=frozenset({"app:a"}))
        )
        identity.assign_role(root_admin, actor_id, Role.AUDITOR)
        p = identity.resolve(actor_id)
        assert p is not None
        assert scope_matches(p, Role.AUDITOR, system="app:z")
        assert not scope_matches(p, Role.SYSTEM_OWNER, system="app:z")

    def test_unknown_attribute_name_is_refused(
        self, identity: IdentityService, root_admin: Principal
    ) -> None:
        actor_id = _human(identity, root_admin)
        identity.assign_role(root_admin, actor_id, Role.AUDITOR)
        p = identity.resolve(actor_id)
        assert p is not None
        with pytest.raises(ValidationFailed):
            scope_matches(p, Role.AUDITOR, sytem="app:a")

    def test_unconfigured_classification_label_is_refused(
        self, identity: IdentityService, root_admin: Principal
    ) -> None:
        actor_id = _human(identity, root_admin)
        with pytest.raises(ValidationFailed):
            identity.assign_role(
                root_admin,
                actor_id,
                Role.SYSTEM_OWNER,
                scope=RoleScope(classifications=frozenset({"top_secret"})),
            )

    def test_time_window_inside_before_and_after(
        self, identity: IdentityService, root_admin: Principal, clock: FixedClock
    ) -> None:
        actor_id = _human(identity, root_admin)
        start = clock.now() + timedelta(hours=1)
        identity.assign_role(
            root_admin,
            actor_id,
            Role.SYSTEM_OWNER,
            valid_from=start,
            valid_until=start + timedelta(hours=2),
        )

        def roles() -> frozenset[Role]:
            p = identity.resolve(actor_id)
            assert p is not None
            return p.roles

        assert roles() == frozenset()  # before the window
        clock.advance(hours=1)
        assert roles() == frozenset({Role.SYSTEM_OWNER})  # window opens (inclusive)
        clock.advance(hours=1, minutes=59)
        assert roles() == frozenset({Role.SYSTEM_OWNER})  # still inside
        clock.advance(minutes=1)
        assert roles() == frozenset()  # expired: valid_until is exclusive


class TestNoClassificationScheme:
    """F17: without a scheme identity still works, but cannot narrow by classification."""

    def test_classification_narrowing_refused_everything_else_works(
        self,
        engine: Engine,
        clock: FixedClock,
        audit: SelectiveAudit,
        root_admin: Principal,
    ) -> None:
        bare = IdentityService(engine, clock, audit, None)
        actor_id = bare.create_actor(root_admin, ActorType.HUMAN, "Person A").id
        with pytest.raises(ValidationFailed, match="classification"):
            bare.assign_role(
                root_admin,
                actor_id,
                Role.SYSTEM_OWNER,
                scope=RoleScope(classifications=frozenset({"internal"})),
            )
        bare.assign_role(
            root_admin, actor_id, Role.SYSTEM_OWNER, scope=RoleScope(systems=frozenset({"app:a"}))
        )
        p = bare.resolve(actor_id)
        assert p is not None
        assert scope_matches(p, Role.SYSTEM_OWNER, system="app:a")


class TestStoredScopeIsValidated:
    """M7: a hand-edited scope never turns into an unscoped principal."""

    @pytest.mark.parametrize(
        "scope_json",
        [
            json.dumps({"systems": ["app:a"]}),  # unknown key
            json.dumps({"system": "app:a"}),  # not a list
            json.dumps({"system": []}),  # empty list would un-narrow
            json.dumps({"environment": ["moon"]}),  # not an environment
            json.dumps(["system"]),  # not an object
            "{not json",
        ],
    )
    def test_bad_scope_json_raises_integrity_failure(
        self,
        identity: IdentityService,
        root_admin: Principal,
        engine: Engine,
        clock: FixedClock,
        scope_json: str,
    ) -> None:
        actor_id = _human(identity, root_admin)
        _raw_assignment(engine, clock, actor_id, scope_json=scope_json)
        with pytest.raises(IntegrityFailure):
            identity.resolve(actor_id)

    def test_good_scope_json_still_loads(
        self,
        identity: IdentityService,
        root_admin: Principal,
        engine: Engine,
        clock: FixedClock,
    ) -> None:
        actor_id = _human(identity, root_admin)
        _raw_assignment(engine, clock, actor_id, scope_json=json.dumps({"system": ["app:a"]}))
        p = identity.resolve(actor_id)
        assert p is not None
        assert not scope_matches(p, Role.SYSTEM_OWNER, system="app:b")
        assert scope_matches(p, Role.SYSTEM_OWNER, system="app:a")


def test_identity_service_is_a_principal_resolver(identity: IdentityService) -> None:
    from ciso.common.protocols import PrincipalResolver

    assert isinstance(identity, PrincipalResolver)
