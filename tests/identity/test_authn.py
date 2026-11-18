"""T1.5: bootstrap credentials and authentication. NFR-004, FR-003.

Also the M1 review fixes: M2 (disable revokes tokens), M4 (issuer recorded), L3 (strict
parsing), F7 (a refusing audit log does not lock readers out), F8 (no audit record for
unknown or malformed tokens).
"""

from __future__ import annotations

import logging
from datetime import timedelta

import pytest
from sqlalchemy import Engine, select
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
from ciso.common.schemas import canonical_json
from ciso.identity.authn import Authenticator, ExternalIdentityAdapter
from ciso.identity.service import IdentityService

pytestmark = pytest.mark.policy

A, S, D = AuditOutcome.ATTEMPT, AuditOutcome.SUCCESS, AuditOutcome.DENIED


def _actor(identity: IdentityService, admin: Principal, role: Role = Role.EMPLOYEE) -> str:
    actor_id = identity.create_actor(admin, ActorType.HUMAN, "Person A").id
    identity.assign_role(admin, actor_id, role)
    return actor_id


def _secret(token: str) -> str:
    return token.split(".", 1)[1]


def _all_identity_cells(engine: Engine) -> list[str]:
    cells: list[str] = []
    with engine.connect() as conn:
        for table in (t.actors, t.role_assignments, t.credentials, t.bootstrap_marker):
            for row in conn.execute(select(table)):
                cells.extend(str(value) for value in row)
    return cells


def _auth_events(audit: SelectiveAudit) -> list[str]:
    return [e.details.get("reason", "") for e in audit.find("identity.authenticate")]


class TestIssue:
    def test_token_shown_once_and_only_a_hash_is_stored(
        self,
        authn: Authenticator,
        identity: IdentityService,
        root_admin: Principal,
        engine: Engine,
    ) -> None:
        actor_id = _actor(identity, root_admin)
        issued = authn.issue_token(actor_id, root_admin, timedelta(hours=1))
        token_id, secret = issued.token.split(".", 1)
        assert token_id == issued.token_id
        assert len(secret) >= 40
        assert issued.token not in repr(issued)
        with engine.connect() as conn:
            row = (
                conn.execute(select(t.credentials).where(t.credentials.c.token_id == token_id))
                .mappings()
                .one()
            )
        assert row["actor_id"] == actor_id
        assert row["created_by"] == root_admin.actor_id
        assert row["secret_hash"]
        assert row["salt"]
        cells = _all_identity_cells(engine)
        assert len(cells) > 10
        assert not [cell for cell in cells if secret in cell or issued.token in cell]

    def test_no_max_ttl_refuses_to_issue(
        self,
        engine: Engine,
        clock: FixedClock,
        audit: SelectiveAudit,
        identity: IdentityService,
        root_admin: Principal,
    ) -> None:
        actor_id = _actor(identity, root_admin)
        closed = Authenticator(
            engine, clock, audit, identity, max_token_ttl=None, scrypt=FAST_SCRYPT
        )
        with pytest.raises(FailClosed):
            closed.issue_token(actor_id, root_admin, timedelta(hours=1))
        with engine.connect() as conn:
            rows = conn.execute(select(t.credentials).where(t.credentials.c.actor_id == actor_id))
            assert rows.all() == []

    def test_ttl_bounds(
        self,
        authn: Authenticator,
        identity: IdentityService,
        root_admin: Principal,
        clock: FixedClock,
    ) -> None:
        actor_id = _actor(identity, root_admin)
        with pytest.raises(ValidationFailed):
            authn.issue_token(actor_id, root_admin, MAX_TTL + timedelta(seconds=1))
        with pytest.raises(ValidationFailed):
            authn.issue_token(actor_id, root_admin, timedelta(0))
        issued = authn.issue_token(actor_id, root_admin, None)
        assert issued.expires_at == clock.now() + MAX_TTL

    def test_only_a_real_human_security_admin_issues(
        self,
        authn: Authenticator,
        identity: IdentityService,
        root_admin: Principal,
        admin: Principal,
    ) -> None:
        actor_id = _actor(identity, root_admin)
        owner = _actor(identity, root_admin, Role.SYSTEM_OWNER)
        for caller in (owner, admin):
            with pytest.raises(AuthorizationError):
                authn.issue_token(actor_id, caller, timedelta(hours=1))
        assert authn.issue_token(actor_id, root_admin.actor_id, timedelta(hours=1)).token

    def test_disabled_actor_gets_no_token(
        self, authn: Authenticator, identity: IdentityService, root_admin: Principal
    ) -> None:
        actor_id = _actor(identity, root_admin)
        identity.disable_actor(root_admin, actor_id)
        with pytest.raises(Conflict):
            authn.issue_token(actor_id, root_admin, timedelta(hours=1))

    def test_attempt_audit_failure_blocks_issue(
        self,
        authn: Authenticator,
        identity: IdentityService,
        root_admin: Principal,
        audit: SelectiveAudit,
        engine: Engine,
    ) -> None:
        actor_id = _actor(identity, root_admin)
        audit.fail_outcomes = {A}
        with pytest.raises(FailClosed):
            authn.issue_token(actor_id, root_admin, timedelta(hours=1))
        with engine.connect() as conn:
            rows = conn.execute(select(t.credentials).where(t.credentials.c.actor_id == actor_id))
            assert rows.all() == []


class TestAuthenticate:
    def test_valid_token_gives_that_actors_principal_and_issuer(
        self,
        authn: Authenticator,
        identity: IdentityService,
        root_admin: Principal,
        engine: Engine,
        clock: FixedClock,
    ) -> None:
        a = _actor(identity, root_admin, Role.EMPLOYEE)
        b = _actor(identity, root_admin, Role.AUDITOR)
        token_a = authn.issue_token(a, root_admin, timedelta(hours=1))
        token_b = authn.issue_token(b, root_admin, timedelta(hours=1))
        pa = authn.authenticate(token_a.token)
        pb = authn.authenticate(token_b.token)
        assert (pa.actor_id, pa.roles) == (a, frozenset({Role.EMPLOYEE}))
        assert (pb.actor_id, pb.roles) == (b, frozenset({Role.AUDITOR}))
        assert pa.credential_issued_by == root_admin.actor_id
        with engine.connect() as conn:
            used = conn.execute(
                select(t.credentials.c.last_used_at).where(
                    t.credentials.c.token_id.in_([token_a.token_id, token_b.token_id])
                )
            ).scalars()
            assert list(used) == [clock.now(), clock.now()]

    def test_every_failure_raises_the_same_error(
        self,
        authn: Authenticator,
        identity: IdentityService,
        root_admin: Principal,
        clock: FixedClock,
        audit: SelectiveAudit,
    ) -> None:
        def fresh(ttl: timedelta = timedelta(hours=1)) -> tuple[str, str]:
            actor_id = _actor(identity, root_admin)
            return actor_id, authn.issue_token(actor_id, root_admin, ttl).token

        _, good = fresh()
        token_id = good.split(".", 1)[0]
        _, revoked = fresh()
        authn.revoke_token(revoked.split(".", 1)[0], root_admin)
        disabled_actor, disabled = fresh()
        _, expiring = fresh(timedelta(minutes=5))
        identity.disable_actor(root_admin, disabled_actor)  # also revokes its tokens (M2)

        unaudited = {
            "malformed": "not-a-token",
            "empty": "",
            "trailing_newline": good + "\n",
            "trailing_space": good + " ",
            "leading_space": " " + good,
            "unknown_token": "tok_0000000000ZZZZZZZZZZZZZZZZ." + _secret(good),
        }
        audited = {
            "wrong_secret": f"{token_id}.{_secret(good)[:-2]}xx",
            "revoked": revoked,
            "actor_disabled": disabled,
        }
        before = len(audit.find("identity.authenticate"))
        messages = set()
        for token in unaudited.values():
            with pytest.raises(AuthenticationError) as exc:
                authn.authenticate(token)
            messages.add(str(exc.value))
        assert len(audit.find("identity.authenticate")) == before  # F8: nothing written
        assert authn.counters()["rejected_unaudited"] == len(unaudited)
        for token in audited.values():
            with pytest.raises(AuthenticationError) as exc:
                authn.authenticate(token)
            messages.add(str(exc.value))
        clock.advance(minutes=5)
        with pytest.raises(AuthenticationError) as exc:
            authn.authenticate(expiring)
        messages.add(str(exc.value))
        assert len(messages) == 1

        # The good token still works, so the refusals above are not a blanket deny.
        assert authn.authenticate(good).actor_id

        denied = [e for e in audit.find("identity.authenticate") if e.outcome is D]
        # A disabled actor's tokens are revoked, so that case is recorded as revoked.
        assert sorted(e.details["reason"] for e in denied) == [
            "expired",
            "revoked",
            "revoked",
            "wrong_secret",
        ]
        wrong = next(e for e in denied if e.details["reason"] == "wrong_secret")
        assert (wrong.actor_id, wrong.actor_type) == ("unauthenticated", ActorType.ANONYMOUS)

    def test_disabled_actor_is_refused_even_with_an_unrevoked_token(
        self,
        authn: Authenticator,
        identity: IdentityService,
        root_admin: Principal,
        engine: Engine,
        audit: SelectiveAudit,
    ) -> None:
        actor_id = _actor(identity, root_admin)
        issued = authn.issue_token(actor_id, root_admin, timedelta(hours=1))
        with engine.begin() as conn:  # hand edit: disabled without the token revocation
            conn.execute(
                t.actors.update().where(t.actors.c.id == actor_id).values(status="disabled")
            )
        with pytest.raises(AuthenticationError):
            authn.authenticate(issued.token)
        assert _auth_events(audit)[-1] == "actor_disabled"

    def test_disable_revokes_every_token_and_enable_restores_none(
        self,
        authn: Authenticator,
        identity: IdentityService,
        root_admin: Principal,
        engine: Engine,
    ) -> None:
        actor_id = _actor(identity, root_admin)
        tokens = [authn.issue_token(actor_id, root_admin, timedelta(hours=1)) for _ in range(3)]
        identity.disable_actor(root_admin, actor_id)
        with engine.connect() as conn:
            revoked = conn.execute(
                select(t.credentials.c.revoked_at).where(t.credentials.c.actor_id == actor_id)
            ).scalars()
            assert all(value is not None for value in revoked)
        identity.enable_actor(root_admin, actor_id)
        for issued in tokens:
            with pytest.raises(AuthenticationError):
                authn.authenticate(issued.token)
        fresh = authn.issue_token(actor_id, root_admin, timedelta(hours=1))
        assert authn.authenticate(fresh.token).actor_id == actor_id

    def test_revoke_is_audited_admin_or_owner_only(
        self,
        authn: Authenticator,
        identity: IdentityService,
        root_admin: Principal,
        audit: SelectiveAudit,
    ) -> None:
        actor_id = _actor(identity, root_admin)
        bystander = _actor(identity, root_admin)
        issued = authn.issue_token(actor_id, root_admin, timedelta(hours=1))
        with pytest.raises(AuthorizationError):
            authn.revoke_token(issued.token_id, bystander)
        assert authn.authenticate(issued.token).actor_id == actor_id
        authn.revoke_token(issued.token_id, actor_id)  # the owner may sign itself out
        assert _outcomes(audit, "identity.token.revoke") == [D, A, S]
        with pytest.raises(AuthenticationError):
            authn.authenticate(issued.token)
        with pytest.raises(Conflict):
            authn.revoke_token(issued.token_id, root_admin)

    def test_refusing_audit_log_does_not_lock_out_a_valid_token(
        self,
        authn: Authenticator,
        identity: IdentityService,
        root_admin: Principal,
        audit: SelectiveAudit,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        issued = authn.issue_token(_actor(identity, root_admin), root_admin, timedelta(hours=1))
        audit.fail = True
        caplog.set_level(logging.ERROR, logger="ciso.identity")
        principal = authn.authenticate(issued.token)
        assert principal.actor_id == issued.actor_id
        assert authn.counters()["success_audit_failures"] == 1
        assert any(r.levelno == logging.ERROR for r in caplog.records)
        # A failure while the log refuses still raises the uniform error.
        with pytest.raises(AuthenticationError):
            authn.authenticate(f"{issued.token_id}.{_secret(issued.token)[:-2]}zz")
        assert authn.counters()["failure_audit_failures"] == 1

    def test_token_never_in_audit_or_logs(
        self,
        authn: Authenticator,
        identity: IdentityService,
        root_admin: Principal,
        audit: SelectiveAudit,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        caplog.set_level(logging.DEBUG, logger="ciso.identity")
        actor_id = _actor(identity, root_admin)
        issued = authn.issue_token(actor_id, root_admin, timedelta(hours=1))
        authn.authenticate(issued.token)
        wrong = f"{issued.token_id}.{_secret(issued.token)[:-2]}zz"
        with pytest.raises(AuthenticationError):
            authn.authenticate(wrong)
        with pytest.raises(AuthenticationError):
            authn.authenticate(issued.token + "\n")
        authn.revoke_token(issued.token_id, root_admin)
        with pytest.raises(AuthenticationError):
            authn.authenticate(issued.token)

        secrets_seen = (issued.token, _secret(issued.token), wrong, _secret(wrong))
        assert len(caplog.records) >= 4
        assert len(audit.events) >= 8
        dumped = [canonical_json(event) for event in audit.events]
        for value in secrets_seen:
            assert value not in caplog.text
            assert not [d for d in dumped if value in d]


def _outcomes(audit: SelectiveAudit, action: str) -> list[AuditOutcome]:
    return [event.outcome for event in audit.find(action)]


def test_external_identity_adapter_is_interface_only() -> None:
    assert ExternalIdentityAdapter.__dict__.get("_is_protocol") is True
