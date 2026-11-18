"""Composition root, M2 part (plan T2.9): settings, readiness, the approval service and
its audit read-back over the real audit log (blueprint 9.5, FR-025; gaps G3, G12, G14).
"""

from __future__ import annotations

import json
from datetime import timedelta
from pathlib import Path

import pytest
from pydantic import ValidationError
from sqlalchemy import inspect, select
from tests.app.helpers import SECRET_ENV, build, provisional
from tests.app.m2_world import (
    BROKER,
    SUBJECT,
    agent_request,
    enabled_settings,
    external_on,
    first_admin,
    human,
)

from ciso.app import Container
from ciso.app.approvals_wiring import AuditRecordReader
from ciso.app.audit_wiring import UnavailableAuditLog
from ciso.app.container import TABLE_MODULES
from ciso.app.readiness import EXTERNAL_NO_DIGEST_KEY, EXTERNAL_NO_TRANSPORT, SECRET_REF_FIELDS
from ciso.app.settings import KEY_REF_FIELDS, SafetySettings, Settings, load_settings
from ciso.approvals import (
    Approval,
    ApprovalFault,
    ApprovalReason,
    ApprovalService,
    ApprovalStatus,
    AuditRecordLookup,
)
from ciso.approvals.tables import approval as approval_table
from ciso.audit import audit_record
from ciso.common.clock import FixedClock
from ciso.common.enums import ActorType, AuditOutcome, Role
from ciso.common.errors import FailClosed, IntegrityFailure
from ciso.common.principal import Principal
from ciso.inference.external import ExternalInferenceGateway

pytestmark = pytest.mark.policy

PROVISIONAL = Path(__file__).resolve().parents[2] / "config" / "provisional-settings.json"
DIGEST_ENV = "CISO_SECRET_EXTERNAL_DIGEST_KEY"


def without(name: str) -> dict[str, str]:
    return {key: value for key, value in SECRET_ENV.items() if key != name}


class TestSettings:
    def test_the_byte_limits_have_no_default_and_must_be_positive_whole_numbers(self) -> None:
        safety = SafetySettings()
        assert safety.external_max_payload_bytes is None
        assert safety.external_max_response_bytes is None
        for bad in (0, -1, 1.5, "100"):
            with pytest.raises(ValidationError):
                SafetySettings(external_max_payload_bytes=bad)  # type: ignore[arg-type]
            with pytest.raises(ValidationError):
                SafetySettings(external_max_response_bytes=bad)  # type: ignore[arg-type]

    def test_the_digest_key_is_a_reference_never_a_value(self) -> None:
        assert Settings().external_digest_key_ref is None
        with pytest.raises(ValidationError, match="external_digest_key_ref"):
            Settings(external_digest_key_ref="a-raw-key-value-that-is-long-enough")
        assert Settings(external_digest_key_ref="secret://k").external_digest_key_ref

    def test_every_key_reference_field_is_checked_at_start_up(self) -> None:
        named = {name for name in Settings.model_fields if name.endswith("_key_ref")}
        assert "external_digest_key_ref" in named
        assert named == set(KEY_REF_FIELDS) == set(SECRET_REF_FIELDS)

    def test_provisional_file_sets_the_limits_and_leaves_the_path_off(self) -> None:
        settings = load_settings(PROVISIONAL)
        assert settings.safety.external_max_payload_bytes == 32768
        assert settings.safety.external_max_response_bytes == 65536
        assert settings.external_digest_key_ref == "secret://external_digest_key"
        assert settings.external_inference.enabled is False
        assert "PROVISIONAL" in json.loads(PROVISIONAL.read_text(encoding="utf-8"))["_comment"]


class TestContainer:
    def test_builds_both_services_registers_their_tables_and_closes(self, tmp_path: Path) -> None:
        names = {module.__name__ for module in TABLE_MODULES}
        assert {"ciso.approvals.tables", "ciso.inference.external.tables"} <= names
        container = build(provisional(tmp_path / "d"), SECRET_ENV)
        with container as c:
            assert isinstance(c.approvals, ApprovalService)
            assert isinstance(c.external_inference, ExternalInferenceGateway)
            tables = set(inspect(c.operational_engine).get_table_names())
            assert {
                "approval",
                "external_inference_proposal",
                "external_inference_authorization",
                "external_inference_record",
            } <= tables
            assert c.readiness().missing == ()
            assert not [w for w in c.readiness().warnings if "external" in w]
        container.close()  # a second close is harmless
        with build(provisional(tmp_path / "d"), SECRET_ENV) as again:  # and it starts again
            assert again.readiness().ready is True

    def test_readiness_names_what_an_enabled_path_lacks(self, tmp_path: Path) -> None:
        bare = external_on(
            provisional(
                tmp_path / "d", external_max_payload_bytes=None, external_max_response_bytes=None
            ),
            approver_role=None,
            allowed_classifications=(),
        )
        with build(bare, SECRET_ENV) as c:
            readiness = c.readiness()
            assert readiness.ready is False
            assert [m for m in readiness.missing if "external" in m] == [
                "external_inference.approver_role",
                "external_inference.allowed_classifications",
                "safety.external_max_payload_bytes",
                "safety.external_max_response_bytes",
            ]
            assert EXTERNAL_NO_TRANSPORT in readiness.warnings

    def test_a_fully_decided_enabled_path_is_ready_with_a_warning(self, tmp_path: Path) -> None:
        with build(enabled_settings(tmp_path / "d"), SECRET_ENV) as c:
            assert c.readiness().missing == ()
            assert EXTERNAL_NO_TRANSPORT in c.readiness().warnings
            assert EXTERNAL_NO_DIGEST_KEY not in c.readiness().warnings
        no_key = enabled_settings(tmp_path / "e").model_copy(
            update={"external_digest_key_ref": None}
        )
        with build(no_key, SECRET_ENV) as c:
            assert c.readiness().missing == ()
            assert EXTERNAL_NO_DIGEST_KEY in c.readiness().warnings

    def test_an_unusable_digest_key_is_missing(self, tmp_path: Path) -> None:
        with build(provisional(tmp_path / "d"), without(DIGEST_ENV)) as c:
            assert "external_digest_key_ref (unresolvable)" in c.readiness().missing
        short = {**SECRET_ENV, DIGEST_ENV: "short"}
        with build(provisional(tmp_path / "e"), short) as c:
            assert any(
                m.startswith("external_digest_key_ref (shorter than") for m in c.readiness().missing
            )

    def test_an_unset_expiry_window_means_nothing_can_be_requested(self, tmp_path: Path) -> None:
        with build(provisional(tmp_path / "d", approval_ttl_seconds=None), SECRET_ENV) as c:
            assert "safety.approval_ttl_seconds" in c.readiness().missing
            with pytest.raises(ApprovalFault) as refused:
                c.approvals.request(
                    **SUBJECT,
                    requested_by="agent_x",
                    requested_by_type=ActorType.AGENT,
                    required_roles=(Role.SYSTEM_OWNER,),
                    target={},
                )
            assert refused.value.reason is ApprovalReason.TTL_UNSET

    def test_the_expiry_window_is_the_configured_one(self, tmp_path: Path) -> None:
        with build(provisional(tmp_path / "d", approval_ttl_seconds=90), SECRET_ENV) as c:
            record = agent_request(c, first_admin(c))
            assert record.expires_at - record.requested_at == timedelta(seconds=90)

    def test_self_approval_follows_the_setting(self, tmp_path: Path) -> None:
        for name, allowed in (("off", False), ("on", True)):
            settings = provisional(tmp_path / name, allow_self_approval=allowed)
            with build(settings, SECRET_ENV) as c:
                admin = first_admin(c)
                second = human(c, admin, "Second admin", Role.SECURITY_ADMIN)
                owner = human(c, second, "Owner", Role.SYSTEM_OWNER)
                record = c.approvals.request(
                    **SUBJECT,
                    requested_by=owner.actor_id,
                    requested_by_type=ActorType.HUMAN,
                    required_roles=(Role.SYSTEM_OWNER,),
                    target={},
                )
                if allowed:
                    assert c.approvals.approve(record.approval_id, owner).self_approved is True
                else:
                    with pytest.raises(ApprovalFault) as refused:
                        c.approvals.approve(record.approval_id, owner)
                    assert refused.value.reason is ApprovalReason.SELF_APPROVAL

    def test_decision_notes_go_through_the_redactor(self, tmp_path: Path) -> None:
        with build(provisional(tmp_path / "d"), SECRET_ENV) as c:
            admin = first_admin(c)
            owner = human(c, admin, "Owner", Role.SYSTEM_OWNER)
            record = agent_request(c, admin)
            secret = SECRET_ENV["CISO_SECRET_EVIDENCE_KEY"]
            done = c.approvals.approve(record.approval_id, owner, note=f"see {secret} now")
            assert secret not in done.decision_note
            assert done.decision_note.startswith("see ")


@pytest.fixture
def world(tmp_path: Path) -> object:
    with build(provisional(tmp_path / "d"), SECRET_ENV, FixedClock()) as container:
        admin = first_admin(container)
        owner = human(container, admin, "Owner", Role.SYSTEM_OWNER)
        yield container, admin, owner


def forge(container: Container, genuine: Approval, **changes: object) -> str:
    """Insert, by SQL, a copy of an approved row under a new id. Returns the new id."""
    forged_id = "apr_" + "0" * 25 + "F"
    with container.operational_engine.begin() as conn:
        row = conn.execute(
            select(approval_table).where(approval_table.c.approval_id == genuine.approval_id)
        ).one()
        values = {**dict(row._mapping), "approval_id": forged_id, **changes}
        conn.execute(approval_table.insert().values(**values))
    return forged_id


def reason_when_used(container: Container, approval_id: str) -> ApprovalReason:
    with pytest.raises(ApprovalFault) as refused:
        container.approvals.consume(approval_id, **SUBJECT, **BROKER)
    assert container.approvals.get(approval_id).status is ApprovalStatus.APPROVED  # not spent
    return refused.value.reason


class TestAuditReadBack:
    """End to end through the real `AuditLog`: a grant counts only if its audit record
    exists and says so (gap G12)."""

    def test_the_adapter_round_trips_a_real_grant(self, world: object) -> None:
        container, admin, owner = world  # type: ignore[misc]
        record = agent_request(container, admin)
        approved = container.approvals.approve(record.approval_id, owner)
        reader = AuditRecordReader(container.audit, container.audit_engine)
        assert isinstance(reader, AuditRecordLookup)
        view = reader.find(approved.decision_audit_ref or "")
        assert view is not None
        assert (view.action, view.outcome) == ("approval.approve", AuditOutcome.SUCCESS)
        assert (view.target, view.actor_id) == (approved.ref, owner.actor_id)
        assert reader.find("aud_00000000000000000000000000") is None
        assert reader.find("") is None
        used = container.approvals.consume(record.approval_id, **SUBJECT, **BROKER)
        assert used.status is ApprovalStatus.CONSUMED

    def test_a_forged_approved_row_is_not_usable(self, world: object) -> None:
        container, admin, owner = world  # type: ignore[misc]
        record = agent_request(container, admin)
        genuine = container.approvals.approve(record.approval_id, owner)
        filed = container.audit.query(limit=10, action_prefix="approval.request")[-1]

        # (a) a copy that points at the genuine grant of ANOTHER approval
        forged = forge(container, genuine)
        assert reason_when_used(container, forged) is ApprovalReason.GRANT_NOT_AUDITED
        # (b) the same copy pointing at a real record that is not a grant
        with container.operational_engine.begin() as conn:
            conn.execute(
                approval_table.update()
                .where(approval_table.c.approval_id == forged)
                .values(decision_audit_ref=filed.id)
            )
        assert reason_when_used(container, forged) is ApprovalReason.GRANT_NOT_AUDITED
        # (c) and at an id the log does not hold
        with container.operational_engine.begin() as conn:
            conn.execute(
                approval_table.update()
                .where(approval_table.c.approval_id == forged)
                .values(decision_audit_ref="aud_00000000000000000000000000")
            )
        assert reason_when_used(container, forged) is ApprovalReason.GRANT_NOT_AUDITED
        denied = [
            r
            for r in container.audit.query(limit=50, action_prefix="approval.consume")
            if r.outcome is AuditOutcome.DENIED
        ]
        assert len(denied) == 3
        # The genuine one still works: the check tells them apart, it does not refuse all.
        used = container.approvals.consume(genuine.approval_id, **SUBJECT, **BROKER)
        assert used.status is ApprovalStatus.CONSUMED

    def test_a_grant_record_written_by_sql_with_a_wrong_hash_fails_closed(
        self, world: object
    ) -> None:
        container, admin, owner = world  # type: ignore[misc]
        record = agent_request(container, admin)
        genuine = container.approvals.approve(record.approval_id, owner)
        fake_ref = "aud_" + "0" * 25 + "F"
        forged = forge(container, genuine, decision_audit_ref=fake_ref)
        with container.audit_engine.begin() as conn:
            head = conn.execute(
                select(audit_record).order_by(audit_record.c.seq.desc()).limit(1)
            ).one()
            conn.execute(
                audit_record.insert().values(
                    id=fake_ref,
                    seq=head.seq + 1,
                    occurred_at=head.occurred_at,
                    actor_id=owner.actor_id,
                    actor_type="human",
                    action="approval.approve",
                    target=f"approval:{forged}",
                    outcome="success",
                    correlation_id="",
                    details="{}",
                    prev_hash=head.hash,
                    hash="f" * 64,
                )
            )
        # The reader itself refuses the row: it does not hash to its own `hash` column.
        with pytest.raises(IntegrityFailure):
            AuditRecordReader(container.audit, container.audit_engine).find(fake_ref)
        assert reason_when_used(container, forged) is ApprovalReason.AUDIT_UNAVAILABLE

    def test_an_unavailable_audit_log_raises(self, world: object) -> None:
        container, _, _ = world  # type: ignore[misc]
        reader = AuditRecordReader(UnavailableAuditLog("not built"), container.audit_engine)
        with pytest.raises(FailClosed):
            reader.find("aud_00000000000000000000000000")

    def test_an_unreadable_audit_database_raises(self, world: object) -> None:
        container, admin, owner = world  # type: ignore[misc]
        record = agent_request(container, admin)
        container.approvals.approve(record.approval_id, owner)
        with container.audit_engine.begin() as conn:
            conn.exec_driver_sql("ALTER TABLE audit_record RENAME TO audit_record_gone")
        try:
            assert reason_when_used(container, record.approval_id) is (
                ApprovalReason.AUDIT_UNAVAILABLE
            )
        finally:
            with container.audit_engine.begin() as conn:
                conn.exec_driver_sql("ALTER TABLE audit_record_gone RENAME TO audit_record")


def test_signed_in_principals_carry_their_issuer(tmp_path: Path) -> None:
    """What the separation-of-duties rule reads: sign-in names who minted the token."""
    with build(provisional(tmp_path / "d"), SECRET_ENV) as c:
        admin = first_admin(c)
        owner = human(c, admin, "Owner", Role.SYSTEM_OWNER)
        assert isinstance(owner, Principal)
        assert owner.credential_issued_by == admin.actor_id
