from __future__ import annotations

import socket
from typing import Any

import pytest
from pydantic import ValidationError
from sqlalchemy import Engine, select
from tests.conftest import EgressAttempt
from tests.fakes.core import FakeAudit, FakeKillSwitch, FakeRedactor, FakeSecrets

from ciso.common.classification import UNKNOWN_LABEL, ClassificationScheme
from ciso.common.db import (
    create_db_engine,
    init_operational_schema,
    register_schema,
    registered_schemas,
    schema_version,
)
from ciso.common.enums import ActorType, AuditOutcome, Environment, KillCapability
from ciso.common.errors import FailClosed, NotFound, ValidationFailed
from ciso.common.protocols import (
    AuditEvent,
    AuditSink,
    KillSwitchReader,
    Redactor,
    SecretResolver,
)

pytestmark = pytest.mark.unit


class TestClassificationScheme:
    def test_unknown_outranks_every_configured_label(
        self, classification: ClassificationScheme
    ) -> None:
        top = classification.labels[-1]
        assert classification.rank(UNKNOWN_LABEL) > classification.rank(top)
        assert classification.rank(None) == classification.rank(UNKNOWN_LABEL)
        assert classification.rank("") == classification.rank(UNKNOWN_LABEL)

    def test_unknown_never_passes_a_ceiling(self, classification: ClassificationScheme) -> None:
        for ceiling in classification.labels:
            assert not classification.is_at_most(UNKNOWN_LABEL, ceiling)
            assert not classification.is_at_most(None, ceiling)

    def test_ceiling_compares_by_order(self, classification: ClassificationScheme) -> None:
        assert classification.is_at_most("public", "internal")
        assert classification.is_at_most("internal", "internal")
        assert not classification.is_at_most("restricted", "internal")

    def test_unrecognised_label_is_an_error_not_a_guess(
        self, classification: ClassificationScheme
    ) -> None:
        with pytest.raises(ValidationFailed):
            classification.rank("top_secret")
        with pytest.raises(ValidationFailed):
            classification.is_at_most("public", UNKNOWN_LABEL)

    def test_most_sensitive_of_a_mixed_set(self, classification: ClassificationScheme) -> None:
        assert classification.most_sensitive(["public", "confidential"]) == "confidential"
        assert classification.most_sensitive(["public", None]) == UNKNOWN_LABEL
        assert classification.most_sensitive([]) == UNKNOWN_LABEL

    @pytest.mark.parametrize(
        "labels",
        [(), ("a", "a"), ("unknown",), ("Has Space",), ("public", "unknown")],
    )
    def test_bad_schemes_are_rejected(self, labels: tuple[str, ...]) -> None:
        with pytest.raises(ValidationError):
            ClassificationScheme(labels=labels)

    def test_no_label_names_are_built_into_the_source(self) -> None:
        """OD-09 is open: the platform must not ship a classification scheme."""
        assert ClassificationScheme(labels=("a1", "b2")).rank("b2") == 1


class TestEnvironment:
    def test_third_party_and_customer_owned_are_never_scannable(self) -> None:
        assert Environment.THIRD_PARTY.never_scannable
        assert Environment.CUSTOMER_OWNED.never_scannable
        assert not Environment.PRODUCTION.never_scannable
        assert not Environment.UNKNOWN.never_scannable


class TestSchemaVersions:
    def test_registered_modules_are_recorded_once(self) -> None:
        register_schema("unit_test_module", 1)
        engine: Engine = create_db_engine(None)
        try:
            init_operational_schema(engine)
            init_operational_schema(engine)
            with engine.connect() as conn:
                rows = conn.execute(
                    select(schema_version).where(schema_version.c.module == "unit_test_module")
                ).all()
            assert [(row.module, row.version) for row in rows] == [("unit_test_module", 1)]
            assert registered_schemas()["unit_test_module"] == 1
        finally:
            engine.dispose()

    def test_version_mismatch_refuses_to_start(self) -> None:
        register_schema("unit_test_mismatch", 1)
        engine = create_db_engine(None)
        try:
            init_operational_schema(engine)
            register_schema("unit_test_mismatch", 2)
            with pytest.raises(RuntimeError, match="no migration path"):
                init_operational_schema(engine)
        finally:
            register_schema("unit_test_mismatch", 1)
            engine.dispose()

    def test_version_zero_is_rejected(self) -> None:
        with pytest.raises(ValueError, match="starts at 1"):
            register_schema("x", 0)


def _event(action: str = "test.action", **details: Any) -> AuditEvent:
    return AuditEvent(
        actor_id="human_admin",
        actor_type=ActorType.HUMAN,
        action=action,
        outcome=AuditOutcome.SUCCESS,
        details=details,
    )


class TestFakesSatisfyTheProtocols:
    def test_runtime_protocol_checks(self) -> None:
        assert isinstance(FakeAudit(), AuditSink)
        assert isinstance(FakeKillSwitch(), KillSwitchReader)
        assert isinstance(FakeSecrets(), SecretResolver)
        assert isinstance(FakeRedactor(), Redactor)

    def test_fake_audit_records_and_can_fail(self, audit: FakeAudit) -> None:
        receipt = audit.append(_event("a.b", ref="x"))
        assert receipt.seq == 1
        assert audit.actions() == ["a.b"]
        audit.fail = True
        with pytest.raises(FailClosed):
            audit.append(_event())
        assert len(audit.events) == 1

    def test_fake_killswitch_reports_blocked_when_broken(self, killswitch: FakeKillSwitch) -> None:
        assert not killswitch.is_blocked(KillCapability.WRITES)
        killswitch.blocked.add(KillCapability.WRITES)
        assert killswitch.is_blocked(KillCapability.WRITES)
        assert not killswitch.is_blocked(KillCapability.ACTIVE_SCANS)
        killswitch.broken = True
        assert killswitch.is_blocked(KillCapability.ACTIVE_SCANS)

    def test_fake_secrets_never_return_an_empty_value(self) -> None:
        secrets = FakeSecrets({"secret://a": "s3cr3t-value"})
        assert secrets.get("secret://a").reveal() == "s3cr3t-value"
        assert "s3cr3t" not in repr(secrets.get("secret://a"))
        with pytest.raises(NotFound):
            secrets.get("secret://missing")

    def test_fake_redactor_walks_nested_values(self) -> None:
        redactor = FakeRedactor("tok-123")
        cleaned = redactor.redact_value({"a": ["x tok-123 y", {"b": "tok-123"}], "n": 1})
        assert cleaned == {"a": ["x [REDACTED] y", {"b": "[REDACTED]"}], "n": 1}


class TestEgressGuard:
    def test_non_loopback_connect_raises_and_is_recorded(self, egress_guard: list[Any]) -> None:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            with pytest.raises(EgressAttempt):
                sock.connect(("203.0.113.10", 443))
            with pytest.raises(EgressAttempt):
                sock.connect_ex(("example.invalid", 443))
        finally:
            sock.close()
        assert egress_guard == [("203.0.113.10", 443), ("example.invalid", 443)]

    def test_loopback_is_allowed(self, egress_guard: list[Any]) -> None:
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            server.bind(("127.0.0.1", 0))
            server.listen(1)
            client.connect(server.getsockname())
        finally:
            client.close()
            server.close()
        assert egress_guard == []
