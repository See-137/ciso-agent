"""T1.11: action envelope, operation catalog and envelope validation (blueprint 9.4)."""

from __future__ import annotations

from datetime import timedelta

import pytest
from pydantic import BaseModel, ValidationError
from tests.policy.conftest import (
    L3_OP,
    TTL,
    EnvelopeBuilder,
    HostArgs,
    NoArgs,
    sample_specs,
    scope_for,
)

from ciso.common.clock import FixedClock
from ciso.common.enums import ActorType, AuthorityLevel, Environment
from ciso.common.errors import ValidationFailed
from ciso.policy import (
    ActionEnvelope,
    EnvelopeRejected,
    EnvelopeScope,
    EnvelopeValidator,
    OperationCatalog,
    OperationSpec,
    Precondition,
    ReasonCode,
    is_protected_name,
)

pytestmark = pytest.mark.policy

REQUEST_FIELDS = {
    "request_id",
    "idempotency_key",
    "requesting_component",
    "actor_id",
    "actor_type",
    "target_resource",
    "scope",
    "operation",
    "arguments",
    "purpose",
    "supporting_evidence",
    "risk_class",
    "authority_level",
    "preconditions",
    "expiry",
    "rollback_plan",
    "verification_plan",
}


def test_every_request_field_of_9_4_is_present() -> None:
    assert set(ActionEnvelope.model_fields) == REQUEST_FIELDS
    assert set(EnvelopeScope.model_fields) == {
        "resource",
        "tenant",
        "environment",
        "boundary",
        "classification",
    }


@pytest.mark.parametrize(
    "result_field",
    ["policy_decision", "approver", "execution_result", "residual_risk", "authenticated_actor"],
)
def test_result_and_principal_fields_cannot_be_prefilled(
    build: EnvelopeBuilder, result_field: str
) -> None:
    with pytest.raises(ValidationError, match="Extra inputs"):
        build(**{result_field: "allow"})


def test_unknown_extra_field_is_rejected(build: EnvelopeBuilder) -> None:
    with pytest.raises(ValidationError):
        build(command="rm -rf /")
    assert build().operation == "asset.read"


def test_anonymous_actor_type_is_rejected(build: EnvelopeBuilder) -> None:
    with pytest.raises(ValidationError, match="anonymous"):
        build(actor_type=ActorType.ANONYMOUS)
    assert build(actor_type=ActorType.SERVICE).actor_type is ActorType.SERVICE


def test_expiry_is_required(build: EnvelopeBuilder) -> None:
    data = build().model_dump()
    del data["expiry"]
    with pytest.raises(ValidationError, match="expiry"):
        ActionEnvelope(**data)


def test_naive_expiry_is_rejected(build: EnvelopeBuilder) -> None:
    with pytest.raises(ValidationError):
        build(expiry=build().expiry.replace(tzinfo=None))


def test_target_and_evidence_must_be_entity_refs(build: EnvelopeBuilder) -> None:
    with pytest.raises(ValidationError):
        build(target_resource="not a ref")
    with pytest.raises(ValidationError):
        build(supporting_evidence=("no-colon",))


def test_envelope_is_frozen(build: EnvelopeBuilder) -> None:
    envelope = build()
    with pytest.raises(ValidationError):
        envelope.operation = "network.isolate_host"  # type: ignore[misc]


def test_arguments_cannot_be_mutated_in_place(build: EnvelopeBuilder) -> None:
    envelope = build("ticket.create_draft", arguments={"channel": "c:1", "title": "t", "x": [1]})
    before = envelope.envelope_hash()
    with pytest.raises(TypeError):
        envelope.arguments["channel"] = "email:outside"  # type: ignore[index]
    with pytest.raises(AttributeError):
        envelope.arguments["x"].append(2)  # type: ignore[index,union-attr]
    assert envelope.envelope_hash() == before
    assert envelope.arguments["channel"] == "c:1"


def test_hash_is_over_the_frozen_content(build: EnvelopeBuilder) -> None:
    source = {"channel": "c:1", "title": "t"}
    envelope = build("ticket.create_draft", arguments=source)
    before = envelope.envelope_hash()
    source["channel"] = "email:outside"
    assert envelope.arguments["channel"] == "c:1"
    assert envelope.envelope_hash() == before


@pytest.mark.parametrize(
    "field_value",
    [
        {"purpose": "bad \ud800 text"},
        {"arguments": {"title": "\udfff", "channel": "c:1"}},
        {"idempotency_key": "idem-\ud800"},
    ],
)
def test_strings_that_are_not_utf8_encodable_are_rejected(
    build: EnvelopeBuilder, field_value: dict[str, object]
) -> None:
    with pytest.raises(ValidationError):
        build("ticket.create_draft", **field_value)
    assert build("ticket.create_draft", purpose="ünïcode is fine ✓").purpose.startswith("ü")


# --- catalog -----------------------------------------------------------------------


def test_catalog_rejects_duplicate_names() -> None:
    specs = sample_specs()
    with pytest.raises(ValidationFailed, match="duplicate"):
        OperationCatalog([*specs, specs[0]])


@pytest.mark.parametrize(
    "name",
    [
        "policy.disable",
        "policies.update",
        "rule.edit",
        "roles.revoke",
        "role.assign",
        "role_assignments.add",
        "identity.role.assign",
        "approvals.decide",
        "approval.grant",
        "approvers.change",
        "playbook.enable",
        "playbooks.approve",
        "connector.add",
        "model.swap",
        "models.update",
        "audit.delete",
        "audit_log.purge",
        "killswitch.release",
        "permissions.grant",
        "prompt.update",
        "finding.suppress",
        "findings.dismiss",
        "alert.mute_all",
    ],
)
def test_protected_names_must_be_marked_protected(name: str) -> None:
    assert is_protected_name(name)
    with pytest.raises(ValidationError, match="protected"):
        OperationSpec(
            name=name, authority_level=AuthorityLevel.L4_HIGH_IMPACT, args_model=NoArgs, writes=True
        )
    ok = OperationSpec(
        name=name,
        authority_level=AuthorityLevel.L4_HIGH_IMPACT,
        args_model=NoArgs,
        writes=True,
        protected=True,
    )
    assert ok.protected


@pytest.mark.parametrize("name", ["asset.read", "ticket.create_draft", "finding.investigate"])
def test_ordinary_names_are_not_protected(name: str) -> None:
    assert not is_protected_name(name)


def test_protected_operation_cannot_be_agent_requestable() -> None:
    with pytest.raises(ValidationError, match="agent_requestable"):
        OperationSpec(
            name="policy.update",
            authority_level=AuthorityLevel.L4_HIGH_IMPACT,
            args_model=NoArgs,
            writes=True,
            protected=True,
            agent_requestable=True,
        )


def test_agent_requestable_defaults_to_false() -> None:
    spec = OperationSpec(
        name="asset.tag", authority_level=AuthorityLevel.L2_COORDINATE, args_model=NoArgs
    )
    assert spec.agent_requestable is False


def test_protected_operation_is_always_a_write() -> None:
    with pytest.raises(ValidationError, match="write"):
        OperationSpec(
            name="roles.revoke",
            authority_level=AuthorityLevel.L4_HIGH_IMPACT,
            args_model=NoArgs,
            protected=True,
        )


def test_channel_argument_must_exist_in_schema() -> None:
    with pytest.raises(ValidationError, match="channel"):
        OperationSpec(
            name="notify.owner",
            authority_level=AuthorityLevel.L2_COORDINATE,
            args_model=HostArgs,
            writes=True,
            channel_argument="channel",
        )


def test_args_model_must_be_closed() -> None:
    class OpenArgs(BaseModel):
        x: int = 0

    with pytest.raises(ValidationError):
        OperationSpec(
            name="asset.open",
            authority_level=AuthorityLevel.L0_OBSERVE,
            args_model=OpenArgs,  # type: ignore[arg-type]
        )


# --- validator ---------------------------------------------------------------------


def _validator(
    catalog: OperationCatalog, clock: FixedClock, ttl: timedelta | None = TTL
) -> EnvelopeValidator:
    return EnvelopeValidator(catalog, clock, ttl, risk_classes=("low", "medium", "high"))


def _code(exc: pytest.ExceptionInfo[EnvelopeRejected]) -> ReasonCode:
    return exc.value.code


def test_unregistered_operation_is_rejected(
    build: EnvelopeBuilder, catalog: OperationCatalog, clock: FixedClock
) -> None:
    validator = _validator(catalog, clock)
    with pytest.raises(EnvelopeRejected) as exc:
        validator.validate(build("shell.run", arguments={"cmd": "whoami"}))
    assert _code(exc) is ReasonCode.UNKNOWN_OPERATION
    assert validator.validate(build("asset.read")).spec.name == "asset.read"


def test_arguments_are_validated_against_the_schema(
    build: EnvelopeBuilder, catalog: OperationCatalog, clock: FixedClock
) -> None:
    validator = _validator(catalog, clock)
    with pytest.raises(EnvelopeRejected) as exc:
        validator.validate(build("network.isolate_host", arguments={"host": 5}))
    assert _code(exc) is ReasonCode.INVALID_ARGUMENTS
    with pytest.raises(EnvelopeRejected) as exc:
        validator.validate(build("network.isolate_host", arguments={"host": "h", "then": "x"}))
    assert _code(exc) is ReasonCode.INVALID_ARGUMENTS
    checked = validator.validate(build("network.isolate_host"))
    assert isinstance(checked.arguments, HostArgs)
    assert checked.arguments.host == "host:web-1"


def test_authority_level_cannot_be_understated(
    build: EnvelopeBuilder, catalog: OperationCatalog, clock: FixedClock
) -> None:
    validator = _validator(catalog, clock)
    with pytest.raises(EnvelopeRejected) as exc:
        validator.validate(
            build("network.isolate_host", authority_level=AuthorityLevel.L2_COORDINATE)
        )
    assert _code(exc) is ReasonCode.AUTHORITY_UNDERSTATED
    checked = validator.validate(build("network.isolate_host"))
    assert checked.authority_level is AuthorityLevel.L4_HIGH_IMPACT


def test_overstated_level_is_kept_not_lowered(
    build: EnvelopeBuilder, catalog: OperationCatalog, clock: FixedClock
) -> None:
    checked = _validator(catalog, clock).validate(
        build("asset.read", authority_level=AuthorityLevel.L4_HIGH_IMPACT)
    )
    assert checked.authority_level is AuthorityLevel.L4_HIGH_IMPACT
    assert checked.spec.authority_level is AuthorityLevel.L0_OBSERVE


def test_expiry_must_be_in_the_future(
    build: EnvelopeBuilder, catalog: OperationCatalog, clock: FixedClock
) -> None:
    validator = _validator(catalog, clock)
    with pytest.raises(EnvelopeRejected) as exc:
        validator.validate(build(expiry=clock.now()))
    assert _code(exc) is ReasonCode.ENVELOPE_EXPIRED
    assert validator.validate(build(expiry=clock.now() + timedelta(seconds=1)))


def test_envelope_expires_as_time_passes(
    build: EnvelopeBuilder, catalog: OperationCatalog, clock: FixedClock
) -> None:
    validator = _validator(catalog, clock)
    envelope = build()
    assert validator.validate(envelope)
    clock.advance(minutes=11)
    with pytest.raises(EnvelopeRejected) as exc:
        validator.validate(envelope)
    assert _code(exc) is ReasonCode.ENVELOPE_EXPIRED


def test_expiry_is_capped_by_ttl(
    build: EnvelopeBuilder, catalog: OperationCatalog, clock: FixedClock
) -> None:
    validator = _validator(catalog, clock)
    with pytest.raises(EnvelopeRejected) as exc:
        validator.validate(build(expiry=clock.now() + TTL + timedelta(seconds=1)))
    assert _code(exc) is ReasonCode.ENVELOPE_TTL_EXCEEDED
    assert validator.validate(build(expiry=clock.now() + TTL))


def test_unset_ttl_refuses_writes_but_not_reads(
    build: EnvelopeBuilder, catalog: OperationCatalog, clock: FixedClock
) -> None:
    validator = _validator(catalog, clock, ttl=None)
    with pytest.raises(EnvelopeRejected) as exc:
        validator.validate(build("ticket.create_draft"))
    assert _code(exc) is ReasonCode.ENVELOPE_TTL_UNSET
    assert validator.validate(build("asset.read")).spec.writes is False


def test_unknown_risk_class_is_rejected(
    build: EnvelopeBuilder, catalog: OperationCatalog, clock: FixedClock
) -> None:
    validator = _validator(catalog, clock)
    with pytest.raises(EnvelopeRejected) as exc:
        validator.validate(build(risk_class="trivial"))
    assert _code(exc) is ReasonCode.UNKNOWN_RISK_CLASS
    assert validator.validate(build(risk_class="high"))


def test_writing_operation_needs_evidence(
    build: EnvelopeBuilder, catalog: OperationCatalog, clock: FixedClock
) -> None:
    validator = _validator(catalog, clock)
    with pytest.raises(EnvelopeRejected) as exc:
        validator.validate(build("ticket.create_draft", supporting_evidence=()))
    assert _code(exc) is ReasonCode.EVIDENCE_REQUIRED
    assert validator.validate(build("asset.read", supporting_evidence=()))


def test_l3_needs_rollback_and_verification_plans(
    build: EnvelopeBuilder, catalog: OperationCatalog, clock: FixedClock
) -> None:
    validator = _validator(catalog, clock)
    for missing in ("rollback_plan", "verification_plan"):
        with pytest.raises(EnvelopeRejected) as exc:
            validator.validate(build(L3_OP, **{missing: None}))
        assert _code(exc) is ReasonCode.PLAN_REQUIRED
    assert validator.validate(build(L3_OP))


def test_channel_is_read_from_validated_arguments(
    build: EnvelopeBuilder, catalog: OperationCatalog, clock: FixedClock
) -> None:
    checked = _validator(catalog, clock).validate(build("ticket.create_draft"))
    assert checked.channel == "outbox:security"
    assert _validator(catalog, clock).validate(build("asset.read")).channel is None


# --- hashing -----------------------------------------------------------------------


def test_hash_is_stable_under_key_order(build: EnvelopeBuilder) -> None:
    a = build("asset.read", arguments={"fields": ["a"]})
    data = a.model_dump()
    reordered = ActionEnvelope(**dict(reversed(list(data.items()))))
    assert a.envelope_hash() == reordered.envelope_hash()
    args_a = build("ticket.create_draft", arguments={"channel": "c:1", "title": "t"})
    args_b = build(
        "ticket.create_draft",
        arguments={"title": "t", "channel": "c:1"},
        request_id=args_a.request_id,
    )
    assert args_a.envelope_hash() == args_b.envelope_hash()
    assert len(a.envelope_hash()) == 64


CHANGES: dict[str, object] = {
    "request_id": "req_01JCZZZZZZZZZZZZZZZZZZZZZZ",
    "idempotency_key": "idem-0002",
    "requesting_component": "scheduler",
    "actor_id": "agent_other",
    "actor_type": ActorType.SERVICE,
    "target_resource": "app:payroll",
    "scope": scope_for("app:billing", Environment.PRODUCTION),
    "operation": "finding.investigate",
    "arguments": {"fields": ["name"]},
    "purpose": "something else",
    "supporting_evidence": ("finding:f2",),
    "risk_class": "high",
    "authority_level": AuthorityLevel.L1_INVESTIGATE,
    "preconditions": (Precondition(name="still_open", ref="finding:f1", expectation="open"),),
    "rollback_plan": None,
    "verification_plan": None,
}


@pytest.mark.parametrize("field", sorted(REQUEST_FIELDS))
def test_hash_changes_when_any_request_field_changes(build: EnvelopeBuilder, field: str) -> None:
    base = build()
    values = dict(CHANGES)
    values["expiry"] = base.expiry + timedelta(seconds=1)
    data = base.model_dump()
    data[field] = values[field]
    changed = ActionEnvelope(**data)
    assert getattr(changed, field) != getattr(base, field)
    assert changed.envelope_hash() != base.envelope_hash()


def test_classification_is_part_of_the_hash(build: EnvelopeBuilder) -> None:
    base = build()
    other = build(
        request_id=base.request_id,
        scope=base.scope.model_copy(update={"classification": "restricted"}),
    )
    assert other.envelope_hash() != base.envelope_hash()
