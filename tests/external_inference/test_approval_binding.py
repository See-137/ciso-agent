"""External inference steps 4 to 7: the approval binds one exact request, is used once,
and what happened is recorded without any text (blueprint 8.4; plan row T2.7; gaps G2,
G3, G12).

Every refusal is asserted by its reason code and by the spy transport's call count, and
each has a neighbouring test in which the allowed path sends.
"""

from __future__ import annotations

import hmac
from collections.abc import Callable
from typing import Any

import pytest
from sqlalchemy import Engine, select, update
from tests.external_inference.conftest import (
    ANSWER_MARKER,
    APPROVER_ROLE,
    MARKER_TEXT,
    MODEL,
    PROVIDER,
    PURPOSE,
    REGISTERED_SECRET,
    REQUESTER,
    SpyTransport,
    approval_rows,
    signed_in,
)
from tests.fakes.core import FakeAudit, FakePrincipals, FakeSecrets, make_principal

from ciso.approvals import (
    ApprovalForbidden,
    ApprovalReason,
    ApprovalService,
    ApprovalStatus,
)
from ciso.common.clock import FixedClock
from ciso.common.enums import ActorType, AuditOutcome, Role
from ciso.common.principal import Principal
from ciso.common.schemas import sha256_hex
from ciso.inference.external import (
    ACTION_AUTHORIZE,
    ACTION_TRANSMIT,
    APPROVAL_SUBJECT_KIND,
    ExternalGateRefused,
    ExternalInferenceGateway,
    ExternalRequestProposal,
    ExternalTransmitFailed,
    GateReason,
    PayloadPreview,
    TransmitOutcome,
    TransportResponse,
    approval_binding,
)
from ciso.inference.external.tables import (
    external_inference_authorization,
    external_inference_record,
)
from ciso.inference.records import UntrustedModelOutput

pytestmark = pytest.mark.external_inference

Gateways = Callable[..., ExternalInferenceGateway]
Proposals = Callable[..., ExternalRequestProposal]
Expected = Callable[..., PayloadPreview]

DIGEST_KEY = "k" * 40
OTHER_TEXT = "a different context item altogether"


def _approved(
    gateway: ExternalInferenceGateway,
    approvals: ApprovalService,
    approver: Principal,
    proposal: ExternalRequestProposal,
) -> str:
    made = gateway.request_approval(proposal, actor_id=REQUESTER)
    approvals.approve(made.approval_id, approver)
    return made.approval_id


def _refused(
    gateway: ExternalInferenceGateway, proposal: ExternalRequestProposal, approval_id: str
) -> ExternalGateRefused:
    with pytest.raises(ExternalGateRefused) as excinfo:
        gateway.transmit(proposal, approval_id, actor_id=REQUESTER)
    return excinfo.value


def _stored_text(engine: Engine, audit: FakeAudit) -> str:
    """Every value in both ledger tables and every audit event, as one string."""
    parts: list[str] = []
    with engine.begin() as conn:
        for table in (external_inference_authorization, external_inference_record):
            parts.extend(repr(tuple(row)) for row in conn.execute(select(table)))
    audit_text = "".join(repr(event.model_dump()) for event in audit.events)
    assert parts
    assert audit_text
    return "".join(parts) + "\x00" + audit_text


# --- step 4: authorize ---------------------------------------------------------------


def test_request_approval_binds_the_five_values_and_names_the_configured_role(
    make_gateway: Gateways, make_proposal: Proposals, expected: Expected, approvals: ApprovalService
) -> None:
    proposal = make_proposal()
    made = make_gateway().request_approval(proposal, actor_id=REQUESTER)
    approval = approvals.get(made.approval_id)
    assert approval.subject_kind == APPROVAL_SUBJECT_KIND == "external_inference"
    assert approval.subject_hash == approval_binding(expected(proposal)).subject_hash()
    assert dict(approval.binding) == {
        "request_id": proposal.request_id,
        "provider": PROVIDER,
        "model": MODEL,
        "purpose_sha256": sha256_hex(PURPOSE),
        "payload_sha256": expected(proposal).payload_hash,
    }
    assert approval.required_roles == (APPROVER_ROLE,)
    assert (approval.requested_by, approval.requested_by_type) == (REQUESTER, ActorType.HUMAN)
    assert approval.status is ApprovalStatus.PENDING


def test_authorization_row_holds_what_was_previewed_and_no_text(
    make_gateway: Gateways,
    make_proposal: Proposals,
    expected: Expected,
    engine: Engine,
    audit: FakeAudit,
) -> None:
    proposal = make_proposal()
    gateway = make_gateway()
    made = gateway.request_approval(proposal, actor_id=REQUESTER)
    stored = gateway.get_authorization(made.approval_id)
    assert stored == made
    assert stored is not None
    assert stored.payload_sha256 == expected(proposal).payload_hash
    assert stored.payload_bytes == len(expected(proposal).preview_bytes or b"")
    assert stored.payload_classification == "public"
    assert [(i.ref, i.classification) for i in stored.kept] == [("evidence:a1", "public")]
    assert stored.required_role is APPROVER_ROLE
    assert MARKER_TEXT in (expected(proposal).preview_bytes or b"").decode()
    everything = _stored_text(engine, audit)
    assert MARKER_TEXT not in everything
    # The purpose is in the database row (step 6 names it) but never in audit details.
    assert PURPOSE not in everything.split("\x00")[1]


def test_the_requester_cannot_approve_their_own_request(
    make_gateway: Gateways,
    make_proposal: Proposals,
    approvals: ApprovalService,
    principals: FakePrincipals,
    spy: SpyTransport,
) -> None:
    both = principals.register(make_principal("human_both", ActorType.HUMAN, APPROVER_ROLE))
    gateway = make_gateway()
    proposal = make_proposal(requester="human_both")
    made = gateway.request_approval(proposal, actor_id="human_both")
    with pytest.raises(ApprovalForbidden) as excinfo:
        approvals.approve(made.approval_id, signed_in(both))
    assert excinfo.value.reason is ApprovalReason.SELF_APPROVAL
    refusal = None
    with pytest.raises(ExternalGateRefused) as refused:
        gateway.transmit(proposal, made.approval_id, actor_id="human_both")
    refusal = refused.value
    assert refusal.reason is GateReason.APPROVAL_REFUSED
    assert refusal.approval_reason == ApprovalReason.NOT_APPROVED.value
    assert spy.calls == []


# --- steps 5 to 7: the allowed path ----------------------------------------------------


def test_transmit_sends_exactly_the_previewed_bytes_once(
    make_gateway: Gateways,
    make_proposal: Proposals,
    expected: Expected,
    approvals: ApprovalService,
    approver: Principal,
    spy: SpyTransport,
) -> None:
    proposal = make_proposal()
    gateway = make_gateway()
    approval_id = _approved(gateway, approvals, approver, proposal)
    result = gateway.transmit(proposal, approval_id, actor_id=REQUESTER)
    assert spy.calls == [(PROVIDER, MODEL, expected(proposal).preview_bytes)]
    assert approvals.get(approval_id).status is ApprovalStatus.CONSUMED
    assert result.request_id == proposal.request_id
    assert result.approval_ref == f"approval:{approval_id}"
    assert result.result_ref == f"external_result:{result.record_id}"


def test_result_is_wrapped_untrusted_and_redacted(
    make_gateway: Gateways,
    make_proposal: Proposals,
    approvals: ApprovalService,
    approver: Principal,
    spy: SpyTransport,
) -> None:
    spy.body = f"{ANSWER_MARKER} and the password is {REGISTERED_SECRET}".encode()
    proposal = make_proposal()
    gateway = make_gateway()
    result = gateway.transmit(
        proposal, _approved(gateway, approvals, approver, proposal), actor_id=REQUESTER
    )
    assert type(result.output) is UntrustedModelOutput
    with pytest.raises(TypeError):
        str(result.output)
    text = result.output.unsafe_text()
    assert ANSWER_MARKER in text
    assert REGISTERED_SECRET not in text
    assert "[REDACTED]" in text
    assert result.response_bytes == len(spy.body)


def test_record_carries_every_step_six_field(
    make_gateway: Gateways,
    make_proposal: Proposals,
    expected: Expected,
    approvals: ApprovalService,
    approver: Principal,
    clock: FixedClock,
) -> None:
    proposal = make_proposal()
    gateway = make_gateway()
    approval_id = _approved(gateway, approvals, approver, proposal)
    approved_at = clock.now()
    clock.advance(minutes=5)
    result = gateway.transmit(proposal, approval_id, actor_id=REQUESTER, correlation_id="c-9")
    record = gateway.get_record(result.record_id)
    assert record is not None
    assert gateway.records_for_request(proposal.request_id) == (record,)
    # approver, time
    assert record.approver == approver.actor_id == "human_owner"
    assert record.approver_roles == (APPROVER_ROLE,)
    assert record.approved_at == approved_at
    assert record.attempted_at == record.completed_at == clock.now()
    # provider, model, purpose
    assert (record.provider_name, record.model_name, record.purpose) == (PROVIDER, MODEL, PURPOSE)
    assert record.purpose_sha256 == sha256_hex(PURPOSE)
    # payload classification, payload hash / reference
    assert record.payload_classification == "public"
    assert record.payload_sha256 == expected(proposal).payload_hash
    assert record.payload_bytes == len(expected(proposal).preview_bytes or b"")
    assert record.request_id == proposal.request_id
    assert [(i.ref, i.classification) for i in record.kept] == [("evidence:a1", "public")]
    # policy decision
    decision = dict(record.policy_decision)
    assert decision["decision"] == "allow"
    assert decision["approver_role"] == APPROVER_ROLE.value
    assert decision["approval_subject_hash"] == approval_binding(expected(proposal)).subject_hash()
    assert list(decision["allowed_classifications"]) == ["internal", "public"]
    # returned-result reference
    assert record.result_ref == result.result_ref
    assert record.response_bytes == len(ANSWER_MARKER)
    assert dict(record.response_metadata) == {"provider_request_id": "r-123", "output_tokens": "7"}
    # who and what
    assert (record.requested_by, record.transmitted_by) == (REQUESTER, REQUESTER)
    assert record.approval_ref == f"approval:{approval_id}"
    assert record.outcome is TransmitOutcome.SENT
    assert record.correlation_id == "c-9"


def test_no_payload_or_answer_text_reaches_the_database_or_the_audit_log(
    make_gateway: Gateways,
    make_proposal: Proposals,
    expected: Expected,
    approvals: ApprovalService,
    approver: Principal,
    engine: Engine,
    audit: FakeAudit,
) -> None:
    proposal = make_proposal()
    gateway = make_gateway()
    gateway.transmit(
        proposal, _approved(gateway, approvals, approver, proposal), actor_id=REQUESTER
    )
    everything = _stored_text(engine, audit)
    assert MARKER_TEXT not in everything
    assert ANSWER_MARKER not in everything
    assert PURPOSE not in everything.split("\x00")[1]
    assert expected(proposal).payload_hash is not None
    assert expected(proposal).payload_hash in everything


def test_answer_digest_is_keyed_and_stored_only_when_a_key_is_configured(
    make_gateway: Gateways,
    make_proposal: Proposals,
    approvals: ApprovalService,
    approver: Principal,
) -> None:
    plain = make_gateway()
    first = make_proposal()
    result = plain.transmit(first, _approved(plain, approvals, approver, first), actor_id=REQUESTER)
    assert result.response_digest is None
    keyed = make_gateway(
        secrets=FakeSecrets({"secret://digest": DIGEST_KEY}), digest_key_ref="secret://digest"
    )
    second = make_proposal(via=keyed)
    result = keyed.transmit(
        second, _approved(keyed, approvals, approver, second), actor_id=REQUESTER
    )
    expected = hmac.new(DIGEST_KEY.encode(), ANSWER_MARKER.encode(), "sha256").hexdigest()
    assert result.response_digest == expected
    record = keyed.get_record(result.record_id)
    assert record is not None
    assert record.response_digest == expected


def test_unresolvable_digest_key_refuses_before_the_approval_is_spent(
    make_gateway: Gateways,
    make_proposal: Proposals,
    approvals: ApprovalService,
    approver: Principal,
    spy: SpyTransport,
) -> None:
    """The key is there while the request is proposed, filed and approved, then gone."""
    keys = {"secret://digest": DIGEST_KEY}
    gateway = make_gateway(secrets=FakeSecrets(keys), digest_key_ref="secret://digest")
    proposal = make_proposal(via=gateway)
    approval_id = _approved(gateway, approvals, approver, proposal)
    lost = make_gateway(secrets=FakeSecrets(), digest_key_ref="secret://digest")
    assert _refused(lost, proposal, approval_id).reason is GateReason.DIGEST_KEY_UNAVAILABLE
    assert spy.calls == []
    assert approvals.get(approval_id).status is ApprovalStatus.APPROVED
    with pytest.raises(ExternalGateRefused) as excinfo:
        lost.request_approval(proposal, actor_id=REQUESTER)
    assert excinfo.value.reason is GateReason.DIGEST_KEY_UNAVAILABLE
    gateway.transmit(proposal, approval_id, actor_id=REQUESTER)
    assert len(spy.calls) == 1


# --- the binding: any difference refuses (gap G2) ---------------------------------------


@pytest.mark.parametrize(
    "change",
    [
        {"text": OTHER_TEXT},
        {"provider": "provider-two"},
        {"model": "model-small-2"},
        {"purpose": "a different purpose"},
        {},
    ],
    ids=["payload", "provider", "model", "purpose", "request_id"],
)
def test_any_difference_from_what_was_authorized_refuses(
    make_gateway: Gateways,
    make_proposal: Proposals,
    expected: Expected,
    approvals: ApprovalService,
    approver: Principal,
    spy: SpyTransport,
    audit: FakeAudit,
    change: dict[str, str],
) -> None:
    approved = make_proposal()
    gateway = make_gateway()
    approval_id = _approved(gateway, approvals, approver, approved)
    refusal = _refused(gateway, make_proposal(**change), approval_id)
    assert refusal.reason is GateReason.BINDING_MISMATCH
    assert spy.calls == []
    assert approvals.get(approval_id).status is ApprovalStatus.APPROVED
    denied = audit.find(ACTION_TRANSMIT)[-1]
    assert (denied.outcome, denied.details["reason"]) == (AuditOutcome.DENIED, "binding_mismatch")
    # The approved proposal still goes through: the guard did not burn the approval.
    gateway.transmit(approved, approval_id, actor_id=REQUESTER)
    assert [call[2] for call in spy.calls] == [expected(approved).preview_bytes]


def test_a_preview_object_is_never_accepted_in_place_of_the_proposal(
    make_gateway: Gateways,
    make_proposal: Proposals,
    expected: Expected,
    approvals: ApprovalService,
    approver: Principal,
    spy: SpyTransport,
) -> None:
    """Even the genuine preview of the approved proposal: the gateway builds the bytes
    itself from the proposal and takes the hash over what it built."""
    approved = make_proposal()
    gateway = make_gateway()
    approval_id = _approved(gateway, approvals, approver, approved)
    genuine = expected(approved)
    assert genuine.sendable
    assert _refused(gateway, genuine, approval_id).reason is GateReason.PROPOSAL_INVALID  # type: ignore[arg-type]
    assert spy.calls == []
    assert approvals.get(approval_id).status is ApprovalStatus.APPROVED
    gateway.transmit(approved, approval_id, actor_id=REQUESTER)
    assert [call[2] for call in spy.calls] == [genuine.preview_bytes]


def test_the_approval_itself_also_refuses_a_different_subject(
    make_gateway: Gateways,
    make_proposal: Proposals,
    expected: Expected,
    approvals: ApprovalService,
    approver: Principal,
    spy: SpyTransport,
    engine: Engine,
) -> None:
    """Even if the gateway's own row is re-pointed, the approval covers one subject."""
    approved, other = make_proposal(), make_proposal(text=OTHER_TEXT)
    gateway = make_gateway()
    approval_id = _approved(gateway, approvals, approver, approved)
    with engine.begin() as conn:
        conn.execute(
            update(external_inference_authorization)
            .where(external_inference_authorization.c.approval_id == approval_id)
            .values(
                subject_hash=approval_binding(expected(other)).subject_hash(),
                payload_sha256=expected(other).payload_hash,
                request_id=other.request_id,
            )
        )
    refusal = _refused(gateway, other, approval_id)
    assert refusal.reason is GateReason.APPROVAL_REFUSED
    assert refusal.approval_reason == ApprovalReason.SUBJECT_MISMATCH.value
    assert spy.calls == []


def test_an_approval_with_no_authorization_row_is_not_accepted(
    make_gateway: Gateways,
    make_proposal: Proposals,
    expected: Expected,
    approvals: ApprovalService,
    approver: Principal,
    spy: SpyTransport,
) -> None:
    proposal = make_proposal()
    gateway = make_gateway()
    assert _refused(gateway, proposal, "apr_" + "0" * 26).reason is (
        GateReason.AUTHORIZATION_NOT_FOUND
    )
    # An approval filed straight at the approvals module, for the right subject.
    binding = approval_binding(expected(proposal))
    direct = approvals.request(
        subject_kind=APPROVAL_SUBJECT_KIND,
        subject_hash=binding.subject_hash(),
        binding={},
        requested_by=REQUESTER,
        requested_by_type=ActorType.HUMAN,
        required_roles=(APPROVER_ROLE,),
        target={},
    )
    approvals.approve(direct.approval_id, approver)
    assert _refused(gateway, proposal, direct.approval_id).reason is (
        GateReason.AUTHORIZATION_NOT_FOUND
    )
    assert spy.calls == []


# --- single use, expiry, rejection, revocation ------------------------------------------


def test_an_approval_is_used_once(
    make_gateway: Gateways,
    make_proposal: Proposals,
    approvals: ApprovalService,
    approver: Principal,
    spy: SpyTransport,
) -> None:
    proposal = make_proposal()
    gateway = make_gateway()
    approval_id = _approved(gateway, approvals, approver, proposal)
    gateway.transmit(proposal, approval_id, actor_id=REQUESTER)
    refusal = _refused(gateway, proposal, approval_id)
    assert refusal.reason is GateReason.APPROVAL_REFUSED
    assert refusal.approval_reason == ApprovalReason.ALREADY_CONSUMED.value
    assert len(spy.calls) == 1
    assert len(gateway.records_for_request(proposal.request_id)) == 1


def test_an_expired_approval_refuses(
    make_gateway: Gateways,
    make_proposal: Proposals,
    approvals: ApprovalService,
    approver: Principal,
    spy: SpyTransport,
    clock: FixedClock,
) -> None:
    proposal = make_proposal()
    gateway = make_gateway()
    approval_id = _approved(gateway, approvals, approver, proposal)
    clock.advance(hours=1)
    refusal = _refused(gateway, proposal, approval_id)
    assert (refusal.reason, refusal.approval_reason) == (GateReason.APPROVAL_REFUSED, "expired")
    assert spy.calls == []


@pytest.mark.parametrize(("decision", "code"), [("reject", "rejected"), (None, "not_approved")])
def test_a_rejected_or_undecided_approval_refuses(
    make_gateway: Gateways,
    make_proposal: Proposals,
    approvals: ApprovalService,
    approver: Principal,
    spy: SpyTransport,
    decision: str | None,
    code: str,
) -> None:
    proposal = make_proposal()
    gateway = make_gateway()
    made = gateway.request_approval(proposal, actor_id=REQUESTER)
    if decision is not None:
        getattr(approvals, decision)(made.approval_id, approver)
    refusal = _refused(gateway, proposal, made.approval_id)
    assert (refusal.reason, refusal.approval_reason) == (GateReason.APPROVAL_REFUSED, code)
    assert spy.calls == []


def test_approver_who_lost_the_role_since_approving_no_longer_counts(
    make_gateway: Gateways,
    make_proposal: Proposals,
    approvals: ApprovalService,
    approver: Principal,
    principals: FakePrincipals,
    spy: SpyTransport,
) -> None:
    proposal = make_proposal()
    gateway = make_gateway()
    approval_id = _approved(gateway, approvals, approver, proposal)
    principals.register(make_principal(approver.actor_id, ActorType.HUMAN, Role.EMPLOYEE))
    refusal = _refused(gateway, proposal, approval_id)
    assert refusal.approval_reason == ApprovalReason.APPROVER_LACKS_ROLE.value
    assert spy.calls == []


def test_an_unexpected_failure_in_approvals_means_do_not_send(
    make_gateway: Gateways,
    make_proposal: Proposals,
    approvals: ApprovalService,
    approver: Principal,
    spy: SpyTransport,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    proposal = make_proposal()
    gateway = make_gateway()
    approval_id = _approved(gateway, approvals, approver, proposal)

    def boom(*args: Any, **kwargs: Any) -> Any:
        raise RuntimeError("approvals fell over")

    monkeypatch.setattr(approvals, "consume", boom)
    assert _refused(gateway, proposal, approval_id).reason is GateReason.APPROVAL_UNAVAILABLE
    assert spy.calls == []


def test_approvals_refusing_the_request_leaves_no_authorization(
    make_gateway: Gateways, make_proposal: Proposals, engine: Engine, clock: FixedClock,
    audit: FakeAudit, principals: FakePrincipals,
) -> None:  # fmt: skip
    """With no expiry window set the approvals module refuses (ADR-0019)."""
    no_ttl = ApprovalService(engine=engine, audit=audit, clock=clock, principals=principals)
    with pytest.raises(ExternalGateRefused) as excinfo:
        make_gateway(approvals=no_ttl).request_approval(make_proposal(), actor_id=REQUESTER)
    assert excinfo.value.reason is GateReason.APPROVAL_REFUSED
    assert excinfo.value.approval_reason == ApprovalReason.TTL_UNSET.value
    assert approval_rows(engine) == 0
    assert [e.outcome for e in audit.find(ACTION_AUTHORIZE)] == [
        AuditOutcome.ATTEMPT,
        AuditOutcome.DENIED,
    ]


# --- failures after the send: recorded, never retried -------------------------------------


def test_transport_failure_is_recorded_and_the_approval_stays_spent(
    make_gateway: Gateways,
    make_proposal: Proposals,
    approvals: ApprovalService,
    approver: Principal,
    spy: SpyTransport,
    audit: FakeAudit,
) -> None:
    spy.raises = ConnectionError(f"could not deliver {MARKER_TEXT}")
    proposal = make_proposal()
    gateway = make_gateway()
    approval_id = _approved(gateway, approvals, approver, proposal)
    with pytest.raises(ExternalTransmitFailed) as excinfo:
        gateway.transmit(proposal, approval_id, actor_id=REQUESTER)
    failure = excinfo.value
    assert failure.outcome is TransmitOutcome.TRANSPORT_ERROR
    assert MARKER_TEXT not in str(failure)
    assert failure.__cause__ is None
    assert len(spy.calls) == 1  # one call, no retry, no other provider
    record = gateway.get_record(failure.record_id)
    assert record is not None
    assert (record.outcome, record.error_type) == (
        TransmitOutcome.TRANSPORT_ERROR,
        "ConnectionError",
    )
    assert record.result_ref is None
    assert record.completed_at is not None
    assert approvals.get(approval_id).status is ApprovalStatus.CONSUMED
    assert [e.outcome for e in audit.find(ACTION_TRANSMIT)] == [
        AuditOutcome.ATTEMPT,
        AuditOutcome.FAILED,
    ]
    spy.raises = None
    assert _refused(gateway, proposal, approval_id).approval_reason == "already_consumed"
    assert len(spy.calls) == 1


@pytest.mark.parametrize(
    ("returned", "outcome"),
    [
        (TransportResponse(body=b"\xff\xfe not utf-8"), TransmitOutcome.MALFORMED_RESPONSE),
        (TransportResponse(body=b"  \n"), TransmitOutcome.EMPTY_RESPONSE),
        ("just a string", TransmitOutcome.MALFORMED_RESPONSE),
        (
            TransportResponse.model_construct(body=b"ok", metadata={"note": "free text here"}),
            TransmitOutcome.MALFORMED_RESPONSE,
        ),
    ],
    ids=["not-utf8", "empty", "wrong-type", "prose-in-metadata"],
)
def test_an_unusable_answer_is_a_recorded_failure(
    make_gateway: Gateways,
    make_proposal: Proposals,
    approvals: ApprovalService,
    approver: Principal,
    spy: SpyTransport,
    returned: Any,
    outcome: TransmitOutcome,
) -> None:
    spy.returns = returned
    proposal = make_proposal()
    gateway = make_gateway()
    approval_id = _approved(gateway, approvals, approver, proposal)
    with pytest.raises(ExternalTransmitFailed) as excinfo:
        gateway.transmit(proposal, approval_id, actor_id=REQUESTER)
    assert excinfo.value.outcome is outcome
    record = gateway.get_record(excinfo.value.record_id)
    assert record is not None
    assert record.outcome is outcome
    assert dict(record.response_metadata) == {}
    assert len(spy.calls) == 1
