"""Regression tests for the M2 review of the external inference gate
(`docs/reviews/m2-approvals-external-inference.md`), named by finding id. Each replays the
reviewer's concrete sequence against the gateway, and each refusal has an allowed path in
the same test or next to it.
"""

from __future__ import annotations

import hmac
import json
from collections.abc import Callable
from typing import Any

import pytest
from pydantic import ValidationError
from sqlalchemy import Engine, select, update
from tests.external_inference.conftest import (
    ALLOWED,
    ANSWER_MARKER,
    APPROVAL_TTL,
    APPROVER_ROLE,
    MARKER_TEXT,
    MAX_PAYLOAD_BYTES,
    MAX_RESPONSE_BYTES,
    MODEL,
    PROVIDER,
    PURPOSE,
    REGISTERED_SECRET,
    REQUESTER,
    SpyTransport,
    approval_rows,
    fail_audit_when,
    signed_in,
)
from tests.fakes.core import FakeAudit, FakeKillSwitch, FakePrincipals, FakeSecrets, make_principal

from ciso.approvals import ApprovalReason, ApprovalService, ApprovalStatus, ApprovalUnavailable
from ciso.common.classification import ClassificationScheme
from ciso.common.clock import FixedClock
from ciso.common.enums import ActorType, AuditOutcome, KillCapability
from ciso.common.errors import FailClosed, ValidationFailed
from ciso.common.principal import Principal
from ciso.common.schemas import canonical_json, sha256_hex
from ciso.inference.external import (
    ACTION_AUTHORIZE,
    ACTION_PREVIEW,
    ACTION_PROPOSE,
    ACTION_TRANSMIT,
    MAX_AUDIT_REFS,
    MAX_ITEM_TEXT_CHARS,
    MAX_ITEMS,
    ContextItem,
    DroppedItem,
    ExternalGateRefused,
    ExternalInferenceGateway,
    ExternalReason,
    ExternalRequestProposal,
    ExternalRequestRefused,
    ExternalTransmitFailed,
    GateReason,
    ItemLabel,
    KeptItem,
    MinimizedPayload,
    PayloadPreview,
    TransmitOutcome,
    minimize,
    parse_payload,
)
from ciso.inference.external import preparing as preparing_module
from ciso.inference.external.binding import new_record
from ciso.inference.external.ledger import ExternalLedger
from ciso.inference.external.tables import (
    external_inference_authorization,
    external_inference_proposal,
    external_inference_record,
)
from ciso.vault.redact import SecretRedactor

pytestmark = pytest.mark.external_inference

Gateways = Callable[..., ExternalInferenceGateway]
Proposals = Callable[..., ExternalRequestProposal]
Expected = Callable[..., PayloadPreview]

DIGEST_KEY = "k" * 40
OTHER_TEXT = "a different context item altogether"
NEVER_PROPOSED = "xrq_" + "0" * 26
TRANSMIT_STEPS = (AuditOutcome.ATTEMPT, AuditOutcome.FAILED)


def _approved(
    gateway: ExternalInferenceGateway,
    approvals: ApprovalService,
    approver: Principal,
    proposal: ExternalRequestProposal,
) -> str:
    made = gateway.request_approval(proposal, actor_id=REQUESTER)
    approvals.approve(made.approval_id, approver)
    return made.approval_id


def _hand_built(clock: FixedClock, **overrides: Any) -> ExternalRequestProposal:
    """A well-formed proposal that never went through `propose`."""
    values: dict[str, Any] = {
        "request_id": NEVER_PROPOSED,
        "requester_actor_id": REQUESTER,
        "requester_actor_type": ActorType.HUMAN,
        "purpose": PURPOSE,
        "provider_name": PROVIDER,
        "model_name": MODEL,
        "items": (
            ContextItem(
                ref="evidence:a1", text=MARKER_TEXT, classification="public", source="registry"
            ),
        ),
        "created_at": clock.now(),
    }
    values.update(overrides)
    return ExternalRequestProposal(**values)


def _forged_preview() -> PayloadPreview:
    """The reviewer's P1 object: built by hand, labelled public, carrying restricted text,
    a registered secret, an extra top-level key and a request id nobody proposed."""
    document = {
        "schema": 1,
        "request_id": "xrq_never_proposed",
        "provider": PROVIDER,
        "model": MODEL,
        "purpose": f"use key {REGISTERED_SECRET}",
        "attachments": "anything else rides along",
        "items": [
            {
                "ref": "free text with spaces\nand newline",
                "classification": "public",
                "text": f"RESTRICTED customer dump; password={REGISTERED_SECRET}",
            }
        ],
    }
    raw = canonical_json(document).encode()
    return PayloadPreview.model_construct(
        request_id="xrq_never_proposed",
        provider_name=PROVIDER,
        model_name=MODEL,
        purpose=f"use key {REGISTERED_SECRET}",
        classification="public",
        kept=(
            ItemLabel.model_construct(
                ref="free text with spaces\nand newline", classification="public"
            ),
        ),
        dropped=(),
        blocked_reason=None,
        preview_bytes=raw,
        payload_hash=sha256_hex(raw),
    )


def _everything_stored(engine: Engine, audit: FakeAudit) -> str:
    parts: list[str] = []
    with engine.begin() as conn:
        for table in (
            external_inference_proposal,
            external_inference_authorization,
            external_inference_record,
        ):
            parts.extend(repr(tuple(row)) for row in conn.execute(select(table)))
    parts.extend(repr(event.model_dump()) for event in audit.events)
    return "".join(parts)


def _refusal(call: Callable[[], Any]) -> ExternalGateRefused:
    with pytest.raises(ExternalGateRefused) as excinfo:
        call()
    return excinfo.value


# --- C1: the gateway is the only producer of sendable bytes -------------------------------


def test_c1_hand_built_preview_is_refused(
    make_gateway: Gateways,
    approvals: ApprovalService,
    approver: Principal,
    spy: SpyTransport,
    engine: Engine,
    audit: FakeAudit,
) -> None:
    """P1 and P1b: this object used to be authorized, approved and sent as it stood."""
    gateway = make_gateway()
    forged = _forged_preview()
    refused = _refusal(lambda: gateway.request_approval(forged, actor_id=REQUESTER))  # type: ignore[arg-type]
    assert refused.reason is GateReason.PROPOSAL_INVALID
    assert approval_rows(engine) == 0
    (denied,) = audit.find(ACTION_AUTHORIZE)
    assert (denied.outcome, denied.details, denied.target) == (
        AuditOutcome.DENIED,
        {"reason": "proposal_invalid"},
        "",
    )
    refused = _refusal(
        lambda: gateway.transmit(forged, "apr_" + "0" * 26, actor_id=REQUESTER)  # type: ignore[arg-type]
    )
    assert refused.reason is GateReason.PROPOSAL_INVALID
    assert spy.calls == []
    stored = _everything_stored(engine, audit)
    assert REGISTERED_SECRET not in stored
    assert "free text" not in stored
    assert "attachments" not in stored


def test_c1_an_object_that_only_looks_like_a_proposal_is_refused(
    make_gateway: Gateways, make_proposal: Proposals, engine: Engine
) -> None:
    """Only the proposal type itself is accepted, not something that dumps like one."""
    proposal = make_proposal()

    class Lookalike:
        request_id = proposal.request_id

        def model_dump(self) -> dict[str, Any]:
            return proposal.model_dump()

    gateway = make_gateway()
    refused = _refusal(lambda: gateway.request_approval(Lookalike(), actor_id=REQUESTER))  # type: ignore[arg-type]
    assert refused.reason is GateReason.PROPOSAL_INVALID
    assert approval_rows(engine) == 0
    assert gateway.request_approval(proposal, actor_id=REQUESTER).request_id == proposal.request_id


def test_c1_never_proposed_request_id_is_refused(
    make_gateway: Gateways,
    clock: FixedClock,
    spy: SpyTransport,
    engine: Engine,
    audit: FakeAudit,
) -> None:
    """A well-formed proposal object that `propose` never recorded."""
    gateway = make_gateway()
    stranger = _hand_built(clock)
    refused = _refusal(lambda: gateway.request_approval(stranger, actor_id=REQUESTER))
    assert refused.reason is GateReason.PROPOSAL_UNKNOWN
    refused = _refusal(lambda: gateway.transmit(stranger, "apr_" + "0" * 26, actor_id=REQUESTER))
    assert refused.reason is GateReason.PROPOSAL_UNKNOWN
    with pytest.raises(ExternalRequestRefused) as excinfo:
        gateway.preview(stranger, actor_id=REQUESTER)
    assert excinfo.value.reason is ExternalReason.PROPOSAL_UNKNOWN
    assert [e.outcome for e in audit.find(ACTION_PREVIEW)] == [AuditOutcome.DENIED]
    assert (approval_rows(engine), spy.calls) == (0, [])
    assert audit.find(ACTION_AUTHORIZE)[0].target == f"external_request:{NEVER_PROPOSED}"


def _item(proposal: ExternalRequestProposal, **update: Any) -> tuple[ContextItem, ...]:
    return (proposal.items[0].model_copy(update=update),)


CHANGES: dict[str, Callable[[ExternalRequestProposal], dict[str, Any]]] = {
    "text": lambda p: {"items": _item(p, text=OTHER_TEXT)},
    "label": lambda p: {"items": _item(p, classification="internal")},
    "ref": lambda p: {"items": _item(p, ref="evidence:zz")},
    "extra-item": lambda p: {"items": (*p.items, *_item(p, ref="evidence:b2"))},
    "provider": lambda p: {"provider_name": "provider-two"},
    "model": lambda p: {"model_name": "model-small-2"},
    "purpose": lambda p: {"purpose": "a different purpose"},
    "requester": lambda p: {"requester_actor_id": "human_owner"},
}


@pytest.mark.parametrize("what", sorted(CHANGES))
def test_c1_changed_proposal_is_refused(
    make_gateway: Gateways,
    make_proposal: Proposals,
    approvals: ApprovalService,
    approver: Principal,
    spy: SpyTransport,
    expected: Expected,
    what: str,
) -> None:
    """The request id is known, but the proposal is not the one recorded under it."""
    gateway = make_gateway()
    proposal = make_proposal()
    changed = proposal.model_copy(update=CHANGES[what](proposal))
    refused = _refusal(lambda: gateway.request_approval(changed, actor_id=REQUESTER))
    assert refused.reason is GateReason.PROPOSAL_MISMATCH
    with pytest.raises(ExternalRequestRefused) as excinfo:
        gateway.preview(changed, actor_id=REQUESTER)
    assert excinfo.value.reason is ExternalReason.PROPOSAL_MISMATCH
    approval_id = _approved(gateway, approvals, approver, proposal)
    refused = _refusal(lambda: gateway.transmit(changed, approval_id, actor_id=REQUESTER))
    assert refused.reason is GateReason.PROPOSAL_MISMATCH
    assert spy.calls == []
    assert approvals.get(approval_id).status is ApprovalStatus.APPROVED
    gateway.transmit(proposal, approval_id, actor_id=REQUESTER)
    assert [call[2] for call in spy.calls] == [expected(proposal).preview_bytes]


def test_c1_proposal_built_around_the_validators_is_refused(
    make_gateway: Gateways, make_proposal: Proposals, engine: Engine
) -> None:
    proposal = make_proposal()
    bent = ExternalRequestProposal.model_construct(
        **{**dict(proposal), "items": _item(proposal, ref="free text\nwith a newline")}
    )
    refused = _refusal(lambda: make_gateway().request_approval(bent, actor_id=REQUESTER))
    assert refused.reason is GateReason.PROPOSAL_INVALID
    assert approval_rows(engine) == 0


def test_c1_gateway_minimizes_and_redacts_itself(
    make_gateway: Gateways,
    approvals: ApprovalService,
    approver: Principal,
    spy: SpyTransport,
    real_redactor: SecretRedactor,
    engine: Engine,
    audit: FakeAudit,
) -> None:
    """What leaves is what the gateway built: restricted items dropped, secrets removed,
    including one that only became known after the proposal was made."""
    gateway = make_gateway()
    late_secret = "late-registered-credential-0042"
    proposal = gateway.propose(
        requester_actor_id=REQUESTER,
        purpose=PURPOSE,
        provider_name=PROVIDER,
        model_name=MODEL,
        items=[
            ContextItem(
                ref="evidence:a1",
                text=f"{MARKER_TEXT} pw {REGISTERED_SECRET} and {late_secret}",
                classification="public",
                source="registry",
            ),
            ContextItem(
                ref="evidence:r9",
                text="RESTRICTED customer dump",
                classification="restricted",
                source="registry",
            ),
        ],
    )
    assert real_redactor.register(late_secret)
    made = gateway.request_approval(proposal, actor_id=REQUESTER)
    assert [d.ref for d in made.dropped] == ["evidence:r9"]
    approvals.approve(made.approval_id, approver)
    gateway.transmit(proposal, made.approval_id, actor_id=REQUESTER)
    ((provider, model, sent),) = spy.calls
    assert (provider, model) == (PROVIDER, MODEL)
    said = json.loads(sent)
    assert sorted(said) == ["items", "model", "provider", "purpose", "request_id", "schema"]
    assert [item["ref"] for item in said["items"]] == ["evidence:a1"]
    assert MARKER_TEXT in said["items"][0]["text"]
    for leaked in (REGISTERED_SECRET, late_secret, "RESTRICTED customer dump"):
        assert leaked.encode() not in sent
    assert sha256_hex(sent) == made.payload_sha256
    assert len(sent) == made.payload_bytes
    stored = _everything_stored(engine, audit)
    for leaked in (REGISTERED_SECRET, late_secret, MARKER_TEXT, "RESTRICTED customer dump"):
        assert leaked not in stored


def test_c1_secret_in_the_purpose_never_reaches_the_database_or_audit(
    make_gateway: Gateways, engine: Engine, audit: FakeAudit, make_item: Callable[..., ContextItem]
) -> None:
    gateway = make_gateway()
    proposal = gateway.propose(
        requester_actor_id=REQUESTER,
        purpose=f"use key {REGISTERED_SECRET} to summarise",
        provider_name=PROVIDER,
        model_name=MODEL,
        items=[make_item()],
    )
    assert REGISTERED_SECRET not in proposal.purpose
    made = gateway.request_approval(proposal, actor_id=REQUESTER)
    assert made.purpose == proposal.purpose
    assert REGISTERED_SECRET not in _everything_stored(engine, audit)


def test_c1_propose_leaves_a_record_with_digests_and_no_text(
    make_gateway: Gateways, engine: Engine, make_item: Callable[..., ContextItem]
) -> None:
    proposal = make_gateway().propose(
        requester_actor_id=REQUESTER,
        purpose=PURPOSE,
        provider_name=PROVIDER,
        model_name=MODEL,
        items=[make_item("a1"), make_item("b2", classification=None)],
        correlation_id="corr-7",
    )
    with engine.begin() as conn:
        (row,) = conn.execute(select(external_inference_proposal)).all()
    assert (row.request_id, row.requester_actor_id) == (proposal.request_id, REQUESTER)
    assert (row.provider_name, row.model_name) == (PROVIDER, MODEL)
    assert (row.purpose_sha256, row.correlation_id) == (sha256_hex(PURPOSE), "corr-7")
    assert json.loads(row.items) == [
        {"ref": "evidence:a1", "classification": "public", "text_digest": sha256_hex(MARKER_TEXT)},
        {"ref": "evidence:b2", "classification": "unknown", "text_digest": sha256_hex(MARKER_TEXT)},
    ]
    assert MARKER_TEXT not in repr(tuple(row))
    assert PURPOSE not in repr(tuple(row))


def test_c1_item_digests_are_keyed_when_a_key_is_configured(
    make_gateway: Gateways,
    make_proposal: Proposals,
    engine: Engine,
    approvals: ApprovalService,
    approver: Principal,
    spy: SpyTransport,
) -> None:
    keyed = make_gateway(
        secrets=FakeSecrets({"secret://digest": DIGEST_KEY}), digest_key_ref="secret://digest"
    )
    proposal = make_proposal(via=keyed)
    with engine.begin() as conn:
        (row,) = conn.execute(select(external_inference_proposal.c["items"])).all()
    (item,) = json.loads(row.items)
    assert item["text_digest"] != sha256_hex(MARKER_TEXT)
    assert (
        item["text_digest"]
        == hmac.new(DIGEST_KEY.encode(), MARKER_TEXT.encode(), "sha256").hexdigest()
    )
    # A gateway without the key cannot recognise the proposal; the keyed one can.
    plain = make_gateway()
    refused = _refusal(lambda: plain.request_approval(proposal, actor_id=REQUESTER))
    assert refused.reason is GateReason.PROPOSAL_MISMATCH
    keyed.transmit(proposal, _approved(keyed, approvals, approver, proposal), actor_id=REQUESTER)
    assert len(spy.calls) == 1


def test_c1_an_unaudited_proposal_leaves_no_record(
    make_gateway: Gateways,
    engine: Engine,
    audit: FakeAudit,
    make_item: Callable[..., ContextItem],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fail_audit_when(
        monkeypatch,
        audit,
        lambda e: e.action == ACTION_PROPOSE and e.outcome is AuditOutcome.SUCCESS,
    )
    with pytest.raises(FailClosed):
        make_gateway().propose(
            requester_actor_id=REQUESTER,
            purpose=PURPOSE,
            provider_name=PROVIDER,
            model_name=MODEL,
            items=[make_item()],
        )
    with engine.begin() as conn:
        assert conn.execute(select(external_inference_proposal)).all() == []


def _preview_from(raw: bytes, request_id: str = NEVER_PROPOSED) -> PayloadPreview:
    return PayloadPreview(
        request_id=request_id,
        provider_name="prov-a",
        model_name="model-1",
        purpose="p",
        classification="public",
        kept=(ItemLabel(ref="evidence:a1", classification="public"),),
        dropped=(),
        blocked_reason=None,
        preview_bytes=raw,
        payload_hash=sha256_hex(raw),
    )


_GOOD_BYTES = (
    b'{"items":[{"classification":"public","ref":"evidence:a1","text":"t"}],'
    b'"model":"model-1","provider":"prov-a","purpose":"p",'
    b'"request_id":"' + NEVER_PROPOSED.encode() + b'","schema":1}'
)


@pytest.mark.parametrize(
    ("old", "new"),
    [
        (b'"model":"model-1"', b'"model":"other-model","model":"model-1"'),
        (b'"schema":1}', b'"schema":1,"zattachments":"rides along"}'),
        (b'"text":"t"}', b'"text":"t","zextra":"x"}'),
        (b'"text":"t"}', b'"text":"t","text":"u"}'),
        (b'"purpose":"p",', b'"purpose": "p",'),
        (b'"schema":1}', b'"schema":2}'),
        (b'"schema":1}', b'"schema":true}'),
        (b'"text":"t"', b'"text":7'),
        (NEVER_PROPOSED.encode(), b"xrq_x"),
        (b'{"classification":"public","ref":"evidence:a1","text":"t"}', b""),
    ],
    ids=[
        "duplicate-key", "extra-key", "extra-item-key", "duplicate-item-key", "not-canonical",
        "other-schema", "bool-schema", "text-not-a-string", "bad-request-id", "no-items",
    ],
)  # fmt: skip
def test_c1_preview_validator_rejects_duplicate_extra_and_odd_bytes(old: bytes, new: bytes) -> None:
    """P15 (two `model` keys) and P1 (an `attachments` key), plus the neighbours."""
    assert _preview_from(_GOOD_BYTES).sendable
    assert old in _GOOD_BYTES
    with pytest.raises(ValidationError) as excinfo:
        _preview_from(_GOOD_BYTES.replace(old, new))
    # A key named twice is refused as such, before anything reads a value from it.
    for twice in (
        b'"model":"other-model","model":"model-1"',
        b'"model":"model-1","model":"model-1"',
    ):
        with pytest.raises(ValueError, match="names a key twice"):
            parse_payload(_GOOD_BYTES.replace(b'"model":"model-1"', twice))
    with pytest.raises(ValueError, match="not acceptable JSON"):
        parse_payload(b"{not json")
    # The same refusal when the named request id agrees with the bytes.
    with pytest.raises(ValidationError):
        _preview_from(_GOOD_BYTES.replace(NEVER_PROPOSED.encode(), b"xrq_x"), "xrq_x")
    assert "rides along" not in str(excinfo.value)


@pytest.mark.parametrize("ref", ["free text with spaces\nand newline", "evidence:a:b", "x", ""])
def test_c1_refs_and_labels_are_shape_checked(ref: str) -> None:
    """P1b: `kept[].ref` and `dropped[].ref` were free-text channels into the audit log."""
    reason = ExternalReason.CLASSIFICATION_NOT_ALLOWED
    with pytest.raises(ValidationError):
        ItemLabel(ref=ref, classification="public")
    with pytest.raises(ValidationError):
        DroppedItem(ref=ref, classification="public", reason=reason)
    with pytest.raises(ValidationError):
        KeptItem(ref=ref, classification="public", source="s", text="t")
    with pytest.raises(ValidationError):
        DroppedItem(ref="evidence:a1", classification="Not A Label\n", reason=reason)
    assert DroppedItem(ref="evidence:a1", classification="unknown", reason=reason).ref


def test_c1_a_label_that_may_not_leave_is_refused_even_if_minimize_keeps_it(
    make_gateway: Gateways,
    make_proposal: Proposals,
    engine: Engine,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Defence in depth: the gateway checks the labels of what it is about to send."""

    def leaky(proposal: ExternalRequestProposal, **settings: Any) -> MinimizedPayload:
        return MinimizedPayload(
            request_id=proposal.request_id,
            provider_name=proposal.provider_name,
            model_name=proposal.model_name,
            purpose=proposal.purpose,
            kept=(KeptItem(ref="evidence:a1", classification="restricted", source="s", text="t"),),
            dropped=(),
            classification="restricted",
            blocked_reason=None,
        )

    proposal = make_proposal()
    monkeypatch.setattr(preparing_module, "minimize", leaky)
    refused = _refusal(lambda: make_gateway().request_approval(proposal, actor_id=REQUESTER))
    assert refused.reason is GateReason.CLASSIFICATION_NOT_ALLOWED
    assert approval_rows(engine) == 0


def test_c1_a_redactor_that_fails_while_minimizing_refuses_without_quoting(
    make_gateway: Gateways,
    make_proposal: Proposals,
    real_redactor: SecretRedactor,
    engine: Engine,
    audit: FakeAudit,
) -> None:
    class Broken:
        def redact(self, text: str) -> str:
            raise RuntimeError(f"cannot redact {text}")

        def redact_value(self, value: Any) -> Any:
            return real_redactor.redact_value(value)

    proposal = make_proposal()
    refused = _refusal(
        lambda: make_gateway(redactor=Broken()).request_approval(proposal, actor_id=REQUESTER)
    )
    assert refused.reason is GateReason.MINIMIZE_FAILED
    assert MARKER_TEXT not in repr(refused) + repr(refused.__cause__) + repr(refused.__context__)
    assert audit.find(ACTION_AUTHORIZE)[-1].details == {
        "reason": "minimize_failed",
        "cause_type": "RuntimeError",
    }
    assert approval_rows(engine) == 0


# --- H2 and M3: who may file, who may transmit ----------------------------------------------


def test_h2_only_the_proposer_may_file_the_request(
    make_gateway: Gateways,
    make_proposal: Proposals,
    approvals: ApprovalService,
    engine: Engine,
) -> None:
    """P3: the owner proposed and previewed, a colleague only filed, the owner approved
    and sent; the author of the payload was not on the record."""
    gateway = make_gateway()
    proposal = make_proposal(requester="human_owner")
    refused = _refusal(lambda: gateway.request_approval(proposal, actor_id=REQUESTER))
    assert refused.reason is GateReason.NOT_REQUESTER
    assert approval_rows(engine) == 0
    made = gateway.request_approval(proposal, actor_id="human_owner")
    assert made.requested_by == "human_owner"
    assert approvals.get(made.approval_id).requested_by == "human_owner"


def test_m3_another_human_cannot_transmit_an_approved_request(
    make_gateway: Gateways,
    make_proposal: Proposals,
    approvals: ApprovalService,
    approver: Principal,
    spy: SpyTransport,
) -> None:
    """P10: the read-only auditor used to be able to send it."""
    gateway = make_gateway()
    proposal = make_proposal()
    approval_id = _approved(gateway, approvals, approver, proposal)
    for other in ("human_aud", approver.actor_id):
        refused = _refusal(lambda who=other: gateway.transmit(proposal, approval_id, actor_id=who))
        assert refused.reason is GateReason.NOT_REQUESTER
    assert spy.calls == []
    assert approvals.get(approval_id).status is ApprovalStatus.APPROVED
    gateway.transmit(proposal, approval_id, actor_id=REQUESTER)
    assert len(spy.calls) == 1


def test_m3_the_authorization_names_who_may_transmit(
    make_gateway: Gateways,
    make_proposal: Proposals,
    approvals: ApprovalService,
    approver: Principal,
    spy: SpyTransport,
    engine: Engine,
) -> None:
    gateway = make_gateway()
    proposal = make_proposal()
    approval_id = _approved(gateway, approvals, approver, proposal)
    with engine.begin() as conn:
        conn.execute(update(external_inference_authorization).values(requested_by="human_aud"))
    refused = _refusal(lambda: gateway.transmit(proposal, approval_id, actor_id=REQUESTER))
    assert refused.reason is GateReason.NOT_REQUESTER
    assert spy.calls == []
    with engine.begin() as conn:
        conn.execute(update(external_inference_authorization).values(requested_by=REQUESTER))
    gateway.transmit(proposal, approval_id, actor_id=REQUESTER)
    assert len(spy.calls) == 1


def test_h2_an_approval_decided_by_the_transmitter_is_refused(
    make_gateway: Gateways,
    make_proposal: Proposals,
    engine: Engine,
    audit: FakeAudit,
    clock: FixedClock,
    principals: FakePrincipals,
    spy: SpyTransport,
) -> None:
    """Even where the approvals module is set to allow self-approval, one person does not
    propose, approve and send on the external path."""
    lenient = ApprovalService(
        engine=engine, audit=audit, clock=clock, principals=principals,
        approval_ttl=APPROVAL_TTL, allow_self_approval=True,
    )  # fmt: skip
    both = principals.register(make_principal("human_both", ActorType.HUMAN, APPROVER_ROLE))
    gateway = make_gateway(approvals=lenient)
    proposal = make_proposal(requester="human_both")
    made = gateway.request_approval(proposal, actor_id="human_both")
    assert lenient.approve(made.approval_id, signed_in(both)).self_approved is True
    refused = _refusal(lambda: gateway.transmit(proposal, made.approval_id, actor_id="human_both"))
    assert refused.reason is GateReason.TRANSMITTER_IS_APPROVER
    assert spy.calls == []
    assert lenient.get(made.approval_id).status is ApprovalStatus.APPROVED
    denied = audit.find(ACTION_TRANSMIT)[-1]
    assert (denied.outcome, denied.details["reason"]) == (
        AuditOutcome.DENIED,
        "transmitter_is_approver",
    )


# --- H3: after the send, a closing audit event and a closed ledger row -----------------------


class _FailsOnAnswer:
    """A redactor that works on the way out and breaks on the answer."""

    def __init__(self, inner: SecretRedactor) -> None:
        self._inner = inner

    def redact(self, text: str) -> str:
        if ANSWER_MARKER in text:
            raise RuntimeError(f"redactor broke on {text}")
        return self._inner.redact(text)

    def redact_value(self, value: Any) -> Any:
        return self._inner.redact_value(value)


def _closing(audit: FakeAudit) -> tuple[list[AuditOutcome], dict[str, Any]]:
    events = audit.find(ACTION_TRANSMIT)
    return [e.outcome for e in events], events[-1].details


def test_h3_redactor_failure_on_the_answer_is_closed_and_recorded(
    make_gateway: Gateways,
    make_proposal: Proposals,
    approvals: ApprovalService,
    approver: Principal,
    spy: SpyTransport,
    audit: FakeAudit,
    real_redactor: SecretRedactor,
) -> None:
    """P6: a raw RuntimeError escaped, the row stayed `attempted`, the audit log held
    only the attempt."""
    gateway = make_gateway(redactor=_FailsOnAnswer(real_redactor))
    proposal = make_proposal()
    approval_id = _approved(gateway, approvals, approver, proposal)
    with pytest.raises(ExternalTransmitFailed) as excinfo:
        gateway.transmit(proposal, approval_id, actor_id=REQUESTER)
    failure = excinfo.value
    assert failure.outcome is TransmitOutcome.RESULT_NOT_PROCESSED
    assert ANSWER_MARKER not in repr(failure) + repr(failure.__cause__) + repr(failure.__context__)
    assert len(spy.calls) == 1
    record = gateway.get_record(failure.record_id)
    assert record is not None
    assert (record.outcome, record.error_type) == (
        TransmitOutcome.RESULT_NOT_PROCESSED,
        "RuntimeError",
    )
    assert record.completed_at is not None
    outcomes, details = _closing(audit)
    assert tuple(outcomes) == TRANSMIT_STEPS
    assert (details["sent"], details["record_id"]) == (True, record.id)
    assert details["outcome"] == "result_not_processed"


@pytest.mark.parametrize("mode", ["raises", "no-row-changed"])
def test_h3_ledger_failure_after_the_send_is_audited_and_flagged(
    make_gateway: Gateways,
    make_proposal: Proposals,
    approvals: ApprovalService,
    approver: Principal,
    spy: SpyTransport,
    audit: FakeAudit,
    monkeypatch: pytest.MonkeyPatch,
    mode: str,
) -> None:
    """P7: `complete_record` failed after the send and the audit log was never told."""
    gateway = make_gateway()
    proposal = make_proposal()
    approval_id = _approved(gateway, approvals, approver, proposal)

    def broken(self: ExternalLedger, record_id: str, **values: Any) -> bool:
        if mode == "raises":
            raise FailClosed("ledger down (scripted)")
        return False

    monkeypatch.setattr(ExternalLedger, "complete_record", broken)
    with pytest.raises(FailClosed, match="handed to the transport"):
        gateway.transmit(proposal, approval_id, actor_id=REQUESTER)
    assert len(spy.calls) == 1
    (record,) = gateway.records_for_request(proposal.request_id)
    assert (record.outcome, record.error_type) == (
        TransmitOutcome.SENT_UNRECORDED,
        "record_incomplete:sent",
    )
    outcomes, details = _closing(audit)
    assert tuple(outcomes) == TRANSMIT_STEPS
    assert (details["sent"], details["record_id"]) == (True, record.id)
    assert (details["record_incomplete"], details["record_flagged"]) == (True, True)


def test_h3_when_the_row_cannot_even_be_flagged_the_audit_event_says_so(
    make_gateway: Gateways,
    make_proposal: Proposals,
    approvals: ApprovalService,
    approver: Principal,
    spy: SpyTransport,
    audit: FakeAudit,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    gateway = make_gateway()
    proposal = make_proposal()
    approval_id = _approved(gateway, approvals, approver, proposal)

    def down(self: ExternalLedger, *args: Any, **values: Any) -> bool:
        raise FailClosed("ledger down (scripted)")

    monkeypatch.setattr(ExternalLedger, "complete_record", down)
    monkeypatch.setattr(ExternalLedger, "mark_unrecorded", down)
    with pytest.raises(FailClosed, match="handed to the transport"):
        gateway.transmit(proposal, approval_id, actor_id=REQUESTER)
    outcomes, details = _closing(audit)
    assert tuple(outcomes) == TRANSMIT_STEPS
    assert (details["sent"], details["record_flagged"]) == (True, False)
    (record,) = gateway.records_for_request(proposal.request_id)
    assert record.outcome is TransmitOutcome.ATTEMPTED  # documented: possibly sent


def test_h3_closing_audit_failure_after_a_failed_send_flags_the_row(
    make_gateway: Gateways,
    make_proposal: Proposals,
    approvals: ApprovalService,
    approver: Principal,
    spy: SpyTransport,
    audit: FakeAudit,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    spy.raises = ConnectionError("no route")
    gateway = make_gateway()
    proposal = make_proposal()
    approval_id = _approved(gateway, approvals, approver, proposal)
    fail_audit_when(
        monkeypatch,
        audit,
        lambda e: e.action == ACTION_TRANSMIT and e.outcome is AuditOutcome.FAILED,
    )
    with pytest.raises(FailClosed):
        gateway.transmit(proposal, approval_id, actor_id=REQUESTER)
    (record,) = gateway.records_for_request(proposal.request_id)
    assert (record.outcome, record.error_type) == (
        TransmitOutcome.SENT_UNRECORDED,
        "closing_audit_failed:transport_error",
    )


# --- M2: the kill switch is read again immediately before the send ----------------------------


@pytest.mark.parametrize("how", ["engaged", "unreadable"])
def test_m2_kill_switch_engaged_after_the_gate_stops_the_send(
    make_gateway: Gateways,
    make_proposal: Proposals,
    approvals: ApprovalService,
    approver: Principal,
    spy: SpyTransport,
    audit: FakeAudit,
    killswitch: FakeKillSwitch,
    monkeypatch: pytest.MonkeyPatch,
    how: str,
) -> None:
    """P8: the operator stops external inference while the approval is being consumed."""
    gateway = make_gateway()
    proposal = make_proposal()
    approval_id = _approved(gateway, approvals, approver, proposal)
    real = audit.append

    def append(event: Any) -> Any:
        if event.action == "approval.consume" and event.outcome is AuditOutcome.ATTEMPT:
            if how == "engaged":
                killswitch.blocked.add(KillCapability.EXTERNAL_INFERENCE)
            else:
                killswitch.broken = True
        return real(event)

    monkeypatch.setattr(audit, "append", append)
    refused = _refusal(lambda: gateway.transmit(proposal, approval_id, actor_id=REQUESTER))
    assert refused.reason is GateReason.KILL_SWITCH_ENGAGED
    assert spy.calls == []
    # Documented: the approval was consumed before the last look and stays consumed.
    assert approvals.get(approval_id).status is ApprovalStatus.CONSUMED
    (record,) = gateway.records_for_request(proposal.request_id)
    assert (record.outcome, record.error_type) == (TransmitOutcome.NOT_SENT, "kill_switch_engaged")
    assert record.completed_at is not None
    outcomes, details = _closing(audit)
    assert outcomes == [AuditOutcome.ATTEMPT, AuditOutcome.DENIED]
    assert (details["sent"], details["reason"], details["record_id"]) == (
        False,
        "kill_switch_engaged",
        record.id,
    )
    assert details["record_incomplete"] is False


# --- M4: a store call that says "nothing changed" is not reported as done ---------------------


def test_m4_authorization_that_cannot_be_taken_back_says_so(
    make_gateway: Gateways,
    make_proposal: Proposals,
    approvals: ApprovalService,
    audit: FakeAudit,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    gateway = make_gateway()
    proposal = make_proposal()
    fail_audit_when(
        monkeypatch,
        audit,
        lambda e: e.action == ACTION_AUTHORIZE and e.outcome is AuditOutcome.SUCCESS,
    )
    monkeypatch.setattr(ExternalLedger, "withdraw_authorization", lambda self, approval_id: False)

    def stuck(approval_id: str, **who: Any) -> Any:
        raise ApprovalUnavailable(ApprovalReason.VOID_FAILED, "scripted")

    monkeypatch.setattr(approvals, "withdraw", stuck)
    with pytest.raises(FailClosed, match="could not be withdrawn"):
        gateway.request_approval(proposal, actor_id=REQUESTER)


def test_m4_a_proposal_record_that_cannot_be_withdrawn_says_so(
    make_gateway: Gateways,
    audit: FakeAudit,
    make_item: Callable[..., ContextItem],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fail_audit_when(
        monkeypatch,
        audit,
        lambda e: e.action == ACTION_PROPOSE and e.outcome is AuditOutcome.SUCCESS,
    )
    monkeypatch.setattr(ExternalLedger, "withdraw_proposal", lambda self, request_id: False)
    with pytest.raises(FailClosed, match="could not be withdrawn"):
        make_gateway().propose(
            requester_actor_id=REQUESTER,
            purpose=PURPOSE,
            provider_name=PROVIDER,
            model_name=MODEL,
            items=[make_item()],
        )


# --- M5: actor ids and correlation ids ------------------------------------------------------------

BAD_ACTORS = [
    "human_emp\n",
    " human_emp",
    "human_emp ",
    "human\x00emp",
    "human_emp" + chr(0x200B),
    "",
]


@pytest.mark.parametrize("actor", BAD_ACTORS)
def test_m5_unclean_actor_ids_are_refused_at_every_entry_point(
    make_gateway: Gateways,
    make_proposal: Proposals,
    make_item: Callable[..., ContextItem],
    audit: FakeAudit,
    principals: FakePrincipals,
    actor: str,
) -> None:
    gateway = make_gateway()
    proposal = make_proposal()
    before = (len(audit.events), len(principals.lookups))
    calls: list[Callable[[], Any]] = [
        lambda: gateway.propose(
            requester_actor_id=actor, purpose="p", provider_name="a", model_name="b",
            items=[make_item()],
        ),
        lambda: gateway.preview(proposal, actor_id=actor),
        lambda: gateway.request_approval(proposal, actor_id=actor),
        lambda: gateway.transmit(proposal, "apr_" + "0" * 26, actor_id=actor),
    ]  # fmt: skip
    for call in calls:
        with pytest.raises(ValidationFailed):
            call()
    assert (len(audit.events), len(principals.lookups)) == before


@pytest.mark.parametrize("correlation", ["c\nid", " c", "c" * 129, "c d"])
def test_m5_unclean_correlation_ids_are_refused(
    make_gateway: Gateways, make_proposal: Proposals, audit: FakeAudit, correlation: str
) -> None:
    gateway = make_gateway()
    proposal = make_proposal()
    before = len(audit.events)
    for call in (
        lambda: gateway.preview(proposal, actor_id=REQUESTER, correlation_id=correlation),
        lambda: gateway.request_approval(proposal, actor_id=REQUESTER, correlation_id=correlation),
        lambda: gateway.transmit(
            proposal, "apr_" + "0" * 26, actor_id=REQUESTER, correlation_id=correlation
        ),
    ):
        with pytest.raises(ValidationFailed):
            call()
    assert len(audit.events) == before
    made = gateway.request_approval(proposal, actor_id=REQUESTER, correlation_id="corr-1.a:b")
    assert made.correlation_id == "corr-1.a:b"


def test_m5_a_hand_built_proposal_cannot_carry_an_unclean_requester(clock: FixedClock) -> None:
    for requester in (" human_owner", "human_owner\n", "a b"):
        with pytest.raises(ValidationError):
            _hand_built(clock, requester_actor_id=requester)


# --- M6: sizes ------------------------------------------------------------------------------------


def test_m6_too_many_items_or_too_long_an_item_is_refused_at_propose(
    make_gateway: Gateways, audit: FakeAudit, engine: Engine
) -> None:
    """P14: 20,000 items and one of 5 MB were accepted."""
    gateway = make_gateway()

    def propose(items: list[ContextItem]) -> ExternalRequestProposal:
        return gateway.propose(
            requester_actor_id=REQUESTER, purpose="p", provider_name="a", model_name="b",
            items=items,
        )  # fmt: skip

    def items(count: int, size: int = 1) -> list[ContextItem]:
        return [
            ContextItem(ref=f"evidence:a{i}", text="x" * size, classification="public", source="s")
            for i in range(count)
        ]

    with pytest.raises(ValidationFailed):
        propose(items(MAX_ITEMS + 1))
    with pytest.raises(ValidationError):
        items(1, MAX_ITEM_TEXT_CHARS + 1)
    with engine.begin() as conn:
        assert conn.execute(select(external_inference_proposal)).all() == []
    assert len(propose(items(MAX_ITEMS)).items) == MAX_ITEMS
    assert len(items(1, MAX_ITEM_TEXT_CHARS)[0].text) == MAX_ITEM_TEXT_CHARS


def test_m6_audit_details_stay_small_whatever_was_offered(
    make_gateway: Gateways,
    approvals: ApprovalService,
    approver: Principal,
    audit: FakeAudit,
) -> None:
    """P14: one audit event carried 1.4 million characters of refs."""
    gateway = make_gateway(max_payload_bytes=200_000)
    count = MAX_ITEMS
    labels = ["public", "restricted"]
    proposal = gateway.propose(
        requester_actor_id=REQUESTER,
        purpose=PURPOSE,
        provider_name=PROVIDER,
        model_name=MODEL,
        items=[
            ContextItem(ref=f"evidence:a{i}", text="x", classification=labels[i % 2], source="s")
            for i in range(count)
        ],
    )
    gateway.preview(proposal, actor_id=REQUESTER)
    made = gateway.request_approval(proposal, actor_id=REQUESTER)
    approvals.approve(made.approval_id, approver)
    gateway.transmit(proposal, made.approval_id, actor_id=REQUESTER)
    own = [e for e in audit.events if e.action.startswith("inference.external.")]
    assert len(own) == 7
    for event in own:
        for name in ("items", "kept", "dropped"):
            if name in event.details:
                assert len(event.details[name]) == MAX_AUDIT_REFS
                assert len(event.details[f"{name}_sha256"]) == 64
        assert len(json.dumps(event.details)) < 6000
    (proposed, _) = [e for e in own if e.action == ACTION_PROPOSE]
    assert proposed.details["items_count"] == count
    sent = own[-1].details
    assert (sent["kept_count"], sent["dropped_count"]) == (count // 2, count // 2)


def test_m6_payload_limit_is_enforced_at_the_byte(
    make_gateway: Gateways, make_proposal: Proposals, expected: Expected, engine: Engine
) -> None:
    proposal = make_proposal()
    size = len(expected(proposal).preview_bytes or b"")
    assert 0 < size < MAX_PAYLOAD_BYTES
    refused = _refusal(
        lambda: make_gateway(max_payload_bytes=size - 1).request_approval(
            proposal, actor_id=REQUESTER
        )
    )
    assert refused.reason is GateReason.PAYLOAD_TOO_LARGE
    assert approval_rows(engine) == 0
    made = make_gateway(max_payload_bytes=size).request_approval(proposal, actor_id=REQUESTER)
    assert made.payload_bytes == size


def test_m6_an_answer_over_the_limit_is_a_recorded_failure(
    make_gateway: Gateways,
    make_proposal: Proposals,
    approvals: ApprovalService,
    approver: Principal,
    spy: SpyTransport,
    audit: FakeAudit,
) -> None:
    gateway = make_gateway()
    spy.body = b"y" * (MAX_RESPONSE_BYTES + 1)
    proposal = make_proposal()
    approval_id = _approved(gateway, approvals, approver, proposal)
    with pytest.raises(ExternalTransmitFailed) as excinfo:
        gateway.transmit(proposal, approval_id, actor_id=REQUESTER)
    assert excinfo.value.outcome is TransmitOutcome.RESPONSE_TOO_LARGE
    record = gateway.get_record(excinfo.value.record_id)
    assert record is not None
    assert (record.outcome, record.response_bytes) == (
        TransmitOutcome.RESPONSE_TOO_LARGE,
        MAX_RESPONSE_BYTES + 1,
    )
    assert record.result_ref is None
    outcomes, details = _closing(audit)
    assert tuple(outcomes) == TRANSMIT_STEPS
    assert details["sent"] is True
    # Exactly at the limit is read.
    spy.body = b"y" * MAX_RESPONSE_BYTES
    again = make_proposal()
    result = gateway.transmit(
        again, _approved(gateway, approvals, approver, again), actor_id=REQUESTER
    )
    assert result.response_bytes == MAX_RESPONSE_BYTES


# --- L3: the purpose redaction inside minimize ----------------------------------------------------


def test_l3_minimize_redacts_the_purpose_itself(
    clock: FixedClock, classification: ClassificationScheme, real_redactor: SecretRedactor
) -> None:
    """`propose` redacts first, so no test reached `minimize` with an unredacted purpose."""
    proposal = _hand_built(clock, purpose=f"use key {REGISTERED_SECRET} to summarise")
    payload = minimize(
        proposal, scheme=classification, allowed_classifications=ALLOWED, redactor=real_redactor
    )
    assert REGISTERED_SECRET not in payload.purpose
    assert payload.purpose.startswith("use key ")
    assert payload.purpose.endswith(" to summarise")


# --- L5: failures before the send close their attempt ---------------------------------------------


def test_l5_record_insert_failure_closes_the_attempt(
    make_gateway: Gateways,
    make_proposal: Proposals,
    approvals: ApprovalService,
    approver: Principal,
    spy: SpyTransport,
    audit: FakeAudit,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    gateway = make_gateway()
    proposal = make_proposal()
    approval_id = _approved(gateway, approvals, approver, proposal)

    def down(self: ExternalLedger, item: Any) -> None:
        raise FailClosed("ledger down (scripted)")

    monkeypatch.setattr(ExternalLedger, "insert_record", down)
    with pytest.raises(FailClosed):
        gateway.transmit(proposal, approval_id, actor_id=REQUESTER)
    assert spy.calls == []
    outcomes, details = _closing(audit)
    assert tuple(outcomes) == TRANSMIT_STEPS
    assert (details["sent"], details["reason"]) == (False, "record_not_written")


def test_l5_authorization_insert_failure_closes_the_attempt_and_voids_the_orphan(
    make_gateway: Gateways,
    make_proposal: Proposals,
    approvals: ApprovalService,
    engine: Engine,
    audit: FakeAudit,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    gateway = make_gateway()
    proposal = make_proposal()

    def down(self: ExternalLedger, item: Any) -> None:
        raise FailClosed("ledger down (scripted)")

    monkeypatch.setattr(ExternalLedger, "insert_authorization", down)
    with pytest.raises(FailClosed):
        gateway.request_approval(proposal, actor_id=REQUESTER)
    events = audit.find(ACTION_AUTHORIZE)
    assert [e.outcome for e in events] == [AuditOutcome.ATTEMPT, AuditOutcome.FAILED]
    assert events[-1].details["reason"] == "authorization_not_recorded"
    assert events[-1].details["approval_withdrawn"] is True
    assert approvals.list_pending() == ()
    orphan_id = events[-1].details["approval_ref"].split(":")[1]
    assert approvals.get(orphan_id).status is ApprovalStatus.VOID
    assert approval_rows(engine) == 1


def test_l5_an_unnamed_failure_in_approvals_closes_the_authorize_attempt(
    make_gateway: Gateways,
    make_proposal: Proposals,
    approvals: ApprovalService,
    audit: FakeAudit,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def boom(**kwargs: Any) -> Any:
        raise RuntimeError("approvals fell over")

    proposal = make_proposal()
    monkeypatch.setattr(approvals, "request", boom)
    refused = _refusal(lambda: make_gateway().request_approval(proposal, actor_id=REQUESTER))
    assert refused.reason is GateReason.APPROVAL_UNAVAILABLE
    assert [e.outcome for e in audit.find(ACTION_AUTHORIZE)] == [
        AuditOutcome.ATTEMPT,
        AuditOutcome.DENIED,
    ]


def test_l5_proposal_insert_failure_closes_the_propose_attempt(
    make_gateway: Gateways,
    audit: FakeAudit,
    make_item: Callable[..., ContextItem],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def down(self: ExternalLedger, item: Any) -> None:
        raise FailClosed("ledger down (scripted)")

    monkeypatch.setattr(ExternalLedger, "insert_proposal", down)
    with pytest.raises(FailClosed):
        make_gateway().propose(
            requester_actor_id=REQUESTER, purpose=PURPOSE, provider_name=PROVIDER,
            model_name=MODEL, items=[make_item()],
        )  # fmt: skip
    events = audit.find(ACTION_PROPOSE)
    assert [e.outcome for e in events] == [AuditOutcome.ATTEMPT, AuditOutcome.FAILED]
    assert events[-1].details["reason"] == "proposal_not_recorded"


def test_the_record_never_invents_an_approver(
    make_gateway: Gateways,
    make_proposal: Proposals,
    approvals: ApprovalService,
    approver: Principal,
    expected: Expected,
    clock: FixedClock,
) -> None:
    """Reviewer's suspicion on `binding.py`: a malformed approval used to yield an empty
    approver and "now" as the approval time."""
    gateway = make_gateway()
    proposal = make_proposal()
    made = gateway.request_approval(proposal, actor_id=REQUESTER)
    approval = approvals.approve(made.approval_id, approver)
    arguments: dict[str, Any] = {
        "stored": made,
        "transmitted_by": REQUESTER,
        "preview": expected(proposal),
        "payload_bytes": made.payload_bytes,
        "approver_role": APPROVER_ROLE,
        "allowed_classifications": frozenset(ALLOWED),
        "now": clock.now(),
        "correlation_id": "",
    }
    assert new_record(approval=approval, **arguments).approver == approver.actor_id
    for missing in ({"decided_by": None}, {"decided_by": ""}, {"decided_at": None}):
        with pytest.raises(FailClosed):
            new_record(approval=approval.model_copy(update=missing), **arguments)
