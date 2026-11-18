"""External inference steps 1 to 3: propose, preview, minimize (blueprint 8.4, 11.1).

Plan row T2.6; gaps G1, G2, G7, G26. Each refusal is asserted by its reason code, and each
guard has a neighbouring test that proves the allowed path works.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from typing import Any

import pytest
from pydantic import ValidationError
from sqlalchemy import Engine
from tests.external_inference.conftest import (
    BEARER_SHAPED,
    JWT_SHAPED,
    MARKER_TEXT,
    REGISTERED_SECRET,
)
from tests.fakes.core import FakeAudit, FakePrincipals, FakeRedactor, make_principal

from ciso.common.classification import UNKNOWN_LABEL, ClassificationScheme
from ciso.common.clock import FixedClock
from ciso.common.enums import ActorType, AuditOutcome
from ciso.common.errors import ExternalInferenceBlocked, FailClosed, ValidationFailed
from ciso.common.ids import is_id
from ciso.common.principal import Principal
from ciso.common.schemas import canonical_json, sha256_hex
from ciso.inference.external import (
    ACTION_PREVIEW,
    ACTION_PROPOSE,
    ApprovalBinding,
    ContextItem,
    ExternalProposalService,
    ExternalReason,
    ExternalRequestProposal,
    ExternalRequestRefused,
    KeptItem,
    MinimizedPayload,
    PayloadPreview,
    approval_binding,
    build_preview,
    classify,
    minimize,
    preview_bytes,
)
from ciso.vault.redact import SecretRedactor

pytestmark = pytest.mark.external_inference

ServiceFactory = Callable[..., ExternalProposalService]
ItemFactory = Callable[..., ContextItem]

HUMAN = "human_emp"
PROVIDER = "provider-one"
MODEL = "model-large-1"
PURPOSE = "summarise the patch backlog"
LONE_SURROGATE = "\ud800"


def _propose(service: ExternalProposalService, *items: ContextItem, **overrides: Any) -> Any:
    args: dict[str, Any] = {
        "requester_actor_id": HUMAN,
        "purpose": PURPOSE,
        "provider_name": PROVIDER,
        "model_name": MODEL,
        "items": list(items),
    }
    args.update(overrides)
    return service.propose(**args)


def _hand_built(
    clock: FixedClock, *items: ContextItem, **overrides: Any
) -> ExternalRequestProposal:
    fields: dict[str, Any] = {
        "request_id": "xrq_" + "0" * 26,
        "requester_actor_id": HUMAN,
        "requester_actor_type": ActorType.HUMAN,
        "purpose": PURPOSE,
        "provider_name": PROVIDER,
        "model_name": MODEL,
        "items": items,
        "created_at": clock.now(),
    }
    fields.update(overrides)
    return ExternalRequestProposal(**fields)


def _audit_text(audit: FakeAudit) -> str:
    return canonical_json([event.model_dump(mode="json") for event in audit.events])


# --- feature flag -----------------------------------------------------------------------


def test_feature_is_off_by_default_and_propose_builds_nothing(
    engine: Engine,
    clock: FixedClock,
    audit: FakeAudit,
    principals: FakePrincipals,
    make_item: ItemFactory,
) -> None:
    redactor = FakeRedactor()
    service = ExternalProposalService(
        engine=engine, clock=clock, audit=audit, redactor=redactor, principals=principals
    )
    with pytest.raises(ExternalRequestRefused) as caught:
        _propose(service, make_item())
    assert caught.value.reason is ExternalReason.FEATURE_DISABLED
    assert isinstance(caught.value, ExternalInferenceBlocked)
    assert redactor.calls == 0
    (event,) = audit.find(ACTION_PROPOSE)
    assert event.outcome is AuditOutcome.DENIED
    assert event.details == {"reason": "feature_disabled"}


def test_preview_is_refused_while_disabled_and_builds_no_payload(
    clock: FixedClock, audit: FakeAudit, make_service: ServiceFactory, make_item: ItemFactory
) -> None:
    redactor = FakeRedactor()
    service = make_service(enabled=False, redactor=redactor)
    with pytest.raises(ExternalRequestRefused) as caught:
        service.preview(_hand_built(clock, make_item()), actor_id=HUMAN)
    assert caught.value.reason is ExternalReason.FEATURE_DISABLED
    assert redactor.calls == 0
    (event,) = audit.find(ACTION_PREVIEW)
    assert event.outcome is AuditOutcome.DENIED


# --- propose ----------------------------------------------------------------------------


def test_propose_returns_an_audited_proposal(
    clock: FixedClock, audit: FakeAudit, make_service: ServiceFactory, make_item: ItemFactory
) -> None:
    proposal = _propose(make_service(), make_item("a1"), make_item("a2", classification="internal"))
    assert is_id(proposal.request_id, "xrq")
    assert proposal.requester_actor_id == HUMAN
    assert proposal.requester_actor_type is ActorType.HUMAN
    assert (proposal.provider_name, proposal.model_name, proposal.purpose) == (
        PROVIDER,
        MODEL,
        PURPOSE,
    )
    assert proposal.created_at == clock.now()
    assert [item.classification for item in proposal.items] == ["public", "internal"]
    attempt, event = audit.find(ACTION_PROPOSE)
    assert (attempt.outcome, event.outcome) == (AuditOutcome.ATTEMPT, AuditOutcome.SUCCESS)
    assert attempt.details == event.details
    assert event.actor_id == HUMAN
    assert event.target == f"external_request:{proposal.request_id}"
    assert event.details["item_count"] == 2
    assert event.details["purpose_sha256"] == sha256_hex(PURPOSE)
    assert event.details["items"][1] == {
        "ref": "evidence:a2",
        "classification": "internal",
        "source": "registry",
    }


@pytest.mark.parametrize("actor_id", ["agent_ciso", "svc_connector"])
def test_agent_and_service_requesters_are_refused(
    audit: FakeAudit, make_service: ServiceFactory, make_item: ItemFactory, actor_id: str
) -> None:
    with pytest.raises(ExternalRequestRefused) as caught:
        _propose(make_service(), make_item(), requester_actor_id=actor_id)
    assert caught.value.reason is ExternalReason.REQUESTER_NOT_HUMAN
    (event,) = audit.find(ACTION_PROPOSE)
    assert event.outcome is AuditOutcome.DENIED
    assert event.details == {"reason": "requester_not_human"}


def test_requester_is_resolved_now_not_taken_on_trust(
    audit: FakeAudit,
    principals: FakePrincipals,
    make_service: ServiceFactory,
    make_item: ItemFactory,
    employee: Principal,
) -> None:
    service = make_service()
    assert _propose(service, make_item()).requester_actor_id == employee.actor_id
    assert principals.lookups == [employee.actor_id]
    principals.remove(employee.actor_id)
    with pytest.raises(ExternalRequestRefused) as caught:
        _propose(service, make_item())
    assert caught.value.reason is ExternalReason.REQUESTER_UNKNOWN
    denied = audit.find(ACTION_PROPOSE)[-1]
    assert denied.outcome is AuditOutcome.DENIED
    assert denied.actor_type is ActorType.ANONYMOUS


def test_an_actor_that_became_an_agent_is_refused(
    principals: FakePrincipals, make_service: ServiceFactory, make_item: ItemFactory
) -> None:
    """The identity store's answer wins over whatever the caller believed earlier."""
    principals.register(make_principal(HUMAN, ActorType.AGENT))
    with pytest.raises(ExternalRequestRefused) as caught:
        _propose(make_service(), make_item())
    assert caught.value.reason is ExternalReason.REQUESTER_NOT_HUMAN


def test_identity_store_down_fails_closed(
    audit: FakeAudit,
    principals: FakePrincipals,
    make_service: ServiceFactory,
    make_item: ItemFactory,
) -> None:
    principals.broken = True
    with pytest.raises(FailClosed):
        _propose(make_service(), make_item())
    assert audit.events == []


@pytest.mark.parametrize(
    "overrides",
    [
        {"purpose": "   "},
        {"provider_name": "has spaces"},
        {"model_name": ""},
        {"items": []},
    ],
)
def test_bad_proposals_are_refused_without_quoting_content(
    audit: FakeAudit,
    make_service: ServiceFactory,
    make_item: ItemFactory,
    overrides: dict[str, Any],
) -> None:
    with pytest.raises(ValidationFailed) as caught:
        _propose(make_service(), make_item(), **overrides)
    assert next(iter(overrides)) in str(caught.value)
    assert MARKER_TEXT not in str(caught.value)
    assert audit.find(ACTION_PROPOSE) == []


def test_repeated_refs_are_refused(make_service: ServiceFactory, make_item: ItemFactory) -> None:
    with pytest.raises(ValidationFailed) as caught:
        _propose(make_service(), make_item("a1"), make_item("a1", text="other"))
    assert "items" in str(caught.value)
    assert MARKER_TEXT not in str(caught.value)


def test_validation_errors_name_fields_not_content(
    make_service: ServiceFactory, make_item: ItemFactory
) -> None:
    with pytest.raises(ValidationFailed) as caught:
        _propose(make_service(), make_item(), purpose=MARKER_TEXT * 40)
    assert "purpose" in str(caught.value)
    assert "ZEBRA" not in str(caught.value)
    assert caught.value.__cause__ is None


def test_a_secret_in_the_purpose_is_redacted_before_it_is_stored(
    make_service: ServiceFactory, make_item: ItemFactory
) -> None:
    proposal = _propose(make_service(), make_item(), purpose=f"use {REGISTERED_SECRET} to log in")
    assert REGISTERED_SECRET not in proposal.purpose
    assert "[REDACTED]" in proposal.purpose


def test_models_refuse_malformed_fields(clock: FixedClock, make_item: ItemFactory) -> None:
    assert _hand_built(clock, make_item()).request_id.startswith("xrq_")
    with pytest.raises(ValidationError):
        _hand_built(clock, make_item(), request_id="not-an-id")
    with pytest.raises(ValidationError):
        _hand_built(clock, make_item(), requester_actor_id=" ")
    with pytest.raises(ValidationError):
        ContextItem(ref="no colon here", text="x", classification="public", source="registry")
    with pytest.raises(ValidationError):
        ContextItem(ref="evidence:a1", text="x", classification="public", source="free text!")
    with pytest.raises(ValidationError):
        MinimizedPayload(
            request_id="xrq_" + "0" * 26,
            provider_name=PROVIDER,
            model_name=MODEL,
            purpose=PURPOSE,
            kept=(),
            dropped=(),
            classification=UNKNOWN_LABEL,
            blocked_reason=None,
        )


def test_text_that_cannot_be_encoded_is_refused(
    make_service: ServiceFactory, make_item: ItemFactory
) -> None:
    with pytest.raises(ValidationError):
        make_item(text=f"broken {LONE_SURROGATE} text")
    with pytest.raises(ValidationFailed) as caught:
        _propose(make_service(), make_item(), purpose=f"broken {LONE_SURROGATE} purpose")
    assert "purpose" in str(caught.value)
    hand_built = MinimizedPayload(
        request_id="xrq_" + "0" * 26,
        provider_name=PROVIDER,
        model_name=MODEL,
        purpose=PURPOSE,
        kept=(
            KeptItem(ref="evidence:a1", classification="public", source="s", text=LONE_SURROGATE),
        ),
        dropped=(),
        classification="public",
        blocked_reason=None,
    )
    with pytest.raises(ValidationFailed) as refused:
        preview_bytes(hand_built)
    assert "UTF-8" in str(refused.value)


# --- classification ---------------------------------------------------------------------


def test_missing_and_unrecognised_labels_become_unknown(
    classification: ClassificationScheme, make_service: ServiceFactory, make_item: ItemFactory
) -> None:
    assert classify(classification, None) == UNKNOWN_LABEL
    assert classify(classification, "") == UNKNOWN_LABEL
    assert classify(classification, "top_secret_ish") == UNKNOWN_LABEL
    assert classify(None, "public") == UNKNOWN_LABEL
    assert classify(classification, "internal") == "internal"
    assert classification.rank(UNKNOWN_LABEL) > classification.rank("restricted")
    proposal = _propose(
        make_service(),
        make_item("a1", classification=None),
        make_item("a2", classification="made_up"),
    )
    assert [item.classification for item in proposal.items] == [UNKNOWN_LABEL, UNKNOWN_LABEL]


def test_unknown_items_are_dropped_with_their_own_reason(
    clock: FixedClock,
    classification: ClassificationScheme,
    real_redactor: SecretRedactor,
    make_item: ItemFactory,
) -> None:
    proposal = _hand_built(
        clock,
        make_item("a1", classification=None),
        make_item("a2", classification="made_up"),
        make_item("a3", classification="public"),
    )
    payload = minimize(
        proposal,
        scheme=classification,
        allowed_classifications=classification.labels,
        redactor=real_redactor,
    )
    assert [(d.ref, d.classification, d.reason) for d in payload.dropped] == [
        ("evidence:a1", UNKNOWN_LABEL, ExternalReason.CLASSIFICATION_UNKNOWN),
        ("evidence:a2", UNKNOWN_LABEL, ExternalReason.CLASSIFICATION_UNKNOWN),
    ]
    assert [k.ref for k in payload.kept] == ["evidence:a3"]
    assert payload.sendable


@pytest.mark.parametrize("allowed", [("unknown",), ("public", "unknown"), ("public", "made_up")])
def test_unknown_or_unconfigured_labels_cannot_be_allowed(
    clock: FixedClock,
    classification: ClassificationScheme,
    real_redactor: SecretRedactor,
    make_item: ItemFactory,
    allowed: tuple[str, ...],
) -> None:
    proposal = _hand_built(clock, make_item("a1", classification=None))
    with pytest.raises(ValidationFailed):
        minimize(
            proposal, scheme=classification, allowed_classifications=allowed, redactor=real_redactor
        )


# --- minimize ---------------------------------------------------------------------------


def test_items_outside_the_allowed_set_are_dropped_and_recorded(
    clock: FixedClock,
    classification: ClassificationScheme,
    real_redactor: SecretRedactor,
    make_item: ItemFactory,
) -> None:
    proposal = _hand_built(
        clock,
        make_item("a1", classification="public"),
        make_item("a2", classification="restricted"),
        make_item("a3", classification="internal"),
        make_item("a4", classification="confidential"),
    )
    payload = minimize(
        proposal,
        scheme=classification,
        allowed_classifications=("public", "internal"),
        redactor=real_redactor,
    )
    assert [(k.ref, k.classification) for k in payload.kept] == [
        ("evidence:a1", "public"),
        ("evidence:a3", "internal"),
    ]
    assert [(d.ref, d.classification, d.reason) for d in payload.dropped] == [
        ("evidence:a2", "restricted", ExternalReason.CLASSIFICATION_NOT_ALLOWED),
        ("evidence:a4", "confidential", ExternalReason.CLASSIFICATION_NOT_ALLOWED),
    ]
    assert len(payload.kept) + len(payload.dropped) == len(proposal.items)
    assert payload.classification == "internal"
    assert payload.blocked_reason is None
    assert payload.sendable


def test_allowed_set_is_empty_by_default_and_blocks_everything(
    clock: FixedClock,
    classification: ClassificationScheme,
    real_redactor: SecretRedactor,
    make_item: ItemFactory,
) -> None:
    """Gap G26: nobody decided which data may leave, so none may."""
    proposal = _hand_built(clock, make_item("a1"), make_item("a2"))
    payload = minimize(proposal, scheme=classification, redactor=real_redactor)
    assert payload.kept == ()
    assert [d.reason for d in payload.dropped] == [ExternalReason.NO_ALLOWED_CLASSIFICATIONS] * 2
    assert payload.blocked_reason is ExternalReason.NO_ALLOWED_CLASSIFICATIONS
    assert not payload.sendable
    assert payload.classification == UNKNOWN_LABEL


def test_no_scheme_blocks_everything(
    clock: FixedClock, real_redactor: SecretRedactor, make_item: ItemFactory
) -> None:
    proposal = _hand_built(clock, make_item("a1"))
    payload = minimize(
        proposal, scheme=None, allowed_classifications=("public",), redactor=real_redactor
    )
    assert payload.kept == ()
    assert [(d.classification, d.reason) for d in payload.dropped] == [
        (UNKNOWN_LABEL, ExternalReason.NO_SCHEME)
    ]
    assert payload.blocked_reason is ExternalReason.NO_SCHEME
    assert not payload.sendable


def test_everything_dropped_item_by_item_is_blocked(
    clock: FixedClock,
    classification: ClassificationScheme,
    real_redactor: SecretRedactor,
    make_item: ItemFactory,
) -> None:
    proposal = _hand_built(clock, make_item("a1", classification="restricted"))
    payload = minimize(
        proposal, scheme=classification, allowed_classifications=("public",), redactor=real_redactor
    )
    assert payload.blocked_reason is ExternalReason.NOTHING_SENDABLE
    with pytest.raises(ExternalRequestRefused) as caught:
        preview_bytes(payload)
    assert caught.value.reason is ExternalReason.NOTHING_SENDABLE
    preview = build_preview(payload)
    assert preview.preview_bytes is None
    assert preview.payload_hash is None
    assert not preview.sendable
    with pytest.raises(ExternalRequestRefused) as refused:
        approval_binding(preview)
    assert refused.value.reason is ExternalReason.NOTHING_SENDABLE


def test_secrets_and_token_shapes_do_not_survive_minimization(
    clock: FixedClock,
    classification: ClassificationScheme,
    real_redactor: SecretRedactor,
    make_item: ItemFactory,
) -> None:
    text = (
        f"login with {REGISTERED_SECRET}; header Authorization: {BEARER_SHAPED}; jwt {JWT_SHAPED}"
    )
    proposal = _hand_built(
        clock,
        make_item("a1", text=text),
        make_item("a2", text="nothing to hide here"),
        purpose=f"check {REGISTERED_SECRET}",
    )
    payload = minimize(
        proposal, scheme=classification, allowed_classifications=("public",), redactor=real_redactor
    )
    raw = preview_bytes(payload)
    for forbidden in (REGISTERED_SECRET, JWT_SHAPED, "abc123def456ghi789"):
        assert forbidden.encode() not in raw
        assert forbidden not in payload.kept[0].text
        assert forbidden not in payload.purpose
    assert b"[REDACTED]" in raw
    assert b"nothing to hide here" in raw
    assert payload.kept[1].text == "nothing to hide here"


def test_minimize_does_not_change_the_proposal(
    clock: FixedClock,
    classification: ClassificationScheme,
    real_redactor: SecretRedactor,
    make_item: ItemFactory,
) -> None:
    proposal = _hand_built(clock, make_item("a1", text=f"x {REGISTERED_SECRET}"))
    before = proposal.model_dump()
    minimize(
        proposal, scheme=classification, allowed_classifications=("public",), redactor=real_redactor
    )
    assert proposal.model_dump() == before


# --- preview bytes and hash -------------------------------------------------------------


def _payload_bytes(
    clock: FixedClock,
    scheme: ClassificationScheme,
    redactor: SecretRedactor,
    items: tuple[ContextItem, ...],
    **overrides: Any,
) -> bytes:
    payload = minimize(
        _hand_built(clock, *items, **overrides),
        scheme=scheme,
        allowed_classifications=("public", "internal"),
        redactor=redactor,
    )
    return preview_bytes(payload)


def test_preview_bytes_are_canonical_and_stable(
    clock: FixedClock,
    classification: ClassificationScheme,
    real_redactor: SecretRedactor,
    make_item: ItemFactory,
) -> None:
    items = (make_item("a1", text="alpha"), make_item("a2", text="béta", source="other"))
    first = _payload_bytes(clock, classification, real_redactor, items)
    second = _payload_bytes(clock, classification, real_redactor, items)
    assert first == second
    # Same content, fields supplied in the opposite order.
    reordered = tuple(
        ContextItem.model_validate(dict(reversed(list(item.model_dump().items()))))
        for item in items
    )
    assert _payload_bytes(clock, classification, real_redactor, reordered) == first
    document = json.loads(first.decode("utf-8"))
    expected = json.dumps(document, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    assert first == expected.encode("utf-8")
    assert document == {
        "schema": 1,
        "request_id": "xrq_" + "0" * 26,
        "provider": PROVIDER,
        "model": MODEL,
        "purpose": PURPOSE,
        "items": [
            {"ref": "evidence:a1", "classification": "public", "text": "alpha"},
            {"ref": "evidence:a2", "classification": "public", "text": "béta"},
        ],
    }


@pytest.mark.parametrize(
    "overrides",
    [
        {"provider_name": "provider-two"},
        {"model_name": "model-large-2"},
        {"purpose": PURPOSE + "."},
        {"request_id": "xrq_" + "0" * 25 + "1"},
    ],
)
def test_hash_changes_with_each_bound_field(
    clock: FixedClock,
    classification: ClassificationScheme,
    real_redactor: SecretRedactor,
    make_item: ItemFactory,
    overrides: dict[str, Any],
) -> None:
    items = (make_item("a1", text="alpha"),)
    base = _payload_bytes(clock, classification, real_redactor, items)
    changed = _payload_bytes(clock, classification, real_redactor, items, **overrides)
    assert sha256_hex(base) != sha256_hex(changed)


def test_hash_changes_with_one_byte_of_content(
    clock: FixedClock,
    classification: ClassificationScheme,
    real_redactor: SecretRedactor,
    make_item: ItemFactory,
) -> None:
    base = _payload_bytes(clock, classification, real_redactor, (make_item("a1", text="alpha"),))
    changed = _payload_bytes(clock, classification, real_redactor, (make_item("a1", text="alphb"),))
    assert len(base) == len(changed)
    assert sha256_hex(base) != sha256_hex(changed)


def test_the_bytes_hashed_are_the_bytes_returned(
    audit: FakeAudit, make_service: ServiceFactory, make_item: ItemFactory
) -> None:
    service = make_service()
    proposal = _propose(
        service,
        make_item("a1", text=f"alpha {REGISTERED_SECRET}"),
        make_item("a2", classification="restricted"),
        make_item("a3", classification=None),
    )
    preview = service.preview(proposal, actor_id="human_owner")
    assert preview.sendable
    assert preview.preview_bytes is not None
    assert preview.payload_hash == sha256_hex(preview.preview_bytes)
    assert REGISTERED_SECRET.encode() not in preview.preview_bytes
    again = service.preview(proposal, actor_id="human_owner")
    assert again.preview_bytes == preview.preview_bytes
    assert again.payload_hash == preview.payload_hash
    assert [(k.ref, k.classification) for k in preview.kept] == [("evidence:a1", "public")]
    assert [(d.ref, d.reason) for d in preview.dropped] == [
        ("evidence:a2", ExternalReason.CLASSIFICATION_NOT_ALLOWED),
        ("evidence:a3", ExternalReason.CLASSIFICATION_UNKNOWN),
    ]
    event = audit.find(ACTION_PREVIEW)[0]
    assert event.outcome is AuditOutcome.SUCCESS
    assert event.actor_id == "human_owner"
    assert event.details["payload_sha256"] == preview.payload_hash
    assert event.details["payload_bytes"] == len(preview.preview_bytes)
    assert (event.details["kept_count"], event.details["dropped_count"]) == (1, 2)
    assert event.details["dropped"][1] == {
        "ref": "evidence:a3",
        "classification": UNKNOWN_LABEL,
        "reason": "classification_unknown",
    }
    assert event.details["sendable"] is True


def test_binding_covers_hash_provider_model_purpose_and_request(
    make_service: ServiceFactory, make_item: ItemFactory
) -> None:
    service = make_service()
    proposal = _propose(service, make_item("a1"))
    preview = service.preview(proposal, actor_id=HUMAN)
    binding = approval_binding(preview)
    assert binding == ApprovalBinding(
        request_id=proposal.request_id,
        provider_name=PROVIDER,
        model_name=MODEL,
        purpose=PURPOSE,
        payload_hash=sha256_hex(preview.preview_bytes or b""),
    )
    assert binding.subject_hash() == sha256_hex(canonical_json(binding))
    other = binding.model_copy(update={"purpose": PURPOSE + "!"})
    assert other.subject_hash() != binding.subject_hash()


def test_a_preview_cannot_claim_a_hash_or_fields_its_bytes_do_not_have(
    make_service: ServiceFactory, make_item: ItemFactory
) -> None:
    service = make_service()
    preview = service.preview(_propose(service, make_item("a1")), actor_id=HUMAN)
    good = preview.model_dump()
    assert PayloadPreview(**good) == preview
    for field, value in (
        ("payload_hash", "0" * 64),
        ("preview_bytes", (preview.preview_bytes or b"") + b" "),
        ("provider_name", "provider-two"),
        ("model_name", "model-large-2"),
        ("purpose", "something else"),
        ("request_id", "xrq_" + "1" * 26),
        ("kept", ()),
        ("preview_bytes", None),
        ("payload_hash", None),
    ):
        with pytest.raises(ValidationError):
            PayloadPreview(**{**good, field: value})
    with pytest.raises(ValidationError):
        PayloadPreview(**{**good, "blocked_reason": ExternalReason.NOTHING_SENDABLE})


def test_blocked_preview_is_returned_with_no_bytes_and_is_audited(
    audit: FakeAudit, make_service: ServiceFactory, make_item: ItemFactory
) -> None:
    service = make_service(allowed_classifications=())
    proposal = _propose(service, make_item("a1"))
    preview = service.preview(proposal, actor_id=HUMAN)
    assert not preview.sendable
    assert preview.blocked_reason is ExternalReason.NO_ALLOWED_CLASSIFICATIONS
    assert preview.preview_bytes is None
    assert preview.payload_hash is None
    assert [d.ref for d in preview.dropped] == ["evidence:a1"]
    (event,) = audit.find(ACTION_PREVIEW)
    assert event.details["sendable"] is False
    assert event.details["blocked_reason"] == "no_allowed_classifications"
    assert event.details["payload_sha256"] is None
    assert event.details["payload_bytes"] == 0


def test_preview_is_refused_for_a_non_human_viewer(
    audit: FakeAudit, make_service: ServiceFactory, make_item: ItemFactory
) -> None:
    service = make_service()
    proposal = _propose(service, make_item("a1"))
    with pytest.raises(ExternalRequestRefused) as caught:
        service.preview(proposal, actor_id="agent_ciso")
    assert caught.value.reason is ExternalReason.REQUESTER_NOT_HUMAN
    assert audit.find(ACTION_PREVIEW)[0].outcome is AuditOutcome.DENIED
    assert service.preview(proposal, actor_id=HUMAN).sendable


# --- audit and leakage ------------------------------------------------------------------


def test_propose_fails_closed_when_audit_is_down(
    audit: FakeAudit, make_service: ServiceFactory, make_item: ItemFactory
) -> None:
    service = make_service()
    audit.fail = True
    with pytest.raises(FailClosed):
        _propose(service, make_item())
    audit.fail = False
    assert _propose(service, make_item()).request_id


def test_preview_fails_closed_when_audit_is_down(
    audit: FakeAudit, make_service: ServiceFactory, make_item: ItemFactory
) -> None:
    service = make_service()
    proposal = _propose(service, make_item())
    audit.fail = True
    with pytest.raises(FailClosed):
        service.preview(proposal, actor_id=HUMAN)
    audit.fail = False
    assert service.preview(proposal, actor_id=HUMAN).sendable


def test_a_refusal_that_cannot_be_audited_fails_closed(
    audit: FakeAudit, make_service: ServiceFactory, make_item: ItemFactory
) -> None:
    audit.fail = True
    with pytest.raises(FailClosed):
        _propose(make_service(enabled=False), make_item())


def test_any_audit_error_becomes_fail_closed(
    make_service: ServiceFactory, make_item: ItemFactory
) -> None:
    class BrokenSink:
        def append(self, event: Any) -> Any:
            raise RuntimeError("disk full")

    with pytest.raises(FailClosed):
        _propose(make_service(audit=BrokenSink()), make_item())


def test_text_never_reaches_audit_or_reprs(
    audit: FakeAudit,
    classification: ClassificationScheme,
    real_redactor: SecretRedactor,
    make_service: ServiceFactory,
    make_item: ItemFactory,
) -> None:
    service = make_service()
    purpose = "PURPLE-HERON-42 review"
    proposal = _propose(
        service, make_item("a1"), make_item("a2", classification="restricted"), purpose=purpose
    )
    preview = service.preview(proposal, actor_id=HUMAN)
    assert preview.preview_bytes is not None
    assert MARKER_TEXT.encode() in preview.preview_bytes
    assert [e.outcome.value for e in audit.events] == ["attempt", "success", "success"]
    for word in ("ZEBRA", "HERON"):
        assert word not in _audit_text(audit)
    payload = minimize(
        proposal,
        scheme=classification,
        allowed_classifications=("public",),
        redactor=real_redactor,
    )
    assert payload.kept[0].text == MARKER_TEXT
    for shown in (
        repr(proposal),
        str(proposal),
        repr(proposal.items[0]),
        repr(payload),
        repr(payload.kept[0]),
        repr(preview),
    ):
        assert "ZEBRA" not in shown
