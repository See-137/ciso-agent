"""Fixtures for the external-inference tests (blueprint 8.4, steps 1 to 3)."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

import pytest
from sqlalchemy import Engine
from tests.fakes.core import FakeAudit, FakePrincipals

from ciso.common.classification import ClassificationScheme
from ciso.common.clock import FixedClock
from ciso.inference.external import ContextItem, ExternalProposalService
from ciso.vault.redact import SecretRedactor

#: A registered secret value and two token-shaped strings nobody registered.
REGISTERED_SECRET = "hunter2-correct-horse-battery"
JWT_SHAPED = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.c2lnbmF0dXJl"
BEARER_SHAPED = "Bearer abc123def456ghi789"
#: Plain text that must never show up in audit details, errors or reprs.
MARKER_TEXT = "ZEBRA-QUARTZ-17 quarterly patch summary"


@pytest.fixture
def real_redactor() -> SecretRedactor:
    redactor = SecretRedactor()
    assert redactor.register(REGISTERED_SECRET)
    return redactor


@pytest.fixture
def make_item() -> Callable[..., ContextItem]:
    def build(
        ident: str = "a1",
        text: str = MARKER_TEXT,
        classification: str | None = "public",
        source: str = "registry",
    ) -> ContextItem:
        return ContextItem(
            ref=f"evidence:{ident}", text=text, classification=classification, source=source
        )

    return build


@pytest.fixture
def make_service(
    engine: Engine,
    clock: FixedClock,
    audit: FakeAudit,
    real_redactor: SecretRedactor,
    principals: FakePrincipals,
    classification: ClassificationScheme,
) -> Callable[..., ExternalProposalService]:
    """An enabled service that allows the two least sensitive test labels. Override any
    argument by keyword; `enabled=False` gives the shipped default."""

    def build(**overrides: Any) -> ExternalProposalService:
        deps: dict[str, Any] = {
            "engine": engine,
            "clock": clock,
            "audit": audit,
            "redactor": real_redactor,
            "principals": principals,
            "scheme": classification,
            "allowed_classifications": ("public", "internal"),
            "enabled": True,
        }
        deps.update(overrides)
        return ExternalProposalService(**deps)

    return build


# --- steps 4 to 7: authorize, transmit, record, reintegrate (plan rows T2.7, T2.8) --------
# Imports sit here so the fixtures above stay exactly as they were.

from datetime import timedelta  # noqa: E402

from sqlalchemy import func, select  # noqa: E402
from tests.fakes.core import FakeKillSwitch  # noqa: E402

from ciso.approvals import ApprovalService  # noqa: E402
from ciso.approvals.tables import approval as approval_table  # noqa: E402
from ciso.common.enums import Role  # noqa: E402
from ciso.common.principal import Principal  # noqa: E402
from ciso.common.protocols import AuditEvent, AuditReceipt  # noqa: E402
from ciso.inference.external import (  # noqa: E402
    ExternalInferenceGateway,
    ExternalRequestProposal,
    PayloadPreview,
    TransportResponse,
    build_preview,
    minimize,
)

APPROVAL_TTL = timedelta(hours=1)
REQUESTER = "human_emp"
APPROVER_ROLE = Role.SYSTEM_OWNER
PROVIDER = "provider-one"
MODEL = "model-large-1"
PURPOSE = "summarise the patch backlog"
ANSWER_MARKER = "OKAPI-BASALT-42 answer body"
ALLOWED = ("public", "internal")
#: Test-only values for the two byte limits. The shipped default is None: refuse.
MAX_PAYLOAD_BYTES = 20_000
MAX_RESPONSE_BYTES = 5_000


class SpyTransport:
    """Test-only `ExternalTransport`. Records every call; never touches the network."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, str, bytes]] = []
        self.body: bytes = ANSWER_MARKER.encode("utf-8")
        self.metadata: dict[str, str] = {"provider_request_id": "r-123", "output_tokens": "7"}
        self.raises: Exception | None = None
        self.returns: Any = None

    def send(self, *, provider_name: str, model_name: str, payload: bytes) -> TransportResponse:
        self.calls.append((provider_name, model_name, payload))
        if self.raises is not None:
            raise self.raises
        if self.returns is not None:
            return self.returns  # type: ignore[no-any-return]
        return TransportResponse(body=self.body, metadata=self.metadata)


def signed_in(principal: Principal, issued_by: str = "human_idp_admin") -> Principal:
    """The principal as sign-in would return it: with a credential issuer."""
    return principal.model_copy(update={"credential_issued_by": issued_by})


def approval_rows(engine: Engine) -> int:
    with engine.begin() as conn:
        return int(conn.execute(select(func.count()).select_from(approval_table)).scalar_one())


def fail_audit_when(
    monkeypatch: pytest.MonkeyPatch, audit: FakeAudit, predicate: Callable[[AuditEvent], bool]
) -> None:
    """Make the audit sink raise for the events `predicate` picks, and record the rest."""
    real = audit.append

    def append(event: AuditEvent) -> AuditReceipt:
        if predicate(event):
            raise RuntimeError("audit path unavailable (scripted)")
        return real(event)

    monkeypatch.setattr(audit, "append", append)


@pytest.fixture
def spy() -> SpyTransport:
    return SpyTransport()


@pytest.fixture
def approvals(
    engine: Engine, audit: FakeAudit, clock: FixedClock, principals: FakePrincipals
) -> ApprovalService:
    return ApprovalService(
        engine=engine, audit=audit, clock=clock, principals=principals, approval_ttl=APPROVAL_TTL
    )


@pytest.fixture
def approver(system_owner: Principal) -> Principal:
    """A second human who holds the configured approver role."""
    return signed_in(system_owner)


@pytest.fixture
def make_gateway(
    engine: Engine,
    clock: FixedClock,
    audit: FakeAudit,
    real_redactor: SecretRedactor,
    principals: FakePrincipals,
    killswitch: FakeKillSwitch,
    approvals: ApprovalService,
    classification: ClassificationScheme,
    spy: SpyTransport,
) -> Callable[..., ExternalInferenceGateway]:
    """A fully enabled gateway with the spy transport. Override any argument by keyword;
    `make_gateway(enabled=False)` and friends give one refusing configuration each."""

    def build(**overrides: Any) -> ExternalInferenceGateway:
        deps: dict[str, Any] = {
            "engine": engine,
            "clock": clock,
            "audit": audit,
            "redactor": real_redactor,
            "principals": principals,
            "killswitch": killswitch,
            "approvals": approvals,
            "scheme": classification,
            "allowed_classifications": ALLOWED,
            "enabled": True,
            "approver_role": APPROVER_ROLE,
            "transport": spy,
            "max_payload_bytes": MAX_PAYLOAD_BYTES,
            "max_response_bytes": MAX_RESPONSE_BYTES,
        }
        deps.update(overrides)
        return ExternalInferenceGateway(**deps)

    return build


@pytest.fixture
def make_proposal(
    make_service: Callable[..., ExternalProposalService],
) -> Callable[..., ExternalRequestProposal]:
    """A proposal that went through `propose` (so its record exists), built from explicit
    values so a test can change exactly one of them. `via` proposes through another
    service or gateway, for example one with a digest key."""
    default = make_service()

    def build(
        *,
        provider: str = PROVIDER,
        model: str = MODEL,
        purpose: str = PURPOSE,
        text: str = MARKER_TEXT,
        label: str | None = "public",
        requester: str = REQUESTER,
        via: Any = None,
    ) -> ExternalRequestProposal:
        made: ExternalRequestProposal = (via or default).propose(
            requester_actor_id=requester,
            purpose=purpose,
            provider_name=provider,
            model_name=model,
            items=[
                ContextItem(ref="evidence:a1", text=text, classification=label, source="registry")
            ],
        )
        return made

    return build


@pytest.fixture
def expected(
    classification: ClassificationScheme, real_redactor: SecretRedactor
) -> Callable[..., PayloadPreview]:
    """What a proposal must minimize to, computed without the gateway: the bytes a test
    compares the transport call against."""

    def build(
        proposal: ExternalRequestProposal, allowed: tuple[str, ...] = ALLOWED
    ) -> PayloadPreview:
        return build_preview(
            minimize(
                proposal,
                scheme=classification,
                allowed_classifications=allowed,
                redactor=real_redactor,
            )
        )

    return build
