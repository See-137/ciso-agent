"""Helpers for the M2 wiring tests: signed-in actors on a real container, a test
transport, and an external gateway rebuilt by the composition root's own builder."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from sqlalchemy import create_engine
from tests.app.helpers import provisional

from ciso.app import Container
from ciso.app.container import build_external_gateway
from ciso.app.settings import ExternalInferenceSettings, Settings
from ciso.approvals import Approval
from ciso.common.enums import ActorType, Role
from ciso.common.ids import new_id
from ciso.common.principal import Principal
from ciso.inference.external import (
    ContextItem,
    ExternalInferenceGateway,
    ExternalRequestProposal,
    TransportResponse,
)

ALLOWED = ("public", "internal")
PROVIDER = "provider-one"
MODEL = "model-large-1"
PURPOSE = "summarise the patch backlog"
MARKER = "ZEBRA-QUARTZ-17 quarterly patch summary"
SUBJECT = {
    "subject_kind": "action_envelope",
    "subject_hash": "ab" * 32,
    "binding": {"envelope_sha256": "cd" * 32},
}
BROKER = {"actor_id": "svc_broker", "actor_type": ActorType.SERVICE}


def external_on(settings: Settings, **changes: Any) -> Settings:
    """`settings` with the external path switched on and fully decided."""
    block = ExternalInferenceSettings(
        enabled=True, approver_role=Role.SYSTEM_OWNER, allowed_classifications=ALLOWED
    )
    return settings.model_copy(update={"external_inference": block.model_copy(update=changes)})


def enabled_settings(data_dir: Path, **safety: Any) -> Settings:
    return external_on(provisional(data_dir, **safety))


class SpyTransport:
    """Test-only `ExternalTransport`. Records every call; never touches the network."""

    def __init__(self, body: bytes = b"OKAPI-BASALT-42 answer body") -> None:
        self.calls: list[tuple[str, str, bytes]] = []
        self.body = body

    def send(self, *, provider_name: str, model_name: str, payload: bytes) -> TransportResponse:
        self.calls.append((provider_name, model_name, payload))
        return TransportResponse(body=self.body)


def gateway_with(container: Container, transport: SpyTransport) -> ExternalInferenceGateway:
    """The container's external gateway as `build_container` wires it, plus a transport."""
    return build_external_gateway(
        container.settings,
        engine=container.operational_engine,
        clock=container.clock,
        audit=container.audit,
        redactor=container.redactor,
        principals=container.identity,
        killswitch=container.killswitch_reader,
        approvals=container.approvals,
        secrets=container.secret_store,
        transport=transport,
    )


def tamper_a_middle_record(settings: Settings) -> None:
    """Change a stored audit record behind the log's back, so the next start-up's
    verification fails while appends keep working."""
    engine = create_engine(f"sqlite:///{settings.audit_db}")
    try:
        with engine.begin() as conn:
            conn.exec_driver_sql("DROP TRIGGER audit_record_no_update")
            conn.exec_driver_sql("UPDATE audit_record SET target = 'asset:forged' WHERE seq = 2")
    finally:
        engine.dispose()


def first_admin(container: Container) -> Principal:
    """Bootstrap the first admin and return it as sign-in would."""
    boot = container.host_local.bootstrap_first_admin("First Admin")
    return container.authenticator.authenticate(boot.token.token)


def human(container: Container, admin: Principal, name: str, *roles: Role) -> Principal:
    """A human holding `roles`, signed in with a token `admin` minted."""
    actor = container.identity.create_actor(admin, ActorType.HUMAN, name)
    for role in roles:
        container.identity.assign_role(admin, actor.id, role)
    token = container.authenticator.issue_token(actor.id, admin).token
    return container.authenticator.authenticate(token)


def agent_request(container: Container, admin: Principal) -> Approval:
    """A pending approval request filed in an agent's name, for a system owner."""
    agent = container.identity.create_actor(admin, ActorType.AGENT, "Proposing agent")
    return container.approvals.request(
        **SUBJECT,
        requested_by=agent.id,
        requested_by_type=ActorType.AGENT,
        required_roles=(Role.SYSTEM_OWNER,),
        target={},
    )


def items() -> tuple[ContextItem, ...]:
    return (
        ContextItem(ref="evidence:a1", text=MARKER, classification="public", source="registry"),
    )


def made_up_proposal(container: Container, requester: str) -> ExternalRequestProposal:
    """Well-formed, but never recorded by `propose`."""
    return ExternalRequestProposal(
        request_id=new_id("xrq"),
        requester_actor_id=requester,
        requester_actor_type=ActorType.HUMAN,
        purpose=PURPOSE,
        provider_name=PROVIDER,
        model_name=MODEL,
        items=items(),
        created_at=container.clock.now(),
    )


def propose(gateway: ExternalInferenceGateway, requester: Principal) -> ExternalRequestProposal:
    return gateway.propose(
        requester_actor_id=requester.actor_id,
        purpose=PURPOSE,
        provider_name=PROVIDER,
        model_name=MODEL,
        items=items(),
    )
