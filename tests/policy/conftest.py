"""Fixtures for the policy tests: a sample operation catalog, a fake context, a builder."""

from __future__ import annotations

from collections.abc import Callable
from datetime import datetime, timedelta
from typing import Any

import pytest
from tests.fakes.core import FakeAudit, FakePrincipals

from ciso.common.clock import FixedClock
from ciso.common.enums import ActorType, AuthorityLevel, Environment, FreshnessState, Role
from ciso.common.ids import new_id
from ciso.common.principal import Principal, RoleGrant
from ciso.common.schemas import Model
from ciso.policy import (
    ActionEnvelope,
    EnvelopeScope,
    OperationCatalog,
    OperationSpec,
    PlaybookStatus,
    PolicyEngine,
    RollbackPlan,
    RuleSet,
    VerificationPlan,
    load_default_ruleset,
)

TTL = timedelta(hours=1)


class NoArgs(Model):
    pass


class ReadArgs(Model):
    fields: tuple[str, ...] = ()


class ChannelArgs(Model):
    channel: str
    title: str


class HostArgs(Model):
    host: str


class NoteArgs(Model):
    note: str


class PolicyChangeArgs(Model):
    rule_id: str


def _protected(name: str, level: AuthorityLevel = AuthorityLevel.L4_HIGH_IMPACT) -> OperationSpec:
    args = PolicyChangeArgs if name == "policy.update_rule" else NoArgs
    return OperationSpec(
        name=name, authority_level=level, args_model=args, writes=True, protected=True
    )


#: Protected operations in the sample catalog, one per family the reviewer listed.
PROTECTED_OPS = [
    "policy.update_rule",
    "policies.update",
    "roles.assign",
    "role.assign",
    "identity.role.assign",
    "audit.delete_record",
    "audit_log.purge",
    "permissions.grant_self",
    "prompt.update_own",
    "killswitch.release",
    "approvers.change",
    "approvals.decide",
    "playbook.enable",
    "connector.add_credential",
    "model.swap",
    "finding.suppress",
]


def sample_specs() -> list[OperationSpec]:
    L = AuthorityLevel
    return [
        OperationSpec(
            name="asset.read",
            authority_level=L.L0_OBSERVE,
            args_model=ReadArgs,
            agent_requestable=True,
        ),
        OperationSpec(
            name="finding.investigate",
            authority_level=L.L1_INVESTIGATE,
            args_model=ReadArgs,
            agent_requestable=True,
        ),
        OperationSpec(
            name="ticket.create_draft",
            authority_level=L.L2_COORDINATE,
            args_model=ChannelArgs,
            writes=True,
            channel_argument="channel",
            agent_requestable=True,
        ),
        OperationSpec(
            name="asset.annotate",
            authority_level=L.L2_COORDINATE,
            args_model=NoteArgs,
            writes=True,
        ),
        OperationSpec(
            name="credential.rotate_key",
            authority_level=L.L3_EXECUTE,
            args_model=HostArgs,
            writes=True,
            agent_requestable=True,
        ),
        OperationSpec(
            name="network.isolate_host",
            authority_level=L.L4_HIGH_IMPACT,
            args_model=HostArgs,
            writes=True,
            agent_requestable=True,
        ),
        *(_protected(name) for name in PROTECTED_OPS),
    ]


DEFAULT_ARGS: dict[str, dict[str, Any]] = {
    "asset.read": {"fields": ["owner"]},
    "finding.investigate": {},
    "ticket.create_draft": {"channel": "outbox:security", "title": "Rotate key"},
    "asset.annotate": {"note": "seen"},
    "credential.rotate_key": {"host": "host:web-1"},
    "network.isolate_host": {"host": "host:web-1"},
    "policy.update_rule": {"rule_id": "r-1"},
}

L3_OP = "credential.rotate_key"


class FakeContext:
    """Answers the engine's questions from plain attributes; can be told to raise."""

    def __init__(self, clock: FixedClock) -> None:
        self.clock = clock
        self.in_scope: Any = True
        self.approved_channels: set[str] = {"outbox:security"}
        self.channel_answer: Any = None
        self.playbooks: dict[tuple[str, str], Any] = {}
        self.freshness: dict[str, FreshnessState] = {}
        self.freshness_answer: Any = None
        self.raise_on: set[str] = set()
        self.calls: list[str] = []

    def _enter(self, name: str) -> None:
        self.calls.append(name)
        if name in self.raise_on:
            raise RuntimeError(f"{name} unavailable")

    def is_within_scope(self, principal: Principal, envelope: ActionEnvelope) -> Any:
        self._enter("is_within_scope")
        return self.in_scope

    def is_channel_approved(self, channel: str) -> Any:
        self._enter("is_channel_approved")
        if self.channel_answer is not None:
            return self.channel_answer
        return channel in self.approved_channels

    def playbook_status(self, operation: str, scope: EnvelopeScope) -> Any:
        self._enter("playbook_status")
        return self.playbooks.get((operation, scope.resource))

    def fact_freshness(self, refs: tuple[str, ...]) -> Any:
        self._enter("fact_freshness")
        if self.freshness_answer is not None:
            return self.freshness_answer
        return {ref: self.freshness.get(ref, FreshnessState.CURRENT) for ref in refs}

    def add_valid_playbook(
        self,
        operation: str = L3_OP,
        resource: str = "app:billing",
        expires_at: datetime | None = None,
    ) -> None:
        self.playbooks[(operation, resource)] = PlaybookStatus(
            playbook_ref="playbook:pb1",
            approved=True,
            enabled=True,
            expires_at=expires_at or self.clock.now() + timedelta(days=30),
        )


EnvelopeBuilder = Callable[..., ActionEnvelope]


def human(actor_id: str, *grants: RoleGrant, roles: tuple[Role, ...] = ()) -> Principal:
    """A human principal in the form identity produces: roles plus scoped grants."""
    held = frozenset(roles) | {grant.role for grant in grants}
    return Principal(
        actor_id=actor_id, actor_type=ActorType.HUMAN, roles=held, grants=tuple(grants)
    )


def grant(role: Role, **scope: str | tuple[str, ...]) -> RoleGrant:
    return RoleGrant(
        role=role,
        scope={
            key: frozenset((value,) if isinstance(value, str) else value)
            for key, value in scope.items()
        },
    )


@pytest.fixture
def catalog() -> OperationCatalog:
    return OperationCatalog(sample_specs())


@pytest.fixture
def context(clock: FixedClock) -> FakeContext:
    return FakeContext(clock)


@pytest.fixture
def default_ruleset() -> RuleSet:
    return load_default_ruleset()


@pytest.fixture
def make_engine(
    catalog: OperationCatalog,
    clock: FixedClock,
    audit: FakeAudit,
    default_ruleset: RuleSet,
    principals: FakePrincipals,
) -> Callable[..., PolicyEngine]:
    def _make(
        ruleset: RuleSet | None = None,
        max_envelope_ttl: timedelta | None = TTL,
        clock_: Any = None,
    ) -> PolicyEngine:
        return PolicyEngine(
            catalog=catalog,
            ruleset=ruleset or default_ruleset,
            clock=clock_ or clock,
            audit=audit,
            principals=principals,
            max_envelope_ttl=max_envelope_ttl,
        )

    return _make


@pytest.fixture
def engine_(make_engine: Callable[..., PolicyEngine]) -> PolicyEngine:
    return make_engine()


def _actor_fields(actor: Principal | str | None, default: Principal) -> dict[str, Any]:
    if isinstance(actor, str):
        return {"actor_id": actor, "actor_type": ActorType.HUMAN}
    chosen = actor or default
    return {"actor_id": chosen.actor_id, "actor_type": chosen.actor_type}


@pytest.fixture
def build(catalog: OperationCatalog, clock: FixedClock, agent: Principal) -> EnvelopeBuilder:
    def _build(
        operation: str = "asset.read", actor: Principal | str | None = None, **over: Any
    ) -> ActionEnvelope:
        spec = catalog.get(operation)
        level = spec.authority_level if spec else AuthorityLevel.L0_OBSERVE
        fields: dict[str, Any] = {
            "request_id": new_id("req"),
            "idempotency_key": "idem-0001",
            "requesting_component": "orchestrator",
            **_actor_fields(actor, agent),
            "target_resource": "app:billing",
            "scope": EnvelopeScope(
                resource="app:billing",
                tenant="tenant_main",
                environment=Environment.STAGING,
                boundary="internal",
                classification="internal",
            ),
            "operation": operation,
            "arguments": DEFAULT_ARGS.get(operation, {}),
            "purpose": "investigate an open finding",
            "supporting_evidence": ("finding:f1",),
            "risk_class": "low",
            "authority_level": level,
            "preconditions": (),
            "expiry": clock.now() + timedelta(minutes=10),
            "rollback_plan": RollbackPlan(description="restore previous key", steps=("undo",)),
            "verification_plan": VerificationPlan(
                method="source_read", description="read the key state back"
            ),
        }
        fields.update(over)
        return ActionEnvelope(**fields)

    return _build


def scope_for(resource: str, environment: Environment = Environment.STAGING) -> EnvelopeScope:
    return EnvelopeScope(
        resource=resource,
        tenant="tenant_main",
        environment=environment,
        boundary="internal",
        classification="internal",
    )
