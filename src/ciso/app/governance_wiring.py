"""How the composition root builds the AI-activity governance services (spec C3, C4).

`build_governance` wires, from `Settings` and the shared parts:

- `AgentRegistry` (attribution) and `AgentAdmin` (registry changes);
- `GovernanceEngine` with the packaged default ruleset, or the deployment ruleset named
  by `governance.ruleset_path`, which REPLACES the default (the loader never merges two
  files; a file that does not load gives a deny-all engine and a readiness warning). It
  reads the GATED kill-switch reader, so a failed start-up integrity check blocks too;
- `Inspector`, with `governance.required_sandbox_checks` passed as set (unset: no sandbox
  result is ever complete);
- `FindingsService`, alerting into `data_dir/alerts` through `DirectoryAlertSink`, with
  a `RecommendationCatalog` built from inspection's rule table remediations and
  governance's reason-code messages;
- the device directory and, when all three central gate values are set, the `CentralGate`;
- `ChangeService` (the pre-push change store, `data_dir/changes`), handed to the
  pipeline; its sandbox jobs go on the container's job queue and are run by
  `python -m ciso.app.sandbox_worker`.

Person references. A person is `actor:<identity actor id>` (`PERSON_REF_KIND`): the agents
registry binds claims to identity actors, so the human actor IS the person. The identity
`Actor.person_ref` (a registry person record) is not used here. `ActorPersonLinks` is the
findings `PersonLinkResolver` built on that rule: an active human actor links to
`actor:<own id>`, anything else to no person.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Final

from sqlalchemy import Engine

from ciso.agents import AgentAdmin, AgentRegistry
from ciso.app.changes import ChangeService
from ciso.app.devices import DeviceDirectory
from ciso.app.governance_gate import GateEndpoint
from ciso.app.governance_pipeline import DecisionPipeline
from ciso.app.settings import Settings
from ciso.common.activity import PERSON_REF_KIND
from ciso.common.clock import Clock
from ciso.common.enums import ActorType
from ciso.common.errors import CisoError
from ciso.common.ids import EntityRef
from ciso.common.protocols import AuditSink, KillSwitchReader, PrincipalResolver, Redactor
from ciso.findings import DirectoryAlertSink, FindingsService, RecommendationCatalog
from ciso.governance import (
    MESSAGES,
    GovernanceEngine,
    GovernanceRuleSet,
    load_default_ruleset,
    load_ruleset,
)
from ciso.identity import Authenticator, IdentityService
from ciso.inspection import RULE_TABLE, Inspector
from ciso.intake import BoundedSeenMessages, CentralGate
from ciso.vault import EnvSecretStore, resolve_key_bytes
from ciso.workflows import JobQueue

logger = logging.getLogger(__name__)

#: Actor id the governance engine and the findings service write on their audit records.
GOVERNANCE_ACTOR: Final = "ciso_governance"
#: Directory under `data_dir` where `DirectoryAlertSink` writes alert files.
ALERTS_DIR: Final = "alerts"
#: Directory under `data_dir` where uploaded changes are kept, encrypted.
CHANGES_DIR: Final = "changes"


class ActorPersonLinks:
    """`PersonLinkResolver`: an active human actor is the person `actor:<id>`."""

    def __init__(self, principals: PrincipalResolver) -> None:
        self._principals = principals

    def person_ref_of(self, actor_id: str) -> str | None:
        principal = self._principals.resolve(actor_id)
        if principal is None or principal.actor_type is not ActorType.HUMAN:
            return None
        return str(EntityRef(PERSON_REF_KIND, principal.actor_id))


def recommendation_catalog() -> RecommendationCatalog:
    """Inspection remediations by check id; governance messages by reason code."""
    return RecommendationCatalog(
        by_check={rule_id: rule.remediation for rule_id, rule in RULE_TABLE.items()},
        by_reason={code.value: text for code, text in MESSAGES.items()},
    )


def governance_ruleset(settings: Settings) -> GovernanceRuleSet:
    path = settings.governance.ruleset_path
    return load_default_ruleset() if path is None else load_ruleset(Path(path))


def build_central_gate(
    settings: Settings, *, secrets: EnvSecretStore, clock: Clock, redactor: Redactor
) -> CentralGate | None:
    """The central gate when its secret, tolerance and replay capacity are all set."""
    gov = settings.governance
    if (
        gov.central_gate_secret_ref is None
        or gov.central_gate_tolerance_seconds is None
        or gov.central_gate_replay_capacity is None
    ):
        return None
    return CentralGate(
        secrets=secrets,
        secret_ref=gov.central_gate_secret_ref,
        previous_secret_ref=gov.central_gate_previous_secret_ref,
        clock=clock,
        redactor=redactor,
        seen=BoundedSeenMessages(gov.central_gate_replay_capacity),
        tolerance_seconds=gov.central_gate_tolerance_seconds,
    )


@dataclass(frozen=True, kw_only=True)
class GovernanceServices:
    registry: AgentRegistry
    agent_admin: AgentAdmin
    engine: GovernanceEngine
    inspector: Inspector
    findings: FindingsService
    devices: DeviceDirectory
    pipeline: DecisionPipeline
    #: The pre-push change store (`POST /v1/changes`).
    changes: ChangeService
    #: The central gate endpoint. Denies every delivery while a gate value is unset.
    gate: GateEndpoint
    warnings: tuple[str, ...]


def governance_warnings(
    settings: Settings, ruleset: GovernanceRuleSet, secrets: EnvSecretStore
) -> tuple[str, ...]:
    """Readiness entries: unset values, a deny-all ruleset, an unresolvable gate secret."""
    found = list(settings.governance.unset())
    if ruleset.deny_all:
        found.append("governance ruleset did not load (every governed action is denied)")
    gov = settings.governance
    ref = gov.central_gate_secret_ref
    if ref is not None:
        try:
            secrets.get(ref)
        except CisoError:
            found.append("governance.central_gate_secret_ref (unresolvable)")
    if gov.change_key_ref is not None:
        try:
            resolve_key_bytes(secrets, gov.change_key_ref)
        except CisoError:
            found.append("governance.change_key_ref (unresolvable or too short)")
    if gov.sandbox_token_ref is not None:
        try:
            secrets.get(gov.sandbox_token_ref)
        except CisoError:
            found.append("governance.sandbox_token_ref (unresolvable)")
    lease = settings.safety.queue_lease_seconds
    timeout = gov.sandbox_timeout_seconds
    if lease is not None and timeout is not None and timeout >= lease:
        found.append("governance.sandbox_timeout_seconds (not below safety.queue_lease_seconds)")
    return tuple(found)


def build_governance(
    settings: Settings,
    *,
    engine: Engine,
    clock: Clock,
    audit: AuditSink,
    killswitch: KillSwitchReader,
    identity: IdentityService,
    authenticator: Authenticator,
    redactor: Redactor,
    secrets: EnvSecretStore,
    queue: JobQueue,
) -> GovernanceServices:
    """Every governance service. `killswitch` must be the container's gated reader."""
    ruleset = governance_ruleset(settings)
    alerts = settings.data_dir / ALERTS_DIR
    alerts.mkdir(parents=True, exist_ok=True)
    registry = AgentRegistry(engine, clock, audit)
    decider = GovernanceEngine(
        ruleset=ruleset, clock=clock, audit=audit, killswitch=killswitch,
        principals=identity, service_actor_id=GOVERNANCE_ACTOR,
    )  # fmt: skip
    inspector = Inspector(required_sandbox_checks=settings.governance.required_sandbox_checks)
    findings = FindingsService(
        engine, clock=clock, audit=audit, principals=identity,
        people=ActorPersonLinks(identity), alert_sink=DirectoryAlertSink(alerts),
        recommendations=recommendation_catalog(), service_actor_id=GOVERNANCE_ACTOR,
    )  # fmt: skip
    devices = DeviceDirectory(
        engine, clock=clock, audit=audit, identity=identity, authenticator=authenticator
    )
    changes = ChangeService(
        engine, clock=clock, audit=audit, queue=queue, secrets=secrets,
        key_ref=settings.governance.change_key_ref,
        retention_seconds=settings.governance.change_retention_seconds,
        store_dir=settings.data_dir / CHANGES_DIR, actor_id=GOVERNANCE_ACTOR,
    )  # fmt: skip
    pipeline = DecisionPipeline(
        clock=clock, audit=audit, redactor=redactor, attribution=registry,
        inspector=inspector, engine=decider, findings=findings, actor_id=GOVERNANCE_ACTOR,
        changes=changes,
    )  # fmt: skip
    gate = GateEndpoint(
        build_central_gate(settings, secrets=secrets, clock=clock, redactor=redactor),
        pipeline=pipeline, audit=audit, actor_id=GOVERNANCE_ACTOR,
    )  # fmt: skip
    return GovernanceServices(
        registry=registry,
        agent_admin=AgentAdmin(engine, clock, audit, identity),
        engine=decider,
        inspector=inspector,
        findings=findings,
        devices=devices,
        pipeline=pipeline,
        changes=changes,
        gate=gate,
        warnings=governance_warnings(settings, ruleset, secrets),
    )
