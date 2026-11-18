"""Builders for the governance engine tests."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

import pytest
from tests.fakes.core import FakeAudit, FakeKillSwitch, FakePrincipals

from ciso.common.activity import (
    ActionKind,
    ActivitySource,
    AgentClass,
    Attribution,
    InspectionFinding,
    InspectionResult,
    ObservedAction,
    Phase,
    Severity,
)
from ciso.common.clock import FixedClock
from ciso.common.enums import InformationState
from ciso.governance import GovernanceEngine, GovernanceRuleSet, load_default_ruleset

SERVICE = "svc_governance"
SESSION = "sess-1"


def make_action(
    kind: ActionKind = ActionKind.SHELL_COMMAND,
    command: str | None = "ls",
    *,
    clock: FixedClock | None = None,
    phase: Phase = Phase.BEFORE,
    **fields: Any,
) -> ObservedAction:
    now = (clock or FixedClock()).now()
    base: dict[str, Any] = {
        "action_id": "act-1",
        "session_id": SESSION,
        "source": ActivitySource.HOOK,
        "phase": phase,
        "kind": kind,
        "received_at": now,
        "command": command if kind is ActionKind.SHELL_COMMAND else None,
    }
    base.update(fields)
    return ObservedAction(**base)


def make_attribution(
    person: str | None = "actor:human_emp",
    *,
    state: InformationState = InformationState.VERIFIED,
    agent_class: AgentClass = AgentClass.EMPLOYEE_OPERATED,
    reasons: tuple[str, ...] = (),
) -> Attribution:
    return Attribution(
        session_id=SESSION,
        person_ref=person,
        agent_ref="agent:a1",
        agent_class=agent_class,
        state=state,
        reasons=reasons,
    )


def make_inspection(
    *findings: tuple[str, Severity], complete: bool = True, action_id: str = "act-1"
) -> InspectionResult:
    return InspectionResult(
        action_id=action_id,
        checks_run=("secret.scan",),
        findings=tuple(
            InspectionFinding(check_id="secret.scan", category=cat, severity=sev, detail="found")
            for cat, sev in findings
        ),
        complete=complete,
    )


@pytest.fixture
def ruleset() -> GovernanceRuleSet:
    loaded = load_default_ruleset()
    assert not loaded.deny_all, loaded.deny_reason
    return loaded


@pytest.fixture
def build(
    clock: FixedClock,
    audit: FakeAudit,
    killswitch: FakeKillSwitch,
    principals: FakePrincipals,
    ruleset: GovernanceRuleSet,
) -> Callable[..., GovernanceEngine]:
    def _build(rules: GovernanceRuleSet | None = None) -> GovernanceEngine:
        return GovernanceEngine(
            ruleset=rules or ruleset,
            clock=clock,
            audit=audit,
            killswitch=killswitch,
            principals=principals,
            service_actor_id=SERVICE,
        )

    return _build
