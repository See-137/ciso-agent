"""Findings fixtures. Importing the tables here registers them before `engine` runs."""

from __future__ import annotations

import sqlite3
from collections.abc import Callable, Iterator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
from sqlalchemy import Engine
from tests.fakes.core import FakeAudit, FakePrincipals

from ciso.common.activity import (
    ActionKind,
    ActivitySource,
    AgentClass,
    Attribution,
    DecisionReason,
    GovernanceDecision,
    InspectionFinding,
    InspectionResult,
    ObservedAction,
    Phase,
    Severity,
    Verdict,
)
from ciso.common.clock import Clock, FixedClock
from ciso.common.db import create_db_engine, init_operational_schema
from ciso.common.enums import InformationState
from ciso.common.errors import FailClosed
from ciso.common.protocols import AuditEvent, AuditReceipt
from ciso.findings import FindingsService, InMemoryAlertSink, RecommendationCatalog, tables

#: Importing the tables registers them before the shared `engine` fixture creates them.
TABLES = (tables.finding, tables.alert, tables.finding_transition)
SERVICE_ACTOR = "svc_governance"
EMP_PERSON = "person:p_emp"
OTHER_PERSON = "person:p_other"
AGENT_REF = "agent:a_1"
RULESET_HASH = "a" * 64


class ScriptedAudit(FakeAudit):
    """FakeAudit that can fail on chosen events and run a probe inside `append`."""

    def __init__(self, clock: Clock | None = None) -> None:
        super().__init__(clock)
        self.fail_if: Callable[[AuditEvent], bool] | None = None
        self.during: Callable[[AuditEvent], None] | None = None

    def append(self, event: AuditEvent) -> AuditReceipt:
        if self.during is not None:
            self.during(event)
        if self.fail_if is not None and self.fail_if(event):
            raise FailClosed("audit path unavailable (scripted)")
        return super().append(event)

    def trail(self) -> list[tuple[str, str]]:
        return [(e.action, e.outcome.value) for e in self.events]


class FakePeople:
    """`PersonLinkResolver` over a dict. `broken = True` simulates an unreadable store."""

    def __init__(self, links: dict[str, str] | None = None) -> None:
        self.links = dict(links or {})
        self.broken = False
        self.lookups: list[str] = []

    def person_ref_of(self, actor_id: str) -> str | None:
        self.lookups.append(actor_id)
        if self.broken:
            raise FailClosed("person store unavailable")
        return self.links.get(actor_id)


@pytest.fixture
def audit(clock: FixedClock) -> ScriptedAudit:
    return ScriptedAudit(clock)


@pytest.fixture
def people() -> FakePeople:
    return FakePeople({"human_emp": EMP_PERSON, "human_admin": "person:p_admin"})


@pytest.fixture
def sink() -> InMemoryAlertSink:
    return InMemoryAlertSink()


@pytest.fixture
def catalog() -> RecommendationCatalog:
    return RecommendationCatalog(
        by_check={"secrets.token": "Remove the credential and rotate it."},
        by_reason={"push_protected_branch": "Open a pull request instead of pushing."},
    )


MakeService = Callable[..., FindingsService]


@pytest.fixture
def make_service(
    engine: Engine,
    clock: FixedClock,
    audit: ScriptedAudit,
    principals: FakePrincipals,
    people: FakePeople,
    sink: InMemoryAlertSink,
    catalog: RecommendationCatalog,
) -> MakeService:
    def build(**overrides: Any) -> FindingsService:
        args: dict[str, Any] = {
            "engine": engine,
            "clock": clock,
            "audit": audit,
            "principals": principals,
            "people": people,
            "alert_sink": sink,
            "recommendations": catalog,
            "service_actor_id": SERVICE_ACTOR,
        }
        args.update(overrides)
        return FindingsService(**args)

    return build


@pytest.fixture
def svc(make_service: MakeService) -> FindingsService:
    return make_service()


@pytest.fixture
def file_db(tmp_path: Path) -> Iterator[tuple[Path, Engine]]:
    path = tmp_path / "ops.db"
    eng = create_db_engine(path)
    init_operational_schema(eng)
    yield path, eng
    eng.dispose()


def lock_probe(path: Path) -> None:
    """Raises if anyone holds the write lock on the database at `path`."""
    other = sqlite3.connect(path, timeout=0, isolation_level=None)
    try:
        other.execute("BEGIN IMMEDIATE")
        other.execute("ROLLBACK")
    finally:
        other.close()


# --- record builders ------------------------------------------------------------------

NOW = datetime(2026, 11, 17, 12, 0, 0, tzinfo=UTC)


def action(
    action_id: str = "act_1",
    *,
    session_id: str = "ses_1",
    phase: Phase = Phase.BEFORE,
    kind: ActionKind = ActionKind.GIT_PUSH,
    repository: str = "repo-a",
    branch: str = "main",
    path: str = "",
    command: str | None = "git push origin main --token=SUPERSECRET",
    evidence_ref: str | None = None,
) -> ObservedAction:
    target = {"repository": repository, "branch": branch}
    if path:
        target["path"] = path
    return ObservedAction(
        action_id=action_id,
        session_id=session_id,
        source=ActivitySource.HOOK,
        phase=phase,
        kind=kind,
        received_at=NOW,
        target=target,
        command=command,
        evidence_ref=evidence_ref,
    )


def decision(
    verdict: Verdict = Verdict.DENY,
    *,
    action_id: str = "act_1",
    session_id: str = "ses_1",
    code: str = "push_protected_branch",
    person_ref: str | None = EMP_PERSON,
    agent_ref: str | None = AGENT_REF,
    finding_refs: tuple[str, ...] = (),
) -> GovernanceDecision:
    return GovernanceDecision(
        action_id=action_id,
        session_id=session_id,
        verdict=verdict,
        reasons=(DecisionReason(code=code, detail="rule matched"),),
        ruleset_version="v1",
        ruleset_hash=RULESET_HASH,
        decided_at=NOW,
        attribution=Attribution(
            session_id=session_id,
            person_ref=person_ref,
            agent_ref=agent_ref,
            agent_class=AgentClass.EMPLOYEE_OPERATED,
            state=InformationState.VERIFIED,
        ),
        finding_refs=finding_refs,
    )


def inspection(
    *items: tuple[str, Severity] | tuple[str, Severity, str],
    action_id: str = "act_1",
) -> InspectionResult:
    findings = []
    for item in items:
        check_id, severity = item[0], item[1]
        location = item[2] if len(item) > 2 else ""
        findings.append(
            InspectionFinding(
                check_id=check_id,
                category=check_id.split(".")[0],
                severity=severity,
                detail="a problem was found",
                location=location,
            )
        )
    return InspectionResult(
        action_id=action_id,
        checks_run=tuple(i[0] for i in items),
        findings=tuple(findings),
        complete=True,
    )
