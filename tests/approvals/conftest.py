"""Approval fixtures. Importing the tables here registers them before `engine` runs."""

from __future__ import annotations

from collections.abc import Callable, Iterator
from datetime import timedelta
from pathlib import Path
from typing import Any

import pytest
from sqlalchemy import Engine, select, update
from tests.fakes.core import FakeAudit, FakePrincipals

from ciso.approvals import Approval, ApprovalFault, ApprovalReason, ApprovalService
from ciso.approvals.tables import approval
from ciso.common.clock import Clock, FixedClock
from ciso.common.db import create_db_engine, init_operational_schema
from ciso.common.enums import ActorType, AuditOutcome, Role
from ciso.common.errors import FailClosed
from ciso.common.principal import Principal
from ciso.common.protocols import AuditEvent, AuditReceipt
from ciso.common.schemas import content_hash

TTL = timedelta(hours=1)
KIND = "external_inference"
HASH = content_hash({"payload": "minimised text"})
OTHER_HASH = content_hash({"payload": "something else"})
BINDING = {"provider": "prov-a", "model": "model-1", "purpose": "triage", "request_id": "req-1"}
TARGET = {"system": "app:billing", "environment": "staging"}
BROKER = "svc_broker"
MakeService = Callable[..., ApprovalService]


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

    def outcomes(self, action: str) -> list[AuditOutcome]:
        return [e.outcome for e in self.find(action)]

    def fail_on(self, action: str, outcome: AuditOutcome) -> None:
        self.fail_if = lambda e: e.action == action and e.outcome is outcome


def signed_in(principal: Principal, issued_by: str = "human_idp_admin") -> Principal:
    """The principal as `authenticate` would return it: with a credential issuer."""
    return principal.model_copy(update={"credential_issued_by": issued_by})


def ask(svc: ApprovalService, **overrides: Any) -> Approval:
    args: dict[str, Any] = {
        "subject_kind": KIND,
        "subject_hash": HASH,
        "binding": BINDING,
        "requested_by": "agent_ciso",
        "requested_by_type": ActorType.AGENT,
        "required_roles": [Role.SYSTEM_OWNER, Role.EXECUTIVE_RISK_OWNER],
        "target": TARGET,
    }
    args.update(overrides)
    return svc.request(**args)


def use_args(**overrides: Any) -> dict[str, Any]:
    args: dict[str, Any] = {
        "subject_kind": KIND,
        "subject_hash": HASH,
        "binding": BINDING,
        "actor_id": BROKER,
        "actor_type": ActorType.SERVICE,
    }
    args.update(overrides)
    return args


def reason_of(excinfo: pytest.ExceptionInfo[Any]) -> ApprovalReason:
    assert isinstance(excinfo.value, ApprovalFault)
    return excinfo.value.reason


def tamper(engine: Engine, approval_id: str, **values: Any) -> None:
    with engine.begin() as conn:
        conn.execute(update(approval).where(approval.c.approval_id == approval_id).values(**values))


def row_count(engine: Engine) -> int:
    with engine.begin() as conn:
        return len(conn.execute(select(approval.c.approval_id)).all())


@pytest.fixture
def audit(clock: FixedClock) -> ScriptedAudit:
    return ScriptedAudit(clock)


@pytest.fixture
def owner(system_owner: Principal) -> Principal:
    return signed_in(system_owner)


@pytest.fixture
def make_service(
    audit: ScriptedAudit, clock: FixedClock, principals: FakePrincipals
) -> MakeService:
    def make(engine: Engine, **overrides: object) -> ApprovalService:
        args: dict[str, object] = {
            "engine": engine,
            "audit": audit,
            "clock": clock,
            "principals": principals,
            "approval_ttl": TTL,
        }
        args.update(overrides)
        return ApprovalService(**args)  # type: ignore[arg-type]

    return make


@pytest.fixture
def svc(engine: Engine, make_service: MakeService) -> ApprovalService:
    return make_service(engine)


@pytest.fixture
def approved(svc: ApprovalService, owner: Principal) -> Approval:
    return svc.approve(ask(svc).approval_id, owner)


@pytest.fixture
def file_db(tmp_path: Path) -> Iterator[tuple[Path, Engine]]:
    path = tmp_path / "ops.db"
    eng = create_db_engine(path)
    init_operational_schema(eng)
    yield path, eng
    eng.dispose()
