"""Fixtures for the execution tests: sample tools, an envelope builder, audit spies."""

from __future__ import annotations

from collections.abc import Callable, Iterator
from datetime import timedelta
from typing import Any

import pytest
from pydantic import Field
from sqlalchemy import Engine, event
from sqlalchemy.engine import Connection
from tests.execution.broker_world import PickyAudit, World
from tests.fakes.core import FakeAudit, FakePrincipals

from ciso.common.clock import FixedClock
from ciso.common.db import READ_ONLY_OPTION
from ciso.common.enums import ActorType, AuditOutcome, AuthorityLevel, Environment
from ciso.common.errors import FailClosed
from ciso.common.ids import new_id
from ciso.common.principal import Principal
from ciso.common.protocols import AuditEvent, AuditReceipt
from ciso.common.schemas import Model
from ciso.execution import (
    ChannelRegistry,
    Tool,
    ToolCall,
    ToolOutcome,
    ToolResult,
    Verification,
)
from ciso.policy import ActionEnvelope, CheckedEnvelope, EnvelopeScope, OperationSpec


class NoteArgs(Model):
    note: str = Field(max_length=4000)


class DraftArgs(Model):
    channel: str = Field(max_length=64)
    title: str = Field(max_length=200)


class Recorder:
    """A fake tool body. Remembers every call it was handed and what it would report."""

    def __init__(self) -> None:
        self.calls: list[ToolCall] = []
        self.verified: list[ToolCall] = []
        self.rolled_back: list[tuple[ToolCall, ToolResult | None]] = []
        self.checked: list[str] = []
        self.matches = True
        self.precondition_holds: Any = True

    def run(self, call: ToolCall) -> ToolResult:
        self.calls.append(call)
        return ToolResult(outcome=ToolOutcome.SUCCEEDED, references=("draft:d1",))

    def verify(self, call: ToolCall) -> Verification:
        self.verified.append(call)
        return Verification(matches=self.matches, detail="read back", observed=("draft:d1",))

    def rollback(self, call: ToolCall, result: ToolResult | None) -> ToolResult:
        self.rolled_back.append((call, result))
        return ToolResult(outcome=ToolOutcome.SUCCEEDED, detail="removed")

    def check(self, precondition: Any, call: ToolCall) -> bool:
        self.checked.append(precondition.name)
        return self.precondition_holds  # type: ignore[no-any-return]


@pytest.fixture
def recorder() -> Recorder:
    return Recorder()


def spec(
    name: str = "note.record",
    level: AuthorityLevel = AuthorityLevel.L1_INVESTIGATE,
    args: type[Model] = NoteArgs,
    **extra: Any,
) -> OperationSpec:
    return OperationSpec(name=name, authority_level=level, args_model=args, **extra)


def make_tool(recorder: Recorder, operation: OperationSpec | None = None, **extra: Any) -> Tool:
    """A tool wired to `recorder`. Writing tools get the recorder's verifier by default."""
    operation = operation or spec()
    if operation.writes:
        extra.setdefault("verify", recorder.verify)
    return Tool(spec=operation, run=recorder.run, **extra)


EnvelopeBuilder = Callable[..., CheckedEnvelope]


@pytest.fixture
def checked(clock: FixedClock) -> EnvelopeBuilder:
    """Builds the `CheckedEnvelope` the broker would hand over for a given spec."""

    def build(
        operation: OperationSpec, arguments: dict[str, Any], **overrides: Any
    ) -> CheckedEnvelope:
        fields: dict[str, Any] = {
            "request_id": new_id("req"),
            "idempotency_key": "idem-1",
            "requesting_component": "orchestrator",
            "actor_id": "agent_ciso",
            "actor_type": ActorType.AGENT,
            "target_resource": "asset:a1",
            "scope": EnvelopeScope(
                resource="system:s1",
                tenant="t1",
                environment=Environment.STAGING,
                boundary="internal",
            ),
            "operation": operation.name,
            "arguments": arguments,
            "purpose": "test",
            "supporting_evidence": ("evidence:e1",),
            "risk_class": "low",
            "authority_level": operation.authority_level,
            "preconditions": (),
            "expiry": clock.now() + timedelta(minutes=5),
        }
        fields.update(overrides)
        envelope = ActionEnvelope(**fields)
        channel = arguments.get(operation.channel_argument or "")
        return CheckedEnvelope.model_construct(
            envelope=envelope,
            spec=operation,
            arguments=None,  # the registry must not rely on this field
            authority_level=operation.authority_level,
            channel=channel,
        )

    return build


class FlakyAudit(FakeAudit):
    """Refuses records with an outcome in `fail_outcomes`; records the rest."""

    def __init__(self, clock: FixedClock) -> None:
        super().__init__(clock)
        self.fail_outcomes: set[AuditOutcome] = set()

    def append(self, event: AuditEvent) -> AuditReceipt:
        if event.outcome in self.fail_outcomes:
            raise FailClosed("audit path unavailable")
        return super().append(event)


class LockSpy(FakeAudit):
    """Fails any append made while a write transaction is open on the watched engine."""

    def __init__(self, clock: FixedClock, engine: Engine) -> None:
        super().__init__(clock)
        self.open_writes = 0
        self.appends_checked = 0
        self.writes_seen = 0
        self._engine = engine
        event.listen(engine, "begin", self._begin)
        event.listen(engine, "commit", self._end)
        event.listen(engine, "rollback", self._end)

    def _begin(self, conn: Connection) -> None:
        if not conn.get_execution_options().get(READ_ONLY_OPTION, False):
            self.open_writes += 1
            self.writes_seen += 1

    def _end(self, conn: Connection) -> None:
        if not conn.get_execution_options().get(READ_ONLY_OPTION, False):
            self.open_writes = max(0, self.open_writes - 1)

    def append(self, event: AuditEvent) -> AuditReceipt:
        self.appends_checked += 1
        assert self.open_writes == 0, f"audit append for {event.action} inside a write lock"
        return super().append(event)

    def close(self) -> None:
        event.remove(self._engine, "begin", self._begin)
        event.remove(self._engine, "commit", self._end)
        event.remove(self._engine, "rollback", self._end)


@pytest.fixture
def flaky_audit(clock: FixedClock) -> FlakyAudit:
    return FlakyAudit(clock)


@pytest.fixture
def lock_spy(clock: FixedClock, engine: Engine) -> Iterator[LockSpy]:
    spy = LockSpy(clock, engine)
    yield spy
    spy.close()


@pytest.fixture
def channels(
    engine: Engine, clock: FixedClock, audit: FakeAudit, principals: FakePrincipals
) -> ChannelRegistry:
    return ChannelRegistry(engine, clock, audit, principals)


# --- broker world (plan rows T2.3, T2.4); helpers live in tests/execution/broker_world.py

WorldFactory = Callable[..., World]


@pytest.fixture
def picky_audit(clock: FixedClock) -> PickyAudit:
    return PickyAudit(clock)


@pytest.fixture
def world_factory(
    engine: Engine, clock: FixedClock, principals: FakePrincipals, system_owner: Principal
) -> WorldFactory:
    """Builds a `World` on the given audit sink; `engine=` and `principals=` override."""

    def make(audit: Any, **overrides: Any) -> World:
        return World(
            overrides.get("engine", engine),
            clock,
            audit,
            overrides.get("principals", principals),
            system_owner,
            overrides.get("extra_tools", ()),
        )

    return make


@pytest.fixture
def world(world_factory: WorldFactory, picky_audit: PickyAudit) -> World:
    return world_factory(picky_audit)
