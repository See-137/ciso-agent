"""The order of the broker's gates, and that nothing is consulted under the write lock.

Blueprint 9.5; ADR-0010 ("a test asserts the order of these gates"); plan row T2.3; plan
gap G5 (audit ordering).
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from itertools import combinations
from typing import Any

import pytest
from sqlalchemy import Engine, event
from tests.execution.broker_world import (
    L2_OP,
    L3_OP,
    L4_OP,
    WRITE_TOKEN_REF,
    PickyAudit,
    World,
)
from tests.execution.conftest import LockSpy, WorldFactory
from tests.fakes.core import FakeKillSwitch, FakePrincipals

from ciso.common.enums import AuditOutcome, KillCapability
from ciso.common.principal import Principal
from ciso.execution import (
    EXECUTE_ACTION,
    ExecutionRefused,
    ExecutionState,
    RefusalReason,
    ToolCall,
)

pytestmark = pytest.mark.broker

R = RefusalReason


class TracingSwitch(FakeKillSwitch):
    def __init__(self, trace: list[str]) -> None:
        super().__init__()
        self._trace = trace

    def is_blocked(self, capability: KillCapability) -> bool:
        self._trace.append(f"killswitch:{capability.value}")
        return super().is_blocked(capability)


class Tap:
    """Forwards the named methods to `inner`, noting each call in `trace` first."""

    def __init__(self, inner: Any, trace: list[str], names: dict[str, str]) -> None:
        self._inner = inner
        self._trace = trace
        self._names = names

    def __getattr__(self, name: str) -> Any:
        target = getattr(self._inner, name)
        if name not in self._names:
            return target

        def call(*args: Any, **kwargs: Any) -> Any:
            self._trace.append(self._names[name])
            return target(*args, **kwargs)

        return call


def traced(world: World, picky_audit: PickyAudit) -> tuple[list[str], dict[str, Any]]:
    """Wire a spy into every collaborator. Returns the trace and the broker's parts."""
    trace: list[str] = []
    switch = TracingSwitch(trace)
    world.l4.trace = trace

    def fetch(call: ToolCall) -> None:
        call.credentials.get(WRITE_TOKEN_REF)

    world.l4.on_run = fetch
    picky_audit.during = lambda e: (
        trace.append(f"audit:{e.outcome.value}") if e.action == EXECUTE_ACTION else None
    )

    def on_sql(conn: Any, cursor: Any, statement: str, *rest: Any) -> None:
        if "execution_run" in statement:
            trace.append(f"db:{statement.split()[0].lower()}")

    event.listen(world.engine, "before_cursor_execute", on_sql)
    parts = world.parts(
        killswitch=switch,
        validator=Tap(world.validator, trace, {"validate": "validate"}),
        policy=Tap(world.policy, trace, {"evaluate": "policy"}),
        principals=Tap(world.principals, trace, {"resolve": "identity"}),
        approvals=Tap(
            world.approvals, trace, {"check": "approval_check", "consume": "approval_consume"}
        ),
    )
    return trace, parts


def test_collaborators_are_consulted_in_the_documented_order(
    world: World, picky_audit: PickyAudit
) -> None:
    envelope = world.envelope(L4_OP)
    approval_id = world.approve(envelope)
    trace, parts = traced(world, picky_audit)
    record = world.broker(**parts).execute(envelope, approval_id)
    assert record.state is ExecutionState.VERIFIED
    expected = [
        "killswitch:writes",
        "killswitch:l3_runs",
        "validate",
        "identity",  # before anything is audited in the actor's name
        "db:select",  # idempotency lookup
        "policy",
        "approval_check",  # nothing spent yet
        "precondition",
        "db:insert",  # rate limit count and pending row, one transaction
        "audit:attempt",
        "db:update",  # attempt audit id stored
        "approval_consume",  # spent only now (review finding M2)
        "tool",
        "verify",
        "audit:success",
    ]
    first = [trace.index(step) for step in expected]
    assert first == sorted(first), list(zip(expected, first, strict=True))
    assert len(set(first)) == len(expected)
    # The actor is resolved three times: before the lookup, after policy, at the last look.
    assert trace.count("identity") == 3
    identity = [n for n, step in enumerate(trace) if step == "identity"]
    assert trace.index("policy") < identity[1] < trace.index("approval_check")
    # The last look (review finding M1): switch, then actor, between consume and the tool.
    writes = [n for n, step in enumerate(trace) if step == "killswitch:writes"]
    l3_runs = [n for n, step in enumerate(trace) if step == "killswitch:l3_runs"]
    assert trace.index("approval_consume") < writes[1] < l3_runs[1] < identity[2]
    assert identity[2] < trace.index("tool")
    # The credential fetch inside the tool asks the kill switch again (G20, L6).
    assert len(writes) == 3
    assert len(l3_runs) == 3
    assert trace.index("tool") < writes[2] < l3_runs[2] < trace.index("verify")
    assert trace.count("tool") == 1
    assert trace.count("policy") == 1
    assert trace.count("approval_consume") == 1
    # The final state reaches the row before the result is audited.
    assert trace[trace.index("audit:success") - 1].startswith("db:")
    assert "db:update" in trace[trace.index("verify") : trace.index("audit:success")]


# --- pairwise order: when two gates would both refuse, the earlier one answers -------


@dataclass
class Breaker:
    name: str
    reason: RefusalReason
    arrange: Callable[[World], None] = lambda world: None
    envelope: dict[str, Any] = field(default_factory=dict)
    broker: dict[str, Any] = field(default_factory=dict)
    skip_approval: bool = False


def _engage(world: World) -> None:
    world.killswitch.blocked.add(KillCapability.WRITES)


def _conflict(world: World) -> None:
    earlier = world.envelope(L2_OP, key="idem-1", arguments={"note": "an earlier request"})
    assert world.broker().execute(earlier).state is ExecutionState.VERIFIED
    world.l2.calls.clear()


def _out_of_scope(world: World) -> None:
    world.context.in_scope = False


def _expire_after_policy(world: World) -> None:
    world.policy.after = lambda: world.clock.advance(minutes=10)


def _stale(world: World) -> None:
    world.l4.precondition_holds = False


def _attempt_audit_down(world: World) -> None:
    world.audit.fail_on(EXECUTE_ACTION, AuditOutcome.ATTEMPT)


BREAKERS = [
    Breaker("1-kill-switch", R.KILL_SWITCH_ENGAGED, arrange=_engage),
    Breaker("2-envelope", R.ENVELOPE_INVALID, envelope={"risk_class": "nonsense"}),
    Breaker("3-idempotency", R.IDEMPOTENCY_CONFLICT, arrange=_conflict),
    Breaker("4-policy", R.POLICY_DENIED, arrange=_out_of_scope),
    Breaker("5-approval", R.APPROVAL_REQUIRED, skip_approval=True),
    Breaker("6-expiry", R.ENVELOPE_EXPIRED, arrange=_expire_after_policy),
    Breaker("7-precondition", R.PRECONDITION_FAILED, arrange=_stale),
    Breaker("8-rate-limit", R.RATE_LIMIT_UNSET, broker={"tool_rate_limit_per_minute": None}),
    Breaker("9-attempt-audit", R.ATTEMPT_AUDIT_FAILED, arrange=_attempt_audit_down),
]


def _run(world: World, breakers: tuple[Breaker, ...]) -> ExecutionRefused:
    envelope_fields: dict[str, Any] = {}
    broker_args: dict[str, Any] = {}
    for breaker in breakers:
        envelope_fields.update(breaker.envelope)
        broker_args.update(breaker.broker)
    envelope = world.envelope(L4_OP, key="idem-1", **envelope_fields)
    approval_id = None
    if not any(breaker.skip_approval for breaker in breakers):
        approval_id = world.approve(envelope)
    # The idempotency arrangement needs a healthy world, so it goes first.
    for breaker in sorted(breakers, key=lambda b: b.arrange is not _conflict):
        breaker.arrange(world)
    with pytest.raises(ExecutionRefused) as excinfo:
        world.broker(**broker_args).execute(envelope, approval_id)
    assert world.tool_calls() == 0
    return excinfo.value


@pytest.mark.parametrize("breaker", BREAKERS, ids=lambda b: b.name)
def test_each_gate_refuses_on_its_own(world: World, breaker: Breaker) -> None:
    assert _run(world, (breaker,)).reason is breaker.reason


@pytest.mark.parametrize(
    "pair", list(combinations(BREAKERS, 2)), ids=lambda p: f"{p[0].name}+{p[1].name}"
)
def test_the_earlier_gate_answers_first(world: World, pair: tuple[Breaker, Breaker]) -> None:
    assert _run(world, pair).reason is pair[0].reason


def test_the_pairwise_matrix_covers_every_gate() -> None:
    assert len(BREAKERS) == 9
    assert len(list(combinations(BREAKERS, 2))) == 36


# --- nothing is consulted while the database write lock is held ----------------------


class LockCheckedPrincipals(FakePrincipals):
    def __init__(self, spy: LockSpy, *principals: Principal) -> None:
        super().__init__(*principals)
        self._spy = spy
        self.checked = 0

    def resolve(self, actor_id: str) -> Principal | None:
        self.checked += 1
        assert self._spy.open_writes == 0, f"identity lookup for {actor_id} inside a write lock"
        return super().resolve(actor_id)


def test_audit_and_identity_are_never_called_inside_a_write_transaction(
    world_factory: WorldFactory,
    lock_spy: LockSpy,
    engine: Engine,
    agent: Principal,
    system_owner: Principal,
) -> None:
    people = LockCheckedPrincipals(lock_spy, agent, system_owner)
    world = world_factory(lock_spy, principals=people)

    def probe(call: ToolCall) -> None:
        assert lock_spy.open_writes == 0, "tool called inside a write lock"

    for tool in (world.l2, world.l3, world.l4):
        tool.on_run = probe
    broker = world.broker()
    # an approved L4 run, a duplicate, a refusal, a rollback and a recovery pass
    high = world.envelope(L4_OP, key="k-high")
    assert broker.execute(high, world.approve(high)).state is ExecutionState.VERIFIED
    assert broker.execute(high).state is ExecutionState.VERIFIED
    world.context.in_scope = False
    with pytest.raises(ExecutionRefused):
        broker.execute(world.envelope(L2_OP, key="k-denied"))
    world.context.in_scope = True
    world.l3.matches = False
    assert broker.execute(world.envelope(L3_OP, key="k-l3")).state is ExecutionState.ROLLED_BACK
    world.l2.run_error = RuntimeError("boom")
    lost = broker.execute(world.envelope(L2_OP, key="k-lost"))
    assert lost.state is ExecutionState.UNKNOWN_OUTCOME
    assert world.recovery().verify(lost.execution_id).state is ExecutionState.VERIFIED
    assert world.recover() == ()
    assert lock_spy.appends_checked >= 12
    assert lock_spy.writes_seen >= 8
    assert people.checked >= 6
    assert world.tool_calls() == 3
