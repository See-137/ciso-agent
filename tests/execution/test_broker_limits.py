"""Broker gates 6 to 8: expiry before use, preconditions, rate limit.

Blueprint 9.4, 9.5, 11.2, 19.3 (execution broker: allowlist, idempotency, rate limit,
kill switch); plan row T2.3; gaps G5, G12, G14, G20. The approval gate has its own file.
"""

from __future__ import annotations

from typing import Any

import pytest
from sqlalchemy import func, select
from tests.execution.broker_world import L3_OP, L4_OP, World

from ciso.common.errors import FailClosed
from ciso.execution import (
    ExecutionBroker,
    ExecutionRefused,
    ExecutionState,
    RefusalReason,
)
from ciso.execution.tables import execution_run
from ciso.policy import (
    PolicyDecision,
    Precondition,
)

pytestmark = pytest.mark.broker

R = RefusalReason


def refused(broker: ExecutionBroker, envelope: Any, approval_id: str | None = None) -> Any:
    with pytest.raises(ExecutionRefused) as excinfo:
        broker.execute(envelope, approval_id)
    return excinfo.value


def rows(world: World) -> int:
    with world.engine.begin() as conn:
        return int(conn.execute(select(func.count()).select_from(execution_run)).scalar_one())


# --- gate 6: expiry right before use -------------------------------------------------


def test_an_envelope_that_expires_during_the_gates_is_refused(world: World) -> None:
    envelope = world.envelope()
    world.policy.after = lambda: world.clock.advance(minutes=5)  # lands exactly on expiry
    error = refused(world.broker(), envelope)
    assert error.reason is R.ENVELOPE_EXPIRED
    assert world.policy.calls == 1
    assert world.tool_calls() == 0
    assert rows(world) == 0


def test_an_envelope_one_second_short_of_expiry_still_runs(world: World) -> None:
    envelope = world.envelope()
    world.policy.after = lambda: world.clock.advance(minutes=4, seconds=59)
    assert world.broker().execute(envelope).state is ExecutionState.VERIFIED


# --- gate 7: preconditions -----------------------------------------------------------


def test_a_stale_precondition_refuses(world: World) -> None:
    envelope = world.envelope(L4_OP)
    approval_id = world.approve(envelope)
    world.l4.precondition_holds = False
    error = refused(world.broker(), envelope, approval_id)
    assert error.reason is R.PRECONDITION_FAILED
    assert "still_open" in error.detail
    assert world.l4.checked == ["still_open"]
    assert len(world.l4.calls) == 0


def test_a_precondition_the_tool_cannot_check_refuses(world: World) -> None:
    unknown = Precondition(name="patch_window", ref="system:s1", expectation="open")
    error = refused(world.broker(), world.envelope(preconditions=(unknown,)))
    assert error.reason is R.PRECONDITION_FAILED
    assert world.tool_calls() == 0


def test_a_precondition_checker_that_raises_refuses(world: World) -> None:
    envelope = world.envelope(L4_OP)
    approval_id = world.approve(envelope)

    world.l4.check_error = RuntimeError("source unavailable")
    error = refused(world.broker(), envelope, approval_id)
    assert error.reason is R.PRECONDITION_UNAVAILABLE
    assert isinstance(error, FailClosed)
    assert len(world.l4.calls) == 0


def test_only_exactly_true_counts_as_a_precondition_that_holds(world: World) -> None:
    envelope = world.envelope(L4_OP)
    approval_id = world.approve(envelope)
    world.l4.precondition_holds = "yes"
    assert refused(world.broker(), envelope, approval_id).reason is R.PRECONDITION_FAILED
    assert len(world.l4.calls) == 0


def test_a_true_precondition_lets_the_action_through(world: World) -> None:
    envelope = world.envelope(L4_OP)
    record = world.broker().execute(envelope, world.approve(envelope))
    assert record.state is ExecutionState.VERIFIED
    assert world.l4.checked == ["still_open"]


# --- gate 8: rate limit --------------------------------------------------------------


def test_an_unset_rate_limit_refuses_every_call(world: World) -> None:
    error = refused(world.broker(tool_rate_limit_per_minute=None), world.envelope())
    assert error.reason is R.RATE_LIMIT_UNSET
    assert isinstance(error, FailClosed)
    default = ExecutionBroker(
        **{k: v for k, v in world.parts().items() if k != "tool_rate_limit_per_minute"}
    )
    assert refused(default, world.envelope(key="k2")).reason is R.RATE_LIMIT_UNSET
    assert world.tool_calls() == 0


@pytest.mark.parametrize("bad", [0, -1, True, 2.5, "3"])
def test_a_rate_limit_must_be_a_positive_integer(world: World, bad: Any) -> None:
    with pytest.raises(ValueError, match="positive integer"):
        world.broker(tool_rate_limit_per_minute=bad)


def test_the_rate_limit_is_per_tool_per_minute_on_the_injected_clock(world: World) -> None:
    broker = world.broker(tool_rate_limit_per_minute=2)
    broker.execute(world.envelope(key="a"))
    world.clock.advance(seconds=30)
    broker.execute(world.envelope(key="b"))
    error = refused(broker, world.envelope(key="c"))
    assert error.reason is R.RATE_LIMITED
    assert len(world.l2.calls) == 2
    assert rows(world) == 2
    # another tool has its own count
    assert broker.execute(world.envelope(L3_OP, key="other")).state is ExecutionState.VERIFIED
    # a fresh broker on the same database still sees the count
    assert refused(world.broker(tool_rate_limit_per_minute=2), world.envelope(key="d")).reason is (
        R.RATE_LIMITED
    )
    world.clock.advance(seconds=31)  # the first call is now older than a minute
    assert broker.execute(world.envelope(key="e")).state is ExecutionState.VERIFIED
    assert refused(broker, world.envelope(key="f")).reason is R.RATE_LIMITED
    assert len(world.l2.calls) == 3


def test_a_replayed_decision_object_cannot_be_passed_in(world: World) -> None:
    """`execute` takes an envelope and an approval id, nothing else (blueprint 9.5)."""
    decision = PolicyDecision.model_construct(outcome="allow")
    with pytest.raises(TypeError):
        world.broker().execute(world.envelope(), None, decision)  # type: ignore[call-arg]
    with pytest.raises(TypeError):
        world.broker().execute(world.envelope(), policy_decision=decision)  # type: ignore[call-arg]
    assert world.tool_calls() == 0
