"""GatedKillSwitch truth table (T1.17, blueprint 10.3, 11.2, NFR-017).

Writes and L3 runs need a verified audit log; external inference and active scans are
blocked while the log is failed or unverifiable; the inner switch always wins.
"""

from __future__ import annotations

import pytest
from tests.fakes.core import FakeKillSwitch

from ciso.common.enums import KillCapability
from ciso.common.protocols import KillSwitchReader
from ciso.ops import GatedKillSwitch, IntegrityState, IntegrityStatus

pytestmark = pytest.mark.resilience

W, L3, EXT, SCAN = (
    KillCapability.WRITES,
    KillCapability.L3_RUNS,
    KillCapability.EXTERNAL_INFERENCE,
    KillCapability.ACTIVE_SCANS,
)

#: capability -> status -> blocked (with the inner switch clear)
EXPECTED: dict[KillCapability, dict[IntegrityStatus, bool]] = {
    W: {
        IntegrityStatus.OK: False,
        IntegrityStatus.UNVERIFIED: True,
        IntegrityStatus.UNVERIFIABLE: True,
        IntegrityStatus.FAILED: True,
    },
    L3: {
        IntegrityStatus.OK: False,
        IntegrityStatus.UNVERIFIED: True,
        IntegrityStatus.UNVERIFIABLE: True,
        IntegrityStatus.FAILED: True,
    },
    EXT: {
        IntegrityStatus.OK: False,
        IntegrityStatus.UNVERIFIED: False,
        IntegrityStatus.UNVERIFIABLE: True,
        IntegrityStatus.FAILED: True,
    },
    SCAN: {
        IntegrityStatus.OK: False,
        IntegrityStatus.UNVERIFIED: False,
        IntegrityStatus.UNVERIFIABLE: True,
        IntegrityStatus.FAILED: True,
    },
}


def _state(status: IntegrityStatus) -> IntegrityState:
    state = IntegrityState()
    if status is not IntegrityStatus.UNVERIFIED:
        state.record_verification(status, None if status is IntegrityStatus.OK else "test")
    return state


def test_every_capability_is_in_the_table() -> None:
    assert set(EXPECTED) == set(KillCapability)


@pytest.mark.parametrize("cap", list(KillCapability))
@pytest.mark.parametrize("status", list(IntegrityStatus))
def test_inner_clear(cap: KillCapability, status: IntegrityStatus) -> None:
    inner = FakeKillSwitch()
    gate = GatedKillSwitch(inner, _state(status))
    assert gate.is_blocked(cap) is EXPECTED[cap][status]
    assert inner.reads == [cap]  # the inner switch is always consulted


@pytest.mark.parametrize("cap", list(KillCapability))
@pytest.mark.parametrize("status", list(IntegrityStatus))
def test_inner_blocked_always_wins(cap: KillCapability, status: IntegrityStatus) -> None:
    inner = FakeKillSwitch()
    inner.blocked.add(cap)
    assert GatedKillSwitch(inner, _state(status)).is_blocked(cap) is True


@pytest.mark.parametrize("cap", list(KillCapability))
def test_inner_unreadable_reads_blocked(cap: KillCapability) -> None:
    inner = FakeKillSwitch()
    inner.broken = True
    assert GatedKillSwitch(inner, _state(IntegrityStatus.OK)).is_blocked(cap) is True


class _Raising:
    def is_blocked(self, capability: KillCapability) -> bool:
        raise RuntimeError("state store gone")


@pytest.mark.parametrize("cap", list(KillCapability))
def test_inner_that_raises_reads_blocked(cap: KillCapability) -> None:
    assert GatedKillSwitch(_Raising(), _state(IntegrityStatus.OK)).is_blocked(cap) is True


def test_startup_blocker_blocks_writes_and_l3_only() -> None:
    state = _state(IntegrityStatus.OK)
    state.block("schema")
    gate = GatedKillSwitch(FakeKillSwitch(), state)
    assert gate.is_blocked(W)
    assert gate.is_blocked(L3)
    assert not gate.is_blocked(EXT)
    assert not gate.is_blocked(SCAN)
    assert state.snapshot().blockers == ("schema",)


def test_later_verification_resets_status_both_ways() -> None:
    state = _state(IntegrityStatus.FAILED)
    gate = GatedKillSwitch(FakeKillSwitch(), state)
    assert gate.is_blocked(W)
    state.record_verification(IntegrityStatus.OK)
    assert not gate.is_blocked(W)
    state.record_verification(IntegrityStatus.FAILED, "hash_mismatch")
    assert gate.is_blocked(W)
    assert state.snapshot().reason == "hash_mismatch"


def test_unverified_is_not_a_verification_result() -> None:
    with pytest.raises(ValueError, match="unverified"):
        IntegrityState().record_verification(IntegrityStatus.UNVERIFIED)


def test_gate_is_a_kill_switch_reader() -> None:
    assert isinstance(GatedKillSwitch(FakeKillSwitch(), IntegrityState()), KillSwitchReader)
