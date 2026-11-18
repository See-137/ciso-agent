"""The kill-switch MAC key must be at least `MIN_KEY_BYTES` long (item 3, M1 fix pass)."""

from __future__ import annotations

from collections.abc import Callable

import pytest
from sqlalchemy import Engine
from tests.fakes.core import FakeSecrets
from tests.killswitch.conftest import KEY_REF

from ciso.common.enums import KillCapability
from ciso.common.errors import FailClosed
from ciso.killswitch import KillSwitch
from ciso.killswitch.integrity import resolve_key
from ciso.vault import MIN_KEY_BYTES

pytestmark = pytest.mark.broker

SHORT = "m" * (MIN_KEY_BYTES - 1)
LONG = "m" * MIN_KEY_BYTES


def test_a_31_byte_mac_key_resolves_to_none() -> None:
    assert resolve_key(FakeSecrets({KEY_REF: SHORT}), KEY_REF) is None


def test_a_32_byte_mac_key_resolves() -> None:
    assert resolve_key(FakeSecrets({KEY_REF: LONG}), KEY_REF) == LONG.encode("utf-8")


def test_switch_with_a_short_key_refuses_and_reads_blocked(
    engine: Engine, make_switch: Callable[..., KillSwitch]
) -> None:
    switch = make_switch(engine, secrets=FakeSecrets({KEY_REF: SHORT}))
    with pytest.raises(FailClosed):
        switch.initialise()
    assert [switch.is_blocked(c) for c in KillCapability] == [True] * len(KillCapability)


def test_switch_with_a_32_byte_key_reads_clear(
    engine: Engine, make_switch: Callable[..., KillSwitch]
) -> None:
    switch = make_switch(engine, secrets=FakeSecrets({KEY_REF: LONG}))
    switch.initialise()
    assert [switch.is_blocked(c) for c in KillCapability] == [False] * len(KillCapability)
