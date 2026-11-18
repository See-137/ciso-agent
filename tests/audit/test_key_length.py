"""Audit anchor and witness keys must be at least `MIN_KEY_BYTES` long (item 3, M1 fix pass)."""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path

import pytest
from tests.audit.helpers import ANCHOR_KEY_REF, WITNESS_KEY_REF, make_event
from tests.fakes.core import FakeSecrets

from ciso.audit import AuditLog, FileHeadWitness, HeadAnchor
from ciso.common.errors import FailClosed
from ciso.vault import MIN_KEY_BYTES

pytestmark = pytest.mark.unit

SHORT = "a" * (MIN_KEY_BYTES - 1)
LONG = "a" * MIN_KEY_BYTES
AT = datetime(2026, 11, 18, tzinfo=UTC)
HEAD = "0" * 64


def test_anchor_refuses_a_31_byte_key_without_echoing_it(anchor_path: Path) -> None:
    anchor = HeadAnchor(anchor_path, FakeSecrets({ANCHOR_KEY_REF: SHORT}), ANCHOR_KEY_REF)
    with pytest.raises(FailClosed) as info:
        anchor.load_key()
    assert ANCHOR_KEY_REF in str(info.value)
    assert SHORT not in str(info.value)


def test_anchor_accepts_a_32_byte_key_and_the_log_works(
    anchor_path: Path, make_log: Callable[..., AuditLog]
) -> None:
    anchor = HeadAnchor(anchor_path, FakeSecrets({ANCHOR_KEY_REF: LONG}), ANCHOR_KEY_REF)
    log = make_log(anchor=anchor)
    log.initialise()
    receipt = log.append(make_event(1))
    assert receipt.seq == 1
    assert log.verify().status.value == "ok"


def test_log_with_a_short_anchor_key_refuses_to_initialise(
    anchor_path: Path, make_log: Callable[..., AuditLog]
) -> None:
    anchor = HeadAnchor(anchor_path, FakeSecrets({ANCHOR_KEY_REF: SHORT}), ANCHOR_KEY_REF)
    with pytest.raises(FailClosed):
        make_log(anchor=anchor).initialise()
    assert not anchor_path.exists()


def test_witness_refuses_a_31_byte_key_on_publish_and_read(witness_path: Path) -> None:
    witness = FileHeadWitness(witness_path, FakeSecrets({WITNESS_KEY_REF: SHORT}), WITNESS_KEY_REF)
    with pytest.raises(FailClosed) as info:
        witness.publish("alog_x", 1, HEAD, AT)
    assert WITNESS_KEY_REF in str(info.value)
    assert not witness_path.exists()
    with pytest.raises(FailClosed):
        witness.latest("alog_x")


def test_witness_accepts_a_32_byte_key(witness_path: Path) -> None:
    witness = FileHeadWitness(witness_path, FakeSecrets({WITNESS_KEY_REF: LONG}), WITNESS_KEY_REF)
    witness.publish("alog_x", 1, HEAD, AT)
    latest = witness.latest("alog_x")
    assert latest is not None
    assert (latest.seq, latest.head_hash) == (1, HEAD)
