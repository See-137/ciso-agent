"""The output digest key must be at least `MIN_KEY_BYTES` long (item 3, M1 fix pass)."""

from __future__ import annotations

from collections.abc import Callable

import pytest
from tests.fakes.core import FakeSecrets
from tests.inference.helpers import SpyProvider

from ciso.common.errors import FailClosed
from ciso.inference import InferenceGateway, InferenceRequest
from ciso.vault import MIN_KEY_BYTES

pytestmark = pytest.mark.unit

KEY_REF = "secret://inference_digest"
SHORT = "d" * (MIN_KEY_BYTES - 1)
LONG = "d" * MIN_KEY_BYTES


def test_a_31_byte_digest_key_stops_before_the_provider(
    make_gateway: Callable[..., InferenceGateway],
    make_request: Callable[..., InferenceRequest],
) -> None:
    spy = SpyProvider(text="no")
    gw = make_gateway(spy, secrets=FakeSecrets({KEY_REF: SHORT}), digest_key_ref=KEY_REF)
    with pytest.raises(FailClosed) as info:
        gw.complete(make_request())
    assert KEY_REF in str(info.value)
    assert SHORT not in str(info.value)
    assert spy.calls == []


def test_a_32_byte_digest_key_is_used(
    make_gateway: Callable[..., InferenceGateway],
    make_request: Callable[..., InferenceRequest],
) -> None:
    spy = SpyProvider(text="no")
    gw = make_gateway(spy, secrets=FakeSecrets({KEY_REF: LONG}), digest_key_ref=KEY_REF)
    result = gw.complete(make_request())
    assert result.record_id
    assert len(spy.calls) == 1
