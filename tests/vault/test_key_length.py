"""Minimum length of a secret used as a cryptographic key (`ciso.vault.MIN_KEY_BYTES`)."""

from __future__ import annotations

import pytest
from tests.fakes.core import FakeSecrets

import ciso.vault as vault
from ciso.common.errors import FailClosed, NotFound
from ciso.vault import MIN_KEY_BYTES, resolve_key_bytes

pytestmark = pytest.mark.unit

REF = "secret://signing_key"


def test_floor_is_32_bytes_and_exported() -> None:
    assert MIN_KEY_BYTES == 32
    assert {"MIN_KEY_BYTES", "resolve_key_bytes"} <= set(vault.__all__)


def test_a_31_byte_key_is_refused_naming_the_reference_not_the_value() -> None:
    value = "k" * 31
    with pytest.raises(FailClosed) as info:
        resolve_key_bytes(FakeSecrets({REF: value}), REF)
    assert REF in str(info.value)
    assert value not in str(info.value)
    assert "32" in str(info.value)


def test_a_32_byte_key_is_returned_as_utf8_bytes() -> None:
    value = "k" * 32
    assert resolve_key_bytes(FakeSecrets({REF: value}), REF) == value.encode("utf-8")


def test_length_is_counted_in_utf8_bytes_not_characters() -> None:
    eleven_chars_33_bytes = "€" * 11  # each euro sign is 3 bytes in UTF-8
    assert len(eleven_chars_33_bytes) < MIN_KEY_BYTES
    key = resolve_key_bytes(FakeSecrets({REF: eleven_chars_33_bytes}), REF)
    assert len(key) == 33
    thirty_one_bytes = "€" * 10 + "k"
    with pytest.raises(FailClosed):
        resolve_key_bytes(FakeSecrets({REF: thirty_one_bytes}), REF)


def test_an_empty_key_is_refused() -> None:
    with pytest.raises(FailClosed, match="empty"):
        resolve_key_bytes(FakeSecrets({REF: ""}), REF)


def test_an_unresolvable_reference_keeps_the_resolver_error() -> None:
    with pytest.raises(NotFound):
        resolve_key_bytes(FakeSecrets(), REF)
