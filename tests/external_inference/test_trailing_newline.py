"""A pattern anchored with `$` and used with `.match()` accepts a trailing newline.

These validators guard identifiers on the external model path: the opaque provider, model
and source names, and the keys and values a transport reports about a call. Each must
refuse a value that ends in a newline, through the public model that uses it.
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from ciso.inference.external import ContextItem, TransportResponse

pytestmark = pytest.mark.external_inference


def test_clean_values_are_accepted() -> None:
    item = ContextItem(ref="evidence:a1", text="t", classification="public", source="registry")
    assert item.source == "registry"
    response = TransportResponse(body=b"x", metadata={"finish": "stop"})
    assert response.metadata["finish"] == "stop"


def test_opaque_source_with_trailing_newline_is_refused() -> None:
    with pytest.raises(ValidationError):
        ContextItem(ref="evidence:a1", text="t", classification="public", source="registry\n")


def test_metadata_key_with_trailing_newline_is_refused() -> None:
    with pytest.raises(ValidationError, match="bad metadata key"):
        TransportResponse(body=b"x", metadata={"finish\n": "stop"})


def test_metadata_value_with_trailing_newline_is_refused() -> None:
    with pytest.raises(ValidationError, match="short identifiers"):
        TransportResponse(body=b"x", metadata={"finish": "stop\n"})
