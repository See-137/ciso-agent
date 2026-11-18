"""`ciso.common` identifier validators refuse a trailing newline.

`$` also matches just before a final line feed, so `^...$` with `.match()` let
`"asset:a1\\n"` through. Each test names the site it guards.
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from ciso.common.classification import ClassificationScheme
from ciso.common.errors import ValidationFailed
from ciso.common.ids import EntityRef, entity_ref, is_id, new_id

pytestmark = pytest.mark.unit


def test_new_id_refuses_a_prefix_with_trailing_newline() -> None:
    assert new_id("fnd").startswith("fnd_")
    with pytest.raises(ValidationFailed, match="bad id prefix"):
        new_id("fnd\n")


def test_is_id_refuses_an_id_with_trailing_newline() -> None:
    ident = new_id("fnd")
    assert is_id(ident) is True
    assert is_id(ident + "\n") is False
    assert is_id(ident + "\n", "fnd") is False


def test_is_id_refuses_an_embedded_newline() -> None:
    ident = new_id("fnd")
    assert is_id(ident[:10] + "\n" + ident[11:]) is False


def test_entity_ref_refuses_an_id_half_with_trailing_newline() -> None:
    assert EntityRef.parse("asset:a1") == EntityRef("asset", "a1")
    with pytest.raises(ValidationFailed, match="bad entity ref"):
        EntityRef.parse("asset:a1\n")
    with pytest.raises(ValidationFailed, match="bad entity ref"):
        entity_ref("asset", "a1\n")


def test_entity_ref_refuses_a_kind_half_with_trailing_newline() -> None:
    assert entity_ref("asset", "a1") == "asset:a1"
    with pytest.raises(ValidationFailed, match="bad entity ref"):
        EntityRef.parse("asset\n:a1")
    with pytest.raises(ValidationFailed, match="bad entity ref"):
        entity_ref("asset\n", "a1")


def test_entity_ref_refuses_an_embedded_newline() -> None:
    with pytest.raises(ValidationFailed, match="bad entity ref"):
        EntityRef.parse("asset:a\n1")


def test_classification_label_with_trailing_newline_is_refused() -> None:
    assert ClassificationScheme(labels=("open", "closed")).labels == ("open", "closed")
    with pytest.raises(ValidationError, match="bad classification label"):
        ClassificationScheme(labels=("open", "closed\n"))
