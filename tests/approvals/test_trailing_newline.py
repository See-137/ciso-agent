"""An approval subject with a trailing newline is refused before anything is stored.

`$` also matches just before a final line feed, so `^...$` with `.match()` accepted a
subject kind or hash ending in `"\\n"`. An approval binds to the exact subject hash, so a
second spelling of the same hash must not exist.
"""

from __future__ import annotations

from typing import Any

import pytest
from sqlalchemy import Engine
from tests.approvals.conftest import HASH, KIND, ask, reason_of, row_count

from ciso.approvals import ApprovalReason, ApprovalService
from ciso.approvals.models import ApprovalInputInvalid
from ciso.approvals.rules import check_subject

pytestmark = pytest.mark.policy


def test_clean_subject_is_accepted() -> None:
    assert check_subject(KIND, HASH) == (KIND, HASH)


def test_subject_kind_with_trailing_newline_is_refused() -> None:
    with pytest.raises(ApprovalInputInvalid, match="bad subject kind") as info:
        check_subject(KIND + "\n", HASH)
    assert reason_of(info) is ApprovalReason.INVALID_SUBJECT


def test_subject_hash_with_trailing_newline_is_refused() -> None:
    with pytest.raises(ApprovalInputInvalid, match="64 lowercase hex") as info:
        check_subject(KIND, HASH + "\n")
    assert reason_of(info) is ApprovalReason.INVALID_SUBJECT


@pytest.mark.parametrize("kind", ["external\n_inference", "\n" + KIND])
def test_subject_kind_with_other_newlines_is_refused(kind: str) -> None:
    with pytest.raises(ApprovalInputInvalid) as info:
        check_subject(kind, HASH)
    assert reason_of(info) is ApprovalReason.INVALID_SUBJECT


@pytest.mark.parametrize(
    "overrides", [{"subject_kind": KIND + "\n"}, {"subject_hash": HASH + "\n"}]
)
def test_request_with_a_newline_subject_stores_nothing(
    svc: ApprovalService, engine: Engine, overrides: dict[str, Any]
) -> None:
    with pytest.raises(ApprovalInputInvalid) as info:
        ask(svc, **overrides)
    assert reason_of(info) is ApprovalReason.INVALID_SUBJECT
    assert row_count(engine) == 0
    assert ask(svc).subject_hash == HASH
    assert row_count(engine) == 1
