"""Reading approvals, store failures, and the package boundary. FR-025; gap G3."""

from __future__ import annotations

import ast
from pathlib import Path

import pytest
from sqlalchemy import Engine
from tests.approvals.conftest import (
    MakeService,
    ScriptedAudit,
    ask,
    reason_of,
    tamper,
    use_args,
)

from ciso.approvals import (
    Approval,
    ApprovalNotFound,
    ApprovalReason,
    ApprovalService,
    ApprovalUnavailable,
)
from ciso.common.clock import FixedClock
from ciso.common.db import create_db_engine
from ciso.common.enums import Role
from ciso.common.errors import (
    FailClosed,
    NotFound,
)
from ciso.common.principal import Principal

pytestmark = pytest.mark.policy

R = ApprovalReason


# --- reads -------------------------------------------------------------------------------


def test_unknown_id_is_not_found_and_not_audited(
    svc: ApprovalService, owner: Principal, audit: ScriptedAudit
) -> None:
    calls = (
        lambda: svc.get("apr_missing"),
        lambda: svc.approve("apr_missing", owner),
        lambda: svc.reject("apr_missing", owner),
        lambda: svc.check("apr_missing", **use_args()),
        lambda: svc.consume("apr_missing", **use_args()),
    )
    for call in calls:
        with pytest.raises(ApprovalNotFound) as excinfo:
            call()
        assert reason_of(excinfo) is R.NOT_FOUND
        assert isinstance(excinfo.value, NotFound)
    assert audit.events == []


def test_list_pending_filters_by_role_state_and_expiry(
    svc: ApprovalService, owner: Principal, clock: FixedClock
) -> None:
    old = ask(svc, required_roles=[Role.SYSTEM_OWNER])
    clock.advance(minutes=30)
    risk_only = ask(svc, required_roles=[Role.EXECUTIVE_RISK_OWNER])
    both = ask(svc)
    decided = ask(svc)
    svc.approve(decided.approval_id, owner)
    ids = [a.approval_id for a in svc.list_pending()]
    assert ids[0] == old.approval_id
    assert set(ids) == {old.approval_id, risk_only.approval_id, both.approval_id}
    assert {a.approval_id for a in svc.list_pending(role=Role.SYSTEM_OWNER)} == {
        old.approval_id,
        both.approval_id,
    }
    clock.advance(minutes=30)  # `old` has now reached its expiry
    assert {a.approval_id for a in svc.list_pending()} == {risk_only.approval_id, both.approval_id}
    assert isinstance(svc.list_pending()[0], Approval)


def test_unreadable_row_is_never_treated_as_an_approval(
    svc: ApprovalService, engine: Engine, approved: Approval
) -> None:
    tamper(engine, approved.approval_id, required_roles='["not_a_role"]')
    for call in (
        lambda: svc.get(approved.approval_id),
        lambda: svc.consume(approved.approval_id, **use_args()),
    ):
        with pytest.raises(ApprovalUnavailable) as excinfo:
            call()
        assert reason_of(excinfo) is R.RECORD_UNREADABLE


def test_store_failure_is_fail_closed(make_service: MakeService) -> None:
    empty = create_db_engine(None)  # no schema: every query fails
    try:
        with pytest.raises(ApprovalUnavailable) as excinfo:
            make_service(empty).get("apr_x")
        assert reason_of(excinfo) is R.STORE_UNAVAILABLE
        assert isinstance(excinfo.value, FailClosed)
    finally:
        empty.dispose()


# --- boundary ----------------------------------------------------------------------------


def test_package_is_standalone() -> None:
    """Gap G3: usable by the broker and the external gateway, so it imports neither."""
    root = Path(__file__).resolve().parents[2] / "src" / "ciso" / "approvals"
    banned = ("inference", "orchestrator", "api", "execution", "policy", "identity", "app")
    files = sorted(root.glob("*.py"))
    assert len(files) >= 5
    seen: set[str] = set()
    for path in files:
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                seen.update(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom):
                assert node.level == 0, f"relative import in {path.name}"
                seen.add(node.module or "")
            elif isinstance(node, ast.Name | ast.Attribute):
                name = node.id if isinstance(node, ast.Name) else node.attr
                assert name not in {"__import__", "import_module"}, path.name
    assert "ciso.common.protocols" in seen
    assert "importlib" not in seen
    for name in seen:
        assert not any(name == f"ciso.{b}" or name.startswith(f"ciso.{b}.") for b in banned), name
