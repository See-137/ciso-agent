"""Accepting a finding's risk needs an approval requested for THAT finding, granted by an
executive risk owner who is not the caller, and spent exactly once."""

from __future__ import annotations

from typing import Any

import pytest
from tests.api.governance_helpers import World, build_world, pre_tool
from tests.api.helpers import ApiFactory

from ciso.common.enums import Role
from ciso.common.errors import FailClosed

pytestmark = pytest.mark.policy


@pytest.fixture
def world(make_api: ApiFactory) -> World:
    return build_world(make_api)


def _two_findings(world: World) -> list[str]:
    world.decide(pre_tool(world, "Bash", {"command": "git push --force origin main"}))
    world.decide(pre_tool(world, "Write", {"file_path": "C:/work/repo/.mcp.json", "content": "{}"}))
    listed = world.api.client.get("/v1/findings", headers=world.admin_headers()).json()
    ids = [f["finding_id"] for f in listed["findings"]]
    assert len(ids) >= 2
    return ids


def _request(world: World, finding_id: str) -> dict[str, Any]:
    r = world.api.client.post(
        f"/v1/findings/{finding_id}/risk-acceptance", headers=world.admin_headers()
    )
    assert r.status_code == 201, r.text
    body: dict[str, Any] = r.json()
    return body


def _exec(world: World) -> str:
    """An executive risk owner whose token was not minted by the requesting admin (an
    approver whose credential the requester issued is refused, review M4)."""
    other, _ = world.api.human("Second admin", Role.SECURITY_ADMIN)
    _, token = world.api.human("Exec", Role.EXECUTIVE_RISK_OWNER, issuer=other)
    return token


def _approve(world: World, approval_id: str, token: str) -> int:
    r = world.api.client.post(
        f"/v1/approvals/{approval_id}/approve", json={}, headers=world.api.headers(token)
    )
    return r.status_code


def _accept(world: World, finding_id: str, approval_id: str, token: str | None = None) -> Any:
    return world.api.client.post(
        f"/v1/findings/{finding_id}/accept-risk",
        json={"approval_id": approval_id},
        headers=world.api.headers(token or world.api.admin_token),
    )


def test_a_bound_granted_approval_accepts_the_risk_once(world: World) -> None:
    first, _ = _two_findings(world)[:2]
    exec_token = _exec(world)
    approval = _request(world, first)
    assert approval["required_roles"] == ["executive_risk_owner"]
    assert approval["binding"]["finding_id"] == first
    assert _approve(world, approval["approval_id"], exec_token) == 200
    r = _accept(world, first, approval["approval_id"])
    assert r.status_code == 200, r.text
    assert (r.json()["status"], r.json()["approval_ref"]) == (
        "risk_accepted",
        approval["approval_id"],
    )
    stored = world.api.container.approvals.get(approval["approval_id"])
    assert stored.status.value == "consumed"


def test_an_approval_for_another_finding_is_refused_and_not_spent(world: World) -> None:
    first, second = _two_findings(world)[:2]
    exec_token = _exec(world)
    approval = _request(world, first)
    _approve(world, approval["approval_id"], exec_token)
    r = _accept(world, second, approval["approval_id"])
    assert r.status_code == 409
    assert r.json()["error"] == "risk_acceptance_refused"
    assert world.api.container.approvals.get(approval["approval_id"]).status.value == "approved"
    finding = world.api.client.get(f"/v1/findings/{second}", headers=world.admin_headers())
    assert finding.json()["status"] == "open"


def test_a_spent_approval_cannot_be_used_again(world: World) -> None:
    first = _two_findings(world)[0]
    exec_token = _exec(world)
    approval = _request(world, first)
    _approve(world, approval["approval_id"], exec_token)
    assert _accept(world, first, approval["approval_id"]).status_code == 200
    assert _accept(world, first, approval["approval_id"]).status_code == 409


def test_a_pending_or_unknown_approval_is_refused(world: World) -> None:
    first = _two_findings(world)[0]
    approval = _request(world, first)
    assert _accept(world, first, approval["approval_id"]).status_code == 409
    assert _accept(world, first, "apr_nope").status_code == 409


def test_the_approver_cannot_accept_the_risk_themselves(world: World) -> None:
    first = _two_findings(world)[0]
    other, _ = world.api.human("Second admin", Role.SECURITY_ADMIN)
    _, dual_token = world.api.human(
        "Dual", Role.SECURITY_ADMIN, Role.EXECUTIVE_RISK_OWNER, issuer=other
    )
    approval = _request(world, first)
    assert _approve(world, approval["approval_id"], dual_token) == 200
    r = _accept(world, first, approval["approval_id"], dual_token)
    assert r.status_code == 409
    assert r.json()["reason"] == "approver_is_caller"
    assert world.api.container.approvals.get(approval["approval_id"]).status.value == "approved"


def test_an_approvals_failure_refuses(world: World, monkeypatch: pytest.MonkeyPatch) -> None:
    first = _two_findings(world)[0]
    exec_token = _exec(world)
    approval = _request(world, first)
    _approve(world, approval["approval_id"], exec_token)

    def down(*_: Any, **__: Any) -> Any:
        raise FailClosed("approvals down")

    monkeypatch.setattr(world.api.container.approvals, "consume", down)
    r = _accept(world, first, approval["approval_id"])
    assert r.status_code == 409
    assert "approvals down" not in r.text
    finding = world.api.client.get(f"/v1/findings/{first}", headers=world.admin_headers())
    assert finding.json()["status"] == "open"


def test_only_an_admin_requests_a_risk_acceptance(world: World) -> None:
    first = _two_findings(world)[0]
    _, owner_token = world.api.human("Owner", Role.SYSTEM_OWNER)
    r = world.api.client.post(
        f"/v1/findings/{first}/risk-acceptance", headers=world.api.headers(owner_token)
    )
    assert r.status_code == 403
