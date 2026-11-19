"""Fix round QF2 through the API (docs/reviews/skill-service-adversarial.md H1 H4 M1 L4 L5
L7, queue Q8 Q10 Q11): each reviewer sequence re-run on the real container."""

from __future__ import annotations

import base64
import json
from typing import Any

import pytest
from tests.api.governance_helpers import (
    DEVICE_NAME,
    OS_ACCOUNT,
    SESSION,
    World,
    build_world,
    gate_frame,
    pre_tool,
    register_device,
    signed_frame,
)
from tests.api.helpers import ApiFactory
from tests.app.change_helpers import HEAD, REPOSITORY, bundle_for, push_upload, sha

from ciso.common.enums import Role

pytestmark = pytest.mark.unit

PUSH = "git push origin feature"
ENGAGE = "/v1/killswitch/engage"


@pytest.fixture
def world(make_api: ApiFactory) -> World:
    return build_world(make_api)


def _session(world: World, session_id: str = SESSION) -> dict[str, Any]:
    r = world.api.client.get(f"/v1/sessions/{session_id}", headers=world.admin_headers())
    assert r.status_code == 200, r.text
    body: dict[str, Any] = r.json()
    return body


# --- H4 / Q8: the device is the token's, never the request's -----------------------------


def test_a_request_naming_another_device_is_refused(world: World) -> None:
    """Reviewer's sequence: a second machine's token, claiming the first machine's name
    and its engineer's account, flipped deny to allow. Now the request is refused."""
    _, other_token = register_device(world.api, "WS-0999")
    request = pre_tool(world, "Bash", {"command": PUSH})
    assert request["device"] == DEVICE_NAME
    r = world.api.client.post(
        "/v1/governance/decide", json=request, headers=world.api.headers(other_token)
    )
    answer = r.json()
    assert (answer["verdict"], answer["reason"]) == ("deny", "invalid_report")
    refusals = world.api.audit_records("governance.pipeline.refuse")
    assert refusals[-1].details["refusal_code"] == "device_mismatch"


def test_the_device_name_comes_from_the_token(world: World) -> None:
    _, other_token = register_device(world.api, "WS-0999")
    request = pre_tool(world, "Bash", {"command": "ls"})
    request["payload"]["session_id"] = "sess-other"
    del request["device"]
    r = world.api.client.post(
        "/v1/governance/decide", json=request, headers=world.api.headers(other_token)
    )
    assert r.status_code == 200
    session = _session(world, "sess-other")
    assert session["device"] == "WS-0999"
    # the engineer's account claim does not count on a machine they are not assigned to
    assert session["person_ref"] is None
    assert session["state"] == "unknown"


def test_an_assigned_device_verifies_its_person(world: World) -> None:
    world.decide(pre_tool(world, "Bash", {"command": "ls"}))
    session = _session(world)
    assert (session["person_ref"], session["state"]) == (f"actor:{world.person_id}", "verified")
    assert session["device"] == DEVICE_NAME


# --- Q11: device assignment routes -------------------------------------------------------


def test_device_assignments_can_be_listed_ended_and_need_a_device(world: World) -> None:
    admin = world.admin_headers()
    path = f"/v1/devices/{world.device_id}/assignments"
    listed = world.api.client.get(path, headers=admin).json()["assignments"]
    assert [a["person_ref"] for a in listed] == [f"actor:{world.person_id}"]
    r = world.api.client.post(
        f"/v1/devices/{world.person_id}/assignments",
        json={"people": [f"actor:{world.person_id}"]},
        headers=admin,
    )
    assert r.status_code == 404  # a person is not a device
    r = world.api.client.post(
        path, json={"people": [f"actor:{world.person_id}"]}, headers=world.api.headers(
            world.person_token)
    )  # fmt: skip
    assert r.status_code == 403
    _, other_token = register_device(world.api, "WS-0999")
    r = world.api.client.delete(f"/v1/devices/{world.device_id}/assignments/dva_none",
                                headers=admin)  # fmt: skip
    assert r.status_code == 404
    r = world.api.client.delete(f"{path}/{listed[0]['id']}", headers=admin)
    assert r.status_code == 200, r.text
    assert r.json()["unassigned_at"] is not None
    assert world.api.client.get(path, headers=admin).json()["assignments"] == []


# --- M1: uploads stop while the kill switch blocks writes ---------------------------------


def test_an_upload_is_refused_while_writes_are_blocked(world: World) -> None:
    h = world.admin_headers()
    body = {"capabilities": ["writes"], "reason": "drill"}
    assert world.api.client.post(ENGAGE, json=body, headers=h).status_code == 200
    r = world.api.client.post(
        "/v1/changes", json=push_upload(session_id=SESSION), headers=world.device_headers()
    )
    assert (r.status_code, r.json()["error"]) == (503, "writes_blocked")


# --- H1: bases and upload refusals ---------------------------------------------------------


def _report_back(world: World, change_id: str) -> None:
    gov = world.api.container.governance
    report = {"job_id": change_id, "checks": [
        {"check_id": c, "status": "passed"} for c in ("secrets", "code", "tests")]}  # fmt: skip
    gov.changes.record_report(
        change_id, gov.inspector.from_sandbox_report(report, action_id=change_id)
    )


def test_an_allowed_scanned_push_becomes_an_approved_base(world: World) -> None:
    bases = {"repository": REPOSITORY, "branch": "feature"}
    headers = world.device_headers()
    r = world.api.client.post("/v1/changes/bases", json=bases, headers=headers)
    assert r.json() == {"bases": []}
    r = world.api.client.post("/v1/changes", json=push_upload(session_id=SESSION),
                              headers=headers)  # fmt: skip
    change_id = r.json()["change_id"]
    _report_back(world, change_id)
    request = pre_tool(world, "Bash", {"command": PUSH})
    request.update({"change_id": change_id, "change_head": HEAD})
    assert world.decide(request)["verdict"] == "allow"
    r = world.api.client.post("/v1/changes/bases", json=bases, headers=headers)
    assert r.json() == {"bases": [HEAD]}
    assert world.api.audit_records("governance.change.approve_head")


def test_upload_refusals_carry_their_code(world: World) -> None:
    headers = world.device_headers()
    forged = push_upload(session_id=SESSION, base=sha("forged"))
    r = world.api.client.post("/v1/changes", json=forged, headers=headers)
    assert (r.status_code, r.json()["error"]) == (422, "base_not_approved")
    assert world.api.client.post("/v1/changes", json=push_upload(session_id=SESSION),
                                 headers=headers).status_code == 201  # fmt: skip
    other = sha("second")
    second = push_upload(session_id=SESSION, head=other, commits=[other],
                         bundle_b64=base64.b64encode(bundle_for(other)).decode())  # fmt: skip
    r = world.api.client.post("/v1/changes", json=second, headers=headers)
    assert (r.status_code, r.json()["error"]) == (409, "device_busy")


def test_bases_need_a_device_and_a_good_repository(world: World) -> None:
    body = {"repository": REPOSITORY, "branch": "feature"}
    r = world.api.client.post("/v1/changes/bases", json=body, headers=world.admin_headers())
    assert r.status_code == 403
    r = world.api.client.post("/v1/changes/bases", json={"repository": "a b", "branch": "x"},
                              headers=world.device_headers())  # fmt: skip
    assert r.status_code == 422


# --- L5: a flood of bad tokens from one address does not lock out good devices -------------


def test_a_known_device_passes_while_its_address_is_flooded(make_api: ApiFactory) -> None:
    world = build_world(make_api, api_rate_limit_per_minute=200)
    world.decide(pre_tool(world, "Bash", {"command": "ls"}))  # the token becomes known
    world.api.container.clock.advance(seconds=61)
    limiter = world.api.app.state.limiter
    for _ in range(200):
        limiter.hit("addr:testclient")
    bad = world.api.client.post("/v1/governance/decide", json={},
                                headers=world.api.headers("bogus-token"))  # fmt: skip
    assert bad.status_code == 429
    good = world.api.client.post("/v1/governance/decide", json=pre_tool(world, "Bash", {
        "command": "ls"}), headers=world.device_headers())  # fmt: skip
    assert good.status_code == 200


# --- Q10: the central gate has its own budget; unset refuses ------------------------------


def _gate(world: World, request_id: str) -> Any:
    stamp = int(world.api.clock.now().timestamp())
    headers, body = signed_frame(gate_frame("tool_call", request_id), stamp)
    return world.api.client.post("/v1/central-gate", content=body, headers=headers)


def _gate_limit(limit: int | None) -> Any:
    def change(settings: Any) -> Any:
        gov = settings.governance.model_copy(update={"central_gate_rate_limit_per_minute": limit})
        return settings.model_copy(update={"governance": gov})

    return change


def test_the_central_gate_has_its_own_rate_budget(make_api: ApiFactory) -> None:
    world = build_world(make_api, change=_gate_limit(2))
    assert _gate(world, "req_r1").status_code == 200
    assert _gate(world, "req_r2").status_code == 200
    assert _gate(world, "req_r3").status_code == 429
    # the general budget is untouched
    assert world.decide(pre_tool(world, "Bash", {"command": "ls"}))["verdict"] == "allow"


def test_an_unset_central_gate_limit_refuses(make_api: ApiFactory) -> None:
    world = build_world(make_api, change=_gate_limit(None))
    r = _gate(world, "req_r4")
    assert (r.status_code, r.json()["error"]) == (503, "rate_limit_not_configured")


# --- L7: a repeated delivery gets the stored verdict, across processes ---------------------


def test_a_retried_delivery_gets_the_same_verdict(world: World) -> None:
    first = _gate(world, "req_l7")
    again = _gate(world, "req_l7")
    assert first.status_code == again.status_code == 200
    assert again.json() == first.json()
    assert again.json().get("deny_reason", "") != "replayed"
    records = world.api.audit_records("governance.central_gate")
    assert records[-1].details.get("replayed") is True
    decisions = [r for r in records if r.details.get("decision_ids")]
    assert len(decisions) == 1  # decided once


def test_the_replay_memory_is_shared_through_the_database(world: World) -> None:
    from ciso.app.gate_replay import DatabaseSeenMessages

    clock = world.api.clock
    now = clock.now()
    a = DatabaseSeenMessages(world.api.container.operational_engine)
    b = DatabaseSeenMessages(world.api.container.operational_engine)
    assert a.remember("msg-1", now=now, until=now.replace(year=now.year + 1)) is True
    assert b.remember("msg-1", now=now, until=now.replace(year=now.year + 1)) is False
    b.store_verdict("msg-1", {"action": "allow"})
    assert a.stored_verdict("msg-1") == {"action": "allow"}


# --- L4: the finding's own subject cannot approve accepting its risk ----------------------


def test_the_findings_subject_cannot_approve_its_risk(world: World) -> None:
    world.decide(pre_tool(world, "Bash", {"command": "git push --force origin main"}))
    listed = world.api.client.get("/v1/findings", headers=world.admin_headers()).json()
    mine = [f for f in listed["findings"] if f["person_ref"] == f"actor:{world.person_id}"]
    assert mine
    finding_id = mine[0]["finding_id"]
    api = world.api
    other, _ = api.human("Second admin", Role.SECURITY_ADMIN)
    api.container.identity.assign_role(api.admin, world.person_id, Role.EXECUTIVE_RISK_OWNER)
    subject_token = api.container.authenticator.issue_token(world.person_id, other).token
    r = api.client.post(f"/v1/findings/{finding_id}/risk-acceptance",
                        headers=world.admin_headers())  # fmt: skip
    approval_id = r.json()["approval_id"]
    r = api.client.post(f"/v1/approvals/{approval_id}/approve", json={},
                        headers=api.headers(subject_token))  # fmt: skip
    assert r.status_code == 200, r.text  # the approvals service alone lets it through
    r = api.client.post(
        f"/v1/findings/{finding_id}/accept-risk", json={"approval_id": approval_id},
        headers=world.admin_headers(),
    )  # fmt: skip
    assert r.status_code == 409
    assert r.json()["reason"] == "approver_is_subject"
    assert api.container.approvals.get(approval_id).status.value == "approved"  # not spent
    assert json.dumps(r.json()).count(OS_ACCOUNT) == 0
