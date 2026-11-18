"""Governance routes: device-only decide and activity, fail-closed pipeline, central gate,
body cap, route permissions."""

from __future__ import annotations

import json
from typing import Any

import pytest
from tests.api.governance_helpers import (
    GATE_SECRET,
    GOV_ENV,
    World,
    build_world,
    envelope,
    gate_frame,
    post_tool,
    pre_tool,
    register_device,
    signed_frame,
)
from tests.api.helpers import ApiFactory

from ciso.api import require, route_table, undeclared_routes
from ciso.api.bodylimit import MAX_BODY_BYTES, MAX_GATE_BODY_BYTES
from ciso.app.governance_pipeline import PUSH_HELD_NOTE
from ciso.common.enums import ActorType, Role
from ciso.common.errors import FailClosed
from ciso.identity import PERMISSIONS, ROLE_TEMPLATES
from ciso.intake import MAX_GATE_BODY_BYTES as INTAKE_GATE_BYTES
from ciso.intake import MAX_REQUEST_BYTES

pytestmark = pytest.mark.unit


@pytest.fixture
def world(make_api: ApiFactory) -> World:
    return build_world(make_api)


def _raise(*_: Any, **__: Any) -> Any:
    raise FailClosed("down")


# --- route table and permissions ------------------------------------------------------

EXPECTED_ROUTES = {
    ("POST", "/v1/governance/decide"): "governance.report",
    ("POST", "/v1/activity"): "governance.report",
    ("POST", "/v1/central-gate"): "signed_webhook",
    ("POST", "/v1/devices"): "identity.manage",
    ("DELETE", "/v1/devices/{device_id}"): "identity.manage",
    ("POST", "/v1/agents"): "agents.manage",
    ("GET", "/v1/agents"): "governance.read",
    ("GET", "/v1/agents/coverage-gaps"): "governance.read",
    ("GET", "/v1/agents/{agent_id}"): "governance.read",
    ("POST", "/v1/agents/{agent_id}/approve"): "agents.manage",
    ("POST", "/v1/agents/{agent_id}/suspend"): "agents.suspend",
    ("POST", "/v1/agents/{agent_id}/unsuspend"): "agents.manage",
    ("POST", "/v1/agents/{agent_id}/retire"): "agents.manage",
    ("POST", "/v1/agents/{agent_id}/classify"): "agents.manage",
    ("POST", "/v1/agents/bindings"): "agents.manage",
    ("DELETE", "/v1/agents/bindings/{binding_id}"): "agents.manage",
    ("GET", "/v1/sessions/{session_id}"): "governance.read",
    ("GET", "/v1/findings"): "finding.read",
    ("GET", "/v1/findings/mine"): "report.read_own",
    ("GET", "/v1/findings/{finding_id}"): "finding.read",
    ("POST", "/v1/findings/{finding_id}/acknowledge"): "finding.acknowledge",
    ("POST", "/v1/findings/{finding_id}/resolve"): "finding.update",
    ("POST", "/v1/findings/{finding_id}/accept-risk"): "finding.update",
    ("POST", "/v1/findings/{finding_id}/risk-acceptance"): "finding.update",
    ("POST", "/v1/findings/{finding_id}/false-positive"): "finding.update",
    ("GET", "/v1/alerts"): "finding.read",
}


def test_every_governance_route_declares_its_permission(make_api: ApiFactory) -> None:
    api = make_api(environ=GOV_ENV)
    table = route_table(api.app)
    assert undeclared_routes(api.app) == []
    assert {key: table[key] for key in EXPECTED_ROUTES} == EXPECTED_ROUTES


def test_no_role_template_grants_the_device_permission() -> None:
    assert "governance.report" in PERMISSIONS
    assert [t.role for t in ROLE_TEMPLATES if "governance.report" in t.permissions] == []


def test_the_device_permission_cannot_be_declared_through_require() -> None:
    with pytest.raises(ValueError, match="require_device"):
        require("governance.report")


def test_the_body_caps_match_the_intake_limits() -> None:
    assert (MAX_BODY_BYTES, MAX_GATE_BODY_BYTES) == (MAX_REQUEST_BYTES, INTAKE_GATE_BYTES)


# --- devices --------------------------------------------------------------------------


def test_a_registered_device_gets_a_working_token_once(world: World) -> None:
    api = world.api
    r = world.api.client.get(f"/v1/sessions/{'none'}", headers=world.admin_headers())
    assert r.status_code == 404
    answer = world.decide(pre_tool(world, "Bash", {"command": "ls"}))
    assert answer["verdict"] == "allow"
    records = api.audit_records("governance.device.register")
    assert [r.outcome.value for r in records] == ["attempt", "success"]
    assert world.device_token not in json.dumps([r.model_dump(mode="json") for r in records])


def test_device_name_must_be_unique_and_well_formed(world: World) -> None:
    h = world.admin_headers()
    created = len(world.api.audit_records("identity.actor.create"))
    for name, status in (("WS-0142", 409), ("bad name", 422)):
        r = world.api.client.post("/v1/devices", json={"name": name}, headers=h)
        assert r.status_code == status, name
    assert len(world.api.audit_records("identity.actor.create")) == created


def test_only_an_admin_registers_devices(world: World) -> None:
    _, auditor = world.api.actor("Aud", ActorType.HUMAN, Role.AUDITOR)
    r = world.api.client.post(
        "/v1/devices", json={"name": "X1"}, headers=world.api.headers(auditor)
    )
    assert r.status_code == 403


@pytest.mark.parametrize("who", ["admin", "person", "plain_service"])
def test_decide_refuses_every_token_but_a_device(world: World, who: str) -> None:
    if who == "admin":
        token = world.api.admin_token
    elif who == "person":
        token = world.person_token
    else:
        _, token = world.api.actor("Some service", ActorType.SERVICE)
    request = pre_tool(world, "Bash", {"command": "ls"})
    for path in ("/v1/governance/decide", "/v1/activity"):
        r = world.api.client.post(path, json=request, headers=world.api.headers(token))
        assert r.status_code == 403, (who, path)


def test_a_revoked_device_is_refused(world: World) -> None:
    r = world.api.client.delete(f"/v1/devices/{world.device_id}", headers=world.admin_headers())
    assert r.status_code == 200
    assert r.json()["revoked_at"]
    assert world.api.container.governance.devices.is_device(world.device_id) is False
    request = pre_tool(world, "Bash", {"command": "ls"})
    r = world.api.client.post("/v1/governance/decide", json=request, headers=world.device_headers())
    assert r.status_code == 401


def test_an_unreadable_device_directory_refuses(
    world: World, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(world.api.container.governance.devices, "is_device", _raise)
    request = pre_tool(world, "Bash", {"command": "ls"})
    r = world.api.client.post("/v1/governance/decide", json=request, headers=world.device_headers())
    assert r.status_code == 503


def test_each_device_has_its_own_rate_budget(make_api: ApiFactory) -> None:
    world = build_world(make_api, api_rate_limit_per_minute=30)
    request = pre_tool(world, "Bash", {"command": "ls"})
    codes = [
        world.api.client.post(
            "/v1/governance/decide", json=request, headers=world.device_headers()
        ).status_code
        for _ in range(31)
    ]
    assert codes[:30] == [200] * 30
    assert codes[30] == 429


# --- the pipeline fails closed --------------------------------------------------------


@pytest.mark.parametrize("body", [b"not json", b"[]", b'{"format": "other"}'])
def test_an_unreadable_report_is_a_denied_and_audited_decision(world: World, body: bytes) -> None:
    r = world.api.client.post(
        "/v1/governance/decide",
        content=body,
        headers={**world.device_headers(), "content-type": "application/json"},
    )
    assert r.status_code == 200
    answer = r.json()
    assert (answer["verdict"], answer["reason"]) == ("deny", "invalid_report")
    assert answer["decision_id"].startswith("dec_")
    refused = world.api.audit_records("governance.pipeline.refuse")
    assert refused[-1].details["decision_id"] == answer["decision_id"]


@pytest.mark.parametrize(
    ("service", "method", "reason"),
    [
        ("registry", "attribute", "attribution_unavailable"),
        ("inspector", "inspect", "inspection_failed"),
        ("findings", "record", "findings_unavailable"),
    ],
)
def test_a_failed_step_is_a_deny(
    world: World, monkeypatch: pytest.MonkeyPatch, service: str, method: str, reason: str
) -> None:
    monkeypatch.setattr(getattr(world.api.container.governance, service), method, _raise)
    command = "git push origin feature" if service == "inspector" else "ls"
    answer = world.decide(pre_tool(world, "Bash", {"command": command}))
    assert (answer["verdict"], answer["reason"]) == ("deny", reason)
    assert "down" not in answer["message"]


def test_an_unexpected_error_is_a_deny_not_a_500(
    world: World, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(world.api.container.governance.engine, "decide", lambda *a: 1 / 0)
    answer = world.decide(pre_tool(world, "Bash", {"command": "ls"}))
    assert (answer["verdict"], answer["reason"]) == ("deny", "internal_error")


def test_a_push_is_held_until_the_sandbox_exists(world: World) -> None:
    answer = world.decide(pre_tool(world, "Bash", {"command": "git push origin feature"}))
    assert answer["verdict"] == "deny"
    assert answer["message"].endswith(PUSH_HELD_NOTE)
    wrapped = world.decide(
        pre_tool(world, "Bash", {"command": "cd sub && git push origin feature"})
    )
    assert wrapped["verdict"] == "deny"
    assert wrapped["message"].endswith(PUSH_HELD_NOTE)


def test_a_read_is_not_held(world: World) -> None:
    answer = world.decide(pre_tool(world, "Bash", {"command": "git status"}))
    assert PUSH_HELD_NOTE not in answer["message"]


# --- activity -------------------------------------------------------------------------


def test_activity_records_after_events(world: World) -> None:
    r = world.api.client.post(
        "/v1/activity",
        json=post_tool(world, "Bash", {"command": "ls"}),
        headers=world.device_headers(),
    )
    assert r.status_code == 202
    assert r.json()["recorded"] is True


def test_activity_refuses_a_before_event(world: World) -> None:
    r = world.api.client.post(
        "/v1/activity",
        json=pre_tool(world, "Bash", {"command": "ls"}),
        headers=world.device_headers(),
    )
    assert r.status_code == 422


def test_activity_failure_is_503_without_detail(
    world: World, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(world.api.container.governance.registry, "attribute", _raise)
    r = world.api.client.post(
        "/v1/activity",
        json=post_tool(world, "Bash", {"command": "ls"}),
        headers=world.device_headers(),
    )
    assert r.status_code == 503
    assert "down" not in r.text


def test_activity_records_findings_for_denials_only(world: World) -> None:
    findings = world.api.container.governance.findings
    before = len(findings.list(world.api.admin.actor_id))
    for command in ("ls", "git status", "npm install left-pad"):
        world.api.client.post("/v1/activity", json=post_tool(world, "Bash", {"command": command}),
                              headers=world.device_headers())  # fmt: skip
    assert len(findings.list(world.api.admin.actor_id)) == before
    world.api.client.post(
        "/v1/activity",
        json=post_tool(world, "Write", {"file_path": "C:\\work\\repo\\.mcp.json", "content": "{}"}),
        headers=world.device_headers(),
    )
    after = findings.list(world.api.admin.actor_id)
    assert len(after) > before
    assert any(f.check_key.startswith("decision.deny.") for f in after)


# --- body cap -------------------------------------------------------------------------


def test_an_oversized_report_is_413(world: World) -> None:
    big = pre_tool(world, "Bash", {"command": "x" * (MAX_BODY_BYTES + 10)})
    r = world.api.client.post("/v1/governance/decide", json=big, headers=world.device_headers())
    assert r.status_code == 413


def test_a_chunked_oversized_body_is_413(world: World) -> None:
    def chunks() -> Any:
        for _ in range(5):
            yield b"x" * (MAX_BODY_BYTES // 4)

    r = world.api.client.post(
        "/v1/governance/decide", content=chunks(), headers=world.device_headers()
    )
    assert r.status_code == 413


# --- central gate ---------------------------------------------------------------------


def _gate(world: World, frame: dict[str, Any], secret_ok: bool = True) -> dict[str, Any]:
    stamp = int(world.api.clock.now().timestamp())
    headers, body = signed_frame(frame, stamp)
    if not secret_ok:
        headers["webhook-signature"] = "v1," + "A" * 44
    r = world.api.client.post("/v1/central-gate", content=body, headers=headers)
    assert r.status_code == 200, r.text
    answer: dict[str, Any] = r.json()
    return answer


def test_central_gate_judges_a_signed_frame(world: World) -> None:
    assert _gate(world, gate_frame("tool_call", "req_g1", "rm -rf /tmp/x"))["action"] == "deny"
    records = world.api.audit_records("governance.central_gate")
    assert records[-1].details["decision_ids"]


def test_central_gate_refuses_a_bad_signature(world: World) -> None:
    answer = _gate(world, gate_frame("tool_call", "req_g2"), secret_ok=False)
    assert answer["action"] == "deny"
    assert world.api.audit_records("governance.central_gate")[-1].outcome.value == "denied"


def test_central_gate_allows_an_unknown_frame_type_after_the_signature(world: World) -> None:
    assert _gate(world, gate_frame("future_kind", "req_g3"))["action"] == "allow"
    last = world.api.audit_records("governance.central_gate")[-1]
    assert last.details == {"reason": "unknown_frame_type", "verdict": "allow"}
    assert _gate(world, gate_frame("future_kind", "req_g4"), secret_ok=False)["action"] == "deny"


def test_central_gate_without_a_secret_denies(make_api: ApiFactory) -> None:
    world = build_world(make_api, environ={k: v for k, v in GOV_ENV.items() if "CENTRAL" not in k})
    assert GATE_SECRET not in json.dumps(world.api.container.readiness().model_dump(mode="json"))
    assert "governance.central_gate_secret_ref (unresolvable)" in (
        world.api.container.readiness().governance
    )
    assert _gate(world, gate_frame("tool_call", "req_g5"))["action"] == "deny"


def test_central_gate_unset_denies(make_api: ApiFactory) -> None:
    def unset(settings: Any) -> Any:
        gov = settings.governance.model_copy(update={"central_gate_tolerance_seconds": None})
        return settings.model_copy(update={"governance": gov})

    world = build_world(make_api, change=unset)
    assert world.api.container.governance.gate.configured is False
    assert _gate(world, gate_frame("tool_call", "req_g6"))["action"] == "deny"


def test_readiness_lists_what_governance_runs_without(world: World) -> None:
    assert "governance.required_sandbox_checks" in world.api.container.readiness().governance


def test_device_registration_answers_once(world: World) -> None:
    device_id, token = register_device(world.api, "WS-0200")
    assert token
    assert world.api.container.governance.devices.is_device(device_id)
    record = world.api.container.identity.get_actor(device_id)
    assert record.actor_type is ActorType.SERVICE


def test_envelope_without_device_is_still_decided(world: World) -> None:
    request = envelope(
        {"session_id": "s-nodev", "hook_event_name": "UserPromptSubmit", "prompt_id": "p1",
         "prompt": "hello"},
        device=None,
    )  # fmt: skip
    assert world.decide(request)["decision_id"].startswith("dec_")


def test_granted_never_confers_the_device_permission(monkeypatch: pytest.MonkeyPatch) -> None:
    from ciso.api import deps

    monkeypatch.setattr(deps, "permissions_for", lambda roles: frozenset({"governance.report"}))
    principal = deps.Principal(actor_id="a", actor_type=ActorType.HUMAN)
    assert "governance.report" not in deps.granted(principal, {})


def test_an_unknown_frame_that_cannot_be_audited_is_denied(
    world: World, monkeypatch: pytest.MonkeyPatch
) -> None:
    audit = world.api.container.audit
    original = audit.append

    def failing(event: Any) -> Any:
        if event.action == "governance.central_gate":
            raise FailClosed("audit down")
        return original(event)

    monkeypatch.setattr(audit, "append", failing)
    assert _gate(world, gate_frame("future_kind", "req_g7"))["action"] == "deny"


def test_central_gate_decision_failure_denies(
    world: World, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(world.api.container.governance.pipeline, "judge", _raise)
    assert _gate(world, gate_frame("tool_call", "req_g8"))["action"] == "deny"


def test_the_body_cap_refuses_by_declared_length_before_reading() -> None:
    import anyio

    from ciso.api.bodylimit import BodyLimitMiddleware

    called: list[str] = []
    sent: list[dict[str, Any]] = []

    async def app(scope: Any, receive: Any, send: Any) -> None:
        called.append("app")

    async def receive() -> dict[str, Any]:
        raise AssertionError("the body must not be read")

    async def send(message: dict[str, Any]) -> None:
        sent.append(message)

    middleware = BodyLimitMiddleware(app, default_limit=10)
    for value in (b"11", b"x1"):
        sent.clear()
        scope = {"type": "http", "path": "/v1/activity", "headers": [(b"content-length", value)]}
        anyio.run(middleware, scope, receive, send)
        assert sent[0]["status"] == 413
    assert called == []
