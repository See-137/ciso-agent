"""Helpers for the governance API and end-to-end tests: a registered device, a person
bound to the device's operating-system account, an approved agent, and hook reports in
the decision-API shape."""

from __future__ import annotations

import base64
import copy
import hashlib
import hmac
import json
from dataclasses import dataclass, field
from typing import Any

from tests.api.helpers import SECRET_ENV, Api, ApiFactory

from ciso.common.enums import Role

DEVICE_NAME = "WS-0142"
OS_ACCOUNT = "CORP\\jdoe"
SESSION = "sess-e2e-1"
CWD = "C:\\work\\repo"
GATE_SECRET = "whsec_" + base64.b64encode(b"g" * 32).decode()
CHANGE_KEY = "change-store-key-for-api-tests-6c0d2f19ab"
SANDBOX_TOKEN = "sandbox-token-for-api-tests-77e1"
GOV_ENV = {
    **SECRET_ENV,
    "CISO_SECRET_CENTRAL_GATE_SIGNING_SECRET": GATE_SECRET,
    "CISO_SECRET_CHANGE_STORE_KEY": CHANGE_KEY,
    "CISO_SECRET_SANDBOX_TOKEN": SANDBOX_TOKEN,
}


@dataclass
class World:
    api: Api
    device_id: str
    device_token: str
    person_id: str
    person_token: str
    agent_id: str
    uses: dict[str, int] = field(default_factory=dict)

    def device_headers(self) -> dict[str, str]:
        return self.api.headers(self.device_token)

    def admin_headers(self) -> dict[str, str]:
        return self.api.headers(self.api.admin_token)

    def next_id(self, kind: str) -> str:
        self.uses[kind] = self.uses.get(kind, 0) + 1
        return f"{kind}_{self.uses[kind]:04d}"

    def decide(self, request: dict[str, Any]) -> dict[str, Any]:
        r = self.api.client.post(
            "/v1/governance/decide", json=request, headers=self.device_headers()
        )
        assert r.status_code == 200, r.text
        body: dict[str, Any] = r.json()
        return body


def envelope(payload: dict[str, Any], *, device: str | None = DEVICE_NAME) -> dict[str, Any]:
    request: dict[str, Any] = {
        "format": "assistant_hook_v1",
        "event": payload["hook_event_name"],
        "surface": "cli",
        "claims": [{"kind": "os_account", "subject": OS_ACCOUNT, "verified": False}],
        "payload": payload,
    }
    if device is not None:
        request["device"] = device
    return request


def pre_tool(world: World, tool_name: str, tool_input: dict[str, Any]) -> dict[str, Any]:
    return envelope(
        {
            "session_id": SESSION,
            "cwd": CWD,
            "permission_mode": "default",
            "hook_event_name": "PreToolUse",
            "tool_name": tool_name,
            "tool_input": tool_input,
            "tool_use_id": world.next_id("toolu"),
        }
    )


def post_tool(world: World, tool_name: str, tool_input: dict[str, Any]) -> dict[str, Any]:
    request = pre_tool(world, tool_name, tool_input)
    request["event"] = "PostToolUse"
    request["payload"]["hook_event_name"] = "PostToolUse"
    return request


def register_device(api: Api, name: str = DEVICE_NAME) -> tuple[str, str]:
    r = api.client.post("/v1/devices", json={"name": name}, headers=api.headers(api.admin_token))
    assert r.status_code == 201, r.text
    body = r.json()
    return str(body["device_id"]), str(body["token"])


def build_world(make_api: ApiFactory, *, assign: bool = True, **kwargs: Any) -> World:
    """A device, an employee bound to the device's OS account, and an approved
    employee-operated agent identified by the device name. With `assign` (the default) the
    device is assigned to the employee, so the session is verified; without it, declared."""
    kwargs.setdefault("environ", GOV_ENV)
    api = make_api(**kwargs)
    device_id, device_token = register_device(api)
    person, person_token = api.human("Jo Doe", Role.EMPLOYEE)
    admin = api.headers(api.admin_token)
    person_ref = f"actor:{person.actor_id}"
    r = api.client.post(
        "/v1/agents/bindings",
        json={"kind": "os_account", "subject": OS_ACCOUNT, "person_ref": person_ref},
        headers=admin,
    )
    assert r.status_code == 201, r.text
    # The default ruleset allows only verified attribution: the device must be assigned
    # to the person for the bound OS account to count as verified.
    if assign:
        api.container.governance.agent_admin.assign_device(api.admin, device_id, [person_ref])
    r = api.client.post(
        "/v1/agents",
        json={
            "display_name": "Jo's coding assistant",
            "agent_class": "employee_operated",
            "surface": "cli",
            "facts": [{"kind": "device", "value": DEVICE_NAME}],
            "operator_ref": person_ref,
        },
        headers=admin,
    )
    assert r.status_code == 201, r.text
    agent_id = r.json()["id"]
    r = api.client.post(f"/v1/agents/{agent_id}/approve", headers=admin)
    assert r.status_code == 200, r.text
    return World(api, device_id, device_token, person.actor_id, person_token, agent_id)


def sign(secret: str, msg_id: str, timestamp: int, body: bytes) -> str:
    """Standard Webhooks v1: base64(HMAC-SHA256(key, "id.timestamp.body"))."""
    key = base64.b64decode(secret.removeprefix("whsec_"), validate=True)
    mac = hmac.new(key, f"{msg_id}.{timestamp}.".encode() + body, hashlib.sha256).digest()
    return "v1," + base64.b64encode(mac).decode()


def signed_frame(frame: dict[str, Any], timestamp: int) -> tuple[dict[str, str], bytes]:
    body = json.dumps(frame).encode()
    ident = str(frame["request_id"])
    headers = {
        "webhook-id": ident,
        "webhook-timestamp": str(timestamp),
        "webhook-signature": sign(GATE_SECRET, ident, timestamp, body),
        "content-type": "application/json",
    }
    return headers, body


def gate_frame(frame_type: str, request_id: str, command: str = "ls -la") -> dict[str, Any]:
    """A central gate tool call frame (platform endpoint documentation's example shape)."""
    block = {
        "type": "tool_use",
        "id": "toolu_gate_" + request_id,
        "tool_name": "bash",
        "input": {"command": command},
        "tool_info": {"type": "client", "tool_type": "bash_20250124"},
    }
    return copy.deepcopy(
        {
            "type": frame_type,
            "request_id": request_id,
            "actor": {"type": "user", "id": "user_01Gate", "email_address": "jo@example.com"},
            "source": {"application": "claude-code"},
            "session_id": "gate-session-1",
            "messages": [{"role": "assistant", "content": [block]}],
            "metadata": {},
        }
    )
