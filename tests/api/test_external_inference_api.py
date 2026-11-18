"""External model routes (plan T2.9; blueprint 8.4, 19.3; FR-018; ADR-0006).

The shipped settings leave the path off, and the build ships no transport. A test that
needs a send to succeed rebuilds the gateway with a test transport through the
composition root's own builder (`with_transport`); it never opens a connection.
"""

from __future__ import annotations

import base64
import hashlib
from typing import Any

import pytest
from tests.api.helpers import SECRET_ENV, Api, ApiFactory, SpyTransport, external_on, with_transport

from ciso.api import route_table, undeclared_routes
from ciso.common.enums import ActorType, Role
from ciso.inference.external import ExternalReason, GateReason

pytestmark = pytest.mark.external_inference

BASE = "/v1/external-inference"
FORBIDDEN = {"error": "forbidden", "message": "not permitted"}
DISABLED = {**FORBIDDEN, "reason": "feature_disabled"}
MARKER = "ZEBRA-QUARTZ-17 quarterly patch summary"
STEPS = ("proposals", "preview", "authorizations", "transmit")
APPROVAL_ID = "apr_00000000000000000000000000"


def proposal_request(**changes: Any) -> dict[str, Any]:
    body: dict[str, Any] = {
        "purpose": "summarise the patch backlog",
        "provider_name": "provider-one",
        "model_name": "model-large-1",
        "items": [
            {
                "ref": "evidence:a1",
                "text": MARKER,
                "classification": "public",
                "source": "registry",
            },
            {
                "ref": "evidence:a2",
                "text": "restricted detail",
                "classification": "restricted",
                "source": "registry",
            },
        ],
    }
    body.update(changes)
    return body


def made_up_proposal(requester: str) -> dict[str, Any]:
    """Well-formed, but never recorded by `propose`."""
    return {
        "request_id": "xrq_00000000000000000000000000",
        "requester_actor_id": requester,
        "requester_actor_type": "human",
        "purpose": "summarise the patch backlog",
        "provider_name": "provider-one",
        "model_name": "model-large-1",
        "items": proposal_request()["items"][:1],
        "created_at": "2026-01-01T00:00:00Z",
    }


def step_body(step: str, proposal: dict[str, Any]) -> dict[str, Any]:
    if step == "proposals":
        return proposal_request()
    if step == "transmit":
        return {"proposal": proposal, "approval_id": APPROVAL_ID}
    return {"proposal": proposal}


def post(api: Api, step: str, token: str, body: dict[str, Any]) -> Any:
    return api.client.post(f"{BASE}/{step}", json=body, headers=api.headers(token))


def propose(api: Api, token: str, **changes: Any) -> dict[str, Any]:
    r = post(api, "proposals", token, proposal_request(**changes))
    assert r.status_code == 201, r.text
    proposal: dict[str, Any] = r.json()["proposal"]
    return proposal


def denied(api: Api, action: str) -> list[str]:
    return [
        str(rec.details.get("reason"))
        for rec in api.audit_records(f"inference.external.{action}")
        if rec.outcome.value == "denied"
    ]


@pytest.fixture
def enabled(make_api: ApiFactory) -> Api:
    """The path switched on and fully decided, with the build's own gateway: no transport."""
    return make_api(change=external_on)


class TestRefusesByDefault:
    @pytest.mark.parametrize("step", STEPS)
    def test_every_step_answers_feature_disabled(self, api: Api, step: str) -> None:
        body = step_body(step, made_up_proposal(api.admin.actor_id))
        r = post(api, step, api.admin_token, body)
        assert r.status_code == 403
        assert r.json() == DISABLED
        assert "refused" not in r.text  # the exception text stays inside
        action = {"proposals": "propose", "authorizations": "authorize"}.get(step, step)
        assert denied(api, action) == ["feature_disabled"]

    def test_reads_find_nothing(self, api: Api) -> None:
        h = api.headers(api.admin_token)
        for path in (f"authorizations/{APPROVAL_ID}", "transmissions/xtx_nope"):
            r = api.client.get(f"{BASE}/{path}", headers=h)
            assert r.status_code == 404
            assert r.json() == {"error": "not_found", "message": "not found"}

    def test_no_approval_is_filed_while_disabled(self, api: Api) -> None:
        body = step_body("authorizations", made_up_proposal(api.admin.actor_id))
        assert post(api, "authorizations", api.admin_token, body).status_code == 403
        assert api.container.approvals.list_pending() == ()


class TestPermissions:
    @pytest.mark.parametrize("step", STEPS)
    @pytest.mark.parametrize(
        ("actor_type", "roles"),
        [
            (ActorType.HUMAN, (Role.EMPLOYEE,)),
            (ActorType.HUMAN, (Role.AUDITOR,)),
            (ActorType.HUMAN, (Role.EXECUTIVE_RISK_OWNER,)),
            (ActorType.AGENT, ()),
            (ActorType.SERVICE, ()),
        ],
    )
    def test_steps_need_the_request_permission(
        self, enabled: Api, step: str, actor_type: ActorType, roles: tuple[Role, ...]
    ) -> None:
        actor_id, token = enabled.actor("Someone", actor_type, *roles)
        r = post(enabled, step, token, step_body(step, made_up_proposal(actor_id)))
        assert r.status_code == 403
        assert r.json() == FORBIDDEN  # the route refused: no gateway reason
        assert enabled.audit_records("inference.external.") == []

    def test_reads_need_the_read_permission(self, api: Api) -> None:
        path = f"{BASE}/authorizations/{APPROVAL_ID}"
        record = f"{BASE}/transmissions/xtx_nope"
        for role, expected in (
            (Role.AUDITOR, 404),
            (Role.SYSTEM_OWNER, 404),
            (Role.EMPLOYEE, 403),
            (Role.EXECUTIVE_RISK_OWNER, 403),
        ):
            _, token = api.human(role.value, role)
            assert api.client.get(path, headers=api.headers(token)).status_code == expected, role
            assert api.client.get(record, headers=api.headers(token)).status_code == expected, role
        assert api.client.get(path).status_code == 401

    def test_route_table_declares_every_external_route(self, api: Api) -> None:
        table = route_table(api.app)
        assert undeclared_routes(api.app) == []
        assert {key: perm for key, perm in table.items() if key[1].startswith(BASE)} == {
            ("POST", f"{BASE}/proposals"): "external_inference.request",
            ("POST", f"{BASE}/preview"): "external_inference.request",
            ("POST", f"{BASE}/authorizations"): "external_inference.request",
            ("POST", f"{BASE}/transmit"): "external_inference.request",
            ("GET", f"{BASE}/authorizations/{{approval_id}}"): "external_inference.read",
            ("GET", f"{BASE}/transmissions/{{record_id}}"): "external_inference.read",
        }

    def test_openapi_lists_the_external_routes(self, api: Api) -> None:
        r = api.client.get("/v1/openapi.json", headers=api.headers(api.admin_token))
        assert r.status_code == 200
        paths = r.json()["paths"]
        for step in STEPS:
            assert set(paths[f"{BASE}/{step}"]) == {"post"}, step
        assert set(paths[f"{BASE}/authorizations/{{approval_id}}"]) == {"get"}
        assert set(paths[f"{BASE}/transmissions/{{record_id}}"]) == {"get"}


class TestWriteGate:
    @pytest.mark.parametrize("step", STEPS)
    def test_engaged_writes_switch_blocks_every_step(self, enabled: Api, step: str) -> None:
        h = enabled.headers(enabled.admin_token)
        body = {"capabilities": ["writes"], "reason": "drill"}
        assert enabled.client.post("/v1/killswitch/engage", json=body, headers=h).status_code == 200
        r = post(
            enabled,
            step,
            enabled.admin_token,
            step_body(step, made_up_proposal(enabled.admin.actor_id)),
        )
        assert r.status_code == 503
        assert r.json()["error"] == "writes_blocked"
        assert enabled.audit_records("inference.external.") == []


class TestEnabledWithoutTransport:
    def test_propose_and_preview_work_and_show_the_exact_payload(self, enabled: Api) -> None:
        proposal = propose(enabled, enabled.admin_token)
        assert proposal["requester_actor_id"] == enabled.admin.actor_id
        assert [item["classification"] for item in proposal["items"]] == ["public", "restricted"]
        r = post(enabled, "preview", enabled.admin_token, {"proposal": proposal})
        assert r.status_code == 200, r.text
        shown = r.json()
        raw = base64.b64decode(shown["payload_base64"])
        assert hashlib.sha256(raw).hexdigest() == shown["payload_sha256"]
        assert len(raw) == shown["payload_bytes"]
        assert MARKER.encode() in raw
        assert b"restricted detail" not in raw
        assert shown["sendable"] is True
        assert shown["kept"] == [{"ref": "evidence:a1", "classification": "public"}]
        assert shown["dropped"] == [
            {
                "ref": "evidence:a2",
                "classification": "restricted",
                "reason": ExternalReason.CLASSIFICATION_NOT_ALLOWED.value,
            }
        ]

    def test_a_preview_with_nothing_sendable_carries_no_payload(self, enabled: Api) -> None:
        items = [dict(proposal_request()["items"][1])]
        proposal = propose(enabled, enabled.admin_token, items=items)
        shown = post(enabled, "preview", enabled.admin_token, {"proposal": proposal}).json()
        assert shown["sendable"] is False
        assert shown["payload_base64"] is None
        assert shown["payload_sha256"] is None
        assert shown["blocked_reason"] == ExternalReason.NOTHING_SENDABLE.value

    def test_authorize_and_transmit_refuse_transport_absent_and_audit_it(
        self, enabled: Api
    ) -> None:
        proposal = propose(enabled, enabled.admin_token)
        expected = {**FORBIDDEN, "reason": GateReason.TRANSPORT_ABSENT.value}
        r = post(enabled, "authorizations", enabled.admin_token, {"proposal": proposal})
        assert r.status_code == 403
        assert r.json() == expected
        r = post(
            enabled,
            "transmit",
            enabled.admin_token,
            {"proposal": proposal, "approval_id": APPROVAL_ID},
        )
        assert r.status_code == 403
        assert r.json() == expected
        assert denied(enabled, "authorize") == ["transport_absent"]
        assert denied(enabled, "transmit") == ["transport_absent"]
        refusal = enabled.audit_records("inference.external.transmit")[-1]
        assert refusal.actor_id == enabled.admin.actor_id
        assert refusal.target == f"external_request:{proposal['request_id']}"
        assert enabled.container.approvals.list_pending() == ()

    def test_a_changed_or_unknown_proposal_is_refused(self, enabled: Api) -> None:
        proposal = propose(enabled, enabled.admin_token)
        changed = {**proposal, "items": [{**proposal["items"][0], "text": "something else"}]}
        r = post(enabled, "preview", enabled.admin_token, {"proposal": changed})
        assert r.status_code == 403
        assert r.json()["reason"] == ExternalReason.PROPOSAL_MISMATCH.value
        unknown = made_up_proposal(enabled.admin.actor_id)
        r = post(enabled, "preview", enabled.admin_token, {"proposal": unknown})
        assert r.status_code == 403
        assert r.json()["reason"] == ExternalReason.PROPOSAL_UNKNOWN.value

    def test_bodies_are_closed_and_errors_do_not_echo_text(self, enabled: Api) -> None:
        body = {**proposal_request(), "requester_actor_id": "act_someone_else"}
        r = post(enabled, "proposals", enabled.admin_token, body)
        assert r.status_code == 422
        assert r.json()["fields"] == ["body.requester_actor_id"]
        bad = proposal_request(items=[{**proposal_request()["items"][0], "ref": MARKER}])
        r = post(enabled, "proposals", enabled.admin_token, bad)
        assert r.status_code == 422
        assert MARKER not in r.text
        assert enabled.audit_records("inference.external.") == []

    def test_an_unresolvable_digest_key_is_reported_missing(self, make_api: ApiFactory) -> None:
        environ = {k: v for k, v in SECRET_ENV.items() if k != "CISO_SECRET_EXTERNAL_DIGEST_KEY"}
        api = make_api(change=external_on, environ=environ)
        assert api.container.readiness().ready is False  # so the fixture made no admin
        assert "external_digest_key_ref (unresolvable)" in api.container.readiness().missing


class TestWithATestTransport:
    """The whole path through the API. The transport is a test double."""

    @pytest.fixture
    def spy(self) -> SpyTransport:
        return SpyTransport()

    @pytest.fixture
    def wired(self, make_api: ApiFactory, spy: SpyTransport) -> Api:
        return make_api(change=external_on, rewire=with_transport(spy))

    def authorized(self, api: Api, token: str) -> tuple[dict[str, Any], dict[str, Any], bytes]:
        proposal = propose(api, token)
        shown = post(api, "preview", token, {"proposal": proposal}).json()
        r = post(api, "authorizations", token, {"proposal": proposal})
        assert r.status_code == 201, r.text
        return proposal, r.json(), base64.b64decode(shown["payload_base64"])

    def test_the_previewed_bytes_are_the_bytes_bound_approved_and_sent(
        self, wired: Api, spy: SpyTransport
    ) -> None:
        requester, token = wired.human("Requester", Role.SECURITY_ADMIN)
        owner, owner_token = wired.human("Owner", Role.SYSTEM_OWNER)
        proposal, authorization, raw = self.authorized(wired, token)
        digest = hashlib.sha256(raw).hexdigest()
        assert authorization["payload_sha256"] == digest
        assert authorization["payload_bytes"] == len(raw)
        assert authorization["requested_by"] == requester.actor_id
        approval_id = authorization["approval_id"]

        seen = wired.client.get(f"/v1/approvals/{approval_id}", headers=wired.headers(owner_token))
        assert seen.status_code == 200
        assert seen.json()["binding"]["payload_sha256"] == digest
        assert seen.json()["requested_by"] == requester.actor_id
        read = wired.client.get(
            f"{BASE}/authorizations/{approval_id}", headers=wired.headers(owner_token)
        )
        assert read.status_code == 200
        assert read.json()["payload_sha256"] == digest

        body = {"proposal": proposal, "approval_id": approval_id}
        early = post(wired, "transmit", token, body)
        assert early.status_code == 403
        assert early.json() == {
            **FORBIDDEN,
            "reason": GateReason.APPROVAL_REFUSED.value,
            "approval_reason": "not_approved",
        }
        assert spy.calls == []

        approve = wired.client.post(
            f"/v1/approvals/{approval_id}/approve", headers=wired.headers(owner_token)
        )
        assert approve.status_code == 200, approve.text
        sent = post(wired, "transmit", token, body)
        assert sent.status_code == 200, sent.text
        assert spy.calls == [("provider-one", "model-large-1", raw)]
        result = sent.json()
        assert result["output"] == {"untrusted": True, "text": "OKAPI-BASALT-42 answer body"}
        record = wired.client.get(
            f"{BASE}/transmissions/{result['record_id']}", headers=wired.headers(owner_token)
        )
        assert record.status_code == 200
        assert record.json()["outcome"] == "sent"
        assert record.json()["payload_sha256"] == digest
        assert record.json()["approver"] == owner.actor_id

        again = post(wired, "transmit", token, body)  # single use
        assert again.status_code == 403
        assert again.json()["approval_reason"] == "already_consumed"
        assert len(spy.calls) == 1

    def test_the_actor_is_the_caller_not_a_field_of_the_body(
        self, wired: Api, spy: SpyTransport
    ) -> None:
        _, token = wired.human("Requester", Role.SECURITY_ADMIN)
        _, other = wired.human("Other admin", Role.SECURITY_ADMIN)
        proposal = propose(wired, token)
        r = post(wired, "authorizations", other, {"proposal": proposal})
        assert r.status_code == 403
        assert r.json()["reason"] == GateReason.NOT_REQUESTER.value
        assert wired.container.approvals.list_pending() == ()

    def test_the_requester_cannot_approve_their_own_external_request(
        self, wired: Api, spy: SpyTransport
    ) -> None:
        _, token = wired.human("Requester", Role.SECURITY_ADMIN, Role.SYSTEM_OWNER)
        _, authorization, _ = self.authorized(wired, token)
        r = wired.client.post(
            f"/v1/approvals/{authorization['approval_id']}/approve", headers=wired.headers(token)
        )
        assert r.status_code == 403
        assert r.json()["reason"] == "self_approval"
        assert spy.calls == []

    def test_a_failed_send_is_502_with_codes_only(self, wired: Api, spy: SpyTransport) -> None:
        _, token = wired.human("Requester", Role.SECURITY_ADMIN)
        _, owner_token = wired.human("Owner", Role.SYSTEM_OWNER)
        proposal, authorization, _ = self.authorized(wired, token)
        approval_id = authorization["approval_id"]
        wired.client.post(
            f"/v1/approvals/{approval_id}/approve", headers=wired.headers(owner_token)
        )
        spy.raises = RuntimeError("upstream said: password=hunter2-very-secret")
        r = post(wired, "transmit", token, {"proposal": proposal, "approval_id": approval_id})
        assert r.status_code == 502
        body = r.json()
        assert body["error"] == "external_transmit_failed"
        assert body["reason"] == "transport_error"
        assert set(body) == {"error", "message", "reason", "record_id"}
        assert "hunter2" not in r.text
        record = wired.client.get(
            f"{BASE}/transmissions/{body['record_id']}", headers=wired.headers(owner_token)
        )
        assert record.json()["outcome"] == "transport_error"
