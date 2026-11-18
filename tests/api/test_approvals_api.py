"""Approval routes (plan T2.9; blueprint 9.5, FR-025; ADR-0016, ADR-0021).

Requests are filed straight on the container's `ApprovalService` (there is no route for
that, which is itself tested); everything else goes through the API with real tokens.
"""

from __future__ import annotations

from datetime import timedelta
from typing import Any

import pytest
from tests.api.helpers import SECRET_ENV, Api

from ciso.api import route_table, undeclared_routes
from ciso.api.deps import STATE_CHANGING
from ciso.approvals import Approval, ApprovalReason, ApprovalStatus
from ciso.common.enums import APPROVER_ROLES, ActorType, Role
from ciso.identity import RoleScope
from ciso.identity.roles import ROLE_TEMPLATES

pytestmark = pytest.mark.policy

FORBIDDEN = {"error": "forbidden", "message": "not permitted"}
BILLING = "app:billing"
PAYROLL = "app:payroll"
ENGAGE = "/v1/killswitch/engage"


def file_request(
    api: Api,
    requested_by: str | None = None,
    requested_by_type: ActorType = ActorType.AGENT,
    roles: tuple[Role, ...] = (Role.SYSTEM_OWNER,),
    target: dict[str, str] | None = None,
) -> Approval:
    """A pending request. By default an agent filed it, so any other human may decide."""
    if requested_by is None:
        requested_by, _ = api.actor("Proposing agent", ActorType.AGENT)
    return api.container.approvals.request(
        subject_kind="action_envelope",
        subject_hash="ab" * 32,
        binding={"envelope_sha256": "cd" * 32},
        requested_by=requested_by,
        requested_by_type=requested_by_type,
        required_roles=roles,
        target=target or {},
    )


def decide(api: Api, record: Approval, token: str, verb: str = "approve", **body: Any) -> Any:
    return api.client.post(
        f"/v1/approvals/{record.approval_id}/{verb}",
        json=body or None,
        headers=api.headers(token),
    )


def status_of(api: Api, record: Approval) -> ApprovalStatus:
    return api.container.approvals.get(record.approval_id).status


class TestDecide:
    def test_the_named_role_approves_and_the_grant_is_audited(self, api: Api) -> None:
        owner, token = api.human("Owner", Role.SYSTEM_OWNER)
        record = file_request(api)
        r = decide(api, record, token, note="reviewed the diff")
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["status"] == "approved"
        assert body["decided_by"] == owner.actor_id
        assert body["decided_roles"] == ["system_owner"]
        assert body["decision_note"] == "reviewed the diff"
        assert body["approver_credential_issuer"] == api.admin.actor_id
        grants = [
            rec for rec in api.audit_records("approval.approve") if rec.outcome.value == "success"
        ]
        assert [(rec.id, rec.actor_id) for rec in grants] == [
            (body["decision_audit_ref"], owner.actor_id)
        ]

    def test_the_named_role_rejects_without_a_body(self, api: Api) -> None:
        owner, token = api.human("Owner", Role.SYSTEM_OWNER)
        record = file_request(api)
        r = decide(api, record, token, "reject")
        assert r.status_code == 200, r.text
        assert r.json()["status"] == "rejected"
        assert r.json()["decided_by"] == owner.actor_id
        assert status_of(api, record) is ApprovalStatus.REJECTED

    @pytest.mark.parametrize("verb", ["approve", "reject"])
    @pytest.mark.parametrize(
        ("actor_type", "roles"),
        [
            (ActorType.HUMAN, (Role.EMPLOYEE,)),
            (ActorType.HUMAN, (Role.AUDITOR,)),
            (ActorType.HUMAN, (Role.SECURITY_ADMIN,)),
            (ActorType.AGENT, ()),
            (ActorType.SERVICE, ()),
        ],
    )
    def test_other_roles_and_non_humans_are_refused(
        self, api: Api, verb: str, actor_type: ActorType, roles: tuple[Role, ...]
    ) -> None:
        _, token = api.actor("Someone", actor_type, *roles)
        record = file_request(api)
        r = decide(api, record, token, verb)
        assert r.status_code == 403
        assert r.json() == FORBIDDEN
        assert status_of(api, record) is ApprovalStatus.PENDING

    def test_no_token_is_401(self, api: Api) -> None:
        record = file_request(api)
        r = api.client.post(f"/v1/approvals/{record.approval_id}/approve")
        assert r.status_code == 401
        assert status_of(api, record) is ApprovalStatus.PENDING

    def test_the_requester_cannot_approve_their_own_request(self, api: Api) -> None:
        owner, token = api.human("Owner", Role.SYSTEM_OWNER)
        record = file_request(api, owner.actor_id, ActorType.HUMAN)
        r = decide(api, record, token)
        assert r.status_code == 403
        assert r.json() == {**FORBIDDEN, "reason": ApprovalReason.SELF_APPROVAL.value}
        assert status_of(api, record) is ApprovalStatus.PENDING
        # A different holder of the role is accepted, so the refusal was about the person.
        _, other_token = api.human("Second owner", Role.SYSTEM_OWNER)
        assert decide(api, record, other_token).status_code == 200

    def test_an_approver_whose_token_the_requester_minted_is_refused(self, api: Api) -> None:
        # The first admin files the request and also minted the owner's token.
        _, token = api.human("Owner", Role.SYSTEM_OWNER, issuer=api.admin)
        record = file_request(api, api.admin.actor_id, ActorType.HUMAN)
        r = decide(api, record, token)
        assert r.status_code == 403
        assert r.json()["reason"] == ApprovalReason.CREDENTIAL_ISSUED_BY_REQUESTER.value
        assert status_of(api, record) is ApprovalStatus.PENDING
        # The same owner with a token somebody else minted is accepted.
        second_admin, _ = api.human("Second admin", Role.SECURITY_ADMIN)
        _, clean = api.human("Other owner", Role.SYSTEM_OWNER, issuer=second_admin)
        assert decide(api, record, clean).status_code == 200

    def test_the_service_applies_the_role_rule_after_the_route_check(self, api: Api) -> None:
        # Holds approval.decide (route passes) but not the role this request names.
        _, token = api.human("Risk owner", Role.EXECUTIVE_RISK_OWNER)
        record = file_request(api, roles=(Role.SYSTEM_OWNER,))
        r = decide(api, record, token)
        assert r.status_code == 403
        assert r.json() == {**FORBIDDEN, "reason": ApprovalReason.APPROVER_LACKS_ROLE.value}
        assert status_of(api, record) is ApprovalStatus.PENDING

    def test_a_decided_request_cannot_be_decided_again(self, api: Api) -> None:
        _, token = api.human("Owner", Role.SYSTEM_OWNER)
        record = file_request(api)
        assert decide(api, record, token, "reject").status_code == 200
        r = decide(api, record, token)
        assert r.status_code == 409
        assert r.json()["reason"] == ApprovalReason.ALREADY_DECIDED.value
        assert status_of(api, record) is ApprovalStatus.REJECTED

    def test_an_expired_request_cannot_be_approved(self, api: Api) -> None:
        _, token = api.human("Owner", Role.SYSTEM_OWNER)
        record = file_request(api)
        api.clock.advance(timedelta(hours=2))  # past the provisional one hour
        r = decide(api, record, token)
        assert r.status_code == 403
        assert r.json()["reason"] == ApprovalReason.EXPIRED.value

    def test_unknown_approval_is_404_for_a_decider_and_403_for_others(self, api: Api) -> None:
        _, owner = api.human("Owner", Role.SYSTEM_OWNER)
        _, employee = api.actor("Employee", ActorType.HUMAN, Role.EMPLOYEE)
        path = "/v1/approvals/apr_00000000000000000000000000/approve"
        r = api.client.post(path, headers=api.headers(owner))
        assert r.status_code == 404
        assert r.json() == {"error": "not_found", "message": "not found", "reason": "not_found"}
        assert api.client.post(path, headers=api.headers(employee)).status_code == 403

    def test_the_note_is_validated_and_redacted(self, api: Api) -> None:
        _, token = api.human("Owner", Role.SYSTEM_OWNER)
        record = file_request(api)
        r = decide(api, record, token, note="ok", force=True)
        assert r.status_code == 422
        assert r.json()["fields"] == ["body.force"]
        r = decide(api, record, token, note="line one\nline two")
        assert r.status_code == 422
        assert r.json()["reason"] == ApprovalReason.INVALID_TEXT.value
        assert status_of(api, record) is ApprovalStatus.PENDING
        secret = SECRET_ENV["CISO_SECRET_KILLSWITCH_KEY"]
        r = decide(api, record, token, note=f"key is {secret} today")
        assert r.status_code == 200, r.text
        assert secret not in r.text
        stored = api.container.approvals.get(record.approval_id).decision_note
        assert stored.startswith("key is ")
        assert stored.endswith(" today")
        assert secret not in stored

    def test_exception_text_never_reaches_the_client(self, api: Api) -> None:
        owner, token = api.human("Owner", Role.SYSTEM_OWNER)
        record = file_request(api, owner.actor_id, ActorType.HUMAN)
        r = decide(api, record, token)
        assert set(r.json()) == {"error", "message", "reason"}
        assert r.json()["reason"] in {reason.value for reason in ApprovalReason}
        assert "Approval" not in r.text
        assert record.approval_id not in r.text


class TestScope:
    def test_a_scoped_owner_decides_inside_the_grant_only(self, api: Api) -> None:
        scope = RoleScope(systems=frozenset({BILLING}))
        _, token = api.human("Billing owner", Role.SYSTEM_OWNER, scope=scope)
        outside = file_request(api, target={"system": PAYROLL})
        inside = file_request(api, target={"system": BILLING})
        unknown = file_request(api)  # no target attributes: only an unscoped grant reaches it

        for record in (outside, unknown):
            r = decide(api, record, token)
            assert r.status_code == 403, r.text
            assert status_of(api, record) is ApprovalStatus.PENDING
            assert decide(api, record, token, "reject").status_code == 403
            read = api.client.get(f"/v1/approvals/{record.approval_id}", headers=api.headers(token))
            assert read.status_code == 403
        read = api.client.get(f"/v1/approvals/{inside.approval_id}", headers=api.headers(token))
        assert read.status_code == 200, read.text
        assert read.json()["target"] == {"system": BILLING}
        listed = api.client.get("/v1/approvals", headers=api.headers(token))
        assert listed.status_code == 403  # the list is platform-wide
        r = decide(api, inside, token)
        assert r.status_code == 200, r.text
        assert r.json()["decided_roles"] == ["system_owner"]

    def test_the_service_checks_scope_even_when_another_role_passes_the_route(
        self, api: Api
    ) -> None:
        # Unscoped risk owner (reaches every target at the route) plus an owner grant
        # that does not reach payroll: the request names system_owner, so it is refused.
        principal, token = api.human("Risk owner", Role.EXECUTIVE_RISK_OWNER)
        api.container.identity.assign_role(
            api.admin,
            principal.actor_id,
            Role.SYSTEM_OWNER,
            scope=RoleScope(systems=frozenset({BILLING})),
        )
        outside = file_request(api, roles=(Role.SYSTEM_OWNER,), target={"system": PAYROLL})
        r = decide(api, outside, token)
        assert r.status_code == 403
        assert r.json()["reason"] == ApprovalReason.APPROVER_LACKS_ROLE.value
        inside = file_request(api, roles=(Role.SYSTEM_OWNER,), target={"system": BILLING})
        assert decide(api, inside, token).status_code == 200


class TestWriteGate:
    def test_engaged_writes_switch_blocks_approve_and_reject(self, api: Api) -> None:
        _, token = api.human("Owner", Role.SYSTEM_OWNER)
        record = file_request(api)
        body = {"capabilities": ["writes"], "reason": "drill"}
        engaged = api.client.post(ENGAGE, json=body, headers=api.headers(api.admin_token))
        assert engaged.status_code == 200
        for verb in ("approve", "reject"):
            r = decide(api, record, token, verb)
            assert r.status_code == 503
            assert r.json()["error"] == "writes_blocked"
        assert status_of(api, record) is ApprovalStatus.PENDING
        read = api.client.get(f"/v1/approvals/{record.approval_id}", headers=api.headers(token))
        assert read.status_code == 200  # reading stays available
        released = api.client.post(
            "/v1/killswitch/release", json=body, headers=api.headers(api.admin_token)
        )
        assert released.status_code == 200
        assert decide(api, record, token).status_code == 200


class TestReads:
    def test_deciders_admin_and_auditor_read_and_others_do_not(self, api: Api) -> None:
        record = file_request(api)
        one = f"/v1/approvals/{record.approval_id}"
        for role in (Role.SYSTEM_OWNER, Role.EXECUTIVE_RISK_OWNER, Role.AUDITOR):
            _, token = api.human(role.value, role)
            listed = api.client.get("/v1/approvals", headers=api.headers(token))
            assert listed.status_code == 200, role
            assert [a["approval_id"] for a in listed.json()["approvals"]] == [record.approval_id]
            assert listed.json()["truncated"] is False
            got = api.client.get(one, headers=api.headers(token))
            assert got.status_code == 200, role
            assert got.json()["status"] == "pending"
            assert got.json()["binding"] == {"envelope_sha256": "cd" * 32}
        admin = api.headers(api.admin_token)
        assert api.client.get("/v1/approvals", headers=admin).status_code == 200
        for actor_type, roles in ((ActorType.HUMAN, (Role.EMPLOYEE,)), (ActorType.AGENT, ())):
            _, token = api.actor("Other", actor_type, *roles)
            assert api.client.get("/v1/approvals", headers=api.headers(token)).status_code == 403
            assert api.client.get(one, headers=api.headers(token)).status_code == 403

    def test_an_auditor_reads_but_cannot_decide(self, api: Api) -> None:
        _, token = api.human("Auditor", Role.AUDITOR)
        record = file_request(api)
        assert decide(api, record, token).status_code == 403
        assert status_of(api, record) is ApprovalStatus.PENDING

    def test_role_filter_limit_and_validation(self, api: Api) -> None:
        h = api.headers(api.admin_token)
        agent, _ = api.actor("Proposing agent", ActorType.AGENT)
        first = file_request(api, agent, roles=(Role.SYSTEM_OWNER,))
        api.clock.advance(timedelta(seconds=1))
        second = file_request(api, agent, roles=(Role.EXECUTIVE_RISK_OWNER,))

        def ids(**params: Any) -> list[str]:
            r = api.client.get("/v1/approvals", params=params, headers=h)
            assert r.status_code == 200, r.text
            return [a["approval_id"] for a in r.json()["approvals"]]

        assert ids() == [first.approval_id, second.approval_id]
        assert ids(role="executive_risk_owner") == [second.approval_id]
        assert ids(role="auditor") == []
        page = api.client.get("/v1/approvals", params={"limit": 1}, headers=h).json()
        assert [a["approval_id"] for a in page["approvals"]] == [first.approval_id]
        assert page["truncated"] is True
        for bad in ({"role": "root"}, {"limit": 0}, {"limit": 501}, {"bogus": "1"}):
            assert api.client.get("/v1/approvals", params=bad, headers=h).status_code == 422, bad

    def test_unknown_id_is_404(self, api: Api) -> None:
        r = api.client.get("/v1/approvals/apr_nope", headers=api.headers(api.admin_token))
        assert r.status_code == 404


class TestRouteTable:
    def test_every_approval_route_declares_its_permission(self, api: Api) -> None:
        table = route_table(api.app)
        assert undeclared_routes(api.app) == []
        assert {key: perm for key, perm in table.items() if "/v1/approvals" in key[1]} == {
            ("GET", "/v1/approvals"): "approval.read",
            ("GET", "/v1/approvals/{approval_id}"): "approval.read",
            ("POST", "/v1/approvals/{approval_id}/approve"): "approval.decide",
            ("POST", "/v1/approvals/{approval_id}/reject"): "approval.decide",
        }

    def test_the_new_permissions_sit_with_the_named_roles(self) -> None:
        holders = {
            name: {tpl.role for tpl in ROLE_TEMPLATES if name in tpl.permissions}
            for name in ("approval.read", "external_inference.request", "external_inference.read")
        }
        admin, owner = Role.SECURITY_ADMIN, Role.SYSTEM_OWNER
        assert holders == {
            "approval.read": {admin, owner, Role.EXECUTIVE_RISK_OWNER, Role.AUDITOR},
            "external_inference.request": {admin, owner},
            "external_inference.read": {admin, owner, Role.AUDITOR},
        }
        deciders = {tpl.role for tpl in ROLE_TEMPLATES if "approval.decide" in tpl.permissions}
        assert deciders == set(APPROVER_ROLES)

    def test_no_route_files_an_approval_request(self, api: Api) -> None:
        h = api.headers(api.admin_token)
        body = {"subject_kind": "action_envelope", "subject_hash": "ab" * 32}
        assert api.client.post("/v1/approvals", json=body, headers=h).status_code == 405
        assert api.client.put("/v1/approvals", json=body, headers=h).status_code == 405
        assert api.container.approvals.list_pending() == ()

    def test_no_state_changing_route_lives_under_policy(self, api: Api) -> None:
        table = route_table(api.app)
        under_policy = [key for key in table if key[1].startswith("/v1/policy")]
        assert under_policy == [("GET", "/v1/policy/ruleset")]
        assert [key for key in under_policy if key[0] in STATE_CHANGING] == []
        h = api.headers(api.admin_token)
        for method in sorted(STATE_CHANGING):
            r = api.client.request(method, "/v1/policy/ruleset", json={}, headers=h)
            assert r.status_code == 405, method

    def test_openapi_lists_the_approval_routes(self, api: Api) -> None:
        r = api.client.get("/v1/openapi.json", headers=api.headers(api.admin_token))
        assert r.status_code == 200
        paths = r.json()["paths"]
        assert set(paths["/v1/approvals"]) == {"get"}
        assert set(paths["/v1/approvals/{approval_id}"]) == {"get"}
        assert set(paths["/v1/approvals/{approval_id}/approve"]) == {"post"}
        assert set(paths["/v1/approvals/{approval_id}/reject"]) == {"post"}
