"""`POST /v1/changes` and `decide` with a change attached (docs/skill/decision-api.md,
pre-push change upload), through the API test client with the default ruleset."""

from __future__ import annotations

import base64
from typing import Any

import pytest
from tests.api.governance_helpers import SESSION, World, build_world, pre_tool, register_device
from tests.api.helpers import ApiFactory
from tests.app.change_helpers import HEAD, SECRET_DIFF, push_upload, sha

from ciso.app.change_models import MAX_CHANGE_BODY_BYTES
from ciso.common.enums import Role

pytestmark = pytest.mark.unit

PUSH = "git push origin feature"
CLEAN_REPORT = {
    "job_id": "x",
    "checks": [
        {"check_id": "secrets", "status": "passed"},
        {"check_id": "code", "status": "passed"},
        {"check_id": "tests", "status": "passed", "tests": {"passed": 1, "failed": 0, "errors": 0}},
    ],
}


@pytest.fixture
def world(make_api: ApiFactory) -> World:
    return build_world(make_api)


def upload(world: World, body: dict[str, Any], token: str | None = None) -> Any:
    headers = world.api.headers(token or world.device_token)
    return world.api.client.post("/v1/changes", json=body, headers=headers)


def submit(world: World, **changes: Any) -> str:
    r = upload(world, push_upload(**{"session_id": SESSION, **changes}))
    assert r.status_code == 201, r.text
    return str(r.json()["change_id"])


def report_back(world: World, change_id: str, report: dict[str, Any] = CLEAN_REPORT) -> None:
    gov = world.api.container.governance
    result = gov.inspector.from_sandbox_report(report, action_id=change_id)
    gov.changes.record_report(change_id, result)


def decide_with(world: World, change_id: str, head: str = HEAD, command: str = PUSH) -> Any:
    request = pre_tool(world, "Bash", {"command": command})
    request.update({"change_id": change_id, "change_head": head})
    return world.decide(request)


def test_an_upload_answers_201_with_a_change_id(world: World) -> None:
    r = upload(world, push_upload(session_id=SESSION))
    assert r.status_code == 201
    body = r.json()
    assert body["change_id"].startswith("chg_")
    assert body["created"] is True
    assert world.api.audit_records("governance.change.submit")


def test_only_a_device_may_upload(world: World) -> None:
    assert upload(world, push_upload(session_id=SESSION), world.person_token).status_code == 403
    r = world.api.client.post("/v1/changes", json=push_upload(session_id=SESSION))
    assert r.status_code == 401


def test_a_malformed_upload_is_422(world: World) -> None:
    assert upload(world, push_upload(session_id=SESSION, head="HEAD")).status_code == 422
    r = world.api.client.post("/v1/changes", content=b"not json", headers=world.device_headers())
    assert r.status_code == 422


def test_an_upload_over_the_cap_is_413(world: World) -> None:
    headers = {**world.device_headers(), "content-length": str(MAX_CHANGE_BODY_BYTES + 1)}
    r = world.api.client.post("/v1/changes", content=b"{}", headers=headers)
    assert r.status_code == 413


def test_an_unconfigured_store_is_503(make_api: ApiFactory) -> None:
    def unset(settings: Any) -> Any:
        gov = settings.governance.model_copy(update={"change_retention_seconds": None})
        return settings.model_copy(update={"governance": gov})

    world = build_world(make_api, change=unset)
    assert upload(world, push_upload(session_id=SESSION)).status_code == 503


def test_pending_then_the_rules_decide(world: World) -> None:
    change_id = submit(world)
    pending = decide_with(world, change_id)
    assert (pending["verdict"], pending["reason"]) == ("deny", "checks_pending")
    assert "minute" in pending["message"]
    assert "needs_change" not in pending
    report_back(world, change_id)
    done = decide_with(world, change_id)
    # The default ruleset allows a verified person's clean, fully scanned push to a
    # branch that is not protected (rule allow-scanned-push-known-people).
    assert (done["verdict"], done["reason"]) == ("allow", "rule_allow")


def test_a_secret_in_the_change_is_denied(world: World) -> None:
    change_id = submit(world, diff_b64=base64.b64encode(SECRET_DIFF.encode()).decode())
    report_back(world, change_id)
    answer = decide_with(world, change_id)
    assert answer["verdict"] == "deny"
    assert answer["reason"] in {"critical_finding", "rule_deny"}


def test_a_failed_sandbox_run_is_not_inspected(world: World) -> None:
    change_id = submit(world)
    world.api.container.governance.changes.record_failure(change_id)
    answer = decide_with(world, change_id)
    assert (answer["verdict"], answer["reason"]) == ("deny", "inspection_incomplete")


@pytest.mark.parametrize(
    ("change", "code"),
    [
        ({"head": sha("other")}, "change_mismatch"),  # different commits
        ({"command": "git push origin other"}, "change_mismatch"),  # another branch
        ({"change_id": "chg_01JD3Z6B8Q4W5X7Y9Z0A1B2C3D"}, "change_unknown"),
        ({"command": "cd x && git push origin feature"}, "change_not_applicable"),
    ],
)
def test_ids_that_do_not_fit_the_action_are_refused(
    world: World, change: dict[str, str], code: str
) -> None:
    change_id = submit(world)
    report_back(world, change_id)
    args = {"change_id": change_id, "head": HEAD, "command": PUSH, **change}
    answer = decide_with(world, args["change_id"], args["head"], args["command"])
    assert (answer["verdict"], answer["reason"]) == ("deny", "change_refused")
    refusal = world.api.audit_records("governance.pipeline.refuse")[-1]
    assert refusal.details["refusal_code"] == code


def test_another_devices_change_is_refused(world: World) -> None:
    _other_id, other_token = register_device(world.api, "WS-0300")
    r = upload(world, push_upload(session_id=SESSION), other_token)
    assert r.status_code == 201
    answer = decide_with(world, r.json()["change_id"])
    assert answer["reason"] == "change_refused"
    refusal = world.api.audit_records("governance.pipeline.refuse")[-1]
    assert refusal.details["refusal_code"] == "change_foreign"


def test_another_sessions_change_is_refused(world: World) -> None:
    change_id = submit(world, session_id="sess-someone-else")
    report_back(world, change_id)
    assert decide_with(world, change_id)["reason"] == "change_refused"


def test_an_expired_change_is_refused(world: World) -> None:
    change_id = submit(world)
    report_back(world, change_id)
    retention = world.api.container.settings.governance.change_retention_seconds
    assert retention is not None
    world.api.clock.advance(seconds=retention)
    answer = decide_with(world, change_id)
    assert answer["reason"] == "change_refused"


@pytest.mark.parametrize(
    "fields",
    [
        {"change_id": "chg_01JD3Z6B8Q4W5X7Y9Z0A1B2C3D"},  # head missing
        {"change_id": "nope", "change_head": HEAD},
        {"change_id": "chg_01JD3Z6B8Q4W5X7Y9Z0A1B2C3D", "change_head": "HEAD"},
    ],
)
def test_a_malformed_change_reference_is_an_invalid_report(
    world: World, fields: dict[str, str]
) -> None:
    request = pre_tool(world, "Bash", {"command": PUSH})
    request.update(fields)
    answer = world.decide(request)
    assert (answer["verdict"], answer["reason"]) == ("deny", "invalid_report")


def test_a_person_never_sees_the_uploaded_content_in_findings(world: World) -> None:
    change_id = submit(world, diff_b64=base64.b64encode(SECRET_DIFF.encode()).decode())
    report_back(world, change_id)
    decide_with(world, change_id)
    _person, token = world.api.human("Sec Admin", Role.SECURITY_ADMIN)
    r = world.api.client.get("/v1/findings", headers=world.api.headers(token))
    assert r.status_code == 200, r.text
    assert "secret" in r.text  # the finding is there
    assert "AKIA" not in r.text


def test_an_upload_larger_than_the_decide_cap_is_accepted(world: World) -> None:
    """`/v1/changes` has its own cap; the 256 KiB decide cap must not apply to it."""
    big = b"# v2 git bundle\n" + b"p" * (600 * 1024)
    r = upload(world, push_upload(session_id=SESSION, bundle_b64=base64.b64encode(big).decode()))
    assert r.status_code == 201, r.text


def test_a_push_denied_for_an_unknown_person_does_not_ask_for_the_change(world: World) -> None:
    request = pre_tool(world, "Bash", {"command": PUSH})
    request["claims"] = [{"kind": "os_account", "subject": r"CORP\stranger", "verified": False}]
    answer = world.decide(request)
    assert (answer["verdict"], answer["reason"]) == ("deny", "rule_deny")
    assert "needs_change" not in answer
