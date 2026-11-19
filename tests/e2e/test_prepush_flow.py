"""Spec S5 end to end through the API test client: a push is held until its change is
uploaded and scanned by a fake sandbox (an HTTP mock behind the real sandbox client and
worker); then a clean push to a feature branch is allowed, a push to a protected branch is
asked, and a push whose tests fail or that carries a secret is denied.

Runs on the packaged default's rules (governance-default-2026.11.19-3 has the pre-push
rules; the test settings load the deployment ruleset derived from it). The held steps
(the first ask, `checks_pending`) make no finding; the final verdict does. Only a
verified person (assigned to the reporting device) is allowed; a declared one is asked.
"""

from __future__ import annotations

import base64
import json
from typing import Any

import httpx
import pytest
from tests.api.governance_helpers import SANDBOX_TOKEN, SESSION, World, build_world, pre_tool
from tests.api.helpers import ApiFactory
from tests.app.change_helpers import HEAD, SECRET_DIFF, push_upload

from ciso.app.sandbox_client import SandboxClient
from ciso.app.sandbox_worker import SandboxWorker
from ciso.governance import load_default_ruleset

pytestmark = pytest.mark.unit


class FakeSandbox:
    """The sandbox service's `POST /v1/jobs`, answering clean or with failed tests."""

    def __init__(self) -> None:
        self.failed_tests = 0
        self.jobs: list[dict[str, Any]] = []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        if request.headers.get("authorization") != "Bearer " + SANDBOX_TOKEN:
            return httpx.Response(401)
        job = json.loads(request.content)
        self.jobs.append(job)
        tests = {"passed": 4, "failed": self.failed_tests, "errors": 0}
        return httpx.Response(
            200,
            json={
                "job_id": job["job_id"],
                "checks": [
                    {"check_id": "secrets", "status": "passed"},
                    {"check_id": "code", "status": "passed"},
                    {
                        "check_id": "tests",
                        "status": "failed" if self.failed_tests else "passed",
                        "tests": tests,
                    },
                ],
            },
        )


def _declared_world(make_api: ApiFactory) -> World:
    built = build_world(make_api, assign=False)
    ruleset = built.api.container.governance.engine.ruleset
    assert ruleset.deny_all is False
    # The test settings name the deployment ruleset, which is derived from the default
    # (config/derive_governance_ruleset.py): the same rules, no e2e-only additions.
    default = load_default_ruleset().document
    assert ruleset.document is not None
    assert default is not None
    assert ruleset.document.rules == default.rules
    assert "allow-scanned-push-known-people" in {r.id for r in default.rules}
    return built


@pytest.fixture
def declared_world(make_api: ApiFactory) -> World:
    """The person is bound to the OS account but not assigned to the device: declared."""
    return _declared_world(make_api)


@pytest.fixture
def world(make_api: ApiFactory) -> World:
    """The person is assigned to the reporting device, so the session is verified (only
    a verified person's push can be allowed: review H4)."""
    built = _declared_world(make_api)
    built.api.container.governance.agent_admin.assign_device(
        built.api.admin, built.device_id, [f"actor:{built.person_id}"]
    )
    return built


def findings(world: World) -> list[dict[str, Any]]:
    r = world.api.client.get("/v1/findings", headers=world.admin_headers())
    assert r.status_code == 200, r.text
    items: list[dict[str, Any]] = r.json()["findings"]
    return items


@pytest.fixture
def sandbox() -> FakeSandbox:
    return FakeSandbox()


def worker(world: World, sandbox: FakeSandbox) -> SandboxWorker:
    container = world.api.container
    gov = container.settings.governance
    client = SandboxClient(
        url=gov.sandbox_url,
        token_ref=gov.sandbox_token_ref,
        secrets=container.secret_store,
        timeout_seconds=gov.sandbox_timeout_seconds,
        transport=httpx.MockTransport(sandbox),
    )
    return SandboxWorker(
        queue=container.queue,
        changes=container.governance.changes,
        client=client,
        inspector=container.governance.inspector,
        required_checks=gov.required_sandbox_checks,
        worker_id="wrk-e2e",
        poll_seconds=gov.worker_poll_seconds,
    )


def push(world: World, command: str, diff: str | None = None) -> tuple[dict[str, Any], Any]:
    """Ask, upload what `needs_change` names, ask again. Returns (second answer, request)."""
    request = pre_tool(world, "Bash", {"command": command})
    first = world.decide(request)
    assert (first["verdict"], first["reason"]) == ("deny", "inspection_incomplete")
    needs = first["needs_change"]
    fields: dict[str, Any] = {"session_id": SESSION, **{k: needs.get(k) for k in
                              ("remote", "branch", "source")}}  # fmt: skip
    if diff is not None:
        fields["diff_b64"] = base64.b64encode(diff.encode()).decode()
    r = world.api.client.post(
        "/v1/changes", json=push_upload(**fields), headers=world.device_headers()
    )
    assert r.status_code == 201, r.text
    request.update({"change_id": r.json()["change_id"], "change_head": HEAD})
    return world.decide(request), request


def test_a_clean_push_of_a_verified_person_is_held_then_allowed(
    world: World, sandbox: FakeSandbox
) -> None:
    held, request = push(world, "git push origin feature")
    assert (held["verdict"], held["reason"]) == ("deny", "checks_pending")
    assert findings(world) == []  # the first ask and checks_pending are protocol steps
    assert worker(world, sandbox).run_once() is True
    assert sandbox.jobs[0]["archive_format"] == "git_bundle"
    assert sandbox.jobs[0]["checks"] == ["secrets", "code", "tests"]
    request["payload"]["tool_use_id"] = world.next_id("toolu")  # the engineer retries
    retried = world.decide(request)
    assert (retried["verdict"], retried["reason"]) == ("allow", "rule_allow")
    verify = world.api.client.get("/v1/audit/verify", headers=world.admin_headers())
    assert verify.status_code == 200
    assert verify.json()["status"] == "ok"


def test_a_clean_push_to_a_protected_branch_is_asked(world: World, sandbox: FakeSandbox) -> None:
    _held, request = push(world, "git push origin main")
    worker(world, sandbox).run_once()
    answer = world.decide(request)
    assert (answer["verdict"], answer["reason"]) == ("ask", "rule_ask")


def test_a_push_whose_tests_fail_is_denied(world: World, sandbox: FakeSandbox) -> None:
    sandbox.failed_tests = 2
    _held, request = push(world, "git push origin feature")
    worker(world, sandbox).run_once()
    answer = world.decide(request)
    assert (answer["verdict"], answer["reason"]) == ("deny", "rule_deny")
    keys = {item["check_key"] for item in findings(world)}
    assert "decision.deny.rule_deny" in keys
    assert any("test_failure" in key for key in keys)


def test_a_push_with_a_planted_secret_is_denied(world: World, sandbox: FakeSandbox) -> None:
    _held, request = push(world, "git push origin feature", diff=SECRET_DIFF)
    worker(world, sandbox).run_once()
    answer = world.decide(request)
    assert answer["verdict"] == "deny"
    assert answer["reason"] in {"critical_finding", "rule_deny"}


def test_a_sandbox_that_is_down_never_lets_the_push_through(world: World) -> None:
    def down(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("refused", request=request)

    _held, request = push(world, "git push origin feature")
    broken = worker(world, FakeSandbox())
    broken._client = SandboxClient(
        url="http://127.0.0.1:8790",
        token_ref="secret://sandbox_token",
        secrets=world.api.container.secret_store,
        timeout_seconds=5.0,
        transport=httpx.MockTransport(down),
    )
    broken.run_once()
    assert world.decide(request)["reason"] == "checks_pending"


def test_a_clean_push_of_a_declared_person_is_asked_not_allowed(
    declared_world: World, sandbox: FakeSandbox
) -> None:
    _held, request = push(declared_world, "git push origin feature")
    worker(declared_world, sandbox).run_once()
    answer = declared_world.decide(request)
    assert (answer["verdict"], answer["reason"]) == ("ask", "default_ask")
