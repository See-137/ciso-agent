"""Spec S5 end to end through the API test client: a push is held until its change is
uploaded and scanned by a fake sandbox (an HTTP mock behind the real sandbox client and
worker); then a clean push to a feature branch is allowed, a push to a protected branch is
asked, and a push whose tests fail or that carries a secret is denied."""

from __future__ import annotations

import base64
import json
from pathlib import Path
from typing import Any

import httpx
import pytest
from tests.api.governance_helpers import SANDBOX_TOKEN, SESSION, World, build_world, pre_tool
from tests.api.helpers import ApiFactory
from tests.app.change_helpers import HEAD, SECRET_DIFF, push_upload
from tests.e2e.prepush_ruleset import write_ruleset

from ciso.app.sandbox_client import SandboxClient
from ciso.app.sandbox_worker import SandboxWorker

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


@pytest.fixture
def world(make_api: ApiFactory, tmp_path: Path) -> World:
    ruleset = write_ruleset(tmp_path / "ruleset.json")

    def scanned(settings: Any) -> Any:
        gov = settings.governance.model_copy(update={"ruleset_path": ruleset})
        return settings.model_copy(update={"governance": gov})

    built = build_world(make_api, change=scanned)
    assert built.api.container.governance.engine.ruleset.deny_all is False
    return built


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


def test_a_clean_push_is_held_then_allowed(world: World, sandbox: FakeSandbox) -> None:
    held, request = push(world, "git push origin feature")
    assert (held["verdict"], held["reason"]) == ("deny", "checks_pending")
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
    findings = world.api.client.get("/v1/findings", headers=world.admin_headers())
    assert "test_failure" in findings.text


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
