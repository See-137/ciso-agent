"""The funnel of docs/skill/spec-draft.md section 4, end to end through the API test client
(no real assistant): a registered device reports hook events for a person's approved
agent; an ordinary read is allowed, a force push and a write to the assistant's own MCP
configuration are denied, a finding and an alert file exist, the person and the admin
see the finding, and the audit log verifies."""

from __future__ import annotations

import json
import statistics
import sys
import time
from pathlib import Path

import pytest
from tests.api.governance_helpers import (
    World,
    build_world,
    envelope,
    post_tool,
    pre_tool,
)
from tests.api.helpers import ApiFactory

from ciso.app.governance_pipeline import PUSH_HELD_NOTE
from ciso.app.governance_wiring import ALERTS_DIR
from ciso.common.enums import Role

pytestmark = pytest.mark.unit

PACK_SOURCE = (
    Path(__file__).resolve().parents[2]
    / "integrations"
    / "claude_code"
    / "managed"
    / "pack_source.json"
)


@pytest.fixture
def world(make_api: ApiFactory) -> World:
    return build_world(make_api)


def _session_start(world: World) -> dict[str, object]:
    return envelope(
        {"session_id": "sess-e2e-1", "cwd": "C:\\work\\repo", "hook_event_name": "SessionStart",
         "source": "startup"}
    )  # fmt: skip


def _prompt(world: World) -> dict[str, object]:
    return envelope(
        {"session_id": "sess-e2e-1", "cwd": "C:\\work\\repo",
         "hook_event_name": "UserPromptSubmit", "prompt_id": world.next_id("prompt"),
         "prompt": "list the files"}
    )  # fmt: skip


def _reason_codes(world: World, decision_id: str) -> list[str]:
    for record in world.api.audit_records("governance.decide"):
        if record.details["decision_id"] == decision_id:
            return list(record.details["reason_codes"])
    raise AssertionError("decision not audited")


def test_the_funnel(world: World) -> None:
    api = world.api
    assert world.decide(_session_start(world))["verdict"] == "allow"
    assert world.decide(_prompt(world))["verdict"] == "allow"

    read = world.decide(pre_tool(world, "Bash", {"command": "ls -la"}))
    assert (read["verdict"], read["reason"]) == ("allow", "rule_allow")

    push = world.decide(pre_tool(world, "Bash", {"command": "git push --force origin main"}))
    assert (push["verdict"], push["reason"]) == ("deny", "rule_deny")
    assert push["message"].endswith(PUSH_HELD_NOTE)

    mcp = world.decide(
        pre_tool(world, "Write", {"file_path": "C:\\work\\repo\\.mcp.json", "content": "{}"})
    )
    assert mcp["verdict"] == "deny"
    assert "agent_config_change" in _reason_codes(world, mcp["decision_id"])

    claude_md = world.decide(
        pre_tool(world, "Edit", {"file_path": "C:\\work\\repo\\CLAUDE.md",
                                 "old_string": "a", "new_string": "b"})
    )  # fmt: skip
    assert claude_md["verdict"] == "deny"
    assert "agent_config_change" in _reason_codes(world, claude_md["decision_id"])

    after = api.client.post("/v1/activity", json=post_tool(world, "Bash", {"command": "ls -la"}),
                            headers=world.device_headers())  # fmt: skip
    assert after.status_code == 202

    # Findings: the push and the MCP write, attributed to the person and the agent.
    admin_h = world.admin_headers()
    listed = api.client.get("/v1/findings", headers=admin_h).json()["findings"]
    keys = {f["check_key"] for f in listed}
    assert "decision.deny.rule_deny" in keys
    assert f"decision.deny.{mcp['reason']}" in keys
    person_ref = f"actor:{world.person_id}"
    assert {f["person_ref"] for f in listed} == {person_ref}
    assert {f["agent_ref"] for f in listed} == {f"agent:{world.agent_id}"}
    decision_ids = {f["decision_id"] for f in listed}
    assert {push["decision_id"], mcp["decision_id"]} <= decision_ids

    # Alerts: one file per deny, holding ids and fixed text only.
    alerts_dir = api.container.settings.data_dir / ALERTS_DIR
    files = sorted(alerts_dir.glob("alt_*.json"))
    assert files
    payloads = [json.loads(path.read_text(encoding="ascii")) for path in files]
    assert push["decision_id"] in {p["decision_id"] for p in payloads}
    assert all("git push" not in path.read_text(encoding="ascii") for path in files)
    alerts = api.client.get("/v1/alerts", headers=admin_h).json()["alerts"]
    assert len(alerts) == len(files)

    # The person sees their own findings and may acknowledge one; the admin resolves it.
    person_h = api.headers(world.person_token)
    mine = api.client.get("/v1/findings/mine", headers=person_h).json()["findings"]
    assert {f["finding_id"] for f in mine} == {f["finding_id"] for f in listed}
    first = mine[0]["finding_id"]
    r = api.client.post(f"/v1/findings/{first}/acknowledge", headers=person_h)
    assert r.status_code == 200
    assert api.client.post(f"/v1/findings/{first}/resolve", headers=person_h).status_code == 403
    assert api.client.post(f"/v1/findings/{first}/resolve", headers=admin_h).status_code == 200

    # Accepting a risk needs an approval somebody granted.
    second = next(f["finding_id"] for f in listed if f["finding_id"] != first)
    r = api.client.post(f"/v1/findings/{second}/accept-risk", json={"approval_id": "apr_nope"},
                        headers=admin_h)  # fmt: skip
    assert (r.status_code, r.json()["error"]) == (409, "risk_acceptance_refused")

    # The session is tied to the person and the agent.
    session = api.client.get("/v1/sessions/sess-e2e-1", headers=admin_h).json()
    assert (session["person_ref"], session["agent_ref"]) == (person_ref, f"agent:{world.agent_id}")

    # Everything above is in the audit log, and the log verifies.
    verify = api.client.get("/v1/audit/verify", headers=admin_h).json()
    assert verify["status"] == "ok"
    decided = api.audit_records("governance.decide")
    assert {push["decision_id"], mcp["decision_id"], read["decision_id"]} <= {
        r.details["decision_id"] for r in decided
    }


def test_the_operator_may_suspend_their_agent_and_its_actions_stop(world: World) -> None:
    api = world.api
    person_h = api.headers(world.person_token)
    r = api.client.post(f"/v1/agents/{world.agent_id}/suspend", headers=person_h)
    assert r.status_code == 200, r.text
    assert r.json()["status"] == "suspended"
    assert (
        api.client.post(f"/v1/agents/{world.agent_id}/unsuspend", headers=person_h).status_code
        == 403
    )
    answer = world.decide(pre_tool(world, "Bash", {"command": "echo hi > out.txt"}))
    assert answer["verdict"] == "deny"


def test_an_unknown_agent_is_a_coverage_gap_and_is_not_trusted(make_api: ApiFactory) -> None:
    world = build_world(make_api)
    api = world.api
    other = envelope(
        {"session_id": "sess-other", "cwd": "C:\\x", "hook_event_name": "PreToolUse",
         "tool_name": "Bash", "tool_input": {"command": "ls"}, "tool_use_id": "toolu_x"},
        device="WS-9999",
    )  # fmt: skip
    answer = world.decide(other)
    assert answer["verdict"] != "allow"
    gaps = api.client.get("/v1/agents/coverage-gaps", headers=world.admin_headers()).json()
    assert [a["agent_class"] for a in gaps["agents"]] == ["unknown"]


def test_an_auditor_reads_but_cannot_change(world: World) -> None:
    api = world.api
    _, auditor = api.human("Aud", Role.AUDITOR)
    h = api.headers(auditor)
    assert api.client.get("/v1/agents", headers=h).status_code == 200
    assert api.client.get("/v1/findings", headers=h).status_code == 200
    assert api.client.post(f"/v1/agents/{world.agent_id}/retire", headers=h).status_code == 403


def test_decide_latency_in_process(world: World) -> None:
    """Median wall time of one decide call through the pipeline (no HTTP), measured here.
    The bound is the provisional decide timeout the managed pack gives the hook client,
    read from the pack source: a decision slower than that would block every action."""
    env = json.loads(PACK_SOURCE.read_text(encoding="utf-8"))["policy"]["env"]
    budget = float(env["AIGOV_DECIDE_TIMEOUT_SECONDS"])
    pipeline = world.api.container.governance.pipeline
    timings = []
    for index in range(40):
        command = "ls -la" if index % 2 else "git push origin feature"
        request = pre_tool(world, "Bash", {"command": command})
        start = time.perf_counter()
        answer = pipeline.decide(request, device_actor_id=world.device_id)
        timings.append(time.perf_counter() - start)
        assert answer.decision_id.startswith("dec_")
    median = statistics.median(timings)
    slowest = max(timings) * 1000
    sys.stderr.write(f"decide latency: median {median * 1000:.2f} ms, max {slowest:.2f} ms\n")
    assert median < budget
