"""Nothing the agent wrote, typed or ran is kept: logs hold decisions, ids and hashes."""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

import pytest
from tests.plugin.conftest import (
    PLANTED_KEY,
    HookRun,
    Repo,
    git,
    prompt_event,
    run_hook,
    tool_event,
)

pytestmark = pytest.mark.privacy

CWD = str(Path(__file__).resolve().parent)
MARKER = "unique-content-marker-4711"


def _all_logs(data: Path) -> str:
    return "\n".join(p.read_text(encoding="utf-8") for p in data.rglob("*.jsonl"))


def test_logs_hold_no_content_prompt_command_or_secret(
    hook: Callable[..., HookRun], data: Path
) -> None:
    hook(
        tool_event(
            "Write",
            {"file_path": CWD + "/a.py", "content": f'k = "{PLANTED_KEY}"  # {MARKER}\n'},
            CWD,
        )
    )
    hook(tool_event("Bash", {"command": f"echo {MARKER}-cmd {PLANTED_KEY}"}, CWD, use_id="t2"))
    hook(prompt_event(f"{MARKER}-prompt {PLANTED_KEY}", CWD))
    logs = _all_logs(data)
    assert "ciso.plugin.result" in logs
    assert "secret.cloud_access_key" in logs
    for forbidden in (PLANTED_KEY, MARKER):
        assert forbidden not in logs


def test_content_is_recorded_only_as_a_hash(hook: Callable[..., HookRun], data: Path) -> None:
    hook(tool_event("Write", {"file_path": CWD + "/n.txt", "content": f"{MARKER}\n"}, CWD))
    logs = _all_logs(data)
    assert '"content_sha256":"' in logs
    assert MARKER not in logs


def test_secret_in_a_target_path_is_redacted(hook: Callable[..., HookRun], data: Path) -> None:
    secret_path = CWD + "/password=" + "Sup3rS3cretValue!" + "/a.txt"
    hook(tool_event("Write", {"file_path": secret_path, "content": "x\n"}, CWD))
    assert "Sup3rS3cretValue" not in _all_logs(data)


def test_push_denial_names_findings_without_values(repo: Repo, data: Path) -> None:
    git(repo.work, "checkout", "-q", "-b", "feature")
    repo.commit("db.py", f'PASSWORD = "{MARKER}-pw-9Xq"\nKEY = "{PLANTED_KEY}"\n')
    run = run_hook(repo.push_event("git push origin feature"), data)
    assert run.decision == "deny"
    assert "db.py:" in run.message
    for forbidden in (PLANTED_KEY, MARKER):
        assert forbidden not in run.stdout + run.stderr + _all_logs(data)
