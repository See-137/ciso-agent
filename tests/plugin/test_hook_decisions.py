"""The enforcing hook end to end, as Claude Code runs it: decisions, answers, failures."""

from __future__ import annotations

import itertools
import json
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest
from tests.plugin.conftest import (
    PLANTED_KEY,
    HookRun,
    base_env,
    prompt_event,
    run_hook,
    tool_event,
)

pytestmark = pytest.mark.unit

CWD = str(Path(__file__).resolve().parent)


def _records(data: Path) -> list[dict[str, Any]]:
    path = data / "audit" / "decisions.jsonl"
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]


def _results(data: Path) -> list[dict[str, Any]]:
    return [r for r in _records(data) if r.get("type") == "ciso.plugin.result"]


def test_read_only_command_is_allowed_with_no_output(
    hook: Callable[..., HookRun], data: Path
) -> None:
    run = hook(tool_event("Bash", {"command": "git status"}, CWD))
    assert (run.code, run.stdout) == (0, "")
    result = _results(data)[-1]
    assert result["verdict"] == "allow"
    assert result["matched_rule_ids"] == ["allow-read-only-shell-known-people"]


def test_read_tool_is_allowed(hook: Callable[..., HookRun]) -> None:
    assert hook(tool_event("Read", {"file_path": CWD + "/conftest.py"}, CWD)).decision == "allow"


def test_writing_mcp_config_is_denied(hook: Callable[..., HookRun], data: Path) -> None:
    run = hook(tool_event("Write", {"file_path": CWD + "/.mcp.json", "content": "{}"}, CWD))
    assert run.decision == "deny"
    assert "path.assistant_config" in json.dumps(_results(data)[-1]["findings"])
    assert "agent_config_change" in _results(data)[-1]["reason_codes"]


def test_writing_a_planted_secret_is_denied_without_echoing_it(
    hook: Callable[..., HookRun],
) -> None:
    content = f'key = "{PLANTED_KEY}"\n'
    run = hook(tool_event("Write", {"file_path": CWD + "/app.py", "content": content}, CWD))
    assert run.decision == "deny"
    assert "Cloud access key id" in run.message
    assert "app.py:1" in run.message
    assert PLANTED_KEY not in run.stdout + run.stderr


def test_an_ordinary_write_is_asked(hook: Callable[..., HookRun]) -> None:
    run = hook(tool_event("Write", {"file_path": CWD + "/notes.txt", "content": "hello\n"}, CWD))
    assert run.decision == "ask"


def test_force_push_to_main_is_denied(hook: Callable[..., HookRun], data: Path) -> None:
    run = hook(tool_event("Bash", {"command": "git push --force origin main"}, CWD))
    assert run.decision == "deny"
    assert "deny-force-push-protected-branch" in _results(data)[-1]["matched_rule_ids"]


def test_prompt_is_allowed_and_a_private_key_prompt_is_blocked(
    hook: Callable[..., HookRun],
) -> None:
    assert hook(prompt_event("please list the files", CWD)).decision == "allow"
    header = "-----BEGIN " + "RSA PRIVATE KEY-----"
    run = hook(prompt_event(f"here is my key {header} abc", CWD))
    assert run.decision == "block"
    assert run.output["hookSpecificOutput"]["suppressOriginalPrompt"] is True


def test_stop_flag_denies_writes_and_keeps_reads(hook: Callable[..., HookRun], data: Path) -> None:
    write = tool_event("Write", {"file_path": CWD + "/notes.txt", "content": "x\n"}, CWD)
    run = hook(write, CISO_STOP="1")
    assert run.decision == "deny"
    assert "kill_switch_engaged" in _results(data)[-1]["reason_codes"]
    assert "paused" in run.message
    assert (
        hook(tool_event("Read", {"file_path": CWD + "/x"}, CWD), CISO_STOP="1").decision == "allow"
    )


@pytest.mark.parametrize("value", ["yes", "on", "garbage"])
def test_any_stop_value_that_is_not_off_engages_it(
    hook: Callable[..., HookRun], value: str
) -> None:
    write = tool_event("Write", {"file_path": CWD + "/notes.txt", "content": "x\n"}, CWD)
    assert hook(write, CISO_STOP=value).decision == "deny"


def test_stop_flag_off_does_not_block(hook: Callable[..., HookRun]) -> None:
    write = tool_event("Write", {"file_path": CWD + "/notes.txt", "content": "x\n"}, CWD)
    assert hook(write, CISO_STOP="0").decision == "ask"


def test_unknown_role_denies(hook: Callable[..., HookRun], data: Path) -> None:
    run = hook(tool_event("Bash", {"command": "git status"}, CWD), CISO_ROLE="superuser")
    assert run.decision == "deny"
    assert "identity_unavailable" in _results(data)[-1]["reason_codes"]


def test_organizational_class_is_recorded(hook: Callable[..., HookRun], data: Path) -> None:
    hook(tool_event("Bash", {"command": "git status"}, CWD), CISO_AGENT_CLASS="organizational")
    assert _results(data)[-1]["agent_class"] == "organizational"


def test_missing_data_dir_blocks_with_exit_2(data: Path) -> None:
    env = base_env(data)
    env.pop("CLAUDE_PLUGIN_DATA")
    run = run_hook(tool_event("Bash", {"command": "git status"}, CWD), data, env=env)
    assert run.code == 2
    assert "no_data_dir" in run.stderr


def test_not_isolated_interpreter_blocks(data: Path) -> None:
    run = run_hook(tool_event("Bash", {"command": "git status"}, CWD), data, isolated=False)
    assert run.code == 2
    assert "isolated" in run.stderr


@pytest.mark.parametrize("raw", [b"not json", b"[1, 2]", b'{"a": 1, "a": 2}'])
def test_unreadable_input_blocks(data: Path, raw: bytes) -> None:
    run = run_hook(raw, data)
    assert run.code == 2
    assert "CISO plugin" in run.stderr


def test_an_event_the_plugin_does_not_enforce_is_denied(
    hook: Callable[..., HookRun], data: Path
) -> None:
    run = hook(
        {
            "hook_event_name": "PostToolUse",
            "session_id": "s",
            "tool_name": "Bash",
            "tool_use_id": "t",
            "tool_input": {"command": "ls"},
        }
    )
    assert run.decision == "block"  # rendered in the prompt form: refused either way
    assert _records(data)[-1]["type"] == "ciso.plugin.refuse"


def test_malformed_tool_input_is_denied(hook: Callable[..., HookRun]) -> None:
    run = hook(tool_event("Write", {"file_path": CWD + "/a.py"}, CWD))
    assert run.decision == "deny"
    assert "could not read this action" in run.message


def test_unwritable_audit_log_blocks(hook: Callable[..., HookRun], data: Path) -> None:
    (data / "audit").mkdir()
    (data / "audit" / "decisions.jsonl").mkdir()  # a folder where the log file should be
    run = hook(tool_event("Bash", {"command": "git status"}, CWD))
    assert run.decision == "deny"
    assert "audit" in run.message


def test_audit_chain_is_linked(hook: Callable[..., HookRun], data: Path) -> None:
    hook(tool_event("Bash", {"command": "git status"}, CWD))
    hook(tool_event("Bash", {"command": "git log -1"}, CWD, use_id="t2"))
    records = _records(data)
    assert len(records) == 4
    assert records[0]["prev"] == "0" * 64
    for before, after in itertools.pairwise(records):
        assert after["prev"] == before["hash"]
        assert after["seq"] == before["seq"] + 1


def test_unwritable_findings_log_blocks_an_action_that_would_be_asked(
    hook: Callable[..., HookRun], data: Path
) -> None:
    """The decision itself is recorded, but its findings cannot be: the action stops."""
    (data / "findings").mkdir()
    (data / "findings" / "findings.jsonl").mkdir()
    write = tool_event(
        "Write", {"file_path": CWD + "/settings.py", "content": "DEBUG = True\n"}, CWD
    )
    run = hook(write)
    assert run.decision == "deny"
    assert "local audit log" in run.message


def test_parallel_hooks_keep_one_chain(data: Path) -> None:
    import subprocess
    import sys

    from tests.plugin.conftest import HOOK

    procs = [
        subprocess.Popen(  # noqa: S603 - fixed argv
            [sys.executable, "-I", "-B", str(HOOK)],
            stdin=subprocess.PIPE,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            env=base_env(data),
        )
        for _ in range(8)
    ]
    for index, proc in enumerate(procs):
        event = tool_event("Bash", {"command": "git status"}, CWD, use_id=f"p{index}")
        assert proc.stdin is not None
        proc.stdin.write(json.dumps(event).encode("utf-8"))
        proc.stdin.close()
    for proc in procs:
        assert proc.wait(timeout=120) == 0
    records = _records(data)
    assert len(records) == 16
    for before, after in itertools.pairwise(records):
        assert after["prev"] == before["hash"]
