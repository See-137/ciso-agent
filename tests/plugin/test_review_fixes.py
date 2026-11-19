"""Fixes for the adversarial plugin review (docs/reviews/ciso-plugin-adversarial.md):
M2 own-skill name, M3 stop flag and identity on the own skill and tool, M6 the
assistant's credential files, and the uv folders the hook runs from (H1)."""

from __future__ import annotations

import json
from collections.abc import Callable
from pathlib import Path

import pytest
from tests.plugin.conftest import PLUGIN_ROOT, TOOL, HookRun, tool_event

pytestmark = pytest.mark.adversarial

CWD = str(Path(__file__).resolve().parent)
HOME = Path.home()


def _own_tool(data: Path, tail: str) -> str:
    """The skill's tool command exactly as SKILL.md documents it."""
    skill = (PLUGIN_ROOT / "skills" / "ciso" / "SKILL.md").read_text(encoding="utf-8")
    line = next(ln for ln in skill.splitlines() if ln.startswith("uv run "))
    line = line.replace("${CLAUDE_PLUGIN_ROOT}", str(PLUGIN_ROOT))
    line = line.replace("${CLAUDE_SKILL_DIR}", str(TOOL.parent.parent))
    return line.replace("<subcommand> <options>", tail.replace("{data}", str(data)))


def _own_records(data: Path) -> int:
    path = data / "audit" / "decisions.jsonl"
    if not path.exists():
        return 0
    return path.read_text(encoding="utf-8").count('"ciso.plugin.own_tool"')


# --- M6 --------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "path",
    [
        HOME / ".claude" / ".credentials.json",
        HOME / ".claude.json",
        HOME / ".config" / "anthropic" / "configs" / "default.json",
        HOME / "relocated-config" / ".credentials.json",
    ],
)
def test_reading_the_assistants_credential_files_is_denied(
    hook: Callable[..., HookRun], path: Path
) -> None:
    run = hook(tool_event("Read", {"file_path": str(path)}, CWD))
    assert run.decision == "deny", run.stdout


def test_reading_an_ordinary_file_in_the_config_folder_is_still_allowed(
    hook: Callable[..., HookRun],
) -> None:
    run = hook(tool_event("Read", {"file_path": str(HOME / ".claude" / "README.md")}, CWD))
    assert run.decision == "allow"


@pytest.mark.parametrize(
    "path",
    [
        HOME / "AppData" / "Local" / "uv" / "cache" / "archive-v0" / "x" / "evil.pth",
        HOME / ".cache" / "uv" / "archive-v0" / "x" / "evil.pth",
        HOME / ".local" / "share" / "uv" / "python" / "x" / "evil.pth",
    ],
)
def test_writing_into_the_uv_folders_is_denied(hook: Callable[..., HookRun], path: Path) -> None:
    run = hook(tool_event("Write", {"file_path": str(path), "content": "import os\n"}, CWD))
    assert run.decision == "deny"


# --- M2 --------------------------------------------------------------------------------


def test_only_the_namespaced_skill_is_the_own_skill(
    hook: Callable[..., HookRun], data: Path
) -> None:
    assert hook(tool_event("Skill", {"skill": "ciso-agent:ciso"}, CWD)).decision == "allow"
    assert _own_records(data) == 1
    bare = hook(tool_event("Skill", {"skill": "ciso"}, CWD, use_id="t2"))
    assert bare.decision == "ask"
    assert _own_records(data) == 1


# --- M3 --------------------------------------------------------------------------------


def test_stop_flag_keeps_the_skill_and_its_read_only_summary(
    hook: Callable[..., HookRun], data: Path
) -> None:
    assert hook(tool_event("Skill", {"skill": "ciso-agent:ciso"}, CWD), CISO_STOP="1").decision == (
        "allow"
    )
    summary = _own_tool(data, 'summary --data-dir "{data}" --days 7')
    assert hook(tool_event("Bash", {"command": summary}, CWD), CISO_STOP="1").decision == "allow"


@pytest.mark.parametrize(
    "tail",
    [
        f'review --repo "{CWD}" --data-dir "{{data}}"',
        f'audit-setup --repo "{CWD}" --data-dir "{{data}}"',
    ],
)
def test_stop_flag_denies_the_parts_of_the_tool_that_write(
    hook: Callable[..., HookRun], data: Path, tail: str
) -> None:
    command = _own_tool(data, tail)
    assert hook(tool_event("Bash", {"command": command}, CWD)).decision == "allow"
    before = _own_records(data)
    run = hook(tool_event("Bash", {"command": command}, CWD, use_id="t2"), CISO_STOP="1")
    assert run.decision == "deny"
    assert _own_records(data) == before


@pytest.mark.parametrize("env", [{"CISO_ROLE": "nonsense"}])
def test_invalid_identity_reaches_the_own_skill_and_tool(
    hook: Callable[..., HookRun], data: Path, env: dict[str, str]
) -> None:
    summary = _own_tool(data, 'summary --data-dir "{data}"')
    assert hook(tool_event("Bash", {"command": summary}, CWD), **env).decision == "deny"
    assert hook(tool_event("Skill", {"skill": "ciso-agent:ciso"}, CWD), **env).decision == "deny"
    assert _own_records(data) == 0


def test_the_documented_tool_command_is_the_own_tool(
    hook: Callable[..., HookRun], data: Path
) -> None:
    command = _own_tool(data, 'summary --data-dir "{data}"')
    assert "--isolated" in command
    assert hook(tool_event("Bash", {"command": command}, CWD)).decision == "allow"
    assert _own_records(data) == 1
    json.dumps(command)


_NO_ACCOUNT = """
import json, sys
from pathlib import Path
root = Path(sys.argv[1]); sys.path.insert(0, str(root / "lib"))
from ciso.common.clock import SystemClock
from ciso_plugin.decide import Context, Decider
from ciso_plugin.settings import PluginSettings
data = Path(sys.argv[2])
ctx = Context(root, data, {}, SystemClock(), None, PluginSettings.from_env({}), None)
for payload in json.loads(sys.argv[3]):
    print(Decider(ctx).decide(payload).verdict.value)
"""


def test_unreadable_os_account_reaches_the_own_skill_and_tool(data: Path) -> None:
    import subprocess

    from tests.plugin.conftest import runtime_python

    summary = _own_tool(data, 'summary --data-dir "{data}"')
    payloads = [
        tool_event("Skill", {"skill": "ciso-agent:ciso"}, CWD),
        tool_event("Bash", {"command": summary}, CWD, use_id="t2"),
    ]
    done = subprocess.run(  # noqa: S603 - fixed argv, the uv runtime
        [
            runtime_python(),
            "-I",
            "-B",
            "-c",
            _NO_ACCOUNT,
            str(PLUGIN_ROOT),
            str(data),
            *[json.dumps(payloads)],
        ],
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )
    assert done.returncode == 0, done.stderr
    assert done.stdout.split() == ["deny", "deny"]
    assert _own_records(data) == 0


# --- M5 --------------------------------------------------------------------------------

CHAIN_LIMIT = "truncation and rewriting cannot be detected locally"


def test_summary_states_what_the_hash_chain_can_and_cannot_show(
    hook: Callable[..., HookRun], data: Path
) -> None:
    from tests.plugin.conftest import run_tool

    for index in range(3):
        hook(tool_event("Read", {"file_path": "README.md"}, CWD, use_id=f"r{index}"))
    log = data / "audit" / "decisions.jsonl"
    lines = log.read_text(encoding="utf-8").splitlines(keepends=True)
    log.write_text("".join(lines[:2]), encoding="utf-8")  # the reviewer's truncation
    done = run_tool(["summary", "--data-dir", str(data)], data)
    assert done.returncode == 0, done.stderr
    assert f"no edits detected in 2 records; {CHAIN_LIMIT}" in done.stdout
    assert "intact" not in done.stdout
    edited = json.loads(lines[0])
    edited["verdict"] = "allow-edited"
    log.write_text(json.dumps(edited) + "\n" + lines[1], encoding="utf-8")
    broken = run_tool(["summary", "--data-dir", str(data)], data)
    assert "BROKEN at line 1" in broken.stdout


def test_readme_and_skill_do_not_claim_more_than_the_chain_shows() -> None:
    readme = (PLUGIN_ROOT / "README.md").read_text(encoding="utf-8")
    skill = (PLUGIN_ROOT / "skills" / "ciso" / "SKILL.md").read_text(encoding="utf-8")
    assert "the hash chain shows edited log lines" not in readme
    assert CHAIN_LIMIT in readme
    assert "whether both hash chains are intact" not in skill


# --- L3 --------------------------------------------------------------------------------


def _link(kind: str, link: Path, target: Path) -> None:
    import os
    import sys

    if kind == "junction":
        if sys.platform != "win32":
            pytest.skip("junctions are Windows only")
        import _winapi

        _winapi.CreateJunction(str(target), str(link))
        return
    try:
        os.symlink(target, link, target_is_directory=target.is_dir())
    except OSError:
        pytest.skip("this account cannot create symbolic links")


@pytest.mark.parametrize("kind", ["junction", "symlink-dir", "symlink-file"])
def test_review_never_follows_a_link_out_of_the_repository(
    tmp_path: Path, data: Path, kind: str
) -> None:
    from tests.plugin.conftest import PLANTED_KEY, run_tool

    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "credentials").write_text(f"key = {PLANTED_KEY}\n", encoding="utf-8")
    project = tmp_path / "project"
    project.mkdir()
    (project / "app.py").write_text("print('ok')\n", encoding="utf-8")
    if kind == "symlink-file":
        _link(kind, project / "creds", outside / "credentials")
    else:
        _link(kind, project / "link", outside)
    done = run_tool(["review", "--repo", str(project)], data)
    assert done.returncode == 0, done.stderr
    assert "Items inspected: 1." in done.stdout
    assert "secret." not in done.stdout
    assert "link" not in done.stdout.split("## Notes")[0]
