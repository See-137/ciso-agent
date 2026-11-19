"""The hook exactly as `hooks/hooks.json` declares it, run through uv (offline: the pinned
packages must already be in the uv cache; the test is skipped when uv is missing)."""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest
from tests.plugin.conftest import PLUGIN_ROOT, base_env, tool_event

pytestmark = pytest.mark.unit

UV = shutil.which("uv")


def _argv() -> list[str]:
    data = json.loads((PLUGIN_ROOT / "hooks" / "hooks.json").read_text(encoding="utf-8"))
    handler = data["hooks"]["PreToolUse"][0]["hooks"][0]
    args = [a.replace("${CLAUDE_PLUGIN_ROOT}", str(PLUGIN_ROOT)) for a in handler["args"]]
    assert handler["command"] == "uv"
    return [str(UV), *args]


@pytest.mark.skipif(UV is None, reason="uv is not installed")
def test_declared_hook_command_runs_and_decides(data: Path, tmp_path: Path) -> None:
    env = base_env(data, {"UV_OFFLINE": "1"})
    cwd = str(tmp_path)
    allowed = subprocess.run(  # noqa: S603 - argv from the plugin's own hooks.json
        _argv(),
        input=json.dumps(tool_event("Bash", {"command": "git status"}, cwd)).encode(),
        capture_output=True,
        env=env,
        cwd=cwd,
        timeout=180,
        check=False,
    )
    if allowed.returncode != 0 and b"No solution found" in allowed.stderr:
        pytest.skip("pinned packages are not in the uv cache (offline)")
    assert (allowed.returncode, allowed.stdout) == (0, b""), allowed.stderr[-400:]
    denied = subprocess.run(  # noqa: S603 - argv from the plugin's own hooks.json
        _argv(),
        input=json.dumps(
            tool_event("Write", {"file_path": cwd + "/.mcp.json", "content": "{}"}, cwd)
        ).encode(),
        capture_output=True,
        env=env,
        cwd=cwd,
        timeout=180,
        check=False,
    )
    assert denied.returncode == 0
    assert json.loads(denied.stdout)["hookSpecificOutput"]["permissionDecision"] == "deny"


@pytest.mark.skipif(UV is None, reason="uv is not installed")
def test_a_planted_venv_in_the_working_directory_is_not_used(data: Path, tmp_path: Path) -> None:
    """uv runs with --directory <plugin root> and --no-config: files in the repository
    (a uv.toml pointing at another index, a .python-version) are not read."""
    (tmp_path / "uv.toml").write_text('index-url = "http://127.0.0.1:9/simple"\n', encoding="utf-8")
    (tmp_path / ".python-version").write_text("3.8\n", encoding="utf-8")
    env = base_env(data, {"UV_OFFLINE": "1"})
    done = subprocess.run(  # noqa: S603 - argv from the plugin's own hooks.json
        _argv(),
        input=json.dumps(tool_event("Bash", {"command": "git status"}, str(tmp_path))).encode(),
        capture_output=True,
        env=env,
        cwd=str(tmp_path),
        timeout=180,
        check=False,
    )
    if done.returncode != 0 and b"No solution found" in done.stderr:
        pytest.skip("pinned packages are not in the uv cache (offline)")
    assert done.returncode == 0, done.stderr[-400:]
