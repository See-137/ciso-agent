"""Fixtures for the CISO agent plugin tests.

The plugin runs as its own process with an isolated interpreter (`-I`) and only its
`lib/` on the path, exactly as Claude Code runs it; these tests do the same, so the code
under test is the plugin's bundled copy, never `src/`. `CISO_PLUGIN_UNDER_TEST` points the
tests at another copy of the plugin (the mutation runs use it).

The interpreter is the environment uv builds for the declared hook command (review H1:
the runtime guard refuses anything else). It is found once per session by running the
declared uv command offline, so the pinned packages must be in the uv cache.
"""

from __future__ import annotations

import functools
import json
import os
import shutil
import subprocess
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
PLUGIN_ROOT = Path(
    os.environ.get("CISO_PLUGIN_UNDER_TEST")
    or REPO_ROOT / "integrations" / "claude_code" / "ciso-plugin"
)
HOOK = PLUGIN_ROOT / "scripts" / "ciso_hook.py"
TOOL = PLUGIN_ROOT / "skills" / "ciso" / "scripts" / "ciso_tool.py"
MANAGED_ROOT = Path(
    os.environ.get("CISO_MANAGED_UNDER_TEST")
    or REPO_ROOT / "integrations" / "claude_code" / "managed-plugin"
)
GIT = shutil.which("git")
UV = shutil.which("uv")


def declared_uv_args(event: str = "PreToolUse", root: Path = PLUGIN_ROOT) -> list[str]:
    """The hook's uv argv from `hooks/hooks.json`, with the plugin root filled in."""
    data = json.loads((PLUGIN_ROOT / "hooks" / "hooks.json").read_text(encoding="utf-8"))
    handler = data["hooks"][event][0]["hooks"][0]
    assert handler["command"] == "uv"
    return [a.replace("${CLAUDE_PLUGIN_ROOT}", str(root)) for a in handler["args"]]


_FIND_ENV = (
    "import pathlib, pydantic; p = pathlib.Path(pydantic.__file__).resolve(); "
    "print(next(d for d in p.parents if (d / 'pyvenv.cfg').is_file()))"
)


@functools.cache
def runtime_python() -> str:
    """The python of the uv environment the declared hook command runs in."""
    if UV is None:
        pytest.fail("uv is not installed: the plugin tests need it (review H1)")
    args = declared_uv_args()
    head = args[: args.index("--") + 1]
    done = subprocess.run(  # noqa: S603 - argv from the plugin's own hooks.json
        [UV, *head, "python", "-I", "-B", "-c", _FIND_ENV],
        capture_output=True,
        text=True,
        env={**os.environ, "UV_OFFLINE": "1"},
        timeout=300,
        check=False,
    )
    if done.returncode != 0:
        pytest.fail("the pinned packages are not in the uv cache: " + done.stderr[-300:])
    env = Path(done.stdout.strip())
    for candidate in (env / "Scripts" / "python.exe", env / "bin" / "python"):
        if candidate.is_file():
            return str(candidate)
    pytest.fail(f"no interpreter in the uv environment {env}")


#: A cloud access key id built from fragments, so no secret shape sits in this file.
PLANTED_KEY = "AK" + "IA" + "Q7RZ4KXN" + "2PLM8WBT"


@dataclass(frozen=True)
class HookRun:
    code: int
    stdout: str
    stderr: str

    @property
    def output(self) -> dict[str, Any]:
        return json.loads(self.stdout) if self.stdout.strip() else {}

    @property
    def decision(self) -> str:
        """allow (no output), deny, ask, or block (prompt) / error (exit 2)."""
        if self.code == 2:
            return "error"
        out = self.output
        if not out:
            return "allow"
        if "decision" in out:
            return str(out["decision"])
        return str(out["hookSpecificOutput"]["permissionDecision"])

    @property
    def message(self) -> str:
        out = self.output
        if "reason" in out:
            return str(out["reason"])
        return str(out.get("hookSpecificOutput", {}).get("permissionDecisionReason", ""))


def base_env(data: Path, extra: Mapping[str, str] | None = None) -> dict[str, str]:
    env = {k: v for k, v in os.environ.items() if not k.startswith("CISO_")}
    env["CLAUDE_PLUGIN_DATA"] = str(data)
    env["CLAUDE_PLUGIN_ROOT"] = str(PLUGIN_ROOT)
    if GIT:
        env["CISO_GIT_PATH"] = GIT
    env.update(extra or {})
    return env


def run_hook(
    payload: Mapping[str, Any] | bytes,
    data: Path,
    extra_env: Mapping[str, str] | None = None,
    *,
    isolated: bool = True,
    env: Mapping[str, str] | None = None,
    hook_path: Path = HOOK,
) -> HookRun:
    raw = payload if isinstance(payload, bytes) else json.dumps(payload).encode("utf-8")
    flags = ["-I", "-B"] if isolated else ["-B"]
    done = subprocess.run(  # noqa: S603 - fixed argv, the uv runtime
        [runtime_python(), *flags, str(hook_path)],
        input=raw,
        capture_output=True,
        env=dict(env) if env is not None else base_env(data, extra_env),
        timeout=120,
        check=False,
    )
    return HookRun(
        done.returncode,
        done.stdout.decode("utf-8", "replace"),
        done.stderr.decode("utf-8", "replace"),
    )


def run_tool(args: list[str], data: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(  # noqa: S603 - fixed argv, the uv runtime
        [runtime_python(), "-I", "-B", str(TOOL), *args],
        capture_output=True,
        text=True,
        env=base_env(data),
        timeout=120,
        check=False,
    )


def tool_event(
    tool: str, tool_input: Mapping[str, Any], cwd: str, use_id: str = "t1"
) -> dict[str, Any]:
    return {
        "hook_event_name": "PreToolUse",
        "session_id": "sess-test",
        "cwd": cwd,
        "tool_name": tool,
        "tool_use_id": use_id,
        "tool_input": dict(tool_input),
    }


def prompt_event(text: str, cwd: str) -> dict[str, Any]:
    return {
        "hook_event_name": "UserPromptSubmit",
        "session_id": "sess-test",
        "cwd": cwd,
        "prompt_id": "p1",
        "prompt": text,
    }


def git(cwd: Path, *args: str) -> str:
    assert GIT is not None
    env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
    env.update(
        {
            "GIT_AUTHOR_NAME": "t",
            "GIT_AUTHOR_EMAIL": "t@example.invalid",
            "GIT_COMMITTER_NAME": "t",
            "GIT_COMMITTER_EMAIL": "t@example.invalid",
        }
    )
    done = subprocess.run(  # noqa: S603 - fixed argv, git from PATH
        [
            GIT,
            "-c",
            "core.hooksPath=",
            "-c",
            "commit.gpgsign=false",
            "-c",
            "init.defaultBranch=main",
            *args,
        ],
        cwd=cwd,
        capture_output=True,
        text=True,
        env=env,
        timeout=60,
        check=True,
    )
    return done.stdout.strip()


@dataclass(frozen=True)
class Repo:
    work: Path
    bare: Path

    def commit(self, name: str, text: str, message: str = "change") -> str:
        path = self.work / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8", newline="\n")
        git(self.work, "add", "--", name)
        git(self.work, "commit", "-q", "-m", message)
        return git(self.work, "rev-parse", "HEAD")

    def remote_ref(self, branch: str) -> str:
        return git(self.bare, "for-each-ref", "--format=%(objectname)", f"refs/heads/{branch}")

    def push_event(self, command: str) -> dict[str, Any]:
        return tool_event("Bash", {"command": command}, str(self.work), use_id="push")


@pytest.fixture
def data(tmp_path: Path) -> Path:
    path = tmp_path / "plugin-data"
    path.mkdir()
    return path


@pytest.fixture
def repo(tmp_path: Path) -> Repo:
    if GIT is None:
        pytest.skip("git is not installed")
    bare = tmp_path / "remote.git"
    work = tmp_path / "work"
    work.mkdir()
    git(tmp_path, "init", "-q", "--bare", str(bare))
    git(work, "init", "-q")
    git(work, "remote", "add", "origin", str(bare))
    made = Repo(work, bare)
    made.commit("README.md", "hello\n", "init")
    git(work, "push", "-q", "origin", "main")
    git(work, "fetch", "-q", "origin")
    return made


@pytest.fixture
def hook(data: Path) -> Callable[..., HookRun]:
    def call(payload: Mapping[str, Any], **env: str) -> HookRun:
        return run_hook(payload, data, env)

    return call
