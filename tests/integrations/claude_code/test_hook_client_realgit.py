"""The client's own git against real repositories (git on this machine), reviews M3, H1,
H2 and Q17: replace objects and diff configuration cannot change what is scanned, the
whole history is listed when no base is approved, and configuration that redirects or
reshapes the push is refused wherever it is set."""

from __future__ import annotations

import base64
import os
import shutil
import subprocess
import time
from collections.abc import Callable
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

pytestmark = pytest.mark.unit

GIT = shutil.which("git")
#: Plain markers, not secrets: the test only asks whether the real content is shown.
REAL = "REAL-CONTENT-" + "7c1e"
DECOY = "DECOY-CONTENT-" + "0b2d"

HOOKS = Path(__file__).resolve().parent / "no-hooks-for-tests"
needs_git = pytest.mark.skipif(GIT is None, reason="git is not installed")


@pytest.fixture
def home(tmp_path: Path) -> Path:
    path = tmp_path / "home"
    path.mkdir()
    return path


@pytest.fixture
def environ(home: Path) -> dict[str, str]:
    """The hook's environment: a private HOME, so the engineer's real global
    configuration is the one in `home` (empty unless a test writes it)."""
    keep = ("PATH", "SYSTEMROOT", "SystemRoot", "TEMP", "TMP", "COMSPEC", "PATHEXT")
    env = {k: v for k, v in os.environ.items() if k in keep}
    env.update({"HOME": str(home), "USERPROFILE": str(home)})
    return env


@pytest.fixture
def hook_env(environ: dict[str, str], hc: ModuleType) -> dict[str, str]:
    """`environ` plus the managed pack's git configuration, as the hook receives it."""
    return {**environ, **hc.managed_git_env(str(HOOKS))}


def sh(cwd: Path, *args: str, env: dict[str, str]) -> str:
    assert GIT is not None
    full = {**env, "GIT_CONFIG_NOSYSTEM": "1", "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@t",
            "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@t"}  # fmt: skip
    done = subprocess.run(  # noqa: S603 - fixed argv, test setup
        [GIT, "-c", "core.autocrlf=false", *args], cwd=cwd, env=full,
        capture_output=True, check=True,
    )  # fmt: skip
    return done.stdout.decode().strip()


@pytest.fixture
def repo(tmp_path: Path, environ: dict[str, str]) -> Path:
    """A repository with one pushed commit on `main` and a local bare remote."""
    remote = tmp_path / "remote.git"
    sh(tmp_path, "init", "-q", "--bare", str(remote), env=environ)
    path = tmp_path / "work"
    path.mkdir()
    sh(path, "init", "-q", "-b", "main", env=environ)
    (path / "readme.txt").write_text("hello\n", encoding="utf-8")
    sh(path, "add", "readme.txt", env=environ)
    sh(path, "commit", "-q", "-m", "first", env=environ)
    sh(path, "remote", "add", "origin", str(remote), env=environ)
    sh(path, "push", "-q", "origin", "main", env=environ)
    return path


def client_git(hc: ModuleType, cwd: Path, environ: dict[str, str], scratch: Path) -> Any:
    assert GIT is not None
    scratch.mkdir(parents=True, exist_ok=True)
    budget = hc.Budget(60.0, time.monotonic, time.monotonic())
    return hc.Git(hc.SubprocessGitRunner(), GIT, str(cwd), budget, environ, str(scratch))


def no_bases(repository: str, branch: str) -> list[str]:
    return []


def build(
    hc: ModuleType,
    cwd: Path,
    environ: dict[str, str],
    tmp_path: Path,
    kind: str,
    bases: Callable[[str, str], list[str]] = no_bases,
) -> dict[str, Any]:
    needs = hc.NeedsChange(kind, "origin" if kind == "push" else None,
                           "main" if kind == "push" else None, None)  # fmt: skip
    git = client_git(hc, cwd, environ, tmp_path / "scratch")
    hook = {**environ, **hc.managed_git_env(str(HOOKS))}
    change: dict[str, Any] = hc.build_change(
        git, needs, str(tmp_path / "scratch"), bases, hook, str(HOOKS)
    )
    return change


def diff_text(change: dict[str, Any]) -> str:
    return base64.b64decode(change["diff_b64"]).decode("utf-8")


# --- M3 ---------------------------------------------------------------------------------


@needs_git
def test_a_replace_object_does_not_hide_the_staged_content(
    hc: ModuleType, repo: Path, environ: dict[str, str], tmp_path: Path
) -> None:
    """Reviewer's M3 sequence: stage the real content, then `git replace` its blob with a
    decoy. The commit scan must still show the real content."""
    (repo / "settings.py").write_text(f"VALUE = '{REAL}'\n", encoding="utf-8")
    sh(repo, "add", "settings.py", env=environ)
    real_blob = sh(repo, "rev-parse", ":settings.py", env=environ)
    decoy = repo / "decoy.txt"
    decoy.write_text(f"VALUE = '{DECOY}'\n", encoding="utf-8")
    decoy_blob = sh(repo, "hash-object", "-w", str(decoy), env=environ)
    decoy.unlink()
    sh(repo, "replace", real_blob, decoy_blob, env=environ)
    text = diff_text(build(hc, repo, environ, tmp_path, "commit"))
    assert REAL in text
    assert DECOY not in text


@needs_git
def test_a_replace_object_does_not_hide_pushed_content(
    hc: ModuleType, repo: Path, environ: dict[str, str], tmp_path: Path
) -> None:
    (repo / "settings.py").write_text(f"VALUE = '{REAL}'\n", encoding="utf-8")
    sh(repo, "add", "settings.py", env=environ)
    sh(repo, "commit", "-q", "-m", "second", env=environ)
    real_blob = sh(repo, "rev-parse", "HEAD:settings.py", env=environ)
    decoy = repo / "decoy.txt"
    decoy.write_text(f"VALUE = '{DECOY}'\n", encoding="utf-8")
    decoy_blob = sh(repo, "hash-object", "-w", str(decoy), env=environ)
    decoy.unlink()
    sh(repo, "replace", real_blob, decoy_blob, env=environ)
    text = diff_text(build(hc, repo, environ, tmp_path, "push"))
    assert REAL in text
    assert DECOY not in text


@needs_git
@pytest.mark.parametrize("where", ["repository", "global"])
def test_diff_relative_does_not_hide_files_outside_the_hook_directory(
    hc: ModuleType, repo: Path, environ: dict[str, str], tmp_path: Path, home: Path, where: str
) -> None:
    """Reviewer's M3 sequence: `diff.relative=true` with the hook's cwd in a
    subdirectory listed only that subdirectory."""
    if where == "repository":
        sh(repo, "config", "diff.relative", "true", env=environ)
    else:
        (home / ".gitconfig").write_text("[diff]\n\trelative = true\n", encoding="utf-8")
    (repo / "sub").mkdir()
    (repo / "sub" / "ok.txt").write_text("fine\n", encoding="utf-8")
    (repo / "creds.txt").write_text(f"{REAL}\n", encoding="utf-8")
    sh(repo, "add", ".", env=environ)
    staged = diff_text(build(hc, repo / "sub", environ, tmp_path, "commit"))
    assert REAL in staged
    assert "sub/ok.txt" in staged
    sh(repo, "commit", "-q", "-m", "second", env=environ)
    pushed = diff_text(build(hc, repo / "sub", environ, tmp_path / "p", "push"))
    assert REAL in pushed
    assert "a/creds.txt" in pushed


@needs_git
def test_noprefix_and_renames_do_not_change_the_diff(
    hc: ModuleType, repo: Path, environ: dict[str, str], tmp_path: Path
) -> None:
    sh(repo, "config", "diff.noprefix", "true", env=environ)
    sh(repo, "config", "diff.renames", "copies", env=environ)
    body = "".join(f"line {n} {REAL}\n" for n in range(20))
    (repo / "readme.txt").write_text(body, encoding="utf-8")
    sh(repo, "add", ".", env=environ)
    sh(repo, "commit", "-q", "-m", "body", env=environ)
    # Copy detection only looks at files the change also modifies: touch the source.
    (repo / "readme.txt").write_text(body + "more\n", encoding="utf-8")
    (repo / "copy.txt").write_text(body, encoding="utf-8")
    sh(repo, "add", ".", env=environ)
    assert "copy from readme.txt" in sh(repo, "diff", "--cached", env=environ)
    text = diff_text(build(hc, repo, environ, tmp_path, "commit"))
    assert "+++ b/copy.txt" in text
    assert f"+line 0 {REAL}" in text  # a new file with its lines, not "copy from"
    assert "copy from" not in text


# --- H1 ---------------------------------------------------------------------------------


@needs_git
def test_a_moved_tracking_ref_does_not_shrink_the_range(
    hc: ModuleType, repo: Path, environ: dict[str, str], tmp_path: Path
) -> None:
    """Reviewer's H1 sequence: two unpushed commits, the first with the real content;
    the agent moves refs/remotes/origin/main to HEAD~1. The range still covers both."""
    (repo / "creds.txt").write_text(f"{REAL}\n", encoding="utf-8")
    sh(repo, "add", "creds.txt", env=environ)
    sh(repo, "commit", "-q", "-m", "add creds", env=environ)
    (repo / "notes.txt").write_text("notes\n", encoding="utf-8")
    sh(repo, "add", "notes.txt", env=environ)
    sh(repo, "commit", "-q", "-m", "notes", env=environ)
    sh(repo, "update-ref", "refs/remotes/origin/main", "HEAD~1", env=environ)
    first = sh(repo, "rev-list", "--max-parents=0", "HEAD", env=environ)
    approved = lambda repository, branch: [first]  # noqa: E731
    change = build(hc, repo, environ, tmp_path, "push", approved)
    assert change["base"] == first
    assert len(change["commits"]) == 2
    assert REAL in diff_text(change)
    root = build(hc, repo, environ, tmp_path / "r", "push")
    assert root["base"] is None
    assert len(root["commits"]) == 3
    assert REAL in diff_text(root)
    assert base64.b64decode(root["bundle_b64"]).startswith(b"# v")
    assert root["repository"] == str(tmp_path / "remote.git")


# --- H2 and Q17 ---------------------------------------------------------------------------


@needs_git
def test_a_plain_repository_passes_the_push_configuration_check(
    hc: ModuleType, repo: Path, environ: dict[str, str], tmp_path: Path
) -> None:
    hc.check_push_config(client_git(hc, repo, environ, tmp_path / "s"), "origin", environ)


@needs_git
@pytest.mark.parametrize(
    ("key", "value"),
    [
        ("remote.origin.pushurl", "https://elsewhere.example.test/x.git"),
        ("remote.origin.receivepack", "git-receive-pack"),
        ("remote.origin.push", "refs/heads/*:refs/heads/*"),
        ("remote.origin.mirror", "true"),
        ("remote.origin.mirror", "false"),
        ("core.sshCommand", "ssh"),
        ("url.https://elsewhere.example.test/.pushInsteadOf", "https://git.example.test/"),
    ],
)
@pytest.mark.parametrize("where", ["repository", "global", "environment"])
def test_configuration_that_changes_the_push_is_refused(
    hc: ModuleType,
    repo: Path,
    environ: dict[str, str],
    tmp_path: Path,
    home: Path,
    key: str,
    value: str,
    where: str,
) -> None:
    env = dict(environ)
    if where == "repository":
        sh(repo, "config", key, value, env=environ)
    elif where == "global":
        sh(home, "config", "--file", str(home / ".gitconfig"), key, value, env=environ)
    else:
        env.update({"GIT_CONFIG_COUNT": "1", "GIT_CONFIG_KEY_0": key, "GIT_CONFIG_VALUE_0": value})
    git = client_git(hc, repo, env, tmp_path / "s")
    with pytest.raises(hc.ClientError) as caught:
        hc.check_push_config(git, "origin", env)
    assert caught.value.code == "push_config"


@needs_git
def test_another_remotes_push_url_does_not_refuse_this_push(
    hc: ModuleType, repo: Path, environ: dict[str, str], tmp_path: Path
) -> None:
    sh(repo, "config", "remote.other.pushurl", "https://elsewhere.example.test/x.git", env=environ)
    hc.check_push_config(client_git(hc, repo, environ, tmp_path / "s"), "origin", environ)
