"""Pushes without a sandbox: what will be sent is resolved and scanned, and every trick the
service reviews found against the earlier client (H1 moved tracking ref, H2 repository
hooks and redirects, M3 replace refs) is refused or still scanned."""

from __future__ import annotations

import json
import shutil
from pathlib import Path
from typing import Any

import pytest
from tests.plugin.conftest import PLANTED_KEY, PLUGIN_ROOT, HookRun, Repo, git, run_hook

pytestmark = pytest.mark.adversarial


def _push(repo: Repo, data: Path, command: str = "git push origin feature", **env: str) -> HookRun:
    return run_hook(repo.push_event(command), data, env)


def _last_result(data: Path) -> dict[str, Any]:
    lines = (data / "audit" / "decisions.jsonl").read_text(encoding="utf-8").splitlines()
    results: list[dict[str, Any]] = [json.loads(x) for x in lines if '"ciso.plugin.result"' in x]
    return results[-1]


def _feature(repo: Repo) -> None:
    git(repo.work, "checkout", "-q", "-b", "feature")


def test_clean_feature_push_is_allowed(repo: Repo, data: Path) -> None:
    _feature(repo)
    repo.commit("app.py", "print('ok')\n")
    run = _push(repo, data)
    assert run.decision == "allow"
    result = _last_result(data)
    assert result["matched_rule_ids"] == ["allow-scanned-push-known-people"]
    assert result["inspection_complete"] is True


def test_secret_in_pushed_commit_is_denied(repo: Repo, data: Path) -> None:
    _feature(repo)
    repo.commit("settings.py", f'TOKEN = "{PLANTED_KEY}"\n')
    run = _push(repo, data)
    assert run.decision == "deny"
    assert "secret.cloud_access_key" in run.message or "Cloud access key id" in run.message
    assert PLANTED_KEY not in run.stdout + run.stderr


def test_secret_added_then_deleted_is_still_found(repo: Repo, data: Path) -> None:
    _feature(repo)
    repo.commit("settings.py", f'TOKEN = "{PLANTED_KEY}"\n', "add")
    repo.commit("settings.py", "TOKEN = load()\n", "remove")
    assert _push(repo, data).decision == "deny"


def test_moving_the_tracking_ref_does_not_shrink_the_scan(repo: Repo, data: Path) -> None:
    """Review H1: the agent moves refs/remotes/origin/feature past the secret commit."""
    _feature(repo)
    repo.commit("settings.py", f'TOKEN = "{PLANTED_KEY}"\n', "add")
    head = repo.commit("notes.txt", "fine\n", "notes")
    git(repo.work, "update-ref", "refs/remotes/origin/feature", head)
    assert _push(repo, data).decision == "deny"


def test_secret_already_on_main_is_not_rescanned_for_a_new_branch(repo: Repo, data: Path) -> None:
    """Commits the remote already has (advertised AND tracked) are not part of the push."""
    repo.commit("old.py", f'TOKEN = "{PLANTED_KEY}"\n', "old")
    git(repo.work, "push", "-q", "origin", "main")
    git(repo.work, "fetch", "-q", "origin")
    _feature(repo)
    repo.commit("app.py", "print('ok')\n")
    assert _push(repo, data).decision == "allow"


@pytest.mark.parametrize(
    ("key", "value"),
    [
        ("remote.origin.pushurl", "../elsewhere.git"),
        ("remote.origin.push", "refs/heads/*:refs/heads/*"),
        ("remote.origin.mirror", "true"),
        ("remote.origin.receivepack", "git-receive-pack"),
        ("remote.origin.uploadpack", "git-upload-pack"),
        ("url.../elsewhere.git.pushInsteadOf", "x"),
        ("core.sshCommand", "ssh"),
        ("push.recurseSubmodules", "on-demand"),
        ("core.hooksPath", ".githooks"),
        ("credential.helper", "store"),
    ],
)
def test_settings_that_redirect_or_widen_the_push_refuse_it(
    repo: Repo, data: Path, key: str, value: str
) -> None:
    _feature(repo)
    repo.commit("app.py", "print('ok')\n")
    git(repo.work, "config", key, value)
    run = _push(repo, data)
    assert run.decision == "deny"
    assert _last_result(data)["note"] == "push_config_redirect"
    assert value not in run.message or value in {"true", "ssh", "store", "x"}


def test_repository_hook_program_refuses_the_push(repo: Repo, data: Path) -> None:
    _feature(repo)
    repo.commit("app.py", "print('ok')\n")
    hooks = repo.work / ".git" / "hooks"
    hooks.mkdir(exist_ok=True)
    (hooks / "pre-push").write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    run = _push(repo, data)
    assert run.decision == "deny"
    assert _last_result(data)["note"] == "repo_hooks"


def test_sample_hooks_do_not_refuse_the_push(repo: Repo, data: Path) -> None:
    _feature(repo)
    repo.commit("app.py", "print('ok')\n")
    hooks = repo.work / ".git" / "hooks"
    hooks.mkdir(exist_ok=True)
    (hooks / "pre-push.sample").write_text("#!/bin/sh\n", encoding="utf-8")
    assert _push(repo, data).decision == "allow"


def test_replace_refs_do_not_hide_the_secret(repo: Repo, data: Path) -> None:
    """Review M3: `git replace` maps the secret blob to a harmless one."""
    _feature(repo)
    repo.commit("settings.py", f'TOKEN = "{PLANTED_KEY}"\n')
    real = git(repo.work, "rev-parse", "HEAD:settings.py")
    (repo.work / "benign.txt").write_text("DEBUG = False\n", encoding="utf-8")
    benign = git(repo.work, "hash-object", "-w", "benign.txt")
    git(repo.work, "replace", real, benign)
    assert _push(repo, data).decision == "deny"


def test_binary_change_makes_the_push_incomplete(repo: Repo, data: Path) -> None:
    _feature(repo)
    (repo.work / "blob.bin").write_bytes(b"\x00\x01\x02binary")
    git(repo.work, "add", "blob.bin")
    git(repo.work, "commit", "-q", "-m", "bin")
    run = _push(repo, data)
    assert run.decision == "deny"
    assert _last_result(data)["inspection_complete"] is False


@pytest.mark.parametrize(
    "command",
    [
        "git push",
        "git push origin",
        "git push --all origin",
        "git push origin feature:main extra",
        "git push origin :feature",
        "git push origin HEAD",
        "git push origin feature && echo x",
    ],
)
def test_pushes_that_cannot_be_scanned_are_denied(repo: Repo, data: Path, command: str) -> None:
    _feature(repo)
    repo.commit("app.py", "print('ok')\n")
    assert _push(repo, data, command).decision == "deny"


def test_unknown_remote_is_denied(repo: Repo, data: Path) -> None:
    _feature(repo)
    repo.commit("app.py", "print('ok')\n")
    run = _push(repo, data, "git push upstream feature")
    assert run.decision == "deny"
    assert _last_result(data)["note"] == "unknown_remote"


def test_push_to_protected_branch_is_asked_after_a_clean_scan(repo: Repo, data: Path) -> None:
    repo.commit("app.py", "print('ok')\n")
    assert _push(repo, data, "git push origin main").decision == "ask"


def test_git_environment_of_the_hook_does_not_reach_its_git(repo: Repo, data: Path) -> None:
    """A GIT_DIR in the hook's environment would point the scan at another repository:
    here a clean clone with its own clean `feature` branch, while the real one holds the
    secret."""
    decoy = repo.work.parent / "decoy"
    git(repo.work.parent, "clone", "-q", str(repo.bare), str(decoy))
    git(decoy, "checkout", "-q", "-b", "feature")
    (decoy / "ok.py").write_text("ok = 1\n", encoding="utf-8")
    git(decoy, "add", "ok.py")
    git(decoy, "commit", "-q", "-m", "clean")
    _feature(repo)
    repo.commit("settings.py", f'TOKEN = "{PLANTED_KEY}"\n')
    assert _push(repo, data).decision == "deny"
    assert _push(repo, data, GIT_DIR=str(decoy / ".git")).decision == "deny"


def test_commit_scans_the_staged_change(repo: Repo, data: Path) -> None:
    (repo.work / "c.py").write_text(f'TOKEN = "{PLANTED_KEY}"\n', encoding="utf-8")
    git(repo.work, "add", "c.py")
    run = run_hook(repo.push_event("git commit -m wip"), data)
    assert run.decision == "deny"
    (repo.work / "c.py").write_text("x = 1\n", encoding="utf-8")
    git(repo.work, "add", "c.py")
    assert run_hook(repo.push_event("git commit -m wip"), data).decision == "ask"


def test_a_remote_tip_the_tracking_ref_disagrees_with_is_not_a_base(repo: Repo, data: Path) -> None:
    """A tip the remote advertises counts as a base only when the local tracking ref holds
    the same commit, so a remote (or a stale ref) alone cannot shrink the scan."""
    git(repo.work, "checkout", "-q", "-b", "other")
    secret = repo.commit("s.py", f'T = "{PLANTED_KEY}"\n', "secret")
    git(repo.work, "push", "-q", "origin", "other")
    git(repo.work, "fetch", "-q", "origin")
    git(repo.work, "update-ref", "refs/remotes/origin/other", git(repo.work, "rev-parse", "main"))
    git(repo.work, "checkout", "-q", "-b", "feature", secret)
    repo.commit("app.py", "print('ok')\n")
    assert _push(repo, data).decision == "deny"
    git(repo.work, "update-ref", "refs/remotes/origin/other", secret)
    assert _push(repo, data).decision == "allow"


def test_more_commits_than_the_cap_refuses_the_push(repo: Repo, data: Path, tmp_path: Path) -> None:
    copy = tmp_path / "plugin-copy"
    for part in ("lib", "scripts", "rules"):
        shutil.copytree(PLUGIN_ROOT / part, copy / part)
    scan = copy / "lib" / "ciso_plugin" / "pushscan.py"
    text = scan.read_text(encoding="utf-8")
    assert "MAX_PUSH_COMMITS: Final = 1000" in text
    scan.write_text(
        text.replace("MAX_PUSH_COMMITS: Final = 1000", "MAX_PUSH_COMMITS: Final = 2"),
        encoding="utf-8",
    )
    hook = copy / "scripts" / "ciso_hook.py"
    _feature(repo)
    repo.commit("a.py", "a = 1\n")
    repo.commit("b.py", "b = 1\n")
    event = repo.push_event("git push origin feature")
    assert run_hook(event, data, hook_path=hook).decision == "allow"
    repo.commit("c.py", "c = 1\n")
    run = run_hook(event, data, hook_path=hook)
    assert run.decision == "deny"
    assert _last_result(data)["note"] == "too_many_commits"
