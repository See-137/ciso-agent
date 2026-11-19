"""Decide mode, pre-push: a deny carrying `needs_change` makes the client build the change
with git (a fake runner here), upload it and ask again. Every failure blocks, the run
stays inside the hook's deadline, and git runs from a fixed argv list, never a shell."""

from __future__ import annotations

import base64
import io
import json
import subprocess
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest
from tests.integrations.claude_code.conftest import (
    HOOKS_DIR,
    PRE_TOOL_USE,
    SERVICE_URL,
    FakeTransport,
    never_writable,
    write_config,
)

from ciso.app.change_models import MAX_CHANGE_BODY_BYTES

pytestmark = pytest.mark.unit

HEAD = "1" * 40
BASE = "2" * 40
OLDER = "3" * 40
TREE = "4" * 40
DIFF = b"diff --git a/x.py b/x.py\n--- a/x.py\n+++ b/x.py\n@@ -0,0 +1 @@\n+print(1)\n"
BUNDLE = b"# v2 git bundle\nbundle-bytes"
CHANGE_ID = "chg_01JD3Z6B8Q4W5X7Y9Z0A1B2C3D"


def decide_answer(verdict: str, needs: dict[str, Any] | None = None) -> bytes:
    body: dict[str, Any] = {
        "verdict": verdict,
        "decision_id": "dec_1",
        "reason": "inspection_incomplete" if needs else "rule_allow",
        "message": "service message",
    }
    if needs is not None:
        body["needs_change"] = needs
    return json.dumps(body).encode()


NEEDS_PUSH = {"kind": "push", "remote": "origin", "branch": "feature", "source": "feature"}
UPLOADED = (201, json.dumps({"change_id": CHANGE_ID, "created": True}).encode())
REMOTE_URL = "https://git.example.test/team/app.git"
EMPTY_TREE = "4b825dc642cb6eb9a060e54bf8d69288fbee4904"


def bases_answer(*bases: str) -> tuple[int, bytes]:
    return 200, json.dumps({"bases": list(bases)}).encode()


BASES = bases_answer(BASE)


@dataclass
class FakeGit:
    """Answers git by subcommand. `fail` names a subcommand that exits 1; `answers`
    overrides stdout per subcommand."""

    git_path: str
    top: str = ""
    shallow: bool = False
    fail: set[str] = field(default_factory=set)
    answers: dict[str, bytes] = field(default_factory=dict)
    raises: dict[str, BaseException] = field(default_factory=dict)
    bundle: bytes = BUNDLE
    calls: list[tuple[list[str], str, float, dict[str, str]]] = field(default_factory=list)
    on_call: Callable[[], None] | None = None
    alternates: list[bytes] = field(default_factory=list)

    @staticmethod
    def words(argv: list[str]) -> list[str]:
        """argv after the fixed prefix and any --git-dir option."""
        rest = argv[1:]
        while rest and (rest[0].startswith("--no-") or rest[0] == "-c"):
            rest = rest[2:] if rest[0] == "-c" else rest[1:]
        return [w for w in rest if not w.startswith("--git-dir=")]

    def run(self, argv: list[str], cwd: str, timeout: float, env: Mapping[str, str]) -> Any:

        hc = __import__("sys").modules["_aigov_hook_client"]
        self.calls.append((list(argv), cwd, timeout, dict(env)))
        if self.on_call is not None:
            self.on_call()
        words = self.words(argv)
        sub = words[0]
        key = " ".join(words[:2]) if sub in ("config", "bundle") else sub
        if key in self.raises:
            raise self.raises[key]
        if key in self.fail or sub in self.fail:
            return hc.GitResult(1, b"")
        if key in self.answers:
            return hc.GitResult(0, self.answers[key])
        if sub == "rev-parse" and "--path-format=absolute" in words:
            return hc.GitResult(0, b"/repo/.git/objects\n")
        if sub == "rev-parse" and words[1] == "--show-toplevel":
            return hc.GitResult(0, self.top.encode() + b"\n")
        if sub == "rev-parse" and words[1] == "--is-shallow-repository":
            return hc.GitResult(0, b"true\n" if self.shallow else b"false\n")
        if sub == "rev-parse":
            ref = words[-1]
            known = {"refs/heads/feature^{commit}": HEAD, "HEAD^{commit}": HEAD,
                     f"{BASE}^{{commit}}": BASE, f"{OLDER}^{{commit}}": OLDER}  # fmt: skip
            return hc.GitResult(0, known[ref].encode()) if ref in known else hc.GitResult(1, b"")
        if key == "config --get-regexp":
            return hc.GitResult(1, b"")
        if sub == "remote":
            return hc.GitResult(0, REMOTE_URL.encode() + b"\n")
        if sub == "merge-base":
            return hc.GitResult(0, b"")
        if sub == "hash-object":
            return hc.GitResult(0, EMPTY_TREE.encode() + b"\n")
        if sub == "rev-list":
            return hc.GitResult(0, (HEAD + "\n" + OLDER + "\n").encode())
        if sub == "diff":
            return hc.GitResult(0, DIFF)
        if sub == "write-tree":
            return hc.GitResult(0, TREE.encode() + b"\n")
        if key == "config --get" or key == "config --get-all":
            return hc.GitResult(1, b"")
        if sub == "update-ref":
            bare = next(w for w in argv if w.startswith("--git-dir="))[len("--git-dir=") :]
            self.alternates.append((Path(bare) / "objects/info/alternates").read_bytes())
        if key == "bundle create":
            Path(words[3]).write_bytes(self.bundle)
        return hc.GitResult(0, b"")


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    path = tmp_path / "repo"
    path.mkdir()
    return path


@pytest.fixture
def git(git_exe: Path, repo: Path) -> FakeGit:
    return FakeGit(str(git_exe), top=str(repo))


@pytest.fixture
def env(environ: dict[str, str], hc: ModuleType) -> dict[str, str]:
    """The hook's environment: the managed pack's git configuration and nothing else."""
    return {**environ, **hc.managed_git_env(str(HOOKS_DIR)), "PATH": "/usr/bin"}


CONFIG: dict[str, Any] = {}


@pytest.fixture(autouse=True)
def _config(config: dict[str, Any]) -> None:
    CONFIG.clear()
    CONFIG.update(config)


@dataclass
class Clock:
    now: float = 100.0

    def __call__(self) -> float:
        return self.now


def run_push(
    hc: ModuleType,
    env: dict[str, str],
    transport: FakeTransport,
    git: FakeGit,
    repo: Path,
    *,
    clock: Clock | None = None,
    payload: dict[str, Any] | None = None,
    conf: dict[str, Any] | None = None,
    writable: Callable[[Path], bool] = never_writable,
) -> tuple[int, str, str]:
    data = dict(payload or PRE_TOOL_USE)
    data["cwd"] = str(repo)
    data.setdefault("tool_input", {"command": "git push origin feature"})
    stdout, stderr = io.StringIO(), io.StringIO()
    code = hc.main(
        ["hook_client.py", "decide"],
        stdin=io.BytesIO(json.dumps(data).encode()),
        stdout=stdout,
        stderr=stderr,
        environ=env,
        transport=transport,
        hostname=lambda: "WS-0142",
        is_windows=True,
        isolated=True,
        git_runner=git,
        monotonic=clock or Clock(),
        config_path=write_config(repo.parent, conf or CONFIG),
        writable=writable,
    )
    return code, stdout.getvalue(), stderr.getvalue()


def blocked(hc: ModuleType, result: tuple[int, str, str]) -> bool:
    code, _out, err = result
    return code == 2 and err.strip() == hc.PREPUSH_BLOCK_MESSAGE


# --- the upload flow -------------------------------------------------------------------


def test_a_push_is_uploaded_and_the_second_answer_applies(
    hc: ModuleType, env: dict[str, str], transport: FakeTransport, git: FakeGit, repo: Path
) -> None:
    transport.results += [(200, decide_answer("deny", NEEDS_PUSH)), BASES, UPLOADED,
                          (200, decide_answer("allow"))]  # fmt: skip
    code, out, _err = run_push(hc, env, transport, git, repo)
    assert (code, out) == (0, "")
    first, bases, upload, second = transport.calls
    assert bases.url == SERVICE_URL + "/v1/changes/bases"
    assert json.loads(bases.body) == {"repository": REMOTE_URL, "branch": "feature"}
    assert upload.url == SERVICE_URL + "/v1/changes"
    assert upload.headers["Authorization"].startswith("Bearer ")
    sent = json.loads(upload.body)
    assert sent == {
        "session_id": "sess-1",
        "kind": "push",
        "repository": REMOTE_URL,
        "remote": "origin",
        "branch": "feature",
        "source": "feature",
        "head": HEAD,
        "base": BASE,
        "commits": [HEAD, OLDER],
        "diff_b64": base64.b64encode(DIFF).decode(),
        "bundle_b64": base64.b64encode(BUNDLE).decode(),
    }
    again = json.loads(second.body)
    assert again.pop("change_id") == CHANGE_ID
    assert again.pop("change_head") == HEAD
    assert again == json.loads(first.body)


def test_the_change_is_built_from_the_pushed_branch_not_head(
    hc: ModuleType, env: dict[str, str], transport: FakeTransport, git: FakeGit, repo: Path
) -> None:
    transport.results += [(200, decide_answer("deny", NEEDS_PUSH)), BASES, UPLOADED,
                          (200, decide_answer("allow"))]  # fmt: skip
    run_push(hc, env, transport, git, repo)
    parsed = [FakeGit.words(argv) for argv, *_ in git.calls]
    assert ["rev-parse", "--verify", "--quiet", "--end-of-options",
            "refs/heads/feature^{commit}"] in parsed  # fmt: skip
    assert ["rev-list", "--max-count=1001", f"{BASE}..{HEAD}"] in parsed
    assert ["update-ref", "refs/heads/aigov", HEAD] in parsed
    assert not any(w[-1] == "HEAD^{commit}" for w in parsed)


def test_an_explicit_head_to_branch_push_is_built_from_head(
    hc: ModuleType, env: dict[str, str], transport: FakeTransport, git: FakeGit, repo: Path
) -> None:
    needs = {"kind": "push", "remote": "origin", "branch": "topic", "source": None}
    transport.results += [
        (200, decide_answer("deny", needs)),
        BASES,
        UPLOADED,
        (200, decide_answer("allow")),
    ]
    payload = {**PRE_TOOL_USE, "tool_input": {"command": "git push origin HEAD:topic"}}
    assert run_push(hc, env, transport, git, repo, payload=payload)[0] == 0
    parsed = [FakeGit.words(argv) for argv, *_ in git.calls]
    assert any(w[-1] == "HEAD^{commit}" for w in parsed)
    assert json.loads(transport.calls[2].body)["branch"] == "topic"


@pytest.mark.parametrize(
    "gitconfig",
    [
        {"config --get-regexp": b"remote.origin.mirror true\n"},
        {"config --get-regexp": b"remote.origin.push refs/heads/*:refs/heads/*\n"},
        {"config --get": b"matching\n"},  # push.default=matching
    ],
)
@pytest.mark.parametrize(
    "needs",
    [
        {"kind": "push", "remote": None, "branch": None, "source": None},
        {"kind": "push", "remote": "origin", "branch": None, "source": None},
        {"kind": "push", "remote": None, "branch": "feature", "source": "feature"},
    ],
)
def test_a_push_that_does_not_name_remote_and_branch_blocks(
    hc: ModuleType,
    env: dict[str, str],
    transport: FakeTransport,
    git: FakeGit,
    repo: Path,
    gitconfig: dict[str, bytes],
    needs: dict[str, Any],
) -> None:
    """Whatever the configuration says (mirror, push refspecs, push.default), a push that
    does not name its remote and branch is never built: the client blocks first."""
    git.answers.update(gitconfig)
    transport.results += [(200, decide_answer("deny", needs))]
    assert blocked(hc, run_push(hc, env, transport, git, repo))
    assert git.calls == []
    assert len(transport.calls) == 1


def test_a_commit_uploads_the_staged_diff_only(
    hc: ModuleType, env: dict[str, str], transport: FakeTransport, git: FakeGit, repo: Path
) -> None:
    transport.results += [(200, decide_answer("deny", {"kind": "commit"})), UPLOADED,
                          (200, decide_answer("allow"))]  # fmt: skip
    payload = {**PRE_TOOL_USE, "tool_input": {"command": "git commit -m x"}}
    assert run_push(hc, env, transport, git, repo, payload=payload)[0] == 0
    sent = json.loads(transport.calls[1].body)
    assert sent == {"session_id": "sess-1", "kind": "commit", "head": TREE, "base": HEAD,
                    "diff_b64": base64.b64encode(DIFF).decode()}  # fmt: skip
    diffs = [(FakeGit.words(argv), cwd) for argv, cwd, *_ in git.calls if "diff" in argv]
    assert diffs == [
        (["diff", "--no-ext-diff", "--no-textconv", "--no-color", "--no-renames", "--cached"],
         str(repo))
    ]  # fmt: skip


def test_a_deny_after_the_upload_is_shown_to_the_engineer(
    hc: ModuleType, env: dict[str, str], transport: FakeTransport, git: FakeGit, repo: Path
) -> None:
    held = json.dumps({"verdict": "deny", "decision_id": "dec_2", "reason": "checks_pending",
                       "message": "Held: retry in a minute"}).encode()  # fmt: skip
    transport.results += [(200, decide_answer("deny", NEEDS_PUSH)), BASES, UPLOADED, (200, held)]
    code, out, _err = run_push(hc, env, transport, git, repo)
    assert code == 0
    reason = json.loads(out)["hookSpecificOutput"]["permissionDecisionReason"]
    assert reason == "Held: retry in a minute (AI-governance decision dec_2)"


def test_needs_change_outside_pre_tool_use_is_just_a_deny(
    hc: ModuleType, env: dict[str, str], transport: FakeTransport, git: FakeGit, repo: Path
) -> None:
    transport.results += [(200, decide_answer("deny", NEEDS_PUSH))]
    prompt = {"session_id": "sess-1", "cwd": "/x", "hook_event_name": "UserPromptSubmit",
              "prompt": "hi"}  # fmt: skip
    code, out, _err = run_push(hc, env, transport, git, repo, payload=prompt)
    assert code == 0
    assert json.loads(out)["decision"] == "block"
    assert git.calls == []


# --- every failure blocks --------------------------------------------------------------


@pytest.mark.parametrize(
    "breakage",
    [
        {"fail": {"rev-parse"}},  # source branch does not resolve
        {"answers": {"rev-list": b""}},  # nothing to push
        {"answers": {"rev-list": ("\n".join(["5" * 40] * 1001)).encode()}},  # too many
        {"answers": {"rev-list": b"not-a-commit\n"}},
        {"fail": {"diff"}},
        {"answers": {"diff": b"x" * (4 * 1024 * 1024 + 1)}},
        {"fail": {"init"}},
        {"fail": {"bundle create"}},
        {"bundle": b"x" * (32 * 1024 * 1024 + 1)},
        {"raises": {"diff": "timeout"}},
        {"raises": {"rev-list": "unavailable"}},
    ],
)
def test_every_git_failure_blocks(
    hc: ModuleType,
    env: dict[str, str],
    transport: FakeTransport,
    git: FakeGit,
    repo: Path,
    breakage: dict[str, Any],
) -> None:
    for name, value in breakage.items():
        if name == "raises":
            value = {k: hc.ClientError(f"git_{v}") for k, v in value.items()}
        setattr(git, name, value)
    transport.results += [(200, decide_answer("deny", NEEDS_PUSH))]
    transport.results += [BASES]
    assert blocked(hc, run_push(hc, env, transport, git, repo))
    assert "/v1/changes" not in [c.url[len(SERVICE_URL) :] for c in transport.calls]


@pytest.mark.parametrize(
    "upload",
    [
        (503, b"{}"),
        (200, json.dumps({"change_id": CHANGE_ID}).encode()),  # not 201
        (201, b"not json"),
        (201, json.dumps({"change_id": "chg_bad"}).encode()),
        (201, json.dumps(["x"]).encode()),
        OSError("connection refused"),
    ],
)
def test_every_upload_failure_blocks(
    hc: ModuleType,
    env: dict[str, str],
    transport: FakeTransport,
    git: FakeGit,
    repo: Path,
    upload: Any,
) -> None:
    transport.results += [(200, decide_answer("deny", NEEDS_PUSH)), BASES, upload]
    assert blocked(hc, run_push(hc, env, transport, git, repo))
    assert len(transport.calls) == 3  # no second decide


@pytest.mark.parametrize(
    "second", [(500, b"{}"), (200, b"{}"), (200, b"not json"), TimeoutError("slow")]
)
def test_a_bad_second_answer_blocks(
    hc: ModuleType,
    env: dict[str, str],
    transport: FakeTransport,
    git: FakeGit,
    repo: Path,
    second: Any,
) -> None:
    transport.results += [(200, decide_answer("deny", NEEDS_PUSH)), BASES, UPLOADED, second]
    assert blocked(hc, run_push(hc, env, transport, git, repo))


@pytest.mark.parametrize(
    "needs",
    [
        {"kind": "rebase"},
        {"kind": "rebase", "remote": "origin", "branch": "feature", "source": "feature"},
        {"kind": "push", "remote": "-oops"},
        {"kind": "push", "branch": "a b"},
        {"kind": "push", "extra": 1},
        "push",
    ],
)
def test_a_malformed_needs_change_blocks(
    hc: ModuleType,
    env: dict[str, str],
    transport: FakeTransport,
    git: FakeGit,
    repo: Path,
    needs: Any,
) -> None:
    transport.results += [(200, decide_answer("deny", needs))]
    code, _out, _err = run_push(hc, env, transport, git, repo)
    assert code == 2
    assert git.calls == []


@pytest.mark.parametrize(
    "change",
    [
        {"git_path_missing": True},
        {"git_path_dir": True},  # a directory, not a file
    ],
)
def test_an_unusable_git_path_blocks(
    hc: ModuleType,
    env: dict[str, str],
    transport: FakeTransport,
    git: FakeGit,
    repo: Path,
    change: dict[str, Any],
) -> None:
    conf = dict(CONFIG)
    conf["git_path"] = str(repo) if "git_path_dir" in change else str(repo / "no-git.exe")
    transport.results += [(200, decide_answer("deny", NEEDS_PUSH))]
    assert blocked(hc, run_push(hc, env, transport, git, repo, conf=conf))
    assert git.calls == []


@pytest.mark.parametrize(("key", "value"), [("git_path", "git"), ("hook_deadline_seconds", 0)])
def test_a_bad_pre_push_setting_blocks_before_anything_is_sent(
    hc: ModuleType,
    env: dict[str, str],
    transport: FakeTransport,
    git: FakeGit,
    repo: Path,
    key: str,
    value: Any,
) -> None:
    """A relative git (looked up in PATH or the cwd) or no deadline: the whole
    configuration file is refused, so even the first decide is not sent."""
    code, _out, _err = run_push(hc, env, transport, git, repo, conf={**CONFIG, key: value})
    assert code == 2
    assert transport.calls == []
    assert git.calls == []


def test_a_user_writable_git_blocks(
    hc: ModuleType, env: dict[str, str], transport: FakeTransport, git: FakeGit, repo: Path
) -> None:
    transport.results += [(200, decide_answer("deny", NEEDS_PUSH))]
    writable = lambda p: str(p) == git.git_path  # noqa: E731
    assert blocked(hc, run_push(hc, env, transport, git, repo, writable=writable))
    assert git.calls == []


def test_a_cwd_that_is_not_a_directory_blocks(
    hc: ModuleType, env: dict[str, str], transport: FakeTransport, git: FakeGit, tmp_path: Path
) -> None:
    transport.results += [(200, decide_answer("deny", NEEDS_PUSH))]
    assert blocked(hc, run_push(hc, env, transport, git, tmp_path / "missing"))
    assert git.calls == []


# --- deadline --------------------------------------------------------------------------


def test_every_step_fits_inside_the_deadline(
    hc: ModuleType, env: dict[str, str], transport: FakeTransport, git: FakeGit, repo: Path
) -> None:
    clock = Clock()
    git.on_call = lambda: setattr(clock, "now", clock.now + 0.5)  # each git step: 0.5 s
    transport.results += [(200, decide_answer("deny", NEEDS_PUSH)), BASES, UPLOADED,
                          (200, decide_answer("allow"))]  # fmt: skip
    assert run_push(hc, env, transport, git, repo, clock=clock)[0] == 0
    timeouts = [t for _argv, _cwd, t, _env in git.calls]
    assert all(0 < t <= 10.0 for t in timeouts)
    assert clock.now - 100 < 14  # the whole run stayed inside the deadline


def test_a_run_that_would_overrun_the_deadline_blocks(
    hc: ModuleType, env: dict[str, str], transport: FakeTransport, git: FakeGit, repo: Path
) -> None:
    clock = Clock()
    git.on_call = lambda: setattr(clock, "now", clock.now + 4.0)  # slow repository
    transport.results += [(200, decide_answer("deny", NEEDS_PUSH))]
    assert blocked(hc, run_push(hc, env, transport, git, repo, clock=clock))
    assert len(git.calls) <= 4
    assert len(transport.calls) == 1


def test_the_upload_timeout_is_cut_to_what_is_left(
    hc: ModuleType, env: dict[str, str], transport: FakeTransport, git: FakeGit, repo: Path
) -> None:
    clock = Clock()
    conf = {**CONFIG, "hook_deadline_seconds": 5}
    transport.results += [(200, decide_answer("deny", NEEDS_PUSH)), BASES, UPLOADED,
                          (200, decide_answer("allow"))]  # fmt: skip
    git.on_call = lambda: setattr(clock, "now", clock.now + 0.2)
    run_push(hc, env, transport, git, repo, clock=clock, conf=conf)
    assert transport.calls[2].timeout < 8.0  # the configured decide timeout was cut


# --- git is run safely -----------------------------------------------------------------


def test_git_runs_from_a_fixed_argv_with_the_admin_git_and_no_git_environment(
    hc: ModuleType, env: dict[str, str], transport: FakeTransport, git: FakeGit, repo: Path
) -> None:
    transport.results += [(200, decide_answer("deny", NEEDS_PUSH)), BASES, UPLOADED,
                          (200, decide_answer("allow"))]  # fmt: skip
    run_push(hc, env, transport, git, repo)
    assert git.calls
    for argv, cwd, _timeout, git_env in git.calls:
        assert isinstance(argv, list)
        assert argv[0] == git.git_path
        safe = list(hc.GIT_SAFE_OPTIONS)
        assert argv[1 : 1 + len(safe)] == safe
        rest = argv[1 + len(safe) :]
        assert rest[0] == "-c"
        assert rest[1].startswith("core.hooksPath=")
        for needed in (
            "--no-replace-objects",
            "diff.relative=false",
            "diff.noprefix=false",
            "diff.mnemonicPrefix=false",
            "diff.external=",
            "core.fsmonitor=false",
        ):
            assert needed in safe  # fmt: skip
        assert not any(name.upper().startswith("GIT_DIR") for name in git_env)
        if git_env.get("GIT_CONFIG_NOSYSTEM") is None:  # the push-configuration read
            assert FakeGit.words(argv)[:2] in (["config", "--get-regexp"], ["remote", "get-url"])
        else:
            assert git_env["GIT_NO_REPLACE_OBJECTS"] == "1"
            assert git_env["GIT_CONFIG_GLOBAL"].endswith("empty-gitconfig")
        assert git_env["GIT_TERMINAL_PROMPT"] == "0"
        assert cwd in (str(repo), str(Path(cwd)))


def test_the_real_runner_never_uses_a_shell(
    hc: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    seen: dict[str, Any] = {}

    def fake_run(argv: Any, **kwargs: Any) -> Any:
        seen["argv"] = argv
        seen.update(kwargs)
        kwargs["stdout"].write(b"abc")
        return subprocess.CompletedProcess(argv, 0)

    monkeypatch.setattr(hc.subprocess, "run", fake_run)
    result = hc.SubprocessGitRunner().run(["/usr/bin/git", "status"], "/repo", 3.0, {"A": "1"})
    assert (result.returncode, result.stdout) == (0, b"abc")
    assert seen["argv"] == ["/usr/bin/git", "status"]
    assert seen["shell"] is False
    assert seen["timeout"] == 3.0
    assert seen["stdin"] is subprocess.DEVNULL


@pytest.mark.parametrize(
    ("error", "code"),
    [
        (subprocess.TimeoutExpired(["git"], 1), "git_timeout"),
        (OSError("no git"), "git_unavailable"),
    ],
)
def test_the_real_runner_turns_errors_into_client_errors(
    hc: ModuleType, monkeypatch: pytest.MonkeyPatch, error: BaseException, code: str
) -> None:
    def fake_run(argv: Any, **kwargs: Any) -> Any:
        raise error

    monkeypatch.setattr(hc.subprocess, "run", fake_run)
    with pytest.raises(hc.ClientError) as caught:
        hc.SubprocessGitRunner().run(["/usr/bin/git"], "/repo", 1.0, {})
    assert caught.value.code == code


def test_the_request_cap_matches_the_service(hc: ModuleType) -> None:
    assert hc.MAX_CHANGE_REQUEST_BYTES == MAX_CHANGE_BODY_BYTES


def test_the_scratch_repository_borrows_the_objects_with_an_exact_path(
    hc: ModuleType, env: dict[str, str], transport: FakeTransport, git: FakeGit, repo: Path
) -> None:
    """Measured in the real run: a text-mode write on Windows ended the alternates line
    with CR, git read a path ending in CR and every bundle failed."""
    transport.results += [(200, decide_answer("deny", NEEDS_PUSH)), BASES, UPLOADED,
                          (200, decide_answer("allow"))]  # fmt: skip
    assert run_push(hc, env, transport, git, repo)[0] == 0
    assert git.alternates == [b"/repo/.git/objects\n"]
