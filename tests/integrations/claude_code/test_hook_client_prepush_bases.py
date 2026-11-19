"""Pre-push, reviews H1, H2, Q17, L3: the scan base comes from the heads the service has
approved (never from local remote-tracking refs), a repository whose configuration
changes where or how the push goes is refused, and a busy device is told to retry."""

# ruff: noqa: F401, F811
# (the pre-push fixtures are imported from their module by name)

from __future__ import annotations

import base64
import json
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest
from tests.integrations.claude_code.conftest import SERVICE_URL, FakeTransport
from tests.integrations.claude_code.test_hook_client_prepush import (
    BASE,
    BASES,
    DIFF,
    EMPTY_TREE,
    HEAD,
    NEEDS_PUSH,
    OLDER,
    UPLOADED,
    FakeGit,
    _config,
    bases_answer,
    decide_answer,
    env,
    git,
    repo,
    run_push,
)

pytestmark = pytest.mark.unit

ALLOWED = (200, decide_answer("allow"))


def words(git: FakeGit) -> list[list[str]]:
    return [FakeGit.words(argv) for argv, *_ in git.calls]


def refused_with(hc: ModuleType, result: tuple[int, str, str], code: str) -> bool:
    exit_code, _out, err = result
    return exit_code == 2 and err.strip() == hc.PREPUSH_MESSAGES[code]


def upload_body(transport: FakeTransport) -> dict[str, Any]:
    found = [c for c in transport.calls if c.url == SERVICE_URL + "/v1/changes"]
    assert len(found) == 1
    body: dict[str, Any] = json.loads(found[0].body)
    return body


def test_an_approved_ancestor_is_the_base(
    hc: ModuleType, env: dict[str, str], transport: FakeTransport, git: FakeGit, repo: Path
) -> None:
    transport.results += [(200, decide_answer("deny", NEEDS_PUSH)), bases_answer(OLDER, BASE),
                          UPLOADED, ALLOWED]  # fmt: skip
    assert run_push(hc, env, transport, git, repo)[0] == 0
    assert upload_body(transport)["base"] == OLDER
    assert ["merge-base", "--is-ancestor", OLDER, HEAD] in words(git)


def test_no_approved_base_scans_from_the_root(
    hc: ModuleType, env: dict[str, str], transport: FakeTransport, git: FakeGit, repo: Path
) -> None:
    """Reviewer's H1 sequence: whatever refs/remotes/origin/* says, with no approved head
    the whole history is listed and diffed against the empty tree."""
    transport.results += [(200, decide_answer("deny", NEEDS_PUSH)), bases_answer(),
                          UPLOADED, ALLOWED]  # fmt: skip
    assert run_push(hc, env, transport, git, repo)[0] == 0
    body = upload_body(transport)
    assert body["base"] is None
    assert body["commits"] == [HEAD, OLDER]
    assert base64.b64decode(body["diff_b64"]) == DIFF
    parsed = words(git)
    assert ["rev-list", "--max-count=1001", HEAD] in parsed
    assert any(w[:1] == ["diff"] and w[-2:] == [EMPTY_TREE, HEAD] for w in parsed)


def test_local_remote_tracking_refs_play_no_part(
    hc: ModuleType, env: dict[str, str], transport: FakeTransport, git: FakeGit, repo: Path
) -> None:
    transport.results += [(200, decide_answer("deny", NEEDS_PUSH)), BASES, UPLOADED, ALLOWED]
    assert run_push(hc, env, transport, git, repo)[0] == 0
    assert not any("refs/remotes" in w for argv, *_ in git.calls for w in argv)


def test_a_listed_base_that_is_not_an_ancestor_is_skipped(
    hc: ModuleType, env: dict[str, str], transport: FakeTransport, git: FakeGit, repo: Path
) -> None:
    git.fail.add("merge-base")  # exit 1: not an ancestor
    transport.results += [(200, decide_answer("deny", NEEDS_PUSH)), BASES, UPLOADED, ALLOWED]
    assert run_push(hc, env, transport, git, repo)[0] == 0
    assert upload_body(transport)["base"] is None


def test_a_listed_base_unknown_here_is_skipped(
    hc: ModuleType, env: dict[str, str], transport: FakeTransport, git: FakeGit, repo: Path
) -> None:
    transport.results += [(200, decide_answer("deny", NEEDS_PUSH)), bases_answer("9" * 40),
                          UPLOADED, ALLOWED]  # fmt: skip
    assert run_push(hc, env, transport, git, repo)[0] == 0
    assert upload_body(transport)["base"] is None
    assert not any(w[:1] == ["merge-base"] for w in words(git))


def test_more_than_1000_unscanned_commits_block_with_a_message(
    hc: ModuleType, env: dict[str, str], transport: FakeTransport, git: FakeGit, repo: Path
) -> None:
    git.answers["rev-list"] = ("\n".join(["5" * 40] * 1001)).encode()
    transport.results += [(200, decide_answer("deny", NEEDS_PUSH)), bases_answer()]
    assert refused_with(hc, run_push(hc, env, transport, git, repo), "too_many_unscanned")
    assert len(transport.calls) == 2  # nothing uploaded


@pytest.mark.parametrize(
    "answer",
    [
        (500, b"{}"),
        (200, b"not json"),
        (200, json.dumps({"bases": ["main"]}).encode()),
        (200, json.dumps({"bases": ["a" * 40] * 65}).encode()),
        (200, json.dumps({"other": []}).encode()),
        OSError("refused"),
    ],
)
def test_a_bad_bases_answer_blocks(
    hc: ModuleType,
    env: dict[str, str],
    transport: FakeTransport,
    git: FakeGit,
    repo: Path,
    answer: Any,
) -> None:
    transport.results += [(200, decide_answer("deny", NEEDS_PUSH)), answer]
    code, _out, err = run_push(hc, env, transport, git, repo)
    assert (code, err.strip()) == (2, hc.PREPUSH_BLOCK_MESSAGE)
    assert len(transport.calls) == 2


@pytest.mark.parametrize(
    ("url", "sent"),
    [
        ("https://user:pw@git.example.test/a.git", "https://git.example.test/a.git"),
        ("ssh://git@git.example.test/a.git", "ssh://git.example.test/a.git"),
        ("git@git.example.test:team/a.git", "git@git.example.test:team/a.git"),
    ],
)
def test_the_repository_is_sent_without_credentials(
    hc: ModuleType,
    env: dict[str, str],
    transport: FakeTransport,
    git: FakeGit,
    repo: Path,
    url: str,
    sent: str,
) -> None:
    git.answers["remote"] = url.encode() + b"\n"
    transport.results += [(200, decide_answer("deny", NEEDS_PUSH)), BASES, UPLOADED, ALLOWED]
    assert run_push(hc, env, transport, git, repo)[0] == 0
    assert json.loads(transport.calls[1].body)["repository"] == sent
    assert upload_body(transport)["repository"] == sent


def test_a_repository_that_redirects_the_push_is_refused(
    hc: ModuleType, env: dict[str, str], transport: FakeTransport, git: FakeGit, repo: Path
) -> None:
    git.answers["config --get-regexp"] = b"remote.origin.pushurl https://elsewhere/x.git\n"
    transport.results += [(200, decide_answer("deny", NEEDS_PUSH))]
    assert refused_with(hc, run_push(hc, env, transport, git, repo), "push_config")
    assert len(transport.calls) == 1


@pytest.mark.parametrize("name", ["GIT_SSH_COMMAND", "GIT_SSH", "GIT_PROXY_COMMAND"])
def test_a_transport_variable_in_the_environment_is_refused(
    hc: ModuleType,
    env: dict[str, str],
    transport: FakeTransport,
    git: FakeGit,
    repo: Path,
    name: str,
) -> None:
    transport.results += [(200, decide_answer("deny", NEEDS_PUSH))]
    result = run_push(hc, {**env, name: "x"}, transport, git, repo)
    assert refused_with(hc, result, "push_config")


def test_an_unreadable_configuration_blocks(
    hc: ModuleType, env: dict[str, str], transport: FakeTransport, git: FakeGit, repo: Path
) -> None:
    git.raises["config --get-regexp"] = hc.ClientError("git_timeout")
    transport.results += [(200, decide_answer("deny", NEEDS_PUSH))]
    code, _out, err = run_push(hc, env, transport, git, repo)
    assert (code, err.strip()) == (2, hc.PREPUSH_BLOCK_MESSAGE)


def test_a_shallow_clone_is_refused(
    hc: ModuleType, env: dict[str, str], transport: FakeTransport, git: FakeGit, repo: Path
) -> None:
    git.shallow = True
    transport.results += [(200, decide_answer("deny", NEEDS_PUSH))]
    assert refused_with(hc, run_push(hc, env, transport, git, repo), "shallow_repository")
    assert len(transport.calls) == 1


def test_a_busy_device_is_told_to_retry(
    hc: ModuleType, env: dict[str, str], transport: FakeTransport, git: FakeGit, repo: Path
) -> None:
    busy = (409, json.dumps({"error": "device_busy", "message": "busy"}).encode())
    transport.results += [(200, decide_answer("deny", NEEDS_PUSH)), BASES, busy]
    assert refused_with(hc, run_push(hc, env, transport, git, repo), "device_busy")


def test_another_409_is_the_generic_block(
    hc: ModuleType, env: dict[str, str], transport: FakeTransport, git: FakeGit, repo: Path
) -> None:
    other = (409, json.dumps({"error": "conflict"}).encode())
    transport.results += [(200, decide_answer("deny", NEEDS_PUSH)), BASES, other]
    code, _out, err = run_push(hc, env, transport, git, repo)
    assert (code, err.strip()) == (2, hc.PREPUSH_BLOCK_MESSAGE)


def test_the_report_id_is_one_per_run_and_reused_by_the_second_decide(
    hc: ModuleType, env: dict[str, str], transport: FakeTransport, git: FakeGit, repo: Path
) -> None:
    transport.results += [(200, decide_answer("deny", NEEDS_PUSH)), BASES, UPLOADED, ALLOWED]
    run_push(hc, env, transport, git, repo)
    first = json.loads(transport.calls[0].body)["report_id"]
    second = json.loads(transport.calls[3].body)["report_id"]
    assert first == second
    assert len(first) == 32
    transport.results += [(200, decide_answer("allow"))]
    run_push(hc, env, transport, git, repo)
    assert json.loads(transport.calls[4].body)["report_id"] != first
