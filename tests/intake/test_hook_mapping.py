"""Mapping a hook report to an `ObservedAction`: kind, phase, target, ids, content."""

from __future__ import annotations

import hashlib
from typing import Any

import pytest
from tests.fakes.core import FakeRedactor
from tests.intake.conftest import (
    DEVICE_ACTOR,
    RECEIVED_AT,
    envelope,
    hook_payload_post_write,
    hook_payload_pre_bash,
    hook_payload_prompt,
    hook_payload_session_end,
    hook_payload_session_start,
    hook_payload_subagent_start,
    pre_tool,
)

from ciso.common.activity import MAX_COMMAND_CHARS, ActionKind, Phase
from ciso.intake import IntakeRefused, NormalizedReport, RefusalCode, normalize_hook_report

pytestmark = pytest.mark.unit


def normalize(request: dict[str, Any]) -> NormalizedReport:
    return normalize_hook_report(
        request, device_actor_id=DEVICE_ACTOR, received_at=RECEIVED_AT, redactor=FakeRedactor()
    )


def bash(command: str) -> NormalizedReport:
    return normalize(pre_tool("Bash", {"command": command}))


@pytest.mark.parametrize(
    ("tool_name", "tool_input", "kind"),
    [
        ("Bash", {"command": "ls"}, ActionKind.SHELL_COMMAND),
        ("Write", {"file_path": "/a/b.txt", "content": "x"}, ActionKind.FILE_WRITE),
        (
            "Edit",
            {"file_path": "/a/b.txt", "old_string": "a", "new_string": "b"},
            ActionKind.FILE_EDIT,
        ),
        (
            "MultiEdit",
            {"file_path": "/a/b.txt", "edits": [{"old_string": "a", "new_string": "b"}]},
            ActionKind.FILE_EDIT,
        ),
        ("Read", {"file_path": "/a/b.txt"}, ActionKind.FILE_READ),
        ("Grep", {"pattern": "TODO.*fix", "path": "/a"}, ActionKind.FILE_READ),
        ("Glob", {"pattern": "**/*.ts"}, ActionKind.FILE_READ),
        ("mcp__memory__create_entities", {}, ActionKind.CONNECTOR_CALL),
        ("WebFetch", {"url": "https://example.com/api", "prompt": "x"}, ActionKind.WEB_FETCH),
        ("WebSearch", {"query": "react hooks best practices"}, ActionKind.WEB_FETCH),
        (
            "Agent",
            {"prompt": "Find all API endpoints", "subagent_type": "Explore"},
            ActionKind.SUBAGENT,
        ),
        ("Task", {"prompt": "Find all API endpoints"}, ActionKind.SUBAGENT),
        ("NotebookEdit", {"cell": 1}, ActionKind.OTHER_TOOL),
        ("SomethingNew", {}, ActionKind.OTHER_TOOL),
        ("mcp__broken", {}, ActionKind.OTHER_TOOL),
    ],
)
def test_tool_name_maps_to_kind(
    tool_name: str, tool_input: dict[str, Any], kind: ActionKind
) -> None:
    action = normalize(pre_tool(tool_name, tool_input)).action
    assert action.kind is kind
    assert action.tool_name == tool_name
    assert action.phase is Phase.BEFORE


@pytest.mark.parametrize(
    ("tool_name", "server"),
    [
        ("mcp__memory__create_entities", "memory"),
        ("mcp__brave-search__web", "brave-search"),
        ("mcp__plugin_my-plugin_db__query", "plugin_my-plugin_db"),
    ],
)
def test_connector_server_is_taken_from_the_tool_name(tool_name: str, server: str) -> None:
    assert normalize(pre_tool(tool_name, {})).action.target["server"] == server


@pytest.mark.parametrize(
    ("event_payload", "kind", "phase"),
    [
        (hook_payload_prompt, ActionKind.PROMPT, Phase.BEFORE),
        (hook_payload_session_start, ActionKind.SESSION_START, Phase.AFTER),
        (hook_payload_session_end, ActionKind.SESSION_END, Phase.AFTER),
        (hook_payload_subagent_start, ActionKind.SUBAGENT, Phase.AFTER),
        (hook_payload_post_write, ActionKind.FILE_WRITE, Phase.AFTER),
    ],
)
def test_event_maps_to_kind_and_phase(event_payload: Any, kind: ActionKind, phase: Phase) -> None:
    action = normalize(envelope(event_payload())).action
    assert (action.kind, action.phase) == (kind, phase)


def test_stop_is_recorded_after_as_other_tool() -> None:
    payload = {
        "session_id": "abc123",
        "cwd": "/Users/...",
        "hook_event_name": "Stop",
        "prompt_id": "550e8400-e29b-41d4-a716-446655440000",
        "stop_hook_active": False,
        "last_assistant_message": "done",
    }
    action = normalize(envelope(payload)).action
    assert (action.kind, action.phase) == (ActionKind.OTHER_TOOL, Phase.AFTER)
    assert action.target["event"] == "Stop"
    assert "done" not in action.model_dump_json()


def test_subagent_start_records_the_agent_type() -> None:
    assert (
        normalize(envelope(hook_payload_subagent_start())).action.target["agent_type"] == "Explore"
    )


def test_subagent_tool_records_the_requested_type() -> None:
    action = normalize(pre_tool("Agent", {"prompt": "p", "subagent_type": "Explore"})).action
    assert action.target["agent_type"] == "Explore"


# --- action ids -----------------------------------------------------------------------


def test_a_retried_report_is_the_same_action() -> None:
    first = normalize(envelope(hook_payload_pre_bash())).action.action_id
    again = normalize(envelope(hook_payload_pre_bash())).action.action_id
    assert first == again
    assert first.startswith("hk_")


def test_action_id_depends_on_session_tool_use_and_event() -> None:
    base = normalize(envelope(hook_payload_pre_bash())).action.action_id
    other_use = hook_payload_pre_bash()
    other_use["tool_use_id"] = "toolu_01OTHER"
    other_session = hook_payload_pre_bash()
    other_session["session_id"] = "def456"
    post = hook_payload_pre_bash()
    post["hook_event_name"] = "PostToolUse"
    ids = {normalize(envelope(p)).action.action_id for p in (other_use, other_session, post)}
    assert base not in ids
    assert len(ids) == 3


def test_prompt_action_id_comes_from_the_prompt_id() -> None:
    first = normalize(envelope(hook_payload_prompt())).action.action_id
    payload = hook_payload_prompt()
    payload["prompt"] = "different text, same prompt id"
    assert normalize(envelope(payload)).action.action_id == first
    payload["prompt_id"] = "660e8400-e29b-41d4-a716-446655440000"
    assert normalize(envelope(payload)).action.action_id != first


def test_subagent_start_needs_an_agent_id() -> None:
    payload = hook_payload_subagent_start()
    del payload["agent_id"]
    with pytest.raises(IntakeRefused) as info:
        normalize(envelope(payload))
    assert info.value.code is RefusalCode.MISSING_CORRELATION_ID


# --- targets --------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("cwd", "repository"),
    [
        ("/home/user/my-project", "my-project"),
        ("/home/user/my-project/", "my-project"),
        ("C:\\Users\\jdoe\\Projects\\CISO_AG", "CISO_AG"),
    ],
)
def test_repository_is_the_last_component_of_cwd(cwd: str, repository: str) -> None:
    payload = hook_payload_pre_bash()
    payload["cwd"] = cwd
    target = normalize(envelope(payload)).action.target
    assert target["repository"] == repository
    assert "jdoe" not in str(dict(target))


def test_root_cwd_gives_no_repository() -> None:
    payload = hook_payload_pre_bash()
    payload["cwd"] = "/"
    assert "repository" not in normalize(envelope(payload)).action.target


def test_file_path_inside_cwd_is_kept_relative() -> None:
    request = pre_tool("Write", {"file_path": "/home/user/my-project/src/a.py", "content": "x"})
    assert normalize(request).action.target["path"] == "src/a.py"


def test_windows_file_path_inside_cwd_is_kept_relative() -> None:
    payload = hook_payload_pre_bash()
    payload["cwd"] = "C:\\Users\\jdoe\\repo"
    payload["tool_name"] = "Read"
    payload["tool_input"] = {"file_path": "C:\\Users\\jdoe\\repo\\src\\a.py"}
    assert normalize(envelope(payload)).action.target["path"] == "src\\a.py"


def test_file_path_outside_cwd_is_kept_in_full() -> None:
    request = pre_tool("Write", {"file_path": "/etc/hosts", "content": "x"})
    assert normalize(request).action.target["path"] == "/etc/hosts"


def test_a_sibling_directory_with_a_shared_prefix_is_outside() -> None:
    request = pre_tool("Write", {"file_path": "/home/user/my-project-evil/a", "content": "x"})
    assert normalize(request).action.target["path"] == "/home/user/my-project-evil/a"


def test_web_fetch_keeps_only_the_host() -> None:
    request = pre_tool(
        "WebFetch", {"url": "https://user:pw@Example.COM:8443/api?token=abc", "prompt": "x"}
    )
    target = normalize(request).action.target
    assert target["host"] == "example.com"
    assert "token" not in str(dict(target))
    assert "pw" not in str(dict(target))


def test_unclean_path_is_refused() -> None:
    request = pre_tool("Write", {"file_path": "/a/\nb", "content": "x"})
    with pytest.raises(IntakeRefused) as info:
        normalize(request)
    assert info.value.code is RefusalCode.INVALID_FIELD


@pytest.mark.parametrize(
    ("tool_name", "tool_input"),
    [
        ("Bash", {}),
        ("Bash", {"command": 5}),
        ("Write", {"file_path": "/a"}),
        ("Write", {"content": "x"}),
        ("Edit", {"file_path": "/a", "old_string": "a"}),
        ("MultiEdit", {"file_path": "/a", "edits": "x"}),
        ("MultiEdit", {"file_path": "/a", "edits": [{"old_string": "a"}]}),
        ("Read", {}),
        ("Grep", {"pattern": "x", "path": 3}),
        ("WebFetch", {"prompt": "x"}),
        ("Agent", {"prompt": 3}),
    ],
)
def test_malformed_tool_input_is_refused(tool_name: str, tool_input: dict[str, Any]) -> None:
    with pytest.raises(IntakeRefused) as info:
        normalize(pre_tool(tool_name, tool_input))
    assert info.value.code is RefusalCode.MALFORMED_TOOL_INPUT


#: Target attributes every hook report carries regardless of the command.
CONTEXT_KEYS = frozenset({"repository", "device"})


# --- git ------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("command", "kind", "target"),
    [
        ("git push", ActionKind.GIT_PUSH, {}),
        ("git push origin main", ActionKind.GIT_PUSH, {"remote": "origin", "branch": "main"}),
        (
            "git push -u origin feature/x",
            ActionKind.GIT_PUSH,
            {"remote": "origin", "branch": "feature/x"},
        ),
        (
            "git push --force origin HEAD:refs/heads/main",
            ActionKind.GIT_PUSH,
            {"remote": "origin", "branch": "main", "force": "true"},
        ),
        (
            "git push origin +dev",
            ActionKind.GIT_PUSH,
            {"remote": "origin", "branch": "dev", "force": "true"},
        ),
        (
            "git -C repo push origin main",
            ActionKind.GIT_PUSH,
            {"remote": "origin", "branch": "main"},
        ),
        (
            "git push https://user:tok3n@git.example.com/r.git main",
            ActionKind.GIT_PUSH,
            {"remote": "https://git.example.com/r.git", "branch": "main"},
        ),
        ('git commit -m "fix: thing (x)"', ActionKind.GIT_COMMIT, {}),
        ("git commit --amend", ActionKind.GIT_COMMIT, {}),
        ("git status", ActionKind.SHELL_COMMAND, {}),
        ("cd repo && git push origin main", ActionKind.SHELL_COMMAND, {}),
        ("git push origin main; rm -rf x", ActionKind.SHELL_COMMAND, {}),
        ("git status\ngit push origin main", ActionKind.SHELL_COMMAND, {}),
        ("git push origin `whoami`", ActionKind.SHELL_COMMAND, {}),
        ("git push origin dev main", ActionKind.SHELL_COMMAND, {}),
        ("git push --all origin", ActionKind.SHELL_COMMAND, {}),
        ("git push --mirror", ActionKind.SHELL_COMMAND, {}),
        ("git push 'unbalanced", ActionKind.SHELL_COMMAND, {}),
        ("echo git push", ActionKind.SHELL_COMMAND, {}),
    ],
)
def test_git_refinement_only_when_plain(
    command: str, kind: ActionKind, target: dict[str, str]
) -> None:
    action = bash(command).action
    assert action.kind is kind
    stated = {k: v for k, v in action.target.items() if k not in CONTEXT_KEYS}
    assert stated == target


#: Commands that must NOT be refined: refinement is a hint, and when in doubt the intake
#: hands governance the less specific `shell_command` (coordinator security finding).
EVASIONS = [
    # (1) shell expansion or quoting-sensitive characters
    "git push origin $BRANCH",
    "git push origin ${BRANCH}",
    'git push origin "$(echo main)"',
    'git commit -m "$(cat msg)"',
    "git push origin `echo main`",
    "git push origin ma\\in",
    "git push origin !main",
    "git push origin ma*",
    "git push origin ma?n",
    "git push origin [m]ain",
    "git push origin {main,dev}",
    "git push ~/repo main",
    "git push origin main\r",
    "git push origin main\ngit push origin prod",
    # compound commands where only the operator check stands between them and a refinement
    "git commit -m wip && make deploy",
    "git commit -m wip || true",
    "git push & evil",
    # (2) global options other than -C <dir>
    "git -c core.sshCommand=evil push origin main",
    "git -c user.name=x commit --amend",
    "git --exec-path=/tmp/x push origin main",
    "git --git-dir=/other/.git push origin main",
    "git --git-dir /other/.git push origin main",
    "git --work-tree=/other commit -m x",
    "git --namespace=n push origin main",
    "git --no-pager push origin main",
    "git -C a -C b push origin main",
    "git -C",
    # (3) push options that run programs or widen what is pushed
    "git push --receive-pack=evil origin main",
    "git push --receive-pack evil origin main",
    "git push --exec=evil origin main",
    "git push -o ci.skip origin main",
    "git push --push-option=ci.skip origin main",
    "git push --repo=other main",
    "git push --mirror origin",
    "git push --all origin",
    "git push --tags origin",
]


@pytest.mark.parametrize("command", EVASIONS)
def test_evasive_git_commands_are_not_refined(command: str) -> None:
    action = bash(command).action
    assert action.kind is ActionKind.SHELL_COMMAND
    assert set(action.target) <= CONTEXT_KEYS


def test_plus_refspec_is_refined_and_marked_force() -> None:
    target = bash("git push origin +main").action.target
    assert (target["branch"], target["force"]) == ("main", "true")


# --- command and content --------------------------------------------------------------


def test_long_command_is_cut_and_marked() -> None:
    action = bash("echo " + "y" * (MAX_COMMAND_CHARS * 2)).action
    assert action.command is not None
    assert len(action.command) == MAX_COMMAND_CHARS
    assert action.command_truncated is True


def test_shell_inspection_carries_the_bounded_command() -> None:
    report = bash("npm test")
    assert report.inspection is not None
    assert report.inspection.kind is ActionKind.SHELL_COMMAND
    assert report.inspection.command == "npm test"
    assert report.inspection.action_id == report.action.action_id


def test_write_hashes_and_carries_the_content() -> None:
    content = "line one\nline two\n"
    report = normalize(
        pre_tool("Write", {"file_path": "/home/user/my-project/a.txt", "content": content})
    )
    raw = content.encode()
    assert report.action.content_sha256 == hashlib.sha256(raw).hexdigest()
    assert report.action.content_bytes == len(raw)
    assert report.action.command is None
    assert report.inspection is not None
    assert report.inspection.content == content
    assert report.inspection.path == "a.txt"


def test_edit_hashes_the_new_text() -> None:
    report = normalize(pre_tool("Edit", {"file_path": "/a", "old_string": "a", "new_string": "bé"}))
    assert report.action.content_sha256 == hashlib.sha256("bé".encode()).hexdigest()
    assert report.action.content_bytes == 3


def test_multi_edit_hashes_the_new_texts_joined_by_newlines() -> None:
    edits = [{"old_string": "a", "new_string": "one"}, {"old_string": "b", "new_string": "two"}]
    report = normalize(pre_tool("MultiEdit", {"file_path": "/a", "edits": edits}))
    assert report.action.content_sha256 == hashlib.sha256(b"one\ntwo").hexdigest()
    assert report.inspection is not None
    assert report.inspection.content == "one\ntwo"


def test_read_has_no_inspection_input() -> None:
    assert normalize(pre_tool("Read", {"file_path": "/a"})).inspection is None


def test_prompt_text_goes_only_to_inspection() -> None:
    report = normalize(envelope(hook_payload_prompt()))
    text = "Write a function to calculate the factorial of a number"
    assert report.inspection is not None
    assert report.inspection.kind is ActionKind.PROMPT
    assert report.inspection.content == text
    assert text not in report.action.model_dump_json()
    assert report.action.command is None
