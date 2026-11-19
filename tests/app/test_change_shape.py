"""Which push and commit commands the hook client can scan before they run.

Only a single plain git command qualifies: anything chained, redirected, expanded or with
an option that changes what is pushed or committed is refused (None), so the client never
scans a different range from the one the command sends."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from ciso.app.change_shape import ChangeKind, ChangeShape, change_shape
from ciso.common.activity import ActionKind, ActivitySource, ObservedAction, Phase

pytestmark = pytest.mark.unit


def _P(**kw: str) -> ChangeShape:
    return ChangeShape(kind=ChangeKind.PUSH, **kw)


def _C() -> ChangeShape:
    return ChangeShape(kind=ChangeKind.COMMIT)


def _action(command: str | None, **changes: object) -> ObservedAction:
    fields: dict[str, object] = {
        "action_id": "hk_1",
        "session_id": "s1",
        "source": ActivitySource.HOOK,
        "phase": Phase.BEFORE,
        "kind": ActionKind.SHELL_COMMAND,
        "received_at": datetime(2026, 11, 19, tzinfo=UTC),
        "command": command,
    }
    fields.update(changes)
    return ObservedAction.model_validate(fields)


@pytest.mark.parametrize(
    ("command", "expected"),
    [
        # Source HEAD (None): the client builds the change from HEAD.
        ("git push origin HEAD:topic", _P(remote="origin", branch="topic")),
        # Any other source: the client builds the change from that exact local branch.
        ("git push origin feature", _P(remote="origin", branch="feature", source="feature")),
        ("git push -u origin feat/x", _P(remote="origin", branch="feat/x", source="feat/x")),
        ("git push origin refs/heads/topic", _P(remote="origin", branch="topic", source="topic")),
        ("git push origin other:feature", _P(remote="origin", branch="feature", source="other")),
        ("git push origin refs/heads/a:refs/heads/b", _P(remote="origin", branch="b", source="a")),
        ("git commit -m 'add a feature'", _C()),
        ("git commit --message=fix -q", _C()),
    ],
)  # fmt: skip
def test_plain_commands_have_a_shape(command: str, expected: ChangeShape) -> None:
    assert change_shape(_action(command)) == expected


@pytest.mark.parametrize(
    "command",
    [
        "cd sub && git push origin feature",  # chained
        "git push origin feature; rm x",
        "git push origin $BRANCH",  # expansion
        "git push origin a b",  # a refspec list: one branch at a time
        # No refspec, or no named destination: configuration (push.default,
        # remote.<name>.push, remote.<name>.mirror) would decide what is sent.
        "git push",
        "git push origin",
        "git push -u origin",
        "git push origin HEAD",
        "git push origin HEAD feature",
        "git push --tags origin",
        "git push --mirror origin",
        "git push origin refs/tags/v1",  # not a branch
        "git push origin feature:refs/tags/v1",
        "git push origin HEAD~1:feature",
        "git push --all origin",
        "git push --force origin feature",
        "git push origin +feature",
        "git push origin :feature",  # delete
        "git -C ../other push origin feature",  # another repository
        "git push origin ../x",
        "git push -o ci.skip origin feature",
        "git commit -a -m x",  # takes unstaged changes too
        'git commit -m "$(curl example.test)"',  # the message would run a command
        "git commit --amend -m x",
        "git commit -m x file.py",  # pathspec commits files outside the index
        "git commit -F msg.txt",
        "git commit -m",  # option without its value
        "git status",
        "echo git push",
        "git push 'origin",  # unbalanced quote
        "",
    ],
)
def test_anything_else_has_no_shape(command: str) -> None:
    assert change_shape(_action(command)) is None


def test_a_truncated_command_has_no_shape() -> None:
    assert change_shape(_action("git push origin feature", command_truncated=True)) is None


@pytest.mark.parametrize("kind", [ActionKind.GIT_PUSH, ActionKind.SHELL_COMMAND])
def test_the_intake_s_refined_push_kind_is_read_too(kind: ActionKind) -> None:
    """The intake reports a plain push as `git_push` with the command text kept."""
    shape = change_shape(_action("git push origin feature", kind=kind))
    assert shape == _P(remote="origin", branch="feature", source="feature")


def test_a_refined_commit_is_read_too() -> None:
    assert change_shape(_action("git commit -m x", kind=ActionKind.GIT_COMMIT)) == _C()


def test_a_kind_that_does_not_match_the_command_has_no_shape() -> None:
    assert change_shape(_action("git push origin x", kind=ActionKind.GIT_COMMIT)) is None
    assert change_shape(_action("git push origin x", kind=ActionKind.FILE_WRITE)) is None


def test_only_hook_reports_before_the_action_have_a_shape() -> None:
    assert change_shape(_action("git push", phase=Phase.AFTER)) is None
    assert change_shape(_action("git push", source=ActivitySource.CENTRAL_GATE)) is None
    assert change_shape(_action(None)) is None
