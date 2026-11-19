"""Which push and commit commands the hook client can scan before they run.

The hook client builds the change on the engineer's machine (docs/skill/decision-api.md,
"Pre-push change upload"): for a push the commits between the remote branch and HEAD,
for a commit the staged index. That is only the change the command will send when the
command is ONE plain git command that sends ONE branch (or the index). So the shape is
read here, conservatively: a chain, a redirection, an expansion, another repository, a
refspec list, a delete, a tag or any option that changes what is pushed or committed
gives `None`, and the decision stays a plain refusal (the engineer is told to push one
branch at a time with the plain form).

A push qualifies only when the command itself names exactly one remote, one source
(HEAD or a branch) and one destination branch. A push without a refspec, or with a bare
`HEAD`, sends whatever configuration says (`push.default`, `remote.<name>.push`,
`remote.<name>.mirror`), so it never qualifies: the engineer is asked to name the branch.

`source` is the local branch the push sends: None means HEAD (`HEAD:<branch>`); otherwise
the client builds the change from exactly `refs/heads/<source>` (`git push <remote>
<branch>`, `refs/heads/<branch>`, `<src>:<dst>`), so the commits scanned are the commits
pushed.

The intake refines a plain push or commit to the kinds `git_push` / `git_commit` and keeps
the command text, so those kinds are read here as well as `shell_command`.

This reads the command only to find the remote and branch it names and to refuse odd
shapes. It never allows anything; the governance rules decide.
"""

from __future__ import annotations

import re
import shlex
from enum import StrEnum
from typing import Final

from ciso.common.activity import ActionKind, ActivitySource, ObservedAction, Phase
from ciso.common.schemas import Model

#: Characters that make a command more than one plain git invocation.
_SHELL_CHARS: Final = frozenset(";&|<>$`(){}[]*?!~#\\\n\r\t")
_REMOTE_RE: Final = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}")
_BRANCH_RE: Final = re.compile(r"[A-Za-z0-9][A-Za-z0-9._/-]{0,199}")
_PUSH_FLAGS: Final = frozenset({"-u", "--set-upstream", "-q", "--quiet", "-v", "--verbose"})
_COMMIT_FLAGS: Final = frozenset({"-q", "--quiet", "-s", "--signoff", "-v", "--verbose"})
_MESSAGE_OPTIONS: Final = frozenset({"-m", "--message"})
_PUSH_KINDS: Final = frozenset({ActionKind.SHELL_COMMAND, ActionKind.GIT_PUSH})
_COMMIT_KINDS: Final = frozenset({ActionKind.SHELL_COMMAND, ActionKind.GIT_COMMIT})
_KINDS: Final = _PUSH_KINDS | _COMMIT_KINDS


class ChangeKind(StrEnum):
    PUSH = "push"
    COMMIT = "commit"


class ChangeShape(Model):
    """What the client must build: a push (HEAD against `remote`/`branch` when named) or a
    commit (the staged index)."""

    kind: ChangeKind
    remote: str | None = None
    branch: str | None = None
    #: The local branch a push sends; None means HEAD.
    source: str | None = None


def _branch(name: str) -> str:
    """A branch name, or raises ValueError for a name we do not trust (a tag, another
    ref namespace, a revision expression)."""
    name = name.removeprefix("refs/heads/")
    if (
        name.startswith("refs/")
        or name == "HEAD"
        or not _BRANCH_RE.fullmatch(name)
        or ".." in name
        or name.endswith((".lock", "/"))
    ):
        raise ValueError("branch name")
    return name


def _push(args: list[str]) -> ChangeShape | None:
    positionals = []
    for arg in args:
        if arg.startswith("-"):
            if arg not in _PUSH_FLAGS:
                return None
            continue
        positionals.append(arg)
    if len(positionals) != 2:
        return None  # no refspec (configuration decides), or a refspec list
    remote = positionals[0]
    if not _REMOTE_RE.fullmatch(remote):
        return None
    src, colon, dst = positionals[1].partition(":")
    if colon and (not src or not dst):
        return None  # a delete, or an empty destination
    try:  # a bare HEAD (no destination named) is refused by `_branch`
        source = None if src == "HEAD" else _branch(src)
        branch = _branch(dst) if colon else _branch(src)
    except ValueError:
        return None  # a tag, a revision expression, a path: not one branch
    return ChangeShape(kind=ChangeKind.PUSH, remote=remote, branch=branch, source=source)


def _commit(args: list[str]) -> ChangeShape | None:
    expect_message = False
    for arg in args:
        if expect_message:
            expect_message = False
            continue
        if arg in _MESSAGE_OPTIONS:
            expect_message = True
        elif arg.startswith("--message=") or arg in _COMMIT_FLAGS:
            continue
        else:
            return None  # -a, --amend, -F, a pathspec, anything else
    if expect_message:
        return None
    return ChangeShape(kind=ChangeKind.COMMIT)


def change_shape(action: ObservedAction) -> ChangeShape | None:
    """The change a hook-reported push or commit will send, or None when the command is
    not one plain git push or commit (see the module docstring)."""
    if (
        action.source is not ActivitySource.HOOK
        or action.phase is not Phase.BEFORE
        or action.kind not in _KINDS
        or action.command is None
        or action.command_truncated
    ):
        return None
    command = action.command.strip()
    if not command or any(ch in _SHELL_CHARS for ch in command):
        return None
    try:
        words = shlex.split(command, posix=True)
    except ValueError:
        return None
    if len(words) < 2 or words[0] != "git":
        return None
    if words[1] == "push" and action.kind in _PUSH_KINDS:
        return _push(words[2:])
    if words[1] == "commit" and action.kind in _COMMIT_KINDS:
        return _commit(words[2:])
    return None
