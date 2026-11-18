"""Classes of an observed action, from its command text or its target.

Shell commands go through the command classifier. File actions are judged by their
`path` target; a file action without a path is `unparseable` (its target is unknown).
A push action uses its `branch` target; with no branch it counts as a push to a
protected branch, and a `force` target of `true` makes it a force push.
"""

from __future__ import annotations

from ciso.common.activity import ActionKind, ObservedAction
from ciso.governance.analysis import Analyzer
from ciso.governance.classes import CommandClass as C
from ciso.governance.commands import ClassifierConfig, CommandAnalysis, classify_command
from ciso.governance.globs import glob_match

_FILE_WRITES = frozenset({ActionKind.FILE_WRITE, ActionKind.FILE_EDIT})
_TRUE = frozenset({"true", "1", "yes"})
#: Used only to see whether a command commits or pushes; branch protection is irrelevant.
_PUSH_PROBE = ClassifierConfig(protected_branches=("**",))
_COMMIT_OR_PUSH = frozenset({C.GIT_PUSH, C.GIT_FORCE_PUSH, C.GIT_COMMIT})


def _path_classes(path: str, config: ClassifierConfig, *, writes: bool) -> frozenset[C]:
    probe = Analyzer(config, None)
    probe.path(path, writes=writes)
    return frozenset(probe.classes)


def action_analysis(action: ObservedAction, config: ClassifierConfig) -> CommandAnalysis:
    """Classes of `action`. Never raises for odd input: unknown becomes `unparseable`."""
    target = action.target
    if action.kind is ActionKind.SHELL_COMMAND:
        return classify_command(
            action.command,
            config,
            target_branch=target.get("branch") or None,
            truncated=action.command_truncated,
        )
    if action.kind in _FILE_WRITES or action.kind is ActionKind.FILE_READ:
        path = target.get("path", "")
        if not path:
            return CommandAnalysis(classes=frozenset({C.UNPARSEABLE}))
        classes = _path_classes(path, config, writes=action.kind in _FILE_WRITES)
        return CommandAnalysis(classes=classes)
    if action.kind is ActionKind.GIT_PUSH:
        branch = target.get("branch", "")
        push: set[C] = {C.GIT_PUSH}
        if not branch or any(
            glob_match(p, branch, "/", casefold=True) for p in config.protected_branches
        ):
            push.add(C.GIT_PUSH_PROTECTED_REF)
        if target.get("force", "").casefold() in _TRUE:
            push.add(C.GIT_FORCE_PUSH)
        return CommandAnalysis(classes=frozenset(push))
    if action.kind is ActionKind.GIT_COMMIT:
        return CommandAnalysis(classes=frozenset({C.GIT_COMMIT}))
    return CommandAnalysis(classes=frozenset())


def shell_needs_inspection(action: ObservedAction) -> bool:
    """A shell command that commits or pushes (or cannot be read) needs inspection."""
    classes = classify_command(
        action.command, _PUSH_PROBE, truncated=action.command_truncated
    ).classes
    return bool(classes & (_COMMIT_OR_PUSH | {C.UNPARSEABLE}))
