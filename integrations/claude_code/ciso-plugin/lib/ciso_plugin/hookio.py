"""The hook process: read the payload on stdin, decide, answer in Claude Code's format.

Answers (hooks reference, PreToolUse and UserPromptSubmit decision control):

- allow: no output, exit 0. Claude Code's own permission rules still apply.
- deny / ask on `PreToolUse`: `hookSpecificOutput.permissionDecision` with the message.
- deny / ask on `UserPromptSubmit`: `decision: "block"` with the message and
  `suppressOriginalPrompt` (a prompt cannot be held for a person, so ask blocks too).
- any failure: a fixed message on stderr and exit code 2, which blocks the action; the
  hooks are also declared `onFailure: "block"`, so a crash or a timeout blocks as well.
"""

from __future__ import annotations

import json
import logging
import os
import sys
from collections.abc import Mapping
from dataclasses import replace
from pathlib import Path
from typing import Any, BinaryIO, Final, TextIO

from ciso.common.activity import Verdict
from ciso.common.clock import SystemClock
from ciso.intake.errors import IntakeRefused, RefusalCode
from ciso.intake.jsonshape import loads_strict
from ciso_plugin.decide import Context, Decider, Outcome
from ciso_plugin.gitrun import SafeGit, no_hooks_dir
from ciso_plugin.identity import os_account
from ciso_plugin.messages import failure_text
from ciso_plugin.settings import PluginSettings, SettingsError, data_dir, git_executable

#: Largest hook payload read from stdin.
MAX_INPUT_BYTES: Final = 4 * 1024 * 1024
MAX_INPUT_DEPTH: Final = 64


class HookFailure(Exception):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def read_payload(stream: BinaryIO) -> dict[str, Any]:
    raw = stream.read(MAX_INPUT_BYTES + 1)
    if len(raw) > MAX_INPUT_BYTES:
        raise HookFailure("input_too_large")
    try:
        value = loads_strict(raw, max_depth=MAX_INPUT_DEPTH, code=RefusalCode.NOT_JSON)
    except IntakeRefused as error:
        raise HookFailure("input_not_json") from error
    if not isinstance(value, dict):
        raise HookFailure("input_not_object")
    return value


def build_context(plugin_root: Path, environ: Mapping[str, str]) -> Context:
    try:
        data = data_dir(environ)
    except (SettingsError, OSError) as error:
        raise HookFailure("no_data_dir") from error
    payload_git: SafeGit | None
    try:
        payload_git = SafeGit(git_executable(environ), "", no_hooks_dir(data), dict(environ))
    except SettingsError:
        payload_git = None
    return Context(
        plugin_root=plugin_root,
        data=data,
        environ=environ,
        clock=SystemClock(),
        account=os_account(),
        settings=PluginSettings.from_env(environ),
        git=payload_git,
    )


def _with_cwd(ctx: Context, payload: Mapping[str, Any]) -> Context:
    """The git runner bound to the payload's working directory (absolute and existing),
    or no git at all."""
    cwd = payload.get("cwd")
    if ctx.git is None or not isinstance(cwd, str):
        return replace(ctx, git=None)
    path = Path(cwd)
    if not path.is_absolute() or not path.is_dir():
        return replace(ctx, git=None)
    return replace(ctx, git=ctx.git.at(str(path)))


def render(event: str, outcome: Outcome) -> str:
    """The JSON to print, or "" for an allow."""
    if outcome.verdict is Verdict.ALLOW:
        return ""
    if event == "PreToolUse":
        body: dict[str, Any] = {
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": outcome.verdict.value,
                "permissionDecisionReason": outcome.message,
            }
        }
    else:
        body = {
            "decision": "block",
            "reason": outcome.message,
            "hookSpecificOutput": {
                "hookEventName": "UserPromptSubmit",
                "suppressOriginalPrompt": True,
            },
        }
    return json.dumps(body, ensure_ascii=True)


def run(
    plugin_root: Path,
    stdin: BinaryIO,
    stdout: TextIO,
    stderr: TextIO,
    environ: Mapping[str, str],
) -> int:
    logging.getLogger().addHandler(logging.NullHandler())
    try:
        payload = read_payload(stdin)
        ctx = _with_cwd(build_context(plugin_root, environ), payload)
        outcome = Decider(ctx).decide(payload)
        text = render(str(payload.get("hook_event_name")), outcome)
    except HookFailure as failure:
        stderr.write(failure_text(failure.code) + "\n")
        return 2
    except Exception as error:  # every other failure blocks too
        stderr.write(failure_text("internal_" + type(error).__name__) + "\n")
        return 2
    if text:
        stdout.write(text + "\n")
    return 0


def main() -> int:
    plugin_root = Path(__file__).resolve().parent.parent.parent
    return run(plugin_root, sys.stdin.buffer, sys.stdout, sys.stderr, dict(os.environ))
