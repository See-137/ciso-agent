"""Recognise a shell command that is plainly one `git commit` or one `git push`.

The refinement is a HINT for governance. When in doubt it gives the less specific
`shell_command` with no stated target, and governance's own classifier, which assumes
the worst, decides. A command is refined only when ALL of these hold:

- one simple command: no `;`, `&&`, `|`, redirection or subshell, no line break;
- no character the shell would expand or that changes quoting: `$`, backtick, backslash,
  `!`, `*`, `?`, `[`, `]`, `{`, `}`, `~` (anywhere in the command, quoted or not);
- the program is `git`, and the only global option is at most one `-C <dir>` (`-c`,
  `--exec-path`, `--git-dir`, `--work-tree`, `--namespace` and every other global option
  stop the refinement, since they can change what git runs or where it writes);
- for a push: none of `--receive-pack`, `--exec`, `-o`/`--push-option`, `--repo`,
  `--mirror`, `--all`, `--tags`, `--branches`, and at most one refspec. A `+` refspec or a
  force flag is recorded as `force`.

A remote URL loses any user-info part (`user:token@`). The command handed in is already
redacted.
"""

from __future__ import annotations

import re
import shlex

from ciso.common.activity import ActionKind

#: Characters `shlex` splits out as operators when punctuation_chars is on.
_OPERATOR_CHARS = frozenset("();<>|&")
#: Characters that make the shell expand or re-quote a word; their presence stops refinement.
_EXPANDING_CHARS = frozenset("$`\\!*?[]{}~\n\r")
_GIT_PROGRAMS = frozenset({"git", "git.exe"})
#: Push options that run a program on the remote, attach data, or widen what is pushed.
_PUSH_REFUSED = frozenset(
    {
        "--receive-pack",
        "--exec",
        "-o",
        "--push-option",
        "--repo",
        "--mirror",
        "--all",
        "--tags",
        "--branches",
    }
)
_FORCE_FLAGS = frozenset({"-f", "--force"})
_USERINFO = re.compile(r"(?<=://)[^/@]*@")
_HEADS = "refs/heads/"


def _tokens(command: str) -> list[str] | None:
    if any(ch in _EXPANDING_CHARS for ch in command):
        return None
    try:
        lexer = shlex.shlex(command, posix=True, punctuation_chars=True)
        lexer.whitespace_split = True
        tokens = list(lexer)
    except ValueError:
        return None
    if any(token and set(token) <= _OPERATOR_CHARS for token in tokens):
        return None
    return tokens


def _subcommand(tokens: list[str]) -> tuple[str, list[str]] | None:
    """(subcommand, its arguments) when the global options are at most one `-C <dir>`."""
    if not tokens or tokens[0] not in _GIT_PROGRAMS:
        return None
    rest = tokens[1:]
    if rest[:1] == ["-C"]:
        if len(rest) < 3:
            return None
        rest = rest[2:]
    if not rest or rest[0].startswith("-"):
        return None
    return rest[0], rest[1:]


def _option_name(arg: str) -> str:
    return arg.split("=", 1)[0] if arg.startswith("--") else arg


def _push_target(args: list[str]) -> dict[str, str] | None:
    """Remote, branch and force from push arguments, or None when not plain."""
    positional: list[str] = []
    target: dict[str, str] = {}
    for arg in args:
        if _option_name(arg) in _PUSH_REFUSED:
            return None
        if arg in _FORCE_FLAGS or _option_name(arg) == "--force-with-lease":
            target["force"] = "true"
        if not arg.startswith("-"):
            positional.append(arg)
    if len(positional) > 2:
        return None
    if positional:
        target["remote"] = _USERINFO.sub("", positional[0])
    if len(positional) == 2:
        refspec = positional[1]
        if refspec.startswith("+"):
            target["force"] = "true"
            refspec = refspec[1:]
        branch = refspec.rsplit(":", 1)[-1] if ":" in refspec else refspec
        target["branch"] = branch.removeprefix(_HEADS)
    return {key: value for key, value in target.items() if value}


def classify_git(command: str) -> tuple[ActionKind, dict[str, str]]:
    """`(GIT_PUSH | GIT_COMMIT, stated target)` for a plain git command, otherwise
    `(SHELL_COMMAND, {})`."""
    tokens = _tokens(command)
    parsed = _subcommand(tokens) if tokens is not None else None
    if parsed is None:
        return ActionKind.SHELL_COMMAND, {}
    sub, args = parsed
    if sub == "commit":
        return ActionKind.GIT_COMMIT, {}
    if sub == "push":
        target = _push_target(args)
        if target is not None:
            return ActionKind.GIT_PUSH, target
    return ActionKind.SHELL_COMMAND, {}
