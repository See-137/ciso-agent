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
- for a push: every long option is resolved to the full git push option it uniquely
  prefixes, as git itself does (`--recei=x` is `--receive-pack=x`, queue Q22); an unknown
  or ambiguous option stops the refinement. None of `--receive-pack`, `--exec`,
  `-o`/`--push-option`, `--repo`, `--mirror`, `--all`, `--tags`, `--branches`,
  `--delete`, `--prune`, `--follow-tags`, `--recurse-submodules`; no short cluster
  holding `o` or `d`, or an unknown short flag; at most one refspec. A `+` refspec or a
  force flag (`-f`, `--force`, `--force-with-lease`, `--force-if-includes`, however
  abbreviated) is recorded as `force`.

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
#: Every long option of `git push` -> whether it takes a value ("required", "optional",
#: "none"). Kept equal to `ciso.governance.git_argv.PUSH_LONG_OPTIONS` by a test.
PUSH_LONG_OPTIONS: dict[str, str] = {
    "verbose": "none",
    "quiet": "none",
    "repo": "required",
    "all": "none",
    "branches": "none",
    "mirror": "none",
    "delete": "none",
    "tags": "none",
    "dry-run": "none",
    "porcelain": "none",
    "force": "none",
    "force-with-lease": "optional",
    "force-if-includes": "none",
    "recurse-submodules": "required",
    "thin": "none",
    "receive-pack": "required",
    "exec": "required",
    "set-upstream": "none",
    "progress": "none",
    "prune": "none",
    "no-verify": "none",
    "follow-tags": "none",
    "signed": "optional",
    "atomic": "none",
    "push-option": "required",
    "ipv4": "none",
    "ipv6": "none",
}
#: Push options that run a program, attach data, widen or delete what is pushed.
_PUSH_REFUSED = frozenset(
    {
        "receive-pack",
        "exec",
        "push-option",
        "repo",
        "mirror",
        "all",
        "tags",
        "branches",
        "delete",
        "prune",
        "follow-tags",
        "recurse-submodules",
    }
)
_FORCE_OPTIONS = frozenset({"force", "force-with-lease", "force-if-includes"})
#: Short push flags git knows; `o` (push option) and `d` (delete) refuse the refinement.
_SHORT_FLAGS = frozenset("vqnfdu46o")
_SHORT_REFUSED = frozenset("od")
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


def _spellings() -> dict[str, tuple[str, bool]]:
    """Every accepted spelling -> (option, negated): `x`, `no-x`, and `x` for `no-x`."""
    out: dict[str, tuple[str, bool]] = {}
    for name in PUSH_LONG_OPTIONS:
        out[name] = (name, False)
        out["no-" + name] = (name, True)
        if name.startswith("no-"):
            out[name[3:]] = (name, True)
    return out


_SPELLINGS = _spellings()


def resolve_long(arg: str) -> tuple[str, bool, str | None] | None:
    """`(option, negated, inline value)` for `--<name>[=value]`, resolving a unique
    abbreviation the way git does; None when unknown or ambiguous."""
    name, eq, value = arg[2:].partition("=")
    if not name:
        return None
    exact = _SPELLINGS.get(name)
    if exact is None:
        found = {hit for spelled, hit in _SPELLINGS.items() if spelled.startswith(name)}
        if len(found) != 1:
            return None
        exact = found.pop()
    return exact[0], exact[1], value if eq else None


def _push_target(args: list[str]) -> dict[str, str] | None:
    """Remote, branch and force from push arguments, or None when not plain."""
    positional: list[str] = []
    target: dict[str, str] = {}
    options_done = False
    for arg in args:
        if options_done or not arg.startswith("-") or arg == "-":
            positional.append(arg)
        elif arg == "--":
            options_done = True
        elif arg.startswith("--"):
            resolved = resolve_long(arg)
            if resolved is None or resolved[0] in _PUSH_REFUSED:
                return None
            if resolved[0] in _FORCE_OPTIONS and not resolved[1]:
                target["force"] = "true"
        else:
            letters = set(arg[1:])
            if not letters <= _SHORT_FLAGS or letters & _SHORT_REFUSED:
                return None
            if "f" in letters:
                target["force"] = "true"
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
