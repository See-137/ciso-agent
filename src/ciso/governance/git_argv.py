"""Classification of one `git` invocation: push, history rewrite, config and hooks.

A push whose destination branch cannot be read from the command or from the action's
target is treated as a push to a protected branch: unknown resolves to the more dangerous
answer. So is a destination containing a wildcard, `--all` and `--mirror`.
"""

from __future__ import annotations

import re
from typing import NamedTuple

from ciso.governance.classes import CommandClass as C
from ciso.governance.globs import glob_match
from ciso.governance.safe_options import GIT_SAFE, spec_allows

#: Global options that take a separate value.
_GLOBAL_WITH_VALUE = frozenset(
    {"-C", "-c", "--git-dir", "--work-tree", "--namespace", "--exec-path", "--config-env"}
)
_PUSH_VALUE_OPTIONS = frozenset({"--repo", "-o", "--push-option", "--receive-pack", "--exec"})
_REWRITE_SUBCOMMANDS = frozenset(
    {"rebase", "filter-branch", "filter-repo", "replace", "update-ref"}
)
_RESET_MODES = frozenset({"--hard", "--soft", "--keep", "--merge", "--mixed"})
_COMMITISH = re.compile(r".*[~^].*|.*@\{.*|[0-9a-f]{7,40}|origin/.*|upstream/.*")
_HOOK_KEYS = ("hookspath", "hooks")


class GitFacts(NamedTuple):
    classes: frozenset[C]
    branches: frozenset[str]
    read_only: bool
    #: POSIX command strings git will run (`rebase -x`, `submodule foreach`, `bisect run`).
    nested: tuple[str, ...]


def _short_flags(args: list[str]) -> set[str]:
    flags: set[str] = set()
    for arg in args:
        if arg.startswith("-") and not arg.startswith("--"):
            flags.update(arg[1:])
    return flags


def _split_globals(args: list[str], found: set[C]) -> list[str]:
    i = 0
    while i < len(args) and args[i].startswith("-"):
        opt, _, inline = args[i].partition("=")
        value = inline
        if opt in _GLOBAL_WITH_VALUE and not inline:
            value = args[i + 1] if i + 1 < len(args) else ""
            i += 1
        if opt in ("-c", "--config-env"):
            found.add(C.GIT_CONFIG_CHANGE)
            if any(k in value.casefold() for k in _HOOK_KEYS):
                found.add(C.GIT_HOOKS_CHANGE)
        i += 1
    return args[i:]


def _push(
    args: list[str], protected: tuple[str, ...], target_branch: str | None, found: set[C]
) -> set[str]:
    found.add(C.GIT_PUSH)
    flags = _short_flags(args)
    long = {a.partition("=")[0] for a in args if a.startswith("--")}
    if (
        "f" in flags
        or "d" in flags
        or long
        & {
            "--force",
            "--force-with-lease",
            "--force-if-includes",
            "--delete",
            "--mirror",
            "--prune",
        }
    ):
        found.add(C.GIT_FORCE_PUSH)
    positionals: list[str] = []
    skip = False
    for arg in args:
        if skip:
            skip = False
            continue
        if arg.startswith("-"):
            skip = arg in _PUSH_VALUE_OPTIONS
            continue
        positionals.append(arg)
    named: set[str] = set()
    unknown = bool(long & {"--all", "--mirror", "--branches"})
    for spec in positionals[1:]:
        if spec.startswith("+"):
            found.add(C.GIT_FORCE_PUSH)
            spec = spec[1:]
        src, colon, dst = spec.partition(":")
        if colon and not src:
            found.add(C.GIT_FORCE_PUSH)
        dest = (dst if colon else src).removeprefix("refs/heads/")
        if dest in ("HEAD", "@", ""):
            unknown = unknown or target_branch is None
            if target_branch:
                named.add(target_branch)
            continue
        named.add(dest)
    if len(positionals) <= 1:
        if target_branch:
            named.add(target_branch)
        else:
            unknown = True
    if unknown or any(
        "*" in b or any(glob_match(pat, b, "/", casefold=True) for pat in protected) for b in named
    ):
        found.add(C.GIT_PUSH_PROTECTED_REF)
    return named


def _config(args: list[str], found: set[C]) -> bool:
    """True when the config call only reads."""
    reads = {
        "--get",
        "--get-all",
        "--get-regexp",
        "--list",
        "-l",
        "--get-urlmatch",
        "get",
        "list",
        "--show-origin",
        "--show-scope",
        "--name-only",
    }
    positionals = [a for a in args if not a.startswith("-")]
    if any(a in reads for a in args) or (
        len(positionals) == 1
        and positionals[0] not in ("set", "unset", "edit", "rename-section", "remove-section")
    ):
        return True
    found.add(C.GIT_CONFIG_CHANGE)
    if any(k in a.casefold() for a in args for k in _HOOK_KEYS):
        found.add(C.GIT_HOOKS_CHANGE)
    return False


def _rewrite(sub: str, args: list[str]) -> bool:
    flags = _short_flags(args)
    long = {a.partition("=")[0] for a in args if a.startswith("--")}
    before_dashdash = args[: args.index("--")] if "--" in args else args
    checks = (
        sub in _REWRITE_SUBCOMMANDS,
        sub == "commit" and "--amend" in long,
        sub == "reset"
        and (
            bool(long & _RESET_MODES)
            or any(_COMMITISH.fullmatch(a) for a in before_dashdash if not a.startswith("-"))
        ),
        sub == "branch"
        and (bool(flags & {"f", "D", "M", "C", "d"}) or bool(long & {"--force", "--delete"})),
        sub in ("checkout", "switch") and bool(flags & {"B", "C"} or "--force-create" in long),
        sub == "tag" and bool(flags & {"f", "d"} or long & {"--force", "--delete"}),
        sub == "reflog" and bool(args) and args[0] in ("expire", "delete"),
        sub == "gc" and any(a.startswith("--prune") for a in args),
    )
    return any(checks)


def _nested(sub: str, args: list[str]) -> tuple[str, ...]:
    out: list[str] = []
    for i, arg in enumerate(args):
        if sub == "rebase" and arg in ("-x", "--exec") and i + 1 < len(args):
            out.append(args[i + 1])
        elif sub == "rebase" and arg.startswith("--exec="):
            out.append(arg.partition("=")[2])
    if sub == "submodule" and args[:1] == ["foreach"]:
        out.append(" ".join(a for a in args[1:] if a != "--recursive"))
    if sub == "bisect" and args[:1] == ["run"]:
        out.append(" ".join(args[1:]))
    return tuple(t for t in out if t)


def _listing_only(sub: str, args: list[str]) -> bool:
    """`remote`, `tag`, `stash` and `reflog` are read-only only in these exact shapes; the
    subcommand AND every argument after it must fit. A bare `git stash` writes."""
    positional = [a for a in args if not a.startswith("-")]
    no_options = len(positional) == len(args)
    if sub == "remote":
        return args in ([], ["-v"], ["--verbose"]) or (
            no_options and len(args) == 2 and args[0] in ("show", "get-url")
        )
    if sub == "tag":
        return not args or (
            args[0] in ("-l", "--list") and all(not a.startswith("-") for a in args[1:])
        )
    if sub == "stash":
        return args == ["list"] or (no_options and args[:1] == ["show"] and len(args) <= 2)
    if sub == "reflog":
        return args in ([], ["show"])
    return False


def _globals_read_only(options: list[str]) -> bool:
    """Only `-C <dir>`, `--no-pager`, `-P` and `--no-optional-locks` keep git read-only."""
    i = 0
    while i < len(options):
        if options[i] == "-C":
            i += 2
        elif options[i] in ("--no-pager", "-P", "--no-optional-locks"):
            i += 1
        else:
            return False
    return True


def check_git(args: list[str], protected: tuple[str, ...], target_branch: str | None) -> GitFacts:
    """Classify `git <args>` (literal argument texts)."""
    found: set[C] = set()
    rest = _split_globals(args, found)
    if not rest:
        return GitFacts(frozenset(found), frozenset(), not found, ())
    sub, sub_args = rest[0], rest[1:]
    branches: set[str] = set()
    read_only = False
    if sub == "push":
        branches = _push(sub_args, protected, target_branch, found)
    elif sub == "config":
        read_only = _config(sub_args, found)
    elif sub == "remote":
        read_only = _listing_only(sub, sub_args)
        if not read_only:
            found.add(C.GIT_CONFIG_CHANGE)
    elif sub in ("credential", "credential-store", "credential-cache"):
        found.add(C.CREDENTIAL_ACCESS)
    elif sub == "clean" and ("f" in _short_flags(sub_args) or "--force" in sub_args):
        found.add(C.DESTRUCTIVE_DELETE)
    elif sub == "branch":
        read_only = all(
            a in ("--list", "-a", "-r", "-v", "-vv", "--show-current", "--all") for a in sub_args
        )
    elif sub in ("tag", "stash", "reflog"):
        read_only = _listing_only(sub, sub_args)
    else:
        spec = GIT_SAFE.get(sub)
        read_only = spec is not None and spec_allows(spec, sub_args)
    read_only = read_only and _globals_read_only(args[: len(args) - len(rest)])
    if sub == "commit":
        found.add(C.GIT_COMMIT)
    if sub in ("commit", "push", "merge", "am") and (
        "--no-verify" in sub_args or (sub == "commit" and "n" in _short_flags(sub_args))
    ):
        found.add(C.GIT_HOOKS_CHANGE)
    if _rewrite(sub, sub_args):
        found.add(C.GIT_HISTORY_REWRITE)
    nested = _nested(sub, sub_args)
    return GitFacts(frozenset(found), frozenset(branches), read_only and not found, nested)
