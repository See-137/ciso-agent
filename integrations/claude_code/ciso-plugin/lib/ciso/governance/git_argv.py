"""Classification of one `git` invocation: push, history rewrite, config and hooks.

A push whose destination branch the command does not name is a push to an UNKNOWN
branch, and unknown counts as protected (review H5): the current branch the source
reports is not where `push.default`, an upstream or `remote.<name>.push` may send it.
Destinations are normalised first (`+`, `src:`, `refs/heads/`, `heads/`). A destination
outside `refs/heads/`, a wildcard, `--all` and `--mirror` are unknown too.

Read-only git runs in the current directory only (review C4): `-C`, `--git-dir`,
`--work-tree`, `--namespace`, `-c` and `--config-env` all make it not read-only, and the
analyzer adds that a directory change earlier in the line does too. An alias defined
with `-c alias.<name>=...` or `git config alias.<name>` hides what runs (obfuscation);
its `!` command and every configuration value git runs as a program are read as code.

git accepts any unique abbreviation of a long option (queue Q22): every long push option
is resolved to the full option it prefixes (`--recei=x` is `--receive-pack=x`). An
unknown or ambiguous one is `unparseable` and leaves the destination unknown. A
`--receive-pack` / `--exec` value is a program git runs: `unparseable`, and the value is
read as code. A short cluster holding `o` other than `-o` itself hides a push-option
value and is `unparseable`. `git rebase --ex`/`--exe` are `--exec`.
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
#: The only global options that keep git read-only.
_READ_ONLY_GLOBALS = frozenset({"--no-pager", "-P", "--no-optional-locks"})
#: Every long option of `git push` -> whether it takes a value ("required", "optional",
#: "none"). Kept equal to `ciso.intake.gitcommand.PUSH_LONG_OPTIONS` by a test.
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
_PUSH_PROGRAM_OPTIONS = frozenset({"receive-pack", "exec"})
_PUSH_SHORT_FLAGS = frozenset("vqnfdu46o")
_REWRITE_SUBCOMMANDS = frozenset(
    {"rebase", "filter-branch", "filter-repo", "replace", "update-ref"}
)
_RESET_MODES = frozenset({"--hard", "--soft", "--keep", "--merge", "--mixed"})
_COMMITISH = re.compile(r".*[~^].*|.*@\{.*|[0-9a-f]{7,40}|origin/.*|upstream/.*")
_HOOK_KEYS = ("hookspath", "hooks")
#: Configuration keys whose value git runs as a shell command.
_EXEC_KEY_RE = re.compile(
    r"core\.(sshcommand|pager|editor|fsmonitor|askpass)|diff\.external|sequence\.editor"
    r"|gpg\.(.+\.)?program|pager\..+|.+\.textconv|.+\.cmd|.+\.command"
    r"|filter\..+\.(clean|smudge|process)|merge\..+\.driver|credential\.helper"
)
_FORCE_LONG = frozenset(
    {"force", "force-with-lease", "force-if-includes", "delete", "mirror", "prune"}
)
_REBASE_EXEC_SPELLINGS = frozenset({"ex", "exe", "exec"})


class PushOption(NamedTuple):
    name: str
    negated: bool
    value: str | None


def _spellings() -> dict[str, tuple[str, bool]]:
    out: dict[str, tuple[str, bool]] = {}
    for name in PUSH_LONG_OPTIONS:
        out[name] = (name, False)
        out["no-" + name] = (name, True)
        if name.startswith("no-"):
            out[name[3:]] = (name, True)
    return out


_SPELLINGS = _spellings()


def resolve_push_option(arg: str) -> PushOption | None:
    """The push option `--<name>[=value]` stands for, resolving a unique abbreviation as
    git does; None when it is unknown or ambiguous."""
    name, eq, value = arg[2:].partition("=")
    if not arg.startswith("--") or not name:
        return None
    exact = _SPELLINGS.get(name)
    if exact is None:
        found = {hit for spelled, hit in _SPELLINGS.items() if spelled.startswith(name)}
        if len(found) != 1:
            return None
        exact = found.pop()
    return PushOption(exact[0], exact[1], value if eq else None)


class GitFacts(NamedTuple):
    classes: frozenset[C]
    branches: frozenset[str]
    read_only: bool
    #: POSIX command strings git will run (`rebase -x`, `submodule foreach`, `bisect run`,
    #: `!` aliases, configuration values that name a program).
    nested: tuple[str, ...]
    #: A push whose destination branch cannot be told from the command.
    unknown_branch: bool = False


def _short_flags(args: list[str]) -> set[str]:
    flags: set[str] = set()
    for arg in args:
        if arg.startswith("-") and not arg.startswith("--"):
            flags.update(arg[1:])
    return flags


def _config_value(key: str, value: str, found: set[C], code: list[str]) -> None:
    """Classes and code of one configuration value being set."""
    low = key.casefold()
    if any(k in low for k in _HOOK_KEYS):
        found.add(C.GIT_HOOKS_CHANGE)
    if low.startswith("alias."):
        found.add(C.OBFUSCATION)
        if value.startswith("!"):
            code.append(value[1:])
    elif _EXEC_KEY_RE.fullmatch(low) and value:
        code.append(value.removeprefix("!"))


class _Globals(NamedTuple):
    rest: list[str]
    options: list[str]
    aliases: dict[str, str]


def _split_globals(args: list[str], found: set[C], code: list[str]) -> _Globals:
    i = 0
    aliases: dict[str, str] = {}
    while i < len(args) and args[i].startswith("-"):
        opt, _, inline = args[i].partition("=")
        value = inline
        if opt in _GLOBAL_WITH_VALUE and not inline:
            value = args[i + 1] if i + 1 < len(args) else ""
            i += 1
        if opt == "-c":
            found.add(C.GIT_CONFIG_CHANGE)
            key, _, setting = value.partition("=")
            _config_value(key, setting, found, code)
            if key.casefold().startswith("alias."):
                aliases[key[6:].casefold()] = setting
        elif opt == "--config-env":
            found.add(C.GIT_CONFIG_CHANGE)
            key = value.partition("=")[0].casefold()
            if key.startswith("alias.") or _EXEC_KEY_RE.fullmatch(key):
                found.add(C.OBFUSCATION)  # the value comes from a variable: unknown code
            if any(k in key for k in _HOOK_KEYS):
                found.add(C.GIT_HOOKS_CHANGE)
        i += 1
    return _Globals(args[i:], args[: len(args) - len(args[i:])], aliases)


def _destination(spec: str, found: set[C]) -> str | None:
    """The branch a refspec lands on, or None when it cannot be told."""
    if spec.startswith("+"):
        found.add(C.GIT_FORCE_PUSH)
        spec = spec[1:]
    src, colon, dst = spec.partition(":")
    if colon and not src:
        found.add(C.GIT_FORCE_PUSH)  # `:dst` deletes the remote branch
    dest = dst if colon else src
    if dest.startswith("refs/heads/"):
        dest = dest[len("refs/heads/") :]
    elif dest.startswith("refs/"):
        return None
    elif dest.startswith("heads/"):
        dest = dest[len("heads/") :]  # git resolves `heads/x` through `refs/%s`
    if dest in ("HEAD", "@", "") or any(c in dest for c in "*~^") or "@{" in dest:
        return None
    return dest


class _PushArgs(NamedTuple):
    positionals: list[str]
    long: set[str]
    shorts: set[str]
    unparseable: bool
    code: list[str]


def _push_args(args: list[str]) -> _PushArgs:
    """Positionals, resolved long options (not negated), short flags, and the programs
    the push would run."""
    out = _PushArgs([], set(), set(), False, [])
    bad = False
    i = 0
    while i < len(args):
        arg = args[i]
        i += 1
        if arg == "--":
            out.positionals.extend(args[i:])
            break
        if not arg.startswith("-") or arg == "-":
            out.positionals.append(arg)
        elif arg.startswith("--"):
            option = resolve_push_option(arg)
            if option is None:
                bad = True
                continue
            value = option.value
            if value is None and PUSH_LONG_OPTIONS[option.name] == "required" and i < len(args):
                value, i = args[i], i + 1
            if option.negated:
                continue
            out.long.add(option.name)
            if option.name in _PUSH_PROGRAM_OPTIONS:
                bad = True
                if value:
                    out.code.append(value)
        elif arg == "-o":
            i += 1  # its value
        else:
            letters = set(arg[1:])
            bad = bad or "o" in letters or not letters <= _PUSH_SHORT_FLAGS
            out.shorts.update(letters)
    return out._replace(unparseable=bad)


def _push(
    args: list[str], protected: tuple[str, ...], found: set[C], code: list[str]
) -> tuple[set[str], bool]:
    found.add(C.GIT_PUSH)
    parsed = _push_args(args)
    if parsed.unparseable:
        found.add(C.UNPARSEABLE)
    code.extend(parsed.code)
    if "f" in parsed.shorts or "d" in parsed.shorts or parsed.long & _FORCE_LONG:
        found.add(C.GIT_FORCE_PUSH)
    if "no-verify" in parsed.long:
        found.add(C.GIT_HOOKS_CHANGE)
    positionals = parsed.positionals
    named: set[str] = set()
    unknown = (
        parsed.unparseable
        or bool(parsed.long & {"all", "mirror", "branches"})
        or len(positionals) <= 1
    )
    for spec in positionals[1:]:
        dest = _destination(spec, found)
        if dest is None:
            unknown = True
        else:
            named.add(dest)
    if unknown or any(glob_match(pat, b, "/", casefold=True) for b in named for pat in protected):
        found.add(C.GIT_PUSH_PROTECTED_REF)
    return named, unknown


def _config(args: list[str], found: set[C], code: list[str]) -> bool:
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
    values = positionals[1:] if positionals[:1] == ["set"] else positionals
    if len(values) >= 2:
        _config_value(values[0], values[1], found, code)
    elif values and values[0].casefold().startswith("alias."):
        found.add(C.OBFUSCATION)
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


def _nested(sub: str, args: list[str]) -> list[str]:
    out: list[str] = []
    for i, arg in enumerate(args):
        name, eq, value = arg.partition("=")
        long_exec = name.startswith("--") and name[2:] in _REBASE_EXEC_SPELLINGS
        if sub == "rebase" and (arg == "-x" or (long_exec and not eq)) and i + 1 < len(args):
            out.append(args[i + 1])
        elif sub == "rebase" and long_exec and eq:
            out.append(value)
    if sub == "submodule" and args[:1] == ["foreach"]:
        out.append(" ".join(a for a in args[1:] if a != "--recursive"))
    if sub == "bisect" and args[:1] == ["run"]:
        out.append(" ".join(args[1:]))
    return out


def _listing_only(sub: str, args: list[str]) -> bool:
    """`remote`, `tag`, `stash` and `reflog` are read-only only in these exact shapes; the
    subcommand AND every argument after it must fit. A bare `git stash` writes, and
    `git stash show` prints a diff, so it is not read-only either."""
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
        return args == ["list"]
    if sub == "reflog":
        return args in ([], ["show"])
    return False


def _read_only(sub: str, sub_args: list[str], found: set[C], code: list[str]) -> bool:
    if sub == "config":
        return _config(sub_args, found, code)
    if sub == "remote":
        listing = _listing_only(sub, sub_args)
        if not listing:
            found.add(C.GIT_CONFIG_CHANGE)
        return listing
    if sub == "branch":
        return all(
            a in ("--list", "-a", "-r", "-v", "-vv", "--show-current", "--all") for a in sub_args
        )
    if sub in ("tag", "stash", "reflog"):
        return _listing_only(sub, sub_args)
    spec = GIT_SAFE.get(sub)
    return spec is not None and spec_allows(spec, sub_args)


def check_git(args: list[str], protected: tuple[str, ...]) -> GitFacts:
    """Classify `git <args>` (literal argument texts)."""
    found: set[C] = set()
    code: list[str] = []
    split = _split_globals(args, found, code)
    rest = split.rest
    if not rest:
        return GitFacts(frozenset(found), frozenset(), False, tuple(c for c in code if c))
    alias = split.aliases.get(rest[0].casefold())
    if alias is not None and not alias.startswith("!") and alias.split():
        rest = alias.split() + rest[1:]  # read what the alias stands for
    sub, sub_args = rest[0], rest[1:]
    branches: set[str] = set()
    unknown = False
    read_only = False
    if sub == "push":
        branches, unknown = _push(sub_args, protected, found, code)
    elif sub in ("credential", "credential-store", "credential-cache"):
        found.add(C.CREDENTIAL_ACCESS)
    elif sub == "clean" and ("f" in _short_flags(sub_args) or "--force" in sub_args):
        found.add(C.DESTRUCTIVE_DELETE)
    else:
        read_only = _read_only(sub, sub_args, found, code)
    read_only = read_only and set(split.options) <= _READ_ONLY_GLOBALS
    if sub == "commit":
        found.add(C.GIT_COMMIT)
    if sub in ("commit", "push", "merge", "am") and (
        "--no-verify" in sub_args or (sub == "commit" and "n" in _short_flags(sub_args))
    ):
        found.add(C.GIT_HOOKS_CHANGE)
    if _rewrite(sub, sub_args):
        found.add(C.GIT_HISTORY_REWRITE)
    nested = tuple(c for c in (*code, *_nested(sub, sub_args)) if c)
    return GitFacts(frozenset(found), frozenset(branches), read_only and not found, nested, unknown)
