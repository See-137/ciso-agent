"""What a plain `git push <remote> <branch>` will send, and the inspection of it.

No sandbox and no server: the hook resolves the push itself (spec C2/C5 without C3/C5).

1. The command must be one plain push naming one remote and one branch
   (`ciso.app.change_shape`, bundled); anything else is refused by the caller.
2. Settings that redirect or widen the push, or run programs during it, refuse it
   (`config_hazards`, `hook_hazards`): `remote.<name>.push|mirror|pushurl|receivepack|
   uploadpack`, any `url.*.pushInsteadOf`, `core.gitProxy`, repository-level
   `core.sshCommand` / `core.askPass` / `credential.*helper`, `push.recurseSubmodules` or
   `submodule.recurse` asking to push submodules, `core.hooksPath` pointing inside the
   repository, and hook programs in the repository's hooks directory.
3. The scan base: `git ls-remote --heads <remote>` (git contacts the remote the push will
   contact anyway; Python opens no connection). An advertised branch tip is used as a base
   only when the local remote-tracking ref for it holds the same commit, so neither a
   lying remote nor a moved local ref alone can shrink the scan. With no usable base the
   range runs to the root. More than `MAX_PUSH_COMMITS` commits refuses the push.
4. Every commit in the range is inspected separately (`git log -p`, merges against their
   first parent, renames off, no textconv): a secret added in one commit and deleted in
   the next is still found. Binary changes make the result incomplete, so the push is
   refused (the ruleset's `missing_inspection: deny`).

Tests are NOT run (no sandbox). That is the optional sandbox add-on's job.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Final

from ciso.app.change_decide import merge_inspections
from ciso.app.change_shape import ChangeKind, ChangeShape
from ciso.common.activity import InspectionResult
from ciso.inspection import inspect_diff
from ciso_plugin.gitrun import GitError, SafeGit

#: Most commits one scanned push may carry.
MAX_PUSH_COMMITS: Final = 1000
CHECK_RANGE: Final = "plugin.push_range"
COMMIT_MARK: Final = "\x01ciso-commit "
_SHA: Final = re.compile(r"[0-9a-f]{40}|[0-9a-f]{64}")
_REMOTE_KEYS: Final = ("push", "mirror", "pushurl", "receivepack", "uploadpack")
_REPO_SCOPES: Final = frozenset({"local", "worktree"})
_SUBMODULE_OK: Final = frozenset({"no", "false", "0", "off", "check"})


class ScanRefused(Exception):
    """The push cannot be scanned or must not run. `code` is fixed; `names` are config
    key names only (never values)."""

    def __init__(self, code: str, names: tuple[str, ...] = ()) -> None:
        super().__init__(code)
        self.code = code
        self.names = names


@dataclass(frozen=True)
class ConfigEntry:
    scope: str
    key: str
    value: str


def read_config(git: SafeGit) -> list[ConfigEntry]:
    """Every config entry git would use here, with its scope (command scope dropped: that
    is this module's own `-c` hardening)."""
    result = git.run("config", "--list", "--show-scope", "-z")
    if result.returncode != 0:
        raise ScanRefused("git_failed")
    parts = result.stdout.decode("utf-8", errors="replace").split("\0")
    entries = []
    for scope, item in zip(parts[0::2], parts[1::2], strict=False):
        key, _, value = item.partition("\n")
        if scope != "command":
            entries.append(ConfigEntry(scope, key.casefold(), value))
    return entries


def _inside(path_text: str, top: Path) -> bool:
    candidate = Path(path_text).expanduser()
    if not candidate.is_absolute():
        return True  # a relative hooks path is resolved inside the work tree
    try:
        candidate.resolve().relative_to(top.resolve())
    except ValueError:
        return False
    return True


def config_hazards(entries: list[ConfigEntry], remote: str, top: Path) -> tuple[str, ...]:
    """Names of settings that redirect or widen this push or run programs during it."""
    remote_prefix = f"remote.{remote.casefold()}."
    found: list[str] = []
    for entry in entries:
        key = entry.key
        if key.startswith(remote_prefix) and key.rpartition(".")[2] in _REMOTE_KEYS:
            found.append(key)
        elif key.startswith("url.") and key.endswith(".pushinsteadof"):
            found.append("url.<base>.pushinsteadof")
        elif key == "core.gitproxy" or (
            entry.scope in _REPO_SCOPES
            and (
                key in {"core.sshcommand", "core.askpass"}
                or (key.startswith("credential.") and key.endswith("helper"))
            )
        ):
            found.append(key)
        elif key in {"push.recursesubmodules", "submodule.recurse"}:
            if entry.value.strip().casefold() not in _SUBMODULE_OK:
                found.append(key)
        elif key == "core.hookspath" and _inside(entry.value, top):
            found.append(key)
    return tuple(dict.fromkeys(found))


def hook_hazards(git: SafeGit, entries: list[ConfigEntry]) -> bool:
    """True when the repository's own hooks directory holds a hook program (anything not
    ending in `.sample`) and no hooks path elsewhere replaces it."""
    if any(e.key == "core.hookspath" for e in entries):
        return False  # outside the repository (checked above): the user's own hooks
    # Not `--git-path hooks`: that follows core.hooksPath, which this git overrides.
    common = git.out("rev-parse", "--path-format=absolute", "--git-common-dir", code="git_dir")
    folder = Path(common) / "hooks"
    if not folder.is_dir():
        return False
    return any(p.is_file() and not p.name.endswith(".sample") for p in folder.iterdir())


def _commit(git: SafeGit, ref: str) -> str | None:
    result = git.run("rev-parse", "--verify", "--quiet", "--end-of-options", ref + "^{commit}")
    text = result.stdout.decode("ascii", errors="replace").strip()
    return text if result.returncode == 0 and _SHA.fullmatch(text) else None


def scan_bases(git: SafeGit, remote: str) -> list[str]:
    """Advertised branch tips that the local tracking refs of `remote` agree with."""
    try:
        listing = git.run("ls-remote", "--heads", "--", remote, network=True)
    except GitError:
        return []
    if listing.returncode != 0:
        return []
    advertised: dict[str, str] = {}
    for line in listing.stdout.decode("utf-8", errors="replace").splitlines():
        sha, _, ref = line.partition("\t")
        if _SHA.fullmatch(sha) and ref.startswith("refs/heads/"):
            advertised[ref.removeprefix("refs/heads/")] = sha
    bases = []
    for branch, sha in sorted(advertised.items()):
        if _commit(git, f"refs/remotes/{remote}/{branch}") == sha:
            bases.append(sha)
    return bases


def split_commits(log_text: str) -> list[tuple[str, str]]:
    """`git log -p` output with `COMMIT_MARK` headers -> (commit, its diff)."""
    out = []
    for chunk in ("\n" + log_text).split("\n" + COMMIT_MARK)[1:]:
        sha, _, diff = chunk.partition("\n")
        out.append((sha.strip(), diff.strip("\n") + "\n"))
    return out


def _range_inspection(
    git: SafeGit, head: str, bases: list[str], action_id: str
) -> InspectionResult:
    listed = git.out(
        "rev-list",
        f"--max-count={MAX_PUSH_COMMITS + 1}",
        head,
        "--not",
        *bases,
        "--",
        code="rev_list",
    ).split()
    if len(listed) > MAX_PUSH_COMMITS:
        raise ScanRefused("too_many_commits")
    if not listed:
        return InspectionResult(action_id=action_id, checks_run=(CHECK_RANGE,), complete=True)
    log = git.out(
        "log",
        "--no-color",
        "--no-ext-diff",
        "--no-textconv",
        "--no-renames",
        "--diff-merges=first-parent",
        "-p",
        "--format=format:%x01ciso-commit %H",
        head,
        "--not",
        *bases,
        "--",
        code="log",
    )
    parts: list[InspectionResult | None] = [
        InspectionResult(action_id=action_id, checks_run=(CHECK_RANGE,), complete=True)
    ]
    seen = 0
    for _sha, diff in split_commits(log):
        seen += 1
        if diff.strip():
            parts.append(inspect_diff(diff, action_id=action_id))
    if seen != len(listed):
        raise ScanRefused("git_failed")
    return merge_inspections(action_id, parts)


def scan_push(git: SafeGit, shape: ChangeShape, action_id: str) -> InspectionResult:
    """The inspection of everything the push sends. Raises `ScanRefused` or `GitError`."""
    if shape.kind is not ChangeKind.PUSH or shape.remote is None or shape.branch is None:
        raise ScanRefused("push_not_plain")
    top_text = git.out("rev-parse", "--show-toplevel", code="not_a_repository")
    top = Path(top_text)
    repo = git.at(str(top))
    entries = read_config(repo)
    if not any(e.key == f"remote.{shape.remote.casefold()}.url" for e in entries):
        raise ScanRefused("unknown_remote")
    hazards = config_hazards(entries, shape.remote, top)
    if hazards:
        raise ScanRefused("push_config_redirect", hazards)
    if hook_hazards(repo, entries):
        raise ScanRefused("repo_hooks")
    ref = "HEAD" if shape.source is None else "refs/heads/" + shape.source
    head = _commit(repo, ref)
    if head is None:
        raise ScanRefused("no_source_commit")
    return _range_inspection(repo, head, scan_bases(repo, shape.remote), action_id)


def scan_commit(git: SafeGit, action_id: str) -> InspectionResult:
    """The inspection of the staged change a plain `git commit -m` records."""
    top = git.out("rev-parse", "--show-toplevel", code="not_a_repository")
    diff = git.at(top).out(
        "diff",
        "--cached",
        "--no-color",
        "--no-ext-diff",
        "--no-textconv",
        "--no-renames",
        code="diff",
    )
    return inspect_diff(diff + "\n" if diff else "", action_id=action_id)
