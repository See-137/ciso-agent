"""Paths that may name a sensitive file without spelling it out (review M1, queue Q3).

A shell expands globs (`.ss?`, `.mc[p].json`) and variables (`$D`, `${D}`, `%D%`,
`$env:D`), and Windows opens a file by its 8.3 short name (`CLAUDE~1` for `.claude`). The
path text then never contains the sensitive name, yet the same file is written. Such a
segment is "wild": it is treated as matching every name it COULD stand for.

How: every wild segment is replaced, in turn, by each entry of `SENSITIVE_NAMES` it could
be (a glob that matches the name; a variable, which can be any name or several segments;
a short name whose stem and extension fit the long name), and the sensitive-path rules are
run on every resulting path. A segment that could be none of them stays as written. When
the combinations would exceed `MAX_CANDIDATES` the path is treated as matching every rule:
too many unknowns to clear it.
"""

from __future__ import annotations

import fnmatch
import itertools
import re
from collections.abc import Iterator
from typing import Final

#: Most concrete paths tried for one wild path.
MAX_CANDIDATES: Final = 20_000

#: Names (and short directory chains) the sensitive-path rules are about. A test checks
#: that each one, under a suitable parent, is reported by some rule.
SENSITIVE_NAMES: Final[tuple[str, ...]] = (
    ".claude", ".claude-plugin", ".mcp.json", "claude.md", "claude.local.md", ".claude.json",
    "settings.json", "settings.local.json", ".cursor", ".cursorrules", ".windsurf",
    ".windsurfrules", "agents.md", "copilot-instructions.md", ".github", "workflows",
    "actions", ".env", ".env.local", ".envrc", "app.env", "id_rsa", "id_dsa", "id_ecdsa",
    "id_ed25519", "key.pem", "key.key", "key.p12", "key.pfx", "key.jks", "key.keystore",
    "key.ppk", ".aws", "credentials", "config", ".azure", ".config", "gcloud", ".kube",
    ".docker", "config.json", ".netrc", "_netrc", ".git-credentials", "credentials.json",
    "application_default_credentials.json", "service-account.json", ".npmrc", ".pypirc",
    ".yarnrc", ".yarnrc.yml", "pip.conf", "pip.ini", ".gem", ".cargo", "credentials.toml",
    ".nuget", "nuget.config", ".gitlab-ci.yml", ".gitlab-ci", ".gitlab", "ci",
    "azure-pipelines.yml", ".azure-pipelines", ".azuredevops", "jenkinsfile", ".circleci",
    "bitbucket-pipelines.yml", ".buildkite", ".travis.yml", ".drone.yml", ".woodpecker.yml",
    ".woodpecker", ".git", "hooks", "pre-commit", ".githooks", ".husky",
    ".pre-commit-config.yaml", "lefthook.yml", ".lefthook", ".ssh", "authorized_keys",
    "authorized_keys2", "rc", ".vscode", "tasks.json", "launch.json", ".idea",
    "runconfigurations", "workspace.xml", "app.code-workspace",
)  # fmt: skip
#: What a whole-segment variable may also stand for: several segments at once.
SENSITIVE_CHAINS: Final[tuple[str, ...]] = (
    ".github/workflows", ".github/actions", ".git/hooks", ".config/gcloud", ".gitlab/ci",
    ".idea/runconfigurations", ".claude/hooks", ".ssh/authorized_keys",
)  # fmt: skip

_GLOB = re.compile(r"[*?\[]")
_VARIABLE = re.compile(r"\$\{[^}/]{0,128}\}|\$env:\w{1,128}|\$\w{1,128}|%\w{1,128}%")
#: An 8.3 short name: up to six stem characters, `~` and a number, up to three of extension.
_SHORT = re.compile(r"(?P<stem>[^~./ ]{1,6})~[0-9]{1,6}(?:\.(?P<ext>[^./ ]{1,3}))?")


def is_wild(segment: str) -> bool:
    return bool(_GLOB.search(segment) or _VARIABLE.search(segment) or _SHORT.fullmatch(segment))


def _short_fits(stem: str, ext: str | None, name: str) -> bool:
    """Could Windows give `name` the short name `stem~N.ext`? Leading dots go, the stem is
    the start of the rest without dots and spaces, the extension the start of the last."""
    bare = name.lstrip(".")
    base, _, long_ext = bare.rpartition(".") if "." in bare else (bare, "", "")
    if not base.replace(".", "").replace(" ", "").startswith(stem):
        return False
    return ext is None or long_ext.startswith(ext)


def options(segment: str) -> tuple[str, ...]:
    """The names a (lower-case) segment could stand for; itself when it is not wild or
    could be none of `SENSITIVE_NAMES`."""
    short = _SHORT.fullmatch(segment)
    if short is not None:
        found = [n for n in SENSITIVE_NAMES if _short_fits(short["stem"], short["ext"], n)]
        return tuple(found) or (segment,)
    if not is_wild(segment):
        return (segment,)
    whole_variable = bool(_VARIABLE.fullmatch(segment))
    pattern = _VARIABLE.sub("*", segment)
    names = SENSITIVE_NAMES + (SENSITIVE_CHAINS if whole_variable else ())
    found = [n for n in names if fnmatch.fnmatchcase(n, pattern)]
    return tuple(found) or (segment,)


def candidates(segments: list[str]) -> Iterator[str] | None:
    """Every concrete path the segments could be, or None when there are too many."""
    choices = [options(segment) for segment in segments]
    total = 1
    for choice in choices:
        total *= len(choice)
        if total > MAX_CANDIDATES:
            return None
    return ("/".join(parts) for parts in itertools.product(*choices))
