"""Paths that may name a sensitive file without spelling it out (review M1, queue Q3, Q13).

A shell expands globs (`.ss?`, `.mc[p].json`) and variables (`$D`, `${D}`, `%D%`,
`$env:D`), and Windows opens a file by its 8.3 short name (`CLAUDE~1` for `.claude`). The
path text then never contains the sensitive name, yet the same file is written.

`as_glob` rewrites what `ciso.common.paths.normalise_path` would otherwise widen to "any
name", so precision is kept where the text says more:

- a short name keeps its stem and extension: `SETTIN~1.JSO` becomes `*settin*.jso*`
  (Windows builds the stem from the long name without leading dots, the extension from
  the start of the long one), so `out~1.txt` cannot be `.env` while `CLAUDE~1` can still
  be `.claude`;
- a variable INSIDE a segment becomes `*` within that segment (`$DATE.txt` is `*.txt`);
  a segment that is a whole variable stays, and the shared normaliser reads it as unknown
  (it may be any path, several segments, and it matches every rule).

Globs are left as written; `may_match` answers "could these meet".
"""

from __future__ import annotations

import re
from typing import Final

#: Names (and short directory chains) the sensitive-path rules are about. A test checks
#: that each one, under a suitable parent, is reported by some rule (coverage data only;
#: matching itself is `ciso.common.paths.may_match` on the rules' patterns).
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
    ".gitleaks.toml", ".gitleaksignore", ".semgrepignore",
)  # fmt: skip
#: What a whole-segment variable may also stand for: several segments at once.
SENSITIVE_CHAINS: Final[tuple[str, ...]] = (
    ".github/workflows", ".github/actions", ".git/hooks", ".config/gcloud", ".gitlab/ci",
    ".idea/runconfigurations", ".claude/hooks", ".ssh/authorized_keys",
)  # fmt: skip

_VARIABLE = re.compile(r"\$\{[^}/]{0,128}\}|\$env:\w{1,128}|\$\w{1,128}|%\w{1,128}%")
#: An 8.3 short name: up to six stem characters, `~` and a number, up to three of extension.
_SHORT = re.compile(r"(?P<stem>[^~./ ]{1,6})~[0-9]{1,6}(?:\.(?P<ext>[^./ ]{1,3}))?")
_SEPARATOR = re.compile(r"[/\\]")


def _segment(part: str) -> str:
    short = _SHORT.fullmatch(part.casefold())
    if short is not None:
        ext = short["ext"]
        return f"*{short['stem']}*" + (f".{ext}*" if ext else "")
    if _VARIABLE.fullmatch(part):
        return part
    return _VARIABLE.sub("*", part)


def as_glob(path: str) -> str:
    """`path` with short names and in-segment variables rewritten as globs (module doc).
    Separators become `/`; everything else is left to the shared normaliser."""
    return "/".join(_segment(part) for part in _SEPARATOR.split(path))
