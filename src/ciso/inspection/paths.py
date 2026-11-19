"""Sensitive target paths for writes, edits and directory targets.

Writing these lets an agent plant credentials, run code on the next commit, build or
session, or change the assistant's own rules, which is a known way out of a sandbox. The
check works on the path text only; it never touches the file system.

Every decision goes through `ciso.common.paths` (queue Q13): the text is read by
`path_wild.as_glob` (short names keep their stem, a variable inside a segment is `*`),
normalised by `normalise_path` (case, both separators, `.`/`..`, trailing dots and
spaces, stream suffixes, device prefixes, home spellings; a whole-segment variable makes
the path unknown) and compared with each rule's glob patterns by `may_match` ("could
these name the same file"). An exclusion (`.env.example`) applies only to a path whose
text is fully known: a glob that could also be `.env.local` is still reported.

A DIRECTORY target (`tar -C`, `unzip -d`, a copy destination) may receive any file below
it: `directory_rules` reports the rules whose sensitive location the directory is, or
lies inside (`.claude`, `.ssh`, `.github/workflows`...). A directory that is the working
directory, a parent, home, a root or unknown also gives one medium finding
(`BULK_WRITE_BROAD`) instead of every name-anywhere rule (`.env`, `*.pem`), which could
all match below it; governance answers such a command `bulk_write` (ask).

The path literals below are the file names the tools themselves use; the rule ids and
texts stay generic.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Final

from ciso.common.activity import Severity
from ciso.common.paths import (
    ANY_SEGMENTS,
    HOME,
    NormalisedPath,
    may_match,
    normalise_path,
)
from ciso.inspection._collect import Collector, location
from ciso.inspection.path_wild import as_glob
from ciso.inspection.rules import Rule
from ciso.inspection.suppression import SCANNER_CONFIG

_PATH = "sensitive_path"

ENV_FILE = Rule(
    "path.env_file",
    _PATH,
    Severity.HIGH,
    "Write to an environment file",
    "Keep environment files out of agent changes; load values from the secret store",
)
PRIVATE_KEY_FILE = Rule(
    "path.private_key_file",
    _PATH,
    Severity.HIGH,
    "Write to a private key or key store file",
    "Do not let agents write key material; issue keys through the key management process",
)
CLOUD_CREDENTIALS = Rule(
    "path.cloud_credentials",
    _PATH,
    Severity.HIGH,
    "Write to a cloud, cluster or registry credential file",
    "Do not let agents write credential files; use short-lived credentials from the store",
)
REGISTRY_CONFIG = Rule(
    "path.package_registry_config",
    _PATH,
    Severity.MEDIUM,
    "Write to a package registry configuration that can hold a publish token",
    "Keep registry tokens out of the repository; configure them on the build service",
)
CI_PIPELINE = Rule(
    "path.ci_pipeline",
    _PATH,
    Severity.HIGH,
    "Change to a build pipeline definition",
    "Pipeline changes need review by the pipeline owner before they are pushed",
)
GIT_HOOK = Rule(
    "path.git_hook",
    _PATH,
    Severity.HIGH,
    "Change to a git hook or git configuration that runs code",
    "Agents may not install or change git hooks; ask a person to review the hook",
)
SSH_ACCESS = Rule(
    "path.ssh_access",
    _PATH,
    Severity.HIGH,
    "Write to an SSH access list or SSH client configuration",
    "Agents may not grant SSH access or change SSH settings; a person must make this change",
)
EDITOR_AUTORUN = Rule(
    "path.editor_autorun",
    _PATH,
    Severity.HIGH,
    "Change to an editor task, launch or settings file that can run code",
    "Editor tasks and run configurations need review by a person before they are kept",
)
ASSISTANT_CONFIG = Rule(
    "path.assistant_config",
    _PATH,
    Severity.CRITICAL,
    "Change to the assistant's own settings, hooks, plugins or instruction files",
    "Agents may not change their own configuration; a person must make this change",
)


BULK_WRITE_BROAD = Rule(
    "path.bulk_write_broad",
    _PATH,
    Severity.MEDIUM,
    "Recursive copy, move or archive extraction into the working directory, a parent, "
    "the home directory or an unknown place",
    "Copy or extract into a new, empty directory and review the files before moving them",
)


@dataclass(frozen=True, slots=True)
class _PathRule:
    rule: Rule
    #: Anchored globs (`ciso.common.paths` syntax); each starts with `**/`.
    patterns: tuple[str, ...]
    exclude: tuple[str, ...] = ()


def _under(*directories: str) -> tuple[str, ...]:
    """Each directory and anything below it."""
    return tuple(f"**/{d}/**" for d in directories)


def _named(*names: str) -> tuple[str, ...]:
    return tuple(f"**/{n}" for n in names)


_KEYS = ("id_rsa", "id_dsa", "id_ecdsa", "id_ed25519")
_KEY_EXTENSIONS = ("pem", "key", "p12", "pfx", "jks", "keystore", "ppk")

_PATH_RULES: Final[tuple[_PathRule, ...]] = (
    # Scanner configuration and ignore files (review H3): category `scan_suppression`.
    _PathRule(SCANNER_CONFIG, _named(".gitleaks.toml", ".gitleaksignore", ".semgrepignore")),
    _PathRule(
        ASSISTANT_CONFIG,
        _under(".claude", ".claude-plugin", ".cursor", ".windsurf")
        + _named(
            ".mcp.json",
            "claude.md",
            "claude.local.md",
            ".claude.json",
            "agents.md",
            ".cursorrules",
            ".windsurfrules",
            ".github/copilot-instructions.md",
        ),
    ),
    _PathRule(
        ENV_FILE,
        _named(".env", ".env.*", ".envrc", "*.env"),
        _named(".env.example", ".env.sample", ".env.template", ".env.dist"),
    ),
    _PathRule(
        PRIVATE_KEY_FILE,
        _named(*_KEYS, *(k + "_sk" for k in _KEYS), *(f"*.{e}" for e in _KEY_EXTENSIONS)),
    ),
    _PathRule(
        CLOUD_CREDENTIALS,
        _under(".azure", ".config/gcloud")
        + _named(
            ".aws/credentials",
            ".aws/config",
            ".kube/config",
            ".docker/config.json",
            ".netrc",
            "_netrc",
            ".git-credentials",
            "credentials.json",
            "application_default_credentials.json",
            "service-account*.json",
            "service_account*.json",
            "serviceaccount*.json",
        ),
    ),
    _PathRule(
        REGISTRY_CONFIG,
        _named(
            ".npmrc",
            ".pypirc",
            ".yarnrc",
            ".yarnrc.yml",
            "pip.conf",
            "pip.ini",
            ".gem/credentials",
            ".cargo/credentials",
            ".cargo/credentials.toml",
            ".nuget/nuget.config",
            "nuget.config",
        ),
    ),
    _PathRule(
        CI_PIPELINE,
        _under(
            ".github/workflows",
            ".github/actions",
            ".gitlab-ci",
            ".gitlab/ci",
            ".azure-pipelines",
            ".azuredevops",
            ".circleci",
            ".buildkite",
            ".woodpecker",
        )
        + _named(
            ".gitlab-ci.yml",
            "azure-pipelines*.yml",
            "azure-pipelines*.yaml",
            "jenkinsfile*",
            "bitbucket-pipelines.yml",
            ".travis.yml",
            ".drone.yml",
            ".woodpecker.yml",
            ".woodpecker.yaml",
        ),
    ),
    _PathRule(
        SSH_ACCESS,
        _named(".ssh/authorized_keys", ".ssh/authorized_keys2", ".ssh/config", ".ssh/rc"),
    ),
    _PathRule(
        EDITOR_AUTORUN,
        _under(".idea/runconfigurations")
        + _named(
            ".vscode/tasks.json",
            ".vscode/launch.json",
            ".vscode/settings.json",
            ".idea/workspace.xml",
            "*.code-workspace",
        ),
    ),
    _PathRule(
        GIT_HOOK,
        _under(".git/hooks", ".githooks", ".husky", ".lefthook")
        + _named(
            ".git/config",
            ".pre-commit-config.yml",
            ".pre-commit-config.yaml",
            "lefthook.yml",
            "lefthook.yaml",
        ),
    ),
)

_GLOB_CHARS: Final = frozenset("*?[")


def _read(path: str) -> NormalisedPath:
    return normalise_path(as_glob(path), windows=True)


def _fully_known(path: NormalisedPath) -> bool:
    return not path.unknown and not any(ch in _GLOB_CHARS for s in path.segments for ch in s)


def _file_hit(entry: _PathRule, path: NormalisedPath, known: bool) -> bool:
    if not any(may_match(pattern, path) for pattern in entry.patterns):
        return False
    return not (known and any(may_match(pattern, path) for pattern in entry.exclude))


def sensitive_path_rules(path: str) -> tuple[Rule, ...]:
    """Every sensitive-path rule the file `path` may be (several can apply to one path).

    Short names, globs and variables match every name they could stand for; a path with
    a whole-segment variable may be any path and matches every rule."""
    normal = _read(path)
    if not normal.unknown and not normal.segments:
        return ()
    known = _fully_known(normal)
    return tuple(entry.rule for entry in _PATH_RULES if _file_hit(entry, normal, known))


def _prefixes(pattern: str) -> tuple[str, ...]:
    """The directory patterns a target directory may match for files of `pattern` to land
    below it: `**/.ssh/config` gives `**/.ssh`; `**/.claude/**` gives `**/.claude`
    and itself. A name-anywhere pattern (`**/.env`) gives none."""
    tail = pattern.split("/")[1:]
    stop = len(tail) if tail[-1] == ANY_SEGMENTS else len(tail) - 1
    return tuple("/".join((ANY_SEGMENTS, *tail[:j])) for j in range(1, stop + 1))


def is_broad(path: NormalisedPath) -> bool:
    """The working directory, only parents of it, home, a root, or unknown."""
    segments = path.segments
    if path.unknown or ANY_SEGMENTS in segments:
        return True
    if all(segment == ".." for segment in segments):  # also the empty path: here
        return True
    if segments in ((HOME,), ("",)):
        return True
    return len(segments) == 1 and len(segments[0]) == 2 and segments[0].endswith(":")


def directory_rules(path: str, *, broad: bool = True) -> tuple[Rule, ...]:
    """The rules a file placed anywhere below directory `path` may break (module doc).
    `broad=False` leaves out `BULK_WRITE_BROAD` (a plain copy into the working directory
    is not a bulk write)."""
    normal = _read(path)
    found = [
        entry.rule
        for entry in _PATH_RULES
        if any(may_match(p, normal) for pattern in entry.patterns for p in _prefixes(pattern))
    ]
    if broad and is_broad(normal):
        found.append(BULK_WRITE_BROAD)
    return tuple(found)


def check_path(path: str, out: Collector, *, shown_as: str | None = None) -> None:
    """Add a finding for each sensitive-path rule the file `path` matches."""
    for rule in sensitive_path_rules(path):
        out.add(rule, location(shown_as if shown_as is not None else path))


def check_directory(path: str, out: Collector, *, broad: bool = True) -> None:
    """Add a finding for each rule a file written below directory `path` may break."""
    for rule in directory_rules(path, broad=broad):
        out.add(rule, location(path or "."))


PATH_RULES: Final[tuple[Rule, ...]] = tuple(entry.rule for entry in _PATH_RULES)
DIRECTORY_RULES: Final[tuple[Rule, ...]] = (BULK_WRITE_BROAD,)
