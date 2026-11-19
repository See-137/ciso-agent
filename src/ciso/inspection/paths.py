"""Sensitive target paths for writes and edits.

Writing these lets an agent plant credentials, run code on the next commit, build or
session, or change the assistant's own rules, which is a known way out of a sandbox. The
check works on the path text only; it never touches the file system.

Normalisation (review M1): both separators, `..` collapsed, case ignored everywhere (the
strictest reading: Windows and the default macOS file system ignore case), and the Windows
quirks that still open the same file are undone: trailing dots and spaces on a component,
an alternate data stream suffix (`name::$DATA`), and the `\\\\?\\` long-path prefix. A
segment that is a glob, a variable or an 8.3 short name matches every sensitive name it
could stand for (`ciso.inspection.path_wild`).

The path literals below are the file names the tools themselves use; the rule ids and
texts stay generic.
"""

from __future__ import annotations

import posixpath
import re
from dataclasses import dataclass
from typing import Final

from ciso.common.activity import Severity
from ciso.inspection._collect import Collector, location
from ciso.inspection.path_wild import candidates, is_wild
from ciso.inspection.rules import Rule

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


@dataclass(frozen=True, slots=True)
class _PathRule:
    rule: Rule
    pattern: re.Pattern[str]


def _p(expression: str) -> re.Pattern[str]:
    """A pattern matched with fullmatch against the normalised path (lower case, `/`)."""
    return re.compile(rf"(?:.*/)?(?:{expression})")


_PATH_RULES: Final[tuple[_PathRule, ...]] = (
    _PathRule(
        ASSISTANT_CONFIG,
        _p(
            r"\.claude/.+|\.claude-plugin/.+|\.mcp\.json|claude(?:\.local)?\.md"
            r"|\.claude\.json|agents\.md|\.cursor/.+|\.cursorrules|\.windsurf/.+"
            r"|\.windsurfrules|\.github/copilot-instructions\.md"
        ),
    ),
    _PathRule(
        ENV_FILE,
        _p(r"\.env(?!\.(?:example|sample|template|dist)$)(?:\.[^/]*)?|\.envrc|[^/]+\.env"),
    ),
    _PathRule(
        PRIVATE_KEY_FILE,
        _p(r"id_(?:rsa|dsa|ecdsa|ed25519)(?:_sk)?|[^/]+\.(?:pem|key|p12|pfx|jks|keystore|ppk)"),
    ),
    _PathRule(
        CLOUD_CREDENTIALS,
        _p(
            r"\.aws/(?:credentials|config)|\.azure/.+|\.config/gcloud/.+|\.kube/config"
            r"|\.docker/config\.json|\.netrc|_netrc|\.git-credentials|credentials\.json"
            r"|application_default_credentials\.json|service[-_]?account[^/]*\.json"
        ),
    ),
    _PathRule(
        REGISTRY_CONFIG,
        _p(
            r"\.npmrc|\.pypirc|\.yarnrc(?:\.yml)?|pip\.conf|pip\.ini|\.gem/credentials"
            r"|\.cargo/credentials(?:\.toml)?|\.nuget/nuget\.config|nuget\.config"
        ),
    ),
    _PathRule(
        CI_PIPELINE,
        _p(
            r"\.github/(?:workflows|actions)/.+|\.gitlab-ci\.yml|\.gitlab-ci/.+"
            r"|\.gitlab/ci/.+|azure-pipelines[^/]*\.ya?ml|\.azure-pipelines/.+|\.azuredevops/.+"
            r"|jenkinsfile[^/]*|\.circleci/.+|bitbucket-pipelines\.yml|\.buildkite/.+"
            r"|\.travis\.yml|\.drone\.yml|\.woodpecker\.ya?ml|\.woodpecker/.+"
        ),
    ),
    _PathRule(SSH_ACCESS, _p(r"\.ssh/(?:authorized_keys2?|config|rc)")),
    _PathRule(
        EDITOR_AUTORUN,
        _p(
            r"\.vscode/(?:tasks|launch|settings)\.json|\.idea/runconfigurations/.+"
            r"|\.idea/workspace\.xml|[^/]+\.code-workspace"
        ),
    ),
    _PathRule(
        GIT_HOOK,
        _p(
            r"\.git/hooks/.+|\.git/config|\.githooks/.+|\.husky/.+"
            r"|\.pre-commit-config\.ya?ml|lefthook\.ya?ml|\.lefthook/.+"
        ),
    ),
)

_DRIVE = re.compile(r"[a-z]:")
_STREAM = re.compile(r"(?P<name>[^:]*):.*")


def normalise_path(path: str) -> str:
    """Lower-case, `/`-separated, `..` collapsed, Windows aliases of a name undone."""
    text = path.replace("\\", "/").lower()
    for prefix in ("//?/", "//./"):
        if text.startswith(prefix):
            text = text[len(prefix) :]
    parts: list[str] = []
    for index, part in enumerate(text.split("/")):
        if index == 0 and _DRIVE.fullmatch(part):
            continue
        stream = _STREAM.fullmatch(part)
        if stream:
            part = stream.group("name")
        part = part.rstrip(" .") if part not in {".", ".."} else part
        parts.append(part)
    joined = posixpath.normpath("/" + "/".join(p for p in parts if p))
    return joined.lstrip("/")


def sensitive_path_rules(path: str) -> tuple[Rule, ...]:
    """Every sensitive-path rule the path matches (several can apply to one path).

    A segment that is a glob, a variable or an 8.3 short name matches every name it could
    stand for (`ciso.inspection.path_wild`); too many such unknowns match every rule."""
    normal = normalise_path(path)
    if not normal or normal == ".":
        return ()
    paths = [normal]
    segments = normal.split("/")
    if any(is_wild(segment) for segment in segments):
        expanded = candidates(segments)
        if expanded is None:
            return PATH_RULES
        paths.extend(expanded)
    return tuple(
        entry.rule
        for entry in _PATH_RULES
        if any(entry.pattern.fullmatch(candidate) for candidate in paths)
    )


def check_path(path: str, out: Collector, *, shown_as: str | None = None) -> None:
    """Add a finding for each sensitive-path rule `path` matches."""
    for rule in sensitive_path_rules(path):
        out.add(rule, location(shown_as if shown_as is not None else path))


PATH_RULES: Final[tuple[Rule, ...]] = tuple(entry.rule for entry in _PATH_RULES)
