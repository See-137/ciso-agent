"""Built-in path patterns that mark a file as sensitive. Generic names only.

A ruleset may ADD patterns (`credential_paths`, `agent_config_paths`); it can never remove
these. Assistant-specific file names (an instruction file or settings directory named
after one product) belong in the deployment's ruleset, not here: the core stays
vendor-neutral. Matching is case-insensitive and segment-aware (`ciso.governance.globs`).
"""

from __future__ import annotations

CREDENTIAL_PATHS: tuple[str, ...] = (
    "**/.ssh",
    "**/.ssh/**",
    "**/id_rsa*",
    "**/id_dsa*",
    "**/id_ecdsa*",
    "**/id_ed25519*",
    "**/*.pem",
    "**/*.key",
    "**/*.p12",
    "**/*.pfx",
    "**/*.jks",
    "**/*.keystore",
    "**/*.kdbx",
    "**/.env",
    "**/.env.*",
    "**/*.env",
    "**/.envrc",
    "**/.netrc",
    "**/_netrc",
    "**/.npmrc",
    "**/.pypirc",
    "**/.git-credentials",
    "**/credentials",
    "**/credentials.json",
    "**/credentials.xml",
    "**/*.credentials",
    "**/.vault-token",
    "**/.kube/config",
    "**/.docker/config.json",
    "**/.gnupg",
    "**/.gnupg/**",
    "**/.password-store/**",
    "**/Login Data",
    "**/Cookies",
    "**/cookies.sqlite",
    "**/key4.db",
    "**/logins.json",
    "**/Keychains/**",
    "**/*.keychain",
    "**/*.keychain-db",
    "/etc/shadow",
    "/etc/gshadow",
    "**/config/sam",
    "**/config/security",
    # Aligned with the inspection lane's list (review H1) and the process environment (H2).
    "**/.aws/config",
    "**/.azure/**",
    "**/.config/gcloud/**",
    "**/application_default_credentials.json",
    "**/.config/gh/hosts.yml",
    "**/credentials.tfrc.json",
    "**/.terraform.d/credentials*",
    "**/.cargo/credentials*",
    "**/*.ppk",
    "/proc/**/environ",
)

AGENT_CONFIG_PATHS: tuple[str, ...] = (
    "**/.mcp.json",
    "**/mcp.json",
    "**/.*/mcp*.json",
    "**/.*/settings.json",
    "**/.*/settings.local.json",
    "**/.*/hooks",
    "**/.*/hooks/**",
    "**/.*/plugins/**",
    "**/.*/agents/**",
    "**/.*/commands/**",
    "**/.*/skills/**",
    "**/AGENTS.md",
    "**/AGENTS.override.md",
    "**/managed-settings.json",
    "**/managed-mcp.json",
)

GIT_HOOK_PATHS: tuple[str, ...] = (
    "**/.git/hooks",
    "**/.git/hooks/**",
    "**/.githooks/**",
    "**/.husky/**",
)

GIT_CONFIG_PATHS: tuple[str, ...] = (
    "**/.git/config",
    "**/.gitconfig",
    "**/.config/git/config",
    "**/.gitmodules",
)

PRIVILEGE_PATHS: tuple[str, ...] = (
    "/etc/sudoers",
    "/etc/sudoers.d/**",
    "/etc/passwd",
    "/etc/group",
    "**/authorized_keys",
)

TAMPER_PATHS: tuple[str, ...] = (
    "/var/log/**",
    "/etc/audit/**",
    "/etc/rsyslog*",
    "**/.bash_history",
    "**/.zsh_history",
    "**/.history",
    "**/ConsoleHost_history.txt",
    "**/winevt/logs/**",
)
