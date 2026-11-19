"""What the organization configures, read from the hook's environment.

The managed settings' `env` block sets these for every Claude Code session and its
subprocesses (hooks included); a managed value overwrites the same variable exported in
the user's shell (settings reference, `env`). Nothing here has a numeric default that
relaxes a control.

- `CISO_STOP`: the organization stop flag. `0`, `false`, `off`, `no` or unset: not engaged.
  `1`, `true`, `on`, `yes`: engaged. Any other value counts as engaged (fail closed).
- `CISO_ROLE`: the role of the person logged in to the device. Default `employee`. An
  unknown role makes the identity lookup fail, so every decision that needs it denies.
- `CISO_AGENT_CLASS`: `employee_operated` (default) or `organizational` for company bots
  that run the plugin. Anything else is `unknown`.
- `CISO_GIT_PATH`: absolute path of the git the pre-push scan runs. Optional; without it
  git is looked up on the absolute entries of `PATH` only.
- `CLAUDE_PLUGIN_DATA`: the plugin's per-user data directory (set by Claude Code for hook
  processes). Required: without it nothing can be audited and BEFORE actions are denied.
"""

from __future__ import annotations

import os
import shutil
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Final

from ciso.common.activity import AgentClass
from ciso.common.enums import KillCapability, Role

ENV_STOP: Final = "CISO_STOP"
ENV_ROLE: Final = "CISO_ROLE"
ENV_AGENT_CLASS: Final = "CISO_AGENT_CLASS"
ENV_GIT: Final = "CISO_GIT_PATH"
ENV_DATA: Final = "CLAUDE_PLUGIN_DATA"

_OFF: Final = frozenset({"", "0", "false", "off", "no"})
_AGENT_CLASSES: Final = {
    AgentClass.EMPLOYEE_OPERATED.value: AgentClass.EMPLOYEE_OPERATED,
    AgentClass.ORGANIZATIONAL.value: AgentClass.ORGANIZATIONAL,
}


class SettingsError(Exception):
    """A required setting is missing or unusable. The message names the setting only."""


def stop_engaged(raw: str | None) -> bool:
    """True when the stop flag is engaged, and for any value that is not clearly off."""
    if raw is None:
        return False
    value = raw.strip().casefold()
    return value not in _OFF


@dataclass(frozen=True)
class EnvKillSwitch:
    """`KillSwitchReader` over the stop flag. Every capability follows the one flag."""

    raw: str | None

    def is_blocked(self, capability: KillCapability) -> bool:
        return stop_engaged(self.raw)


def role_of(raw: str | None) -> Role | None:
    """The configured role, `employee` when unset, None when the value is not a role."""
    if raw is None or not raw.strip():
        return Role.EMPLOYEE
    try:
        return Role(raw.strip())
    except ValueError:
        return None


def agent_class_of(raw: str | None) -> AgentClass:
    if raw is None or not raw.strip():
        return AgentClass.EMPLOYEE_OPERATED
    return _AGENT_CLASSES.get(raw.strip(), AgentClass.UNKNOWN)


def data_dir(environ: Mapping[str, str]) -> Path:
    raw = environ.get(ENV_DATA, "")
    if not raw:
        raise SettingsError("plugin data directory not set")
    path = Path(raw)
    if not path.is_absolute():
        raise SettingsError("plugin data directory is not absolute")
    path.mkdir(parents=True, exist_ok=True)
    return path


def git_executable(environ: Mapping[str, str]) -> str:
    """The git to run: `CISO_GIT_PATH` when set (absolute, a file), else the first `git`
    found on the ABSOLUTE entries of PATH, so a relative entry or the working directory
    (the agent's repository) can never supply it."""
    configured = environ.get(ENV_GIT, "")
    if configured:
        path = Path(configured)
        if not path.is_absolute() or not path.is_file():
            raise SettingsError("CISO_GIT_PATH is not an absolute path to a file")
        return str(path)
    entries = [e for e in environ.get("PATH", "").split(os.pathsep) if e and Path(e).is_absolute()]
    found = shutil.which("git", path=os.pathsep.join(entries)) if entries else None
    if not found or not Path(found).is_absolute():
        raise SettingsError("git not found")
    return found


@dataclass(frozen=True)
class PluginSettings:
    stop_raw: str | None
    role: Role | None
    agent_class: AgentClass

    @classmethod
    def from_env(cls, environ: Mapping[str, str]) -> PluginSettings:
        return cls(
            stop_raw=environ.get(ENV_STOP),
            role=role_of(environ.get(ENV_ROLE)),
            agent_class=agent_class_of(environ.get(ENV_AGENT_CLASS)),
        )
