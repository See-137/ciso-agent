"""Who is behind the session, in local mode (no identity service, no agent registry).

The person is the operating-system account the hook process runs as, read from the OS
(the Windows logon token through `GetUserNameExW`, the password database elsewhere), not
from environment variables. On a managed device that account is treated as `verified`
with the reason `local_os_account`: this TRUSTS THE DEVICE'S LOGIN. There is no central
identity; whoever is logged in to the machine is the person, with the role the managed
settings give (`CISO_ROLE`). If the account cannot be read, the attribution is `unknown`
and the ruleset denies every non-read action.
"""

from __future__ import annotations

import re
import sys
from dataclasses import dataclass
from typing import Final

from ciso.common.activity import PERSON_REF_KIND, AgentClass, Attribution, ObservedAction
from ciso.common.enums import ActorType, InformationState, Role
from ciso.common.principal import Principal

REASON_LOCAL_ACCOUNT: Final = "local_os_account"
REASON_NO_ACCOUNT: Final = "os_account_unavailable"
AGENT_REF: Final = "agent:local-plugin"
_UNSAFE: Final = re.compile(r"[^A-Za-z0-9_.-]")
#: Longest account name read (the OS limit is far below this).
MAX_ACCOUNT_CHARS: Final = 256


def _windows_account() -> str | None:
    if sys.platform != "win32":
        return None
    import ctypes

    size = ctypes.c_ulong(MAX_ACCOUNT_CHARS + 1)
    buffer = ctypes.create_unicode_buffer(MAX_ACCOUNT_CHARS + 1)
    name_sam_compatible = 2
    try:
        if ctypes.windll.secur32.GetUserNameExW(name_sam_compatible, buffer, ctypes.byref(size)):
            return buffer.value or None
        size = ctypes.c_ulong(MAX_ACCOUNT_CHARS + 1)
        if ctypes.windll.advapi32.GetUserNameW(buffer, ctypes.byref(size)):
            return buffer.value or None
    except (OSError, AttributeError):
        return None
    return None


def _posix_account() -> str | None:
    if sys.platform == "win32":
        return None
    import os
    import pwd

    try:
        return pwd.getpwuid(os.getuid()).pw_name or None
    except KeyError:
        return None


def os_account() -> str | None:
    """The logged-in account (`DOMAIN\\user` on Windows), or None when it cannot be read."""
    account = _windows_account() if sys.platform == "win32" else _posix_account()
    if account is None or len(account) > MAX_ACCOUNT_CHARS or account != account.strip():
        return None
    if any(ord(ch) < 32 for ch in account):
        return None
    return account


def actor_id_for(account: str) -> str:
    """A reference-safe id for the account (`os.` plus the name, unsafe characters as `_`)."""
    return ("os." + _UNSAFE.sub("_", account))[:128]


@dataclass(frozen=True)
class LocalPrincipals:
    """`PrincipalResolver` that knows exactly one person: the logged-in account, with the
    configured role. Raises when the role setting is invalid (the engine then denies)."""

    actor_id: str | None
    role: Role | None

    def resolve(self, actor_id: str) -> Principal | None:
        if self.role is None:
            raise LookupError("configured role is not a known role")
        if self.actor_id is None or actor_id != self.actor_id:
            return None
        return Principal(
            actor_id=actor_id, actor_type=ActorType.HUMAN, roles=frozenset({self.role})
        )


@dataclass(frozen=True)
class LocalAttribution:
    """`AttributionResolver` for local mode. See the module docstring for what it trusts."""

    account: str | None
    agent_class: AgentClass

    @property
    def actor_id(self) -> str | None:
        return None if self.account is None else actor_id_for(self.account)

    def attribute(self, action: ObservedAction) -> Attribution:
        if self.actor_id is None:
            return Attribution(session_id=action.session_id, reasons=(REASON_NO_ACCOUNT,))
        return Attribution(
            session_id=action.session_id,
            person_ref=f"{PERSON_REF_KIND}:{self.actor_id}",
            agent_ref=AGENT_REF,
            agent_class=self.agent_class,
            state=InformationState.VERIFIED,
            reasons=(REASON_LOCAL_ACCOUNT,),
        )
