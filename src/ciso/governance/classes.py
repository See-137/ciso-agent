"""What an observed action can be, as far as its text and target show."""

from __future__ import annotations

from enum import StrEnum


class CommandClass(StrEnum):
    """Classes found in an action. Several can hold at once.

    `unparseable` means the text could not be read with confidence; it is never a sign of
    safety. `read_only_command` is the only class that says something is harmless, and it
    is given only when every program in the command is a known reader and nothing else
    was found.
    """

    GIT_PUSH = "git_push"
    GIT_FORCE_PUSH = "git_force_push"
    GIT_PUSH_PROTECTED_REF = "git_push_protected_ref"
    GIT_HISTORY_REWRITE = "git_history_rewrite"
    GIT_CONFIG_CHANGE = "git_config_change"
    GIT_HOOKS_CHANGE = "git_hooks_change"
    GIT_COMMIT = "git_commit"
    DESTRUCTIVE_DELETE = "destructive_delete"
    REMOTE_SCRIPT_EXECUTION = "remote_script_execution"
    NETWORK_TRANSFER = "network_transfer"
    CREDENTIAL_ACCESS = "credential_access"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    PACKAGE_INSTALL = "package_install"
    CONTAINER_OR_VM_CONTROL = "container_or_vm_control"
    AGENT_CONFIG_CHANGE = "agent_config_change"
    SECURITY_TOOL_TAMPER = "security_tool_tamper"
    OBFUSCATION = "obfuscation"
    #: An environment variable that chooses what code runs was set for the command.
    ENVIRONMENT_HIJACK = "environment_hijack"
    #: A recursive copy or move, a sync or an archive extraction into the current
    #: directory, a parent, the home directory, a root or an unknown place (queue Q15):
    #: it can plant files, agent configuration among them, that no path rule sees.
    BULK_WRITE = "bulk_write"
    UNPARSEABLE = "unparseable"
    READ_ONLY_COMMAND = "read_only_command"


#: Classes the engine denies whatever the rules say (built-in invariant).
ALWAYS_DENIED: frozenset[CommandClass] = frozenset(
    {CommandClass.AGENT_CONFIG_CHANGE, CommandClass.SECURITY_TOOL_TAMPER}
)
