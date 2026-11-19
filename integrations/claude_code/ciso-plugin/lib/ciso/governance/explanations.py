"""Reason codes and the fixed message shown to the engineer for each.

Messages never echo anything from the action (no command text, path or content): they
say what kind of thing was stopped and what to do next.
"""

from __future__ import annotations

from enum import StrEnum


class ReasonCode(StrEnum):
    RULESET_UNAVAILABLE = "ruleset_unavailable"
    KILL_SWITCH_ENGAGED = "kill_switch_engaged"
    ATTRIBUTION_DISPUTED = "attribution_disputed"
    ATTRIBUTION_MISMATCH = "attribution_mismatch"
    CRITICAL_FINDING = "critical_finding"
    AGENT_CONFIG_CHANGE = "agent_config_change"
    SECURITY_TOOL_TAMPER = "security_tool_tamper"
    IDENTITY_UNAVAILABLE = "identity_unavailable"
    INSPECTION_MISSING = "inspection_missing"
    INSPECTION_INCOMPLETE = "inspection_incomplete"
    RULE_DENY = "rule_deny"
    RULE_ASK = "rule_ask"
    RULE_ALLOW = "rule_allow"
    DEFAULT_DENY = "default_deny"
    DEFAULT_ASK = "default_ask"
    DEFAULT_ALLOW = "default_allow"
    UNPARSEABLE_COMMAND = "unparseable_command"
    AUDIT_UNAVAILABLE = "audit_unavailable"
    INTERNAL_ERROR = "internal_error"


_CONTACT = "If you think this is wrong, contact the security team."

MESSAGES: dict[ReasonCode, str] = {
    ReasonCode.RULESET_UNAVAILABLE: (
        "Blocked: the governance rules could not be loaded, so no action can be approved. "
        "Try again later. " + _CONTACT
    ),
    ReasonCode.KILL_SWITCH_ENGAGED: (
        "Blocked: the security team has paused all changes by AI agents. Reading is still "
        "allowed. Wait for the pause to be lifted."
    ),
    ReasonCode.ATTRIBUTION_DISPUTED: (
        "Blocked: this session is linked to more than one person, so changes are stopped. "
        "Sign in again with your own company account. " + _CONTACT
    ),
    ReasonCode.ATTRIBUTION_MISMATCH: (
        "Blocked: the identity record does not belong to this session. Start a new session. "
        + _CONTACT
    ),
    ReasonCode.CRITICAL_FINDING: (
        "Blocked: a critical problem was found in the content of this change. Review the "
        "finding in the security report and remove the problem before trying again."
    ),
    ReasonCode.AGENT_CONFIG_CHANGE: (
        "Blocked: AI agents may not change their own settings, hooks, plugins, tool "
        "servers or instruction files. Make this change yourself, by hand, if it is needed."
    ),
    ReasonCode.SECURITY_TOOL_TAMPER: (
        "Blocked: this would disable or weaken a security control (antivirus, firewall, "
        "logging or history). This is never allowed for AI agents. " + _CONTACT
    ),
    ReasonCode.IDENTITY_UNAVAILABLE: (
        "Blocked: the identity service could not be reached, so the decision could not be "
        "made. Try again in a moment."
    ),
    ReasonCode.INSPECTION_MISSING: (
        "Held: this change must be scanned before it can go ahead, and no scan result was "
        "available. Try again; if it keeps happening, contact the security team."
    ),
    ReasonCode.INSPECTION_INCOMPLETE: (
        "Held: the scan of this change did not finish, so it cannot be approved yet. Try "
        "again; if it keeps happening, contact the security team."
    ),
    ReasonCode.RULE_DENY: (
        "Blocked by company policy for AI agents. Ask the agent for a different approach, "
        "or do this step yourself if you are allowed to. " + _CONTACT
    ),
    ReasonCode.RULE_ASK: (
        "This action needs your confirmation under company policy. Check what it does "
        "before you approve it."
    ),
    ReasonCode.RULE_ALLOW: "Allowed by company policy.",
    ReasonCode.DEFAULT_DENY: (
        "Blocked: no company rule allows this kind of action for AI agents. " + _CONTACT
    ),
    ReasonCode.DEFAULT_ASK: (
        "This action needs your confirmation: no company rule covers it. Check what it does "
        "before you approve it."
    ),
    ReasonCode.DEFAULT_ALLOW: "Allowed: this is a read-only action.",
    ReasonCode.UNPARSEABLE_COMMAND: (
        "This command could not be read with confidence, so it cannot be approved "
        "automatically. Check it carefully, or split it into simpler commands."
    ),
    ReasonCode.AUDIT_UNAVAILABLE: (
        "Blocked: the decision could not be recorded in the audit log, so the action cannot "
        "go ahead. Try again in a moment."
    ),
    ReasonCode.INTERNAL_ERROR: (
        "Blocked: the governance service had an internal error. Try again. " + _CONTACT
    ),
}

#: Short, fixed details recorded with each reason (never action content).
DETAILS: dict[ReasonCode, str] = {code: code.value.replace("_", " ") for code in ReasonCode}


def explanation(code: ReasonCode) -> str:
    return MESSAGES[code]
