"""Shared contract for governing AI activity (docs/skill/spec-draft.md, sections 3 and 4).

An `ObservedAction` is something a human's or an organization's AI agent did or is about
to do: a prompt, a shell command, a file write, a connector call, a push. It is reported
by an integration (a hook inside the assistant, the assistant's central gate, telemetry,
an audit feed) and judged by `ciso.governance` before it takes effect where the source
allows that.

Rules that hold for every field here:

- An observed action is a CLAIM made by the source, never proof. Who did it is decided by
  `ciso.agents` from the identity claims, and an unproven claim stays unproven.
- No secret, no file content and no prompt text is stored on these records. The command
  text is kept, bounded, and only after the intake has passed it through the redactor;
  content travels separately (`InspectionInput`) and is never persisted by this contract.
- Every mapping is frozen.
"""

from __future__ import annotations

import unicodedata
from enum import StrEnum
from typing import Annotated, Protocol, runtime_checkable

from pydantic import AfterValidator, ConfigDict, Field, field_validator, model_validator

from ciso.common.enums import InformationState
from ciso.common.schemas import FrozenMap, Model, UtcDatetime

#: Longest command text kept on a record. Longer commands are cut and marked truncated.
MAX_COMMAND_CHARS = 4000
#: Longest identifier or target value (repository, branch, path, server name).
MAX_FIELD_CHARS = 512
#: Most identity claims or target attributes on one record.
MAX_ENTRIES = 16
#: Most findings carried by one inspection result.
MAX_FINDINGS = 200
#: Largest content an `InspectionInput` may carry, in characters. Equal to the inspection
#: lane's `MAX_CONTENT_CHARS`; content above it is refused when the input is built, so an
#: oversized change can never reach a check that would silently skip it.
MAX_INSPECTION_CHARS = 1_048_576
#: Reference kind of a person: `actor:<identity actor id>`. Attribution (`ciso.agents`)
#: writes it, governance and findings read it; nobody hard-codes the string.
PERSON_REF_KIND = "actor"


def clean_text(value: str) -> str:
    """Refuse control, format and line-separator characters and untrimmed text.

    These records end up in the audit log and in messages shown to people; a newline or a
    direction override in a field could forge a line or hide text.
    """
    if value != value.strip():
        raise ValueError("text must not start or end with whitespace")
    for ch in value:
        if unicodedata.category(ch) in {"Cc", "Cf", "Zl", "Zp"}:
            raise ValueError("text must not contain control or format characters")
    return value


#: Bounded, clean text. Empty is allowed; fields that must not be empty say so.
Text = Annotated[str, Field(max_length=MAX_FIELD_CHARS), AfterValidator(clean_text)]


class AgentClass(StrEnum):
    """Who runs the agent. Unknown is not trusted and is never treated as organizational."""

    ORGANIZATIONAL = "organizational"
    EMPLOYEE_OPERATED = "employee_operated"
    UNKNOWN = "unknown"


class ActionKind(StrEnum):
    PROMPT = "prompt"
    SHELL_COMMAND = "shell_command"
    FILE_READ = "file_read"
    FILE_WRITE = "file_write"
    FILE_EDIT = "file_edit"
    CONNECTOR_CALL = "connector_call"
    WEB_FETCH = "web_fetch"
    SUBAGENT = "subagent"
    GIT_COMMIT = "git_commit"
    GIT_PUSH = "git_push"
    SESSION_START = "session_start"
    SESSION_END = "session_end"
    #: The agent finished a turn (the assistant's `Stop` event). Reported after the fact.
    TURN_END = "turn_end"
    OTHER_TOOL = "other_tool"


class ActivitySource(StrEnum):
    """Where the report came from. Only HOOK and CENTRAL_GATE are asked before the action."""

    HOOK = "hook"
    CENTRAL_GATE = "central_gate"
    TELEMETRY = "telemetry"
    AUDIT_FEED = "audit_feed"
    SANDBOX = "sandbox"


class Phase(StrEnum):
    """Before the action runs (it can still be stopped) or after it ran (record only)."""

    BEFORE = "before"
    AFTER = "after"


class IdentityClaim(Model):
    """One statement about who is behind a session, and who vouches for it.

    `kind` names the claim, for example `os_account` (the operating-system login the hook
    read), `assistant_account` (the account the assistant's central gate reports) or
    `api_key` (a key id). `verified` is True only when the integration checked a signature
    or the claim came over an authenticated channel from the issuer.
    """

    kind: Annotated[str, Field(pattern=r"^[a-z][a-z0-9_]{0,31}$")]
    subject: Text
    verified: bool = False

    @field_validator("subject")
    @classmethod
    def _clean(cls, value: str) -> str:
        if not value or value != value.strip() or any(ord(ch) < 32 for ch in value):
            raise ValueError("identity subject must be clean, non-empty text")
        return value


class ObservedAction(Model):
    """One reported agent action. See the module docstring for what may and may not be here."""

    action_id: Text
    session_id: Text
    source: ActivitySource
    phase: Phase
    kind: ActionKind
    tool_name: Text = ""
    surface: Text = ""
    received_at: UtcDatetime
    occurred_at: UtcDatetime | None = None
    identity_claims: Annotated[tuple[IdentityClaim, ...], Field(max_length=MAX_ENTRIES)] = ()
    #: Where the action lands: `repository`, `branch`, `path`, `server`, `host`, `remote`.
    target: FrozenMap[str, str] = Field(default_factory=dict)
    #: Already redacted by the intake. Kept out of `repr` all the same.
    command: Annotated[str, Field(max_length=MAX_COMMAND_CHARS)] | None = Field(
        default=None, repr=False
    )
    command_truncated: bool = False
    content_sha256: Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")] | None = None
    content_bytes: Annotated[int, Field(ge=0)] | None = None
    #: An evidence reference when the source supplied content worth keeping (encrypted).
    evidence_ref: Text | None = Field(default=None, repr=False)

    @model_validator(mode="after")
    def _bounded_target(self) -> ObservedAction:
        if len(self.target) > MAX_ENTRIES:
            raise ValueError("too many target attributes")
        for key, value in self.target.items():
            if not key or len(key) > 64 or len(value) > MAX_FIELD_CHARS:
                raise ValueError("target attributes must be short strings")
            clean_text(key)
            clean_text(value)
        return self


class Attribution(Model):
    """Who is behind a session, as far as the evidence goes.

    `state` uses the blueprint's information states: `verified` only when a verified
    identity claim names a registered person; `declared` when the claim is registered but
    unverified; `inferred` when only indirect evidence links them; `unknown` otherwise.
    An unknown person or agent never gains a role.
    """

    session_id: Text
    person_ref: Text | None = None
    agent_ref: Text | None = None
    agent_class: AgentClass = AgentClass.UNKNOWN
    state: InformationState = InformationState.UNKNOWN
    reasons: Annotated[tuple[Text, ...], Field(max_length=MAX_ENTRIES)] = ()


@runtime_checkable
class AttributionResolver(Protocol):
    def attribute(self, action: ObservedAction) -> Attribution:
        """Who is behind this action now. Raises when the registry cannot be read; callers
        treat that as a refusal."""
        ...


class Severity(StrEnum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class InspectionFinding(Model):
    """One problem a check found. `detail` names the problem, never the secret or the text.

    `remediation` is the check's fixed advice (from the check's own table, never composed
    from the content); empty when the check has none.
    """

    check_id: Annotated[str, Field(pattern=r"^[a-z][a-z0-9_.-]{0,63}$")]
    category: Annotated[str, Field(pattern=r"^[a-z][a-z0-9_]{0,31}$")]
    severity: Severity
    detail: Text
    location: Text = ""
    remediation: Text = ""


class InspectionInput(Model):
    """Content to inspect. Held in memory only; never stored by the contract's users.

    Fields stay out of `repr` so content cannot reach a log through an exception or a
    debug print. `content` is bounded by `MAX_INSPECTION_CHARS` (a structural bound):
    longer content is refused here, and the caller treats the action as not inspected.
    """

    #: A validation error must not quote the content it refused.
    model_config = ConfigDict(hide_input_in_errors=True)

    action_id: Text
    kind: ActionKind
    path: Text = ""
    command: Annotated[str, Field(max_length=MAX_COMMAND_CHARS)] | None = Field(
        default=None, repr=False
    )
    content: Annotated[str, Field(max_length=MAX_INSPECTION_CHARS)] | None = Field(
        default=None, repr=False
    )


class InspectionResult(Model):
    """What the deterministic checks found. `complete` is False when any check that should
    have run could not; the decision then treats the action as not inspected."""

    action_id: Text
    checks_run: Annotated[tuple[Text, ...], Field(max_length=64)] = ()
    findings: Annotated[tuple[InspectionFinding, ...], Field(max_length=MAX_FINDINGS)] = ()
    complete: bool

    @property
    def worst(self) -> Severity | None:
        order = list(Severity)
        if not self.findings:
            return None
        return max((f.severity for f in self.findings), key=order.index)


class Verdict(StrEnum):
    ALLOW = "allow"
    DENY = "deny"
    ASK = "ask"


class DecisionReason(Model):
    code: Annotated[str, Field(pattern=r"^[a-z][a-z0-9_]{0,63}$")]
    detail: Text


#: A decision id: `dec_` plus the platform id body (`ciso.common.ids.new_id("dec")`).
DECISION_ID_PATTERN = r"^dec_[0-9A-HJKMNP-TV-Z]{26}$"


class GovernanceDecision(Model):
    """The answer for one observed action. A source that can stop the action applies it;
    `explanation` is safe to show the person whose agent was stopped. `decision_id` is
    set by the governance engine (`new_id("dec")`) and is what the engineer quotes."""

    decision_id: Annotated[str, Field(pattern=DECISION_ID_PATTERN)]
    action_id: Text
    session_id: Text
    verdict: Verdict
    reasons: Annotated[tuple[DecisionReason, ...], Field(min_length=1, max_length=32)]
    matched_rule_ids: Annotated[tuple[Text, ...], Field(max_length=32)] = ()
    ruleset_version: Text
    ruleset_hash: Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
    decided_at: UtcDatetime
    attribution: Attribution
    explanation: Text = ""
    finding_refs: Annotated[tuple[Text, ...], Field(max_length=MAX_FINDINGS)] = ()
