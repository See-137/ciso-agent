"""Finding and alert records, filters, statuses and audit action names.

Spec `docs/skill/spec-draft.md` section 4 steps 6 and 7 (detect, report), milestone S6.
A finding holds references and short, clean labels only: never command text, file content,
prompt text or a secret (spec D1). Evidence is a list of references to records kept
elsewhere.
"""

from __future__ import annotations

import re
from enum import StrEnum
from typing import Annotated, Protocol, runtime_checkable

from pydantic import AfterValidator, Field

from ciso.common.activity import ActionKind, AgentClass, Severity, Text, Verdict, clean_text
from ciso.common.errors import ValidationFailed
from ciso.common.schemas import FrozenMap, Model, UtcDatetime

#: Audit action names. Values are a wire format: do not rename.
RECORD_ACTION = "findings.record"
ACKNOWLEDGE_ACTION = "findings.acknowledge"
RESOLVE_ACTION = "findings.resolve"
ACCEPT_RISK_ACTION = "findings.accept_risk"
FALSE_POSITIVE_ACTION = "findings.false_positive"
READ_ACTION = "findings.read"

FINDING_PREFIX = "fnd"
ALERT_PREFIX = "alt"
TRANSITION_PREFIX = "fnt"

#: Most evidence references kept on one finding.
MAX_EVIDENCE_REFS = 32
#: Most rows one list call returns, and the default when the caller gives no limit.
MAX_PAGE = 500
DEFAULT_PAGE = 100
#: Longest recommendation text.
MAX_RECOMMENDATION_CHARS = 512

#: A reference to a record kept elsewhere: a decision id, an approval id, an evidence ref.
_REF_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}")


def check_ref(value: str) -> str:
    """Accept a short reference string (letters, digits, `_ . : -`) and nothing else."""
    if not _REF_RE.fullmatch(value):
        raise ValidationFailed("a reference must be 1-128 characters of [A-Za-z0-9_.:-]")
    return value


def check_note(value: str) -> str:
    """A non-empty, clean, bounded note (a false-positive reason)."""
    try:
        clean_text(value)
    except ValueError as exc:
        raise ValidationFailed(str(exc)) from exc
    if not value or len(value) > MAX_RECOMMENDATION_CHARS:
        raise ValidationFailed("a note must be 1-512 clean characters")
    return value


Ref = Annotated[str, AfterValidator(check_ref)]


class FindingStatus(StrEnum):
    """Lifecycle. A finding is never deleted. Values are a wire format: do not rename."""

    OPEN = "open"
    ACKNOWLEDGED = "acknowledged"
    RESOLVED = "resolved"
    RISK_ACCEPTED = "risk_accepted"
    FALSE_POSITIVE = "false_positive"


#: Statuses a new occurrence is folded into (dedupe). Any other status is closed, and a
#: new occurrence opens a new finding: a closed finding never hides new activity.
ACTIVE_STATUSES: frozenset[FindingStatus] = frozenset(
    {FindingStatus.OPEN, FindingStatus.ACKNOWLEDGED}
)


class FindingOrigin(StrEnum):
    """`inspection`: a check found something. `decision`: the rules said deny or ask."""

    INSPECTION = "inspection"
    DECISION = "decision"


class AlertTrigger(StrEnum):
    #: A finding became high or critical (new, or raised to that level by a new occurrence).
    SEVERE_FINDING = "severe_finding"
    #: The rules denied an action before it ran.
    BEFORE_DENY = "before_deny"


class AlertStatus(StrEnum):
    PENDING = "pending"
    DELIVERED = "delivered"


class Finding(Model):
    """One detected problem, folded over repeated occurrences (see `fingerprint`)."""

    finding_id: str
    fingerprint: Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
    origin: FindingOrigin
    status: FindingStatus
    severity: Severity
    category: Text
    #: The check id (inspection) or `decision.<verdict>.<reason code>` (decision).
    check_key: Text
    title: Text
    session_id: Text
    person_ref: Text | None = None
    agent_ref: Text | None = None
    agent_class: AgentClass
    action_kind: ActionKind
    repository: Text = ""
    branch: Text = ""
    path: Text = ""
    decision_id: Ref
    verdict: Verdict
    last_decision_id: Ref
    evidence_refs: tuple[Text, ...] = Field(default=(), repr=False)
    recommendation: Text
    occurrences: Annotated[int, Field(ge=1)]
    first_seen: UtcDatetime
    last_seen: UtcDatetime
    status_changed_by: str = ""
    status_changed_at: UtcDatetime | None = None
    approval_ref: Ref | None = None
    status_reason: Text = Field(default="", repr=False)
    version: Annotated[int, Field(ge=1)] = 1

    @property
    def ref(self) -> str:
        return f"finding:{self.finding_id}"


class Alert(Model):
    """A notice to the security owner. Content is limited to `payload()`."""

    alert_id: str
    trigger: AlertTrigger
    finding_id: str
    decision_id: Ref
    severity: Severity
    title: Text
    person_ref: Text | None = None
    agent_ref: Text | None = None
    repository: Text = ""
    branch: Text = ""
    recommendation: Text
    created_at: UtcDatetime
    status: AlertStatus = AlertStatus.PENDING
    attempts: Annotated[int, Field(ge=0)] = 0
    #: Exception type name of the last failed delivery; never its message.
    last_failure: str = ""
    delivered_at: UtcDatetime | None = None

    def payload(self) -> dict[str, str]:
        """What a sink may send: ids, severity, title, refs, repository, recommendation."""
        return {
            "alert_id": self.alert_id,
            "trigger": self.trigger.value,
            "finding_id": self.finding_id,
            "decision_id": self.decision_id,
            "severity": self.severity.value,
            "title": self.title,
            "person_ref": self.person_ref or "",
            "agent_ref": self.agent_ref or "",
            "repository": self.repository,
            "branch": self.branch,
            "recommendation": self.recommendation,
            "created_at": self.created_at.isoformat(),
        }


class RecordOutcome(Model):
    """What `FindingsService.record` did. `created` lists findings that are new."""

    findings: tuple[Finding, ...] = ()
    created: tuple[str, ...] = ()
    alerts: tuple[Alert, ...] = ()


class FindingFilter(Model):
    """Every field narrows; None means "any". `since` compares with `last_seen`."""

    status: FindingStatus | None = None
    severity: Severity | None = None
    person_ref: Text | None = None
    agent_ref: Text | None = None
    repository: Text | None = None
    since: UtcDatetime | None = None
    limit: Annotated[int, Field(ge=1, le=MAX_PAGE)] = DEFAULT_PAGE


class FindingSummary(Model):
    total: int
    by_severity: FrozenMap[str, int]
    by_status: FrozenMap[str, int]


@runtime_checkable
class PersonLinkResolver(Protocol):
    """Which person (a `PERSON_REF_KIND` reference, `actor:<id>`) a platform actor is, NOW.

    `Principal` carries no person reference, so "the person this finding is about" needs
    this second lookup. Return None when the actor has no person or is unknown; raise when
    the store cannot be read (callers refuse).
    """

    def person_ref_of(self, actor_id: str) -> str | None: ...
