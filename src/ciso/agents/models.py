"""Records of the identity and agent registry (docs/skill/spec-draft.md, milestone S1).

Person references are `EntityRef` strings to identity actors (`actor:<id>`); agent
references are `agent:<id>`. This package never imports `ciso.identity`: who an actor is
NOW comes through an injected `PrincipalResolver`.
"""

from __future__ import annotations

from collections.abc import Mapping
from enum import StrEnum
from types import MappingProxyType
from typing import Annotated, Final

from pydantic import Field, field_validator, model_validator

from ciso.common.activity import PERSON_REF_KIND, ActivitySource, AgentClass, Text, clean_text
from ciso.common.enums import InformationState
from ciso.common.errors import AuthorizationError, Conflict, NotFound, ValidationFailed
from ciso.common.ids import EntityRef
from ciso.common.schemas import Model, UtcDatetime

#: Most identifying facts on one agent record.
MAX_FACTS = 16
#: Most distinct claims stored for one session. Past this the session is disputed.
MAX_SESSION_CLAIMS = 64
#: Most rows a list read returns.
MAX_LIST = 500
#: Longest display name.
MAX_NAME_CHARS = 200

#: Reference kind for an agent record. The person kind (`PERSON_REF_KIND`, an identity
#: actor) is the shared contract's constant, re-exported here for existing callers.
AGENT_REF_KIND = "agent"
#: Fact kind under which a session's device name is matched.
DEVICE_FACT = "device"
#: Target key of an `ObservedAction` that carries the reporting device's name. The shared
#: contract has no device field yet (contract change requested).
DEVICE_TARGET_KEY = "device"
#: Claim kind the hook intake derives from the device token: the authenticated machine.
DEVICE_ACTOR_CLAIM = "device_actor"
#: The only claims whose `verified` flag the registry believes, and the one source each
#: may come from: the device actor from a hook report (the API authenticated its token),
#: the assistant account from the signed central gate. Any other claim marked verified is
#: stored and judged as unverified (review M5): a client never vouches for itself.
ISSUER_VERIFIED: Final[Mapping[str, ActivitySource]] = MappingProxyType(
    {
        DEVICE_ACTOR_CLAIM: ActivitySource.HOOK,
        "assistant_account": ActivitySource.CENTRAL_GATE,
        "assistant_email": ActivitySource.CENTRAL_GATE,
    }
)
#: Person claims a verified device actor may vouch for: the claim's person must be
#: assigned to that device (`DeviceAssignment`) for the session to be `verified`.
DEVICE_VOUCHED_KINDS: Final = frozenset({"os_account"})

_KIND = r"[a-z][a-z0-9_]{0,31}"
_SURFACE = r"[a-z0-9][a-z0-9_.-]{0,31}"


class AgentStatus(StrEnum):
    DECLARED = "declared"
    OBSERVED = "observed"
    APPROVED = "approved"
    SUSPENDED = "suspended"
    RETIRED = "retired"


class RefusalCode(StrEnum):
    """Why an admin operation was refused. Recorded in audit and on the raised error."""

    RESOLVER_UNAVAILABLE = "resolver_unavailable"
    UNKNOWN_CALLER = "unknown_caller"
    CALLER_NOT_HUMAN = "caller_not_human"
    CALLER_NOT_SECURITY_ADMIN = "caller_not_security_admin"
    NOT_RESPONSIBLE_FOR_AGENT = "not_responsible_for_agent"
    AGENT_NOT_FOUND = "agent_not_found"
    BINDING_NOT_FOUND = "binding_not_found"
    WRONG_STATUS = "wrong_status"
    OWNER_REQUIRED = "owner_required"
    OPERATOR_REQUIRED = "operator_required"
    CLASS_UNKNOWN = "class_unknown"
    BINDING_EXISTS = "binding_exists"
    DEVICE_NOT_A_SERVICE = "device_not_a_service_actor"
    PERSON_NOT_HUMAN = "person_not_an_active_human"
    ASSIGNMENT_EXISTS = "assignment_exists"
    ASSIGNMENT_NOT_FOUND = "assignment_not_found"


class AttributionReason(StrEnum):
    """Reason codes put on an `Attribution`. Governance decides on them; nothing here does."""

    CONFLICTING_CLAIMS = "conflicting_identity_claims"
    CLAIM_LIMIT_REACHED = "session_claim_limit_reached"
    NO_BOUND_CLAIM = "no_bound_identity_claim"
    AGENT_UNKNOWN = "agent_unknown"
    AGENT_AMBIGUOUS = "agent_ambiguous"
    AGENT_NOT_APPROVED = "agent_not_approved"
    AGENT_SUSPENDED = "agent_suspended"
    AGENT_RETIRED = "agent_retired"
    OPERATOR_MISMATCH = "operator_mismatch"
    SESSION_DEVICE_CHANGED = "session_device_changed"
    #: The session belongs to another device actor (or the report has none): nothing of
    #: the session's attribution is inherited (review H4).
    SESSION_DEVICE_MISMATCH = "session_device_mismatch"
    #: A bound person claim came from a verified device that is not assigned to that
    #: person, so it stays `declared`.
    PERSON_NOT_ON_DEVICE = "person_not_assigned_to_device"


class _Coded(Exception):
    code: RefusalCode

    def __init__(self, code: RefusalCode, message: str = "") -> None:
        self.code = code
        super().__init__(f"{code.value}: {message}" if message else code.value)


class AgentsRefused(_Coded, AuthorizationError):
    """The caller may not do this. `code` says why."""


class AgentsConflict(_Coded, Conflict):
    """The registry's state does not allow this. `code` says why."""


class AgentsNotFound(_Coded, NotFound):
    """No such agent or binding."""


def check_person_ref(value: str) -> str:
    """A person reference must be `actor:<id>`."""
    ref = EntityRef.parse(value)
    if ref.kind != PERSON_REF_KIND:
        raise ValidationFailed(f"a person reference must be {PERSON_REF_KIND}:<id>")
    return str(ref)


def agent_ref(agent_id: str) -> str:
    return str(EntityRef(AGENT_REF_KIND, agent_id))


Kind = Annotated[str, Field(pattern=f"^{_KIND}$")]
Surface = Annotated[str, Field(pattern=f"^({_SURFACE})?$")]
PersonRef = Annotated[str, Field(max_length=200)]


class AgentFact(Model):
    """One identifying fact: `device` `WS-0142`, `api_key` `key_123`, `assistant_account`
    `jdoe@corp.example`. A session matches an agent when it shows every fact the agent has."""

    kind: Kind
    value: Text

    @field_validator("value")
    @classmethod
    def _non_empty(cls, value: str) -> str:
        if not value:
            raise ValueError("fact value must not be empty")
        return value


class AgentRecord(Model):
    id: str
    display_name: Annotated[str, Field(min_length=1, max_length=MAX_NAME_CHARS)]
    agent_class: AgentClass
    status: AgentStatus
    surface: Surface
    facts: Annotated[tuple[AgentFact, ...], Field(max_length=MAX_FACTS)] = ()
    owner_ref: PersonRef | None = None
    operator_ref: PersonRef | None = None
    #: The session that first showed this agent, for records created by attribution.
    observed_session_id: Text | None = None
    status_before_suspension: AgentStatus | None = None
    created_at: UtcDatetime
    updated_at: UtcDatetime

    @field_validator("display_name")
    @classmethod
    def _clean(cls, value: str) -> str:
        return clean_text(value)

    @property
    def ref(self) -> str:
        return agent_ref(self.id)


class IdentityBinding(Model):
    """`(kind, subject)` belongs to `person_ref`. Active while `unbound_at` is None."""

    id: str
    kind: Kind
    subject: Annotated[Text, Field(min_length=1)]
    person_ref: PersonRef
    bound_at: UtcDatetime
    bound_by: str
    unbound_at: UtcDatetime | None = None
    unbound_by: str | None = None


class DeviceAssignment(Model):
    """`person_ref` uses the device actor `device_actor`. Active while `unassigned_at` is
    None. A verified device vouches only for the people assigned to it."""

    id: str
    device_actor: Annotated[Text, Field(min_length=1, max_length=64)]
    person_ref: PersonRef
    assigned_at: UtcDatetime
    assigned_by: str
    unassigned_at: UtcDatetime | None = None
    unassigned_by: str | None = None


class SeenClaim(Model):
    kind: Kind
    subject: Text
    verified: bool
    first_seen: UtcDatetime


class SessionRecord(Model):
    session_id: Text
    first_seen: UtcDatetime
    last_seen: UtcDatetime
    device: Text
    #: The device actor that first reported the session ("" until one did).
    device_actor: Text = ""
    surface: Text
    agent_ref: Text | None = None
    person_ref: Text | None = None
    state: InformationState
    claims: Annotated[tuple[SeenClaim, ...], Field(max_length=MAX_SESSION_CLAIMS)] = ()


class Registration(Model):
    """What `AgentAdmin.register_agent` needs. Class rules are checked on construction."""

    display_name: Annotated[str, Field(min_length=1, max_length=MAX_NAME_CHARS)]
    agent_class: AgentClass
    surface: Surface
    facts: Annotated[tuple[AgentFact, ...], Field(min_length=1, max_length=MAX_FACTS)]
    owner_ref: PersonRef | None = None
    operator_ref: PersonRef | None = None

    @field_validator("display_name")
    @classmethod
    def _clean(cls, value: str) -> str:
        return clean_text(value)

    @field_validator("owner_ref", "operator_ref")
    @classmethod
    def _person(cls, value: str | None) -> str | None:
        return None if value is None else check_person_ref(value)

    @model_validator(mode="after")
    def _distinct_facts(self) -> Registration:
        if len({(f.kind, f.value) for f in self.facts}) != len(self.facts):
            raise ValueError("facts must be distinct")
        return self
