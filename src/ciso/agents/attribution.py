"""The fixed rules that decide who is behind a session (docs/skill/spec-draft.md, S1).

Pure functions over already-loaded rows; `AgentRegistry` does the reading and writing.

Who vouches (review M5). A claim's `verified` flag reaching these rules was already
checked by the registry against `ISSUER_VERIFIED` (a device actor from a hook report, an
assistant account from the signed central gate); a client's own flag never survives. A
device actor is a machine, not a person: a binding of one is ignored here; a device vouches
for people only through `DeviceAssignment`.

Person rules, over every claim seen in the session so far (not only this action's):
- the session has more distinct claims than `MAX_SESSION_CLAIMS`: `disputed`, no person;
- bound claims name two or more people: `disputed`, no person; one is never picked;
- bound claims all name one person: `verified` if any of them is issuer-verified, or is an
  `os_account` claim of a person assigned to the session's verified device actor; else
  `declared` (with `person_not_assigned_to_device` when a verified device did not vouch);
- no bound claim: `unknown`, no person.

Agent rules (review H3):
- a candidate matches when its surface equals the session's and the session shows every
  one of its facts (an agent with no facts matches nothing). An `organizational` agent's
  facts must all be VERIFIED facts (the device actor, a signed assistant account): a
  client's own claims never make an organizational agent;
- registered (non-observed) matches are preferred over observed ones; more than one match
  in the preferred tier is `agent_ambiguous` and no agent is returned;
- an `employee_operated` agent whose operator is not the attributed person adds
  `operator_mismatch` and caps the state at `inferred`.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from typing import NamedTuple

from ciso.agents.models import (
    DEVICE_ACTOR_CLAIM,
    DEVICE_VOUCHED_KINDS,
    AgentRecord,
    AgentStatus,
    AttributionReason,
    SeenClaim,
)
from ciso.common.activity import AgentClass
from ciso.common.enums import InformationState

#: States better than `inferred`; an operator mismatch brings them down to `inferred`.
_ABOVE_INFERRED = frozenset({InformationState.VERIFIED, InformationState.DECLARED})

_STATUS_REASON = {
    AgentStatus.DECLARED: AttributionReason.AGENT_NOT_APPROVED,
    AgentStatus.OBSERVED: AttributionReason.AGENT_NOT_APPROVED,
    AgentStatus.SUSPENDED: AttributionReason.AGENT_SUSPENDED,
    AgentStatus.RETIRED: AttributionReason.AGENT_RETIRED,
}


class PersonDecision(NamedTuple):
    person_ref: str | None
    state: InformationState
    reasons: tuple[AttributionReason, ...]


class AgentMatch(NamedTuple):
    agent: AgentRecord | None
    ambiguous: bool


def decide_person(
    claims: Iterable[SeenClaim],
    bound: Mapping[tuple[str, str], str],
    overflow: bool,
    device_people: frozenset[str] | None = None,
) -> PersonDecision:
    """Apply the person rules in the module docstring. `bound` maps (kind, subject) to the
    person its ACTIVE binding names; `device_people` is who is assigned to the session's
    verified device actor (None: the session has no verified device actor)."""
    if overflow:
        return PersonDecision(
            None, InformationState.DISPUTED, (AttributionReason.CLAIM_LIMIT_REACHED,)
        )
    people: dict[str, bool] = {}
    unvouched = False
    for claim in claims:
        person = bound.get((claim.kind, claim.subject))
        if person is None or claim.kind == DEVICE_ACTOR_CLAIM:
            continue
        on_device = claim.kind in DEVICE_VOUCHED_KINDS and device_people is not None
        vouched = on_device and person in (device_people or frozenset())
        unvouched = unvouched or (on_device and not vouched)
        people[person] = people.get(person, False) or claim.verified or vouched
    if len(people) > 1:
        return PersonDecision(
            None, InformationState.DISPUTED, (AttributionReason.CONFLICTING_CLAIMS,)
        )
    if not people:
        return PersonDecision(None, InformationState.UNKNOWN, (AttributionReason.NO_BOUND_CLAIM,))
    (person, verified), *_ = people.items()
    if verified:
        return PersonDecision(person, InformationState.VERIFIED, ())
    reasons = (AttributionReason.PERSON_NOT_ON_DEVICE,) if unvouched else ()
    return PersonDecision(person, InformationState.DECLARED, reasons)


def matches(
    agent: AgentRecord,
    surface: str,
    facts: frozenset[tuple[str, str]],
    verified: frozenset[tuple[str, str]] = frozenset(),
) -> bool:
    """`facts`: every fact the session shows; `verified`: the verified ones among them.
    An organizational agent is matched through verified facts only."""
    if agent.status is AgentStatus.RETIRED or not agent.facts or agent.surface != surface:
        return False
    usable = verified if agent.agent_class is AgentClass.ORGANIZATIONAL else facts
    return all((fact.kind, fact.value) in usable for fact in agent.facts)


def match_agent(
    candidates: Sequence[AgentRecord],
    surface: str,
    facts: frozenset[tuple[str, str]],
    verified: frozenset[tuple[str, str]] = frozenset(),
) -> AgentMatch:
    """Apply the agent matching rules in the module docstring."""
    found = [agent for agent in candidates if matches(agent, surface, facts, verified)]
    registered = [agent for agent in found if agent.observed_session_id is None]
    tier = registered or found
    if len(tier) > 1:
        return AgentMatch(None, True)
    return AgentMatch(tier[0] if tier else None, False)


def agent_outcome(
    agent: AgentRecord | None, person: PersonDecision
) -> tuple[AgentClass, InformationState, tuple[AttributionReason, ...]]:
    """The agent class to report, the person state after the operator rule, and the
    agent-related reasons."""
    if agent is None:
        return AgentClass.UNKNOWN, person.state, ()
    reasons: list[AttributionReason] = []
    status_reason = _STATUS_REASON.get(agent.status)
    if status_reason is not None:
        reasons.append(status_reason)
    if agent.agent_class is AgentClass.UNKNOWN:
        reasons.append(AttributionReason.AGENT_UNKNOWN)
    state = person.state
    if (
        agent.agent_class is AgentClass.EMPLOYEE_OPERATED
        and agent.operator_ref != person.person_ref
    ):
        reasons.append(AttributionReason.OPERATOR_MISMATCH)
        if state in _ABOVE_INFERRED:
            state = InformationState.INFERRED
    return agent.agent_class, state, tuple(reasons)
