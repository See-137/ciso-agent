"""The fixed rules that decide who is behind a session (docs/skill/spec-draft.md, S1).

Pure functions over already-loaded rows; `AgentRegistry` does the reading and writing.

Person rules, over every claim seen in the session so far (not only this action's):
- the session has more distinct claims than `MAX_SESSION_CLAIMS`: `disputed`, no person;
- bound claims name two or more people: `disputed`, no person; one is never picked;
- bound claims all name one person: `verified` if any of them was verified, else `declared`;
- no bound claim: `unknown`, no person.

Agent rules:
- a candidate matches when its surface equals the session's and the session shows every
  one of its facts (an agent with no facts matches nothing);
- registered (non-observed) matches are preferred over observed ones; more than one match
  in the preferred tier is `agent_ambiguous` and no agent is returned;
- an `employee_operated` agent whose operator is not the attributed person adds
  `operator_mismatch` and caps the state at `inferred`.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from typing import NamedTuple

from ciso.agents.models import (
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
    claims: Iterable[SeenClaim], bound: Mapping[tuple[str, str], str], overflow: bool
) -> PersonDecision:
    """Apply the person rules in the module docstring. `bound` maps (kind, subject) to the
    person its ACTIVE binding names."""
    if overflow:
        return PersonDecision(
            None, InformationState.DISPUTED, (AttributionReason.CLAIM_LIMIT_REACHED,)
        )
    people: dict[str, bool] = {}
    for claim in claims:
        person = bound.get((claim.kind, claim.subject))
        if person is not None:
            people[person] = people.get(person, False) or claim.verified
    if len(people) > 1:
        return PersonDecision(
            None, InformationState.DISPUTED, (AttributionReason.CONFLICTING_CLAIMS,)
        )
    if not people:
        return PersonDecision(None, InformationState.UNKNOWN, (AttributionReason.NO_BOUND_CLAIM,))
    (person, verified), *_ = people.items()
    state = InformationState.VERIFIED if verified else InformationState.DECLARED
    return PersonDecision(person, state, ())


def matches(agent: AgentRecord, surface: str, facts: frozenset[tuple[str, str]]) -> bool:
    if agent.status is AgentStatus.RETIRED or not agent.facts or agent.surface != surface:
        return False
    return all((fact.kind, fact.value) in facts for fact in agent.facts)


def match_agent(
    candidates: Sequence[AgentRecord], surface: str, facts: frozenset[tuple[str, str]]
) -> AgentMatch:
    """Apply the agent matching rules in the module docstring."""
    found = [agent for agent in candidates if matches(agent, surface, facts)]
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
