"""The pure matching rule in `ciso.agents.attribution`, without the SQL prefilter.

`store.candidate_agents` already narrows by surface and shared facts; these tests hold the
rule itself, so it stays correct if a caller hands it unfiltered candidates.
"""

from __future__ import annotations

import pytest

from ciso.agents import AgentFact, AgentRecord, AgentStatus
from ciso.agents.attribution import match_agent, matches
from ciso.common.activity import AgentClass
from ciso.common.clock import FixedClock

pytestmark = pytest.mark.unit

SESSION = frozenset({("device", "WS-1"), ("os_account", "CORP\\alice")})


def _agent(surface: str = "cli", facts: tuple[AgentFact, ...] = ()) -> AgentRecord:
    now = FixedClock().now()
    return AgentRecord(
        id="agt_test",
        display_name="Test agent",
        agent_class=AgentClass.UNKNOWN,
        status=AgentStatus.OBSERVED,
        surface=surface,
        facts=facts,
        observed_session_id="s",
        created_at=now,
        updated_at=now,
    )


DEVICE = (AgentFact(kind="device", value="WS-1"),)


def test_agent_with_no_facts_matches_nothing() -> None:
    assert not matches(_agent(facts=()), "cli", SESSION)
    assert match_agent([_agent(facts=())], "cli", SESSION).agent is None


def test_surface_must_be_equal() -> None:
    assert matches(_agent(facts=DEVICE), "cli", SESSION)
    assert not matches(_agent(surface="ide", facts=DEVICE), "cli", SESSION)
    assert match_agent([_agent(surface="ide", facts=DEVICE)], "cli", SESSION).agent is None
