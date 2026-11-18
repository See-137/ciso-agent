"""Row reading and writing for the agent registry. Internal to `ciso.agents`.

Stored rows are validated on the way out: a malformed row raises (pydantic), and callers
turn that into `FailClosed`, never into a trusted record.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from datetime import datetime
from typing import Any

from sqlalchemy import Connection, Row, and_, or_, select

from ciso.agents import tables as t
from ciso.agents.models import (
    MAX_LIST,
    AgentFact,
    AgentRecord,
    AgentsNotFound,
    IdentityBinding,
    RefusalCode,
    SeenClaim,
    SessionRecord,
)


def _facts(conn: Connection, agent_ids: Iterable[str]) -> dict[str, list[AgentFact]]:
    ids = list(agent_ids)
    out: dict[str, list[AgentFact]] = {agent_id: [] for agent_id in ids}
    if not ids:
        return out
    query = (
        select(t.agent_facts)
        .where(t.agent_facts.c.agent_id.in_(ids))
        .order_by(t.agent_facts.c.agent_id, t.agent_facts.c.kind, t.agent_facts.c.value)
    )
    for row in conn.execute(query):
        out[row.agent_id].append(AgentFact(kind=row.kind, value=row.value))
    return out


def _agent(row: Row[Any], facts: list[AgentFact]) -> AgentRecord:
    return AgentRecord(
        id=row.id,
        display_name=row.display_name,
        agent_class=row.agent_class,
        status=row.status,
        surface=row.surface,
        facts=tuple(facts),
        owner_ref=row.owner_ref,
        operator_ref=row.operator_ref,
        observed_session_id=row.observed_session_id,
        status_before_suspension=row.status_before_suspension,
        created_at=row.created_at,
        updated_at=row.updated_at,
    )


def agents_from_rows(conn: Connection, rows: list[Row[Any]]) -> tuple[AgentRecord, ...]:
    facts = _facts(conn, (row.id for row in rows))
    return tuple(_agent(row, facts[row.id]) for row in rows)


def find_agent(conn: Connection, agent_id: str) -> AgentRecord | None:
    row = conn.execute(select(t.agents).where(t.agents.c.id == agent_id)).first()
    return None if row is None else agents_from_rows(conn, [row])[0]


def load_agent(conn: Connection, agent_id: str) -> AgentRecord:
    agent = find_agent(conn, agent_id)
    if agent is None:
        raise AgentsNotFound(RefusalCode.AGENT_NOT_FOUND, agent_id)
    return agent


def query_agents(
    conn: Connection, *conditions: Any, limit: int = MAX_LIST
) -> tuple[AgentRecord, ...]:
    query = select(t.agents).where(*conditions).order_by(t.agents.c.id).limit(min(limit, MAX_LIST))
    return agents_from_rows(conn, list(conn.execute(query)))


def insert_agent(conn: Connection, agent: AgentRecord) -> None:
    conn.execute(
        t.agents.insert().values(
            id=agent.id,
            display_name=agent.display_name,
            agent_class=agent.agent_class.value,
            status=agent.status.value,
            surface=agent.surface,
            owner_ref=agent.owner_ref,
            operator_ref=agent.operator_ref,
            observed_session_id=agent.observed_session_id,
            status_before_suspension=None,
            created_at=agent.created_at,
            updated_at=agent.updated_at,
        )
    )
    if agent.facts:
        conn.execute(
            t.agent_facts.insert(),
            [{"agent_id": agent.id, "kind": f.kind, "value": f.value} for f in agent.facts],
        )


def update_agent(conn: Connection, agent: AgentRecord) -> None:
    """Write the mutable columns of `agent` (class, status, refs, times)."""
    conn.execute(
        t.agents.update()
        .where(t.agents.c.id == agent.id)
        .values(
            agent_class=agent.agent_class.value,
            status=agent.status.value,
            owner_ref=agent.owner_ref,
            operator_ref=agent.operator_ref,
            status_before_suspension=(
                None
                if agent.status_before_suspension is None
                else agent.status_before_suspension.value
            ),
            updated_at=agent.updated_at,
        )
    )


def candidate_agents(
    conn: Connection, surface: str, facts: frozenset[tuple[str, str]]
) -> tuple[AgentRecord, ...]:
    """Agents on `surface` that share at least one fact with the session. Retired ones are
    included; `attribution.matches` drops them."""
    if not facts:
        return ()
    shares = or_(
        *(and_(t.agent_facts.c.kind == k, t.agent_facts.c.value == v) for k, v in sorted(facts))
    )
    ids = select(t.agent_facts.c.agent_id).where(shares)
    query = (
        select(t.agents)
        .where(t.agents.c.id.in_(ids))
        .where(t.agents.c.surface == surface)
        .order_by(t.agents.c.id)
    )
    return agents_from_rows(conn, list(conn.execute(query)))


# -- bindings ---------------------------------------------------------------------------


def binding_from_row(row: Row[Any]) -> IdentityBinding:
    return IdentityBinding(
        id=row.id,
        kind=row.kind,
        subject=row.subject,
        person_ref=row.person_ref,
        bound_at=row.bound_at,
        bound_by=row.bound_by,
        unbound_at=row.unbound_at,
        unbound_by=row.unbound_by,
    )


def active_bindings(
    conn: Connection, claims: Iterable[tuple[str, str]]
) -> Mapping[tuple[str, str], str]:
    """(kind, subject) -> person for every claim given that has an ACTIVE binding."""
    keys = sorted(set(claims))
    if not keys:
        return {}
    match = or_(*(and_(t.bindings.c.kind == k, t.bindings.c.subject == s) for k, s in keys))
    query = select(t.bindings).where(t.bindings.c.unbound_at.is_(None)).where(match)
    return {(row.kind, row.subject): row.person_ref for row in conn.execute(query)}


# -- sessions ---------------------------------------------------------------------------


def find_session_row(conn: Connection, session_id: str) -> Row[Any] | None:
    return conn.execute(select(t.sessions).where(t.sessions.c.session_id == session_id)).first()


def seen_claims(conn: Connection, session_id: str) -> tuple[SeenClaim, ...]:
    query = (
        select(t.session_claims)
        .where(t.session_claims.c.session_id == session_id)
        .order_by(t.session_claims.c.first_seen, t.session_claims.c.kind)
    )
    return tuple(
        SeenClaim(kind=r.kind, subject=r.subject, verified=r.verified, first_seen=r.first_seen)
        for r in conn.execute(query)
    )


def session_from_row(conn: Connection, row: Row[Any]) -> SessionRecord:
    return SessionRecord(
        session_id=row.session_id,
        first_seen=row.first_seen,
        last_seen=row.last_seen,
        device=row.device,
        surface=row.surface,
        agent_ref=row.agent_ref,
        person_ref=row.person_ref,
        state=row.state,
        claims=seen_claims(conn, row.session_id),
    )


def add_claims(
    conn: Connection,
    session_id: str,
    new: Iterable[tuple[str, str, bool]],
    known: Iterable[SeenClaim],
    now: datetime,
) -> list[dict[str, Any]]:
    """Rows for claims not seen before in this session. Earlier rows are never changed."""
    have = {(c.kind, c.subject, c.verified) for c in known}
    rows: list[dict[str, Any]] = []
    for kind, subject, verified in new:
        if (kind, subject, verified) not in have:
            have.add((kind, subject, verified))
            rows.append(
                {
                    "session_id": session_id,
                    "kind": kind,
                    "subject": subject,
                    "verified": verified,
                    "first_seen": now,
                }
            )
    return rows
