"""`AgentRegistry`: who is behind an observed action, and the registry's reads (S1).

`attribute(action)` is the `ciso.common.activity.AttributionResolver`. It records the
session (first and last seen, device, surface, every distinct claim seen, never
overwriting an earlier one), applies the fixed rules in `ciso.agents.attribution`, and
stores the person and agent it decided. One short write transaction per call; the audit
sink is called only after it closes.

An unknown agent is recorded once per session as an `observed` agent of class `unknown`
with no owner, and never trusted. A registry that cannot be read or written raises
`FailClosed`; callers treat that as a refusal (spec section 6, rule 3).
"""

from __future__ import annotations

import logging
import re
from datetime import datetime
from typing import Any, Final

from pydantic import ValidationError
from sqlalchemy import Connection, Engine, select
from sqlalchemy.exc import SQLAlchemyError

from ciso.agents import store
from ciso.agents import tables as t
from ciso.agents.attribution import agent_outcome, decide_person, match_agent
from ciso.agents.gate import write_audit
from ciso.agents.models import (
    AGENT_REF_KIND,
    DEVICE_ACTOR_CLAIM,
    DEVICE_FACT,
    DEVICE_TARGET_KEY,
    ISSUER_VERIFIED,
    MAX_FACTS,
    MAX_LIST,
    MAX_SESSION_CLAIMS,
    AgentFact,
    AgentRecord,
    AgentStatus,
    AttributionReason,
    DeviceAssignment,
    IdentityBinding,
    SeenClaim,
    SessionRecord,
    check_person_ref,
)
from ciso.common.activity import (
    ActivitySource,
    AgentClass,
    Attribution,
    IdentityClaim,
    ObservedAction,
)
from ciso.common.clock import Clock
from ciso.common.db import read_connection
from ciso.common.enums import ActorType, AuditOutcome, InformationState
from ciso.common.errors import FailClosed, IntegrityFailure, NotFound
from ciso.common.ids import EntityRef, new_id
from ciso.common.protocols import AuditEvent, AuditSink

logger = logging.getLogger(__name__)

#: Actor id on audit records the registry writes by itself (an observed agent appearing).
REGISTRY_ACTOR = "ciso_agents"
_SURFACE_RE = re.compile(r"[a-z0-9][a-z0-9_.-]{0,31}")
_STORAGE_ERRORS = (SQLAlchemyError, ValidationError, IntegrityFailure, ValueError)
#: `_device_actor` result when one report names two different verified device actors.
_AMBIGUOUS: Final = "<ambiguous>"


class AgentRegistry:
    def __init__(self, engine: Engine, clock: Clock, audit: AuditSink) -> None:
        self._engine = engine
        self._clock = clock
        self._audit = audit

    # -- AttributionResolver ---------------------------------------------------------

    def attribute(self, action: ObservedAction) -> Attribution:
        """Who is behind `action` now. Raises `FailClosed` when the registry or the audit
        path cannot be used."""
        try:
            with self._engine.begin() as conn:
                attribution, created = self._decide(conn, action, self._clock.now())
        except FailClosed:
            raise
        except _STORAGE_ERRORS as exc:
            logger.error("agents: registry unavailable during attribution")
            raise FailClosed("agent registry unavailable") from exc
        if created is not None:
            write_audit(
                self._audit,
                AuditEvent(
                    actor_id=REGISTRY_ACTOR,
                    actor_type=ActorType.SERVICE,
                    action="agents.agent.observed",
                    target=created.id,
                    outcome=AuditOutcome.SUCCESS,
                    details={"agent_class": created.agent_class.value, "surface": created.surface},
                ),
            )
        return attribution

    def _decide(
        self, conn: Connection, action: ObservedAction, now: datetime
    ) -> tuple[Attribution, AgentRecord | None]:
        device = action.target.get(DEVICE_TARGET_KEY, "")
        surface = action.surface if _SURFACE_RE.fullmatch(action.surface) else ""
        reporter = _device_actor(action)
        reasons: list[AttributionReason] = []
        row = store.find_session_row(conn, action.session_id)
        if row is None:
            if reporter is _AMBIGUOUS:
                return _mismatch(action.session_id), None
            conn.execute(
                t.sessions.insert().values(
                    session_id=action.session_id,
                    first_seen=now,
                    last_seen=now,
                    device=device,
                    device_actor=reporter or "",
                    surface=surface,
                    state=InformationState.UNKNOWN.value,
                    claim_overflow=0,
                )
            )
            agent_ref, overflow, owner = None, False, reporter or ""
        else:
            owner = row.device_actor
            if reporter is _AMBIGUOUS or (owner and not _may_join(action, reporter, owner)):
                return _mismatch(action.session_id), None
            if not owner and reporter:
                owner = reporter
            if device and row.device != device:
                reasons.append(AttributionReason.SESSION_DEVICE_CHANGED)
            device, surface = row.device, row.surface
            agent_ref, overflow = row.agent_ref, bool(row.claim_overflow)

        claims, overflow = self._record_claims(conn, action, now, overflow)
        keys = [(c.kind, c.subject) for c in claims]
        device_people = store.assigned_people(conn, owner) if owner else None
        person = decide_person(claims, store.active_bindings(conn, keys), overflow, device_people)

        created: AgentRecord | None = None
        agent: AgentRecord | None
        if agent_ref is not None:
            agent = _sticky_agent(conn, agent_ref)
        else:
            verified, facts = _session_facts(claims, device)
            candidates = store.candidate_agents(conn, surface, facts)
            match = match_agent(candidates, surface, facts, verified)
            agent = match.agent
            if match.ambiguous:
                reasons.append(AttributionReason.AGENT_AMBIGUOUS)
            elif agent is None:
                agent = created = _observed_agent(conn, action.session_id, surface, facts, now)

        agent_class, state, agent_reasons = agent_outcome(agent, person)
        conn.execute(
            t.sessions.update()
            .where(t.sessions.c.session_id == action.session_id)
            .values(
                last_seen=now,
                device_actor=owner,
                agent_ref=agent.ref if agent is not None else None,
                person_ref=person.person_ref,
                state=state.value,
                claim_overflow=int(overflow),
            )
        )
        attribution = Attribution(
            session_id=action.session_id,
            person_ref=person.person_ref,
            agent_ref=agent.ref if agent is not None else None,
            agent_class=agent_class,
            state=state,
            reasons=tuple(r.value for r in (*person.reasons, *reasons, *agent_reasons)),
        )
        return attribution, created

    def _record_claims(
        self, conn: Connection, action: ObservedAction, now: datetime, overflow: bool
    ) -> tuple[tuple[SeenClaim, ...], bool]:
        known = store.seen_claims(conn, action.session_id)
        new = [(c.kind, c.subject, _trusted(c, action.source)) for c in action.identity_claims]
        rows = store.add_claims(conn, action.session_id, new, known, now)
        room = MAX_SESSION_CLAIMS - len(known)
        if len(rows) > room:
            overflow = True
            rows = rows[: max(room, 0)]
        if rows:
            conn.execute(t.session_claims.insert(), rows)
        added = tuple(
            SeenClaim(kind=r["kind"], subject=r["subject"], verified=r["verified"], first_seen=now)
            for r in rows
        )
        return known + added, overflow

    # -- reads -----------------------------------------------------------------------

    def list_device_assignments(
        self,
        *,
        device_actor: str | None = None,
        person_ref: str | None = None,
        include_ended: bool = False,
    ) -> tuple[DeviceAssignment, ...]:
        """Device assignments, oldest first, at most `MAX_LIST`. Active ones only unless
        `include_ended`."""
        a = t.device_assignments
        query = select(a).order_by(a.c.assigned_at, a.c.id).limit(MAX_LIST)
        if device_actor is not None:
            query = query.where(a.c.device_actor == device_actor)
        if person_ref is not None:
            query = query.where(a.c.person_ref == check_person_ref(person_ref))
        if not include_ended:
            query = query.where(a.c.unassigned_at.is_(None))
        with self._reading() as conn:
            return tuple(store.assignment_from_row(row) for row in conn.execute(query))

    def get_agent(self, agent_id: str) -> AgentRecord:
        with self._reading() as conn:
            return store.load_agent(conn, agent_id)

    def list_agents(
        self,
        *,
        agent_class: AgentClass | None = None,
        status: AgentStatus | None = None,
        operator_ref: str | None = None,
        limit: int = MAX_LIST,
    ) -> tuple[AgentRecord, ...]:
        conditions: list[Any] = []
        if agent_class is not None:
            conditions.append(t.agents.c.agent_class == agent_class.value)
        if status is not None:
            conditions.append(t.agents.c.status == status.value)
        if operator_ref is not None:
            conditions.append(t.agents.c.operator_ref == check_person_ref(operator_ref))
        with self._reading() as conn:
            return store.query_agents(conn, *conditions, limit=limit)

    def list_coverage_gaps(self, limit: int = MAX_LIST) -> tuple[AgentRecord, ...]:
        """Agents that are not retired and are either `observed` or of class `unknown`."""
        gap = (t.agents.c.status == AgentStatus.OBSERVED.value) | (
            t.agents.c.agent_class == AgentClass.UNKNOWN.value
        )
        not_retired = t.agents.c.status != AgentStatus.RETIRED.value
        with self._reading() as conn:
            return store.query_agents(conn, gap, not_retired, limit=limit)

    def get_session(self, session_id: str) -> SessionRecord:
        with self._reading() as conn:
            row = store.find_session_row(conn, session_id)
            if row is None:
                raise NotFound("no such session")
            return store.session_from_row(conn, row)

    def list_sessions_for_person(
        self, person_ref: str, limit: int = MAX_LIST
    ) -> tuple[SessionRecord, ...]:
        query = (
            select(t.sessions)
            .where(t.sessions.c.person_ref == check_person_ref(person_ref))
            .order_by(t.sessions.c.last_seen.desc(), t.sessions.c.session_id)
            .limit(min(limit, MAX_LIST))
        )
        with self._reading() as conn:
            return tuple(store.session_from_row(conn, row) for row in conn.execute(query))

    def list_bindings(
        self, person_ref: str | None = None, *, include_unbound: bool = False
    ) -> tuple[IdentityBinding, ...]:
        query = select(t.bindings).order_by(t.bindings.c.bound_at, t.bindings.c.id).limit(MAX_LIST)
        if person_ref is not None:
            query = query.where(t.bindings.c.person_ref == check_person_ref(person_ref))
        if not include_unbound:
            query = query.where(t.bindings.c.unbound_at.is_(None))
        with self._reading() as conn:
            return tuple(store.binding_from_row(row) for row in conn.execute(query))

    def _reading(self) -> Any:
        return read_connection(self._engine)


def _trusted(claim: IdentityClaim, source: ActivitySource) -> bool:
    """A claim is verified only when its kind may be vouched for by this source (M5)."""
    return claim.verified and ISSUER_VERIFIED.get(claim.kind) is source


def _device_actor(action: ObservedAction) -> str | None:
    """The verified device actor of this report: None when there is none, `_AMBIGUOUS`
    when it names two."""
    found = {
        c.subject
        for c in action.identity_claims
        if c.kind == DEVICE_ACTOR_CLAIM and _trusted(c, action.source)
    }
    if len(found) > 1:
        return _AMBIGUOUS
    return next(iter(found), None)


def _may_join(action: ObservedAction, reporter: str | None, owner: str) -> bool:
    """May this report use a session bound to device actor `owner` (review H4)? Only its
    own device, or a signed central gate report that carries its own verified claim (it is
    then judged on that claim joined with the session's, never on the session's alone)."""
    if reporter is not None:
        return reporter == owner
    return action.source is ActivitySource.CENTRAL_GATE and any(
        _trusted(c, action.source) for c in action.identity_claims
    )


def _mismatch(session_id: str) -> Attribution:
    """Nothing of the session is inherited and nothing is written to it."""
    return Attribution(
        session_id=session_id,
        state=InformationState.DISPUTED,
        reasons=(AttributionReason.SESSION_DEVICE_MISMATCH.value,),
    )


def _session_facts(
    claims: tuple[SeenClaim, ...], device: str
) -> tuple[frozenset[tuple[str, str]], frozenset[tuple[str, str]]]:
    """(verified facts, every fact). An unverified device-actor claim is no fact at all;
    the device name is a client claim, never verified."""
    verified = frozenset((c.kind, c.subject) for c in claims if c.verified)
    loose = frozenset(
        (c.kind, c.subject) for c in claims if not c.verified and c.kind != DEVICE_ACTOR_CLAIM
    )
    named = frozenset({(DEVICE_FACT, device)}) if device else frozenset()
    return verified, verified | loose | named


def _sticky_agent(conn: Connection, ref: str) -> AgentRecord:
    """The agent a session was already tied to. A dangling reference is an integrity fault."""
    parsed = EntityRef.parse(ref)
    agent = store.find_agent(conn, parsed.id) if parsed.kind == AGENT_REF_KIND else None
    if agent is None:
        raise IntegrityFailure("session points at a missing agent record")
    return agent


def _observed_agent(
    conn: Connection,
    session_id: str,
    surface: str,
    facts: frozenset[tuple[str, str]],
    now: datetime,
) -> AgentRecord:
    """Record an agent first seen now: class unknown, no owner, status observed."""
    ordered = sorted(facts, key=lambda kv: (kv[0] != DEVICE_FACT, kv))[:MAX_FACTS]
    agent = AgentRecord(
        id=new_id("agt"),
        display_name="Observed agent",
        agent_class=AgentClass.UNKNOWN,
        status=AgentStatus.OBSERVED,
        surface=surface,
        facts=tuple(AgentFact(kind=k, value=v) for k, v in ordered),
        observed_session_id=session_id,
        created_at=now,
        updated_at=now,
    )
    store.insert_agent(conn, agent)
    return agent
