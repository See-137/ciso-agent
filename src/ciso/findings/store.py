"""Row mapping and queries for the findings tables. Callers own the transactions."""

from __future__ import annotations

import json
from collections import Counter
from datetime import datetime
from typing import Any

from sqlalchemy import Select, select, update
from sqlalchemy.engine import Connection

from ciso.common.activity import ActionKind, AgentClass, Severity, Verdict
from ciso.common.errors import Conflict, NotFound
from ciso.findings.models import (
    ACTIVE_STATUSES,
    Alert,
    AlertStatus,
    AlertTrigger,
    Finding,
    FindingFilter,
    FindingOrigin,
    FindingStatus,
    FindingSummary,
)
from ciso.findings.tables import alert, finding, finding_transition


def finding_from_row(row: Any) -> Finding:
    return Finding(
        finding_id=row.finding_id,
        fingerprint=row.fingerprint,
        origin=FindingOrigin(row.origin),
        status=FindingStatus(row.status),
        severity=Severity(row.severity),
        category=row.category,
        check_key=row.check_key,
        title=row.title,
        session_id=row.session_id,
        person_ref=row.person_ref,
        agent_ref=row.agent_ref,
        agent_class=AgentClass(row.agent_class),
        action_kind=ActionKind(row.action_kind),
        repository=row.repository,
        branch=row.branch,
        path=row.path,
        decision_id=row.decision_id,
        verdict=Verdict(row.verdict),
        last_decision_id=row.last_decision_id,
        evidence_refs=tuple(json.loads(row.evidence_refs)),
        recommendation=row.recommendation,
        occurrences=row.occurrences,
        first_seen=row.first_seen,
        last_seen=row.last_seen,
        status_changed_by=row.status_changed_by,
        status_changed_at=row.status_changed_at,
        approval_ref=row.approval_ref,
        status_reason=row.status_reason,
        version=row.version,
    )


def finding_values(item: Finding) -> dict[str, Any]:
    values = item.model_dump()
    values["evidence_refs"] = json.dumps(list(item.evidence_refs))
    for key in ("origin", "status", "severity", "agent_class", "action_kind", "verdict"):
        values[key] = getattr(item, key).value
    return values


def alert_from_row(row: Any) -> Alert:
    return Alert(
        alert_id=row.alert_id,
        trigger=AlertTrigger(row.trigger),
        finding_id=row.finding_id,
        decision_id=row.decision_id,
        severity=Severity(row.severity),
        title=row.title,
        person_ref=row.person_ref,
        agent_ref=row.agent_ref,
        repository=row.repository,
        branch=row.branch,
        recommendation=row.recommendation,
        created_at=row.created_at,
        status=AlertStatus(row.status),
        attempts=row.attempts,
        last_failure=row.last_failure,
        delivered_at=row.delivered_at,
    )


def alert_values(item: Alert) -> dict[str, Any]:
    values = item.model_dump()
    for key in ("trigger", "severity", "status"):
        values[key] = getattr(item, key).value
    return values


def find_active(conn: Connection, fingerprint: str) -> Finding | None:
    row = conn.execute(
        select(finding).where(
            finding.c.fingerprint == fingerprint,
            finding.c.status.in_([s.value for s in ACTIVE_STATUSES]),
        )
    ).one_or_none()
    return None if row is None else finding_from_row(row)


def load(conn: Connection, finding_id: str) -> Finding:
    row = conn.execute(select(finding).where(finding.c.finding_id == finding_id)).one_or_none()
    if row is None:
        raise NotFound("no such finding")
    return finding_from_row(row)


def insert(conn: Connection, item: Finding) -> None:
    conn.execute(finding.insert().values(**finding_values(item)))


def replace(conn: Connection, before: Finding, after: Finding) -> None:
    """Write `after` over `before` only if the stored version is still `before.version`."""
    result = conn.execute(
        update(finding)
        .where(finding.c.finding_id == before.finding_id, finding.c.version == before.version)
        .values(**finding_values(after))
    )
    if result.rowcount != 1:
        raise Conflict("the finding changed meanwhile")


def insert_transition(
    conn: Connection, transition_id: str, before: Finding, after: Finding
) -> None:
    conn.execute(
        finding_transition.insert().values(
            transition_id=transition_id,
            finding_id=after.finding_id,
            from_status=before.status.value,
            to_status=after.status.value,
            actor_id=after.status_changed_by,
            at=after.status_changed_at,
            approval_ref=after.approval_ref,
        )
    )


def _filtered(query: Select[Any], filters: FindingFilter) -> Select[Any]:
    if filters.status is not None:
        query = query.where(finding.c.status == filters.status.value)
    if filters.severity is not None:
        query = query.where(finding.c.severity == filters.severity.value)
    if filters.person_ref is not None:
        query = query.where(finding.c.person_ref == filters.person_ref)
    if filters.agent_ref is not None:
        query = query.where(finding.c.agent_ref == filters.agent_ref)
    if filters.repository is not None:
        query = query.where(finding.c.repository == filters.repository)
    if filters.since is not None:
        query = query.where(finding.c.last_seen >= filters.since)
    return query


def query(conn: Connection, filters: FindingFilter) -> tuple[Finding, ...]:
    stmt = _filtered(select(finding), filters).order_by(
        finding.c.last_seen.desc(), finding.c.finding_id.desc()
    )
    return tuple(finding_from_row(r) for r in conn.execute(stmt.limit(filters.limit)))


def summarise(conn: Connection, filters: FindingFilter) -> FindingSummary:
    stmt = _filtered(select(finding.c.severity, finding.c.status), filters)
    rows = list(conn.execute(stmt))
    return FindingSummary(
        total=len(rows),
        by_severity=dict(Counter(r.severity for r in rows)),
        by_status=dict(Counter(r.status for r in rows)),
    )


def insert_alert(conn: Connection, item: Alert) -> None:
    conn.execute(alert.insert().values(**alert_values(item)))


def mark_attempt(
    conn: Connection, item: Alert, *, delivered_at: datetime | None, failure: str
) -> Alert:
    """Record one delivery attempt on a still-pending alert; returns the stored state."""
    after = item.model_copy(
        update={
            "attempts": item.attempts + 1,
            "status": AlertStatus.DELIVERED if delivered_at else AlertStatus.PENDING,
            "delivered_at": delivered_at,
            "last_failure": failure,
        }
    )
    result = conn.execute(
        update(alert)
        .where(alert.c.alert_id == item.alert_id, alert.c.status == AlertStatus.PENDING.value)
        .values(
            attempts=alert.c.attempts + 1,
            status=after.status.value,
            delivered_at=delivered_at,
            last_failure=failure,
        )
    )
    if result.rowcount != 1:
        raise Conflict("the alert is no longer pending")
    return after


def alerts_with(conn: Connection, status: AlertStatus | None, limit: int) -> tuple[Alert, ...]:
    stmt = select(alert).order_by(alert.c.created_at, alert.c.alert_id).limit(limit)
    if status is not None:
        stmt = stmt.where(alert.c.status == status.value)
    return tuple(alert_from_row(r) for r in conn.execute(stmt))
