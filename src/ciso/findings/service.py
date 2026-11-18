"""Findings service: record, transition, alert. Spec section 4 steps 6-7; milestone S6.

Every write is audited attempt -> short transaction -> result, and neither the audit sink,
the principal resolver, the person-link resolver nor the alert sink is ever called while
the operational write lock is held. Privileges are decided on the actor as the resolver
sees it now, never on an object the caller hands in.
"""

from __future__ import annotations

import logging
from collections.abc import Sequence
from datetime import datetime
from typing import Any

from sqlalchemy import Engine
from sqlalchemy.engine import Connection

from ciso.common.activity import GovernanceDecision, InspectionResult, ObservedAction
from ciso.common.clock import Clock
from ciso.common.enums import ActorType, AuditOutcome
from ciso.common.errors import FailClosed
from ciso.common.ids import new_id
from ciso.common.protocols import AuditSink, PrincipalResolver
from ciso.findings import rules, store
from ciso.findings.access import Access
from ciso.findings.alerts import AlertSink
from ciso.findings.journal import Journal
from ciso.findings.models import (
    ALERT_PREFIX,
    FINDING_PREFIX,
    MAX_PAGE,
    RECORD_ACTION,
    Alert,
    AlertStatus,
    AlertTrigger,
    Finding,
    FindingOrigin,
    FindingStatus,
    PersonLinkResolver,
    RecordOutcome,
    check_ref,
)
from ciso.findings.recommendations import RecommendationCatalog

logger = logging.getLogger(__name__)


class FindingsService(Access):
    """Turns governance decisions into findings and alerts, and moves findings along.

    `service_actor_id` is the actor id recorded in the audit log for `record` (the
    governance service calling in). Reads and transitions are in `Access`.
    """

    def __init__(
        self,
        engine: Engine,
        *,
        clock: Clock,
        audit: AuditSink,
        principals: PrincipalResolver,
        people: PersonLinkResolver,
        alert_sink: AlertSink,
        recommendations: RecommendationCatalog,
        service_actor_id: str,
    ) -> None:
        super().__init__(engine, clock=clock, journal=Journal(audit), principals=principals,
                         people=people)  # fmt: skip
        self._service_actor = check_ref(service_actor_id)
        self._sink = alert_sink
        self._catalog = recommendations

    # --- record ----------------------------------------------------------------------

    def record(
        self,
        decision: GovernanceDecision,
        action: ObservedAction,
        inspection: InspectionResult | None,
        *,
        decision_id: str,
    ) -> RecordOutcome:
        """Create or fold findings for one decision and raise its alerts.

        Deny or ask: one decision finding. Inspection findings of medium or worse: one
        each, whatever the verdict. Nothing else creates a finding. Alert delivery never
        raises out of here; a failure stays on the alert as `pending`. Raises
        `FailClosed` if the attempt cannot be audited (nothing stored) or if the result
        cannot be (stored and alerted, then raised).
        """
        check_ref(decision_id)
        rules.check_consistent(decision, action, inspection)
        drafts = rules.drafts_for(decision, action, inspection)
        if not drafts:
            return RecordOutcome()
        target = f"decision:{decision_id}"
        details: dict[str, Any] = {
            "decision_id": decision_id,
            "action_id": action.action_id,
            "verdict": decision.verdict.value,
            "checks": [d.check_key for d in drafts],
        }
        actor = (self._service_actor, ActorType.SERVICE)
        self._journal.attempt(RECORD_ACTION, *actor, target, details)
        now = self._clock.now()
        try:
            with self._engine.begin() as conn:
                found, created, alerts = self._fold(conn, drafts, decision, action, decision_id,
                                                    now)  # fmt: skip
        except Exception as exc:
            self._journal.best_effort(RECORD_ACTION, *actor, AuditOutcome.FAILED, target,
                                      {**details, "reason": type(exc).__name__})  # fmt: skip
            raise
        result = {**details, "created": list(created), "findings": [f.finding_id for f in found],
                  "alerts": [a.alert_id for a in alerts]}  # fmt: skip
        audit_error: Exception | None = None
        try:
            self._journal.emit(RECORD_ACTION, *actor, AuditOutcome.SUCCESS, target, result)
        except Exception as exc:
            audit_error = exc
        delivered = tuple(self._deliver(a) for a in alerts)
        if audit_error is not None:
            raise FailClosed("findings were stored but the result was not audited") from (
                audit_error
            )
        return RecordOutcome(findings=found, created=created, alerts=delivered)

    def _fold(
        self,
        conn: Connection,
        drafts: Sequence[rules.Draft],
        decision: GovernanceDecision,
        action: ObservedAction,
        decision_id: str,
        now: datetime,
    ) -> tuple[tuple[Finding, ...], tuple[str, ...], tuple[Alert, ...]]:
        by_id: dict[str, Finding] = {}
        created: list[str] = []
        alerts: list[Alert] = []
        for draft in drafts:
            fingerprint = rules.fingerprint(draft, decision, action)
            existing = store.find_active(conn, fingerprint)
            if existing is None:
                item = self._new_finding(draft, fingerprint, decision, action, decision_id, now)
                store.insert(conn, item)
                created.append(item.finding_id)
                severe = item.severity in rules.ALERT_LEVELS
            else:
                item = existing.model_copy(
                    update={
                        "occurrences": existing.occurrences + 1,
                        "last_seen": now,
                        "last_decision_id": decision_id,
                        "severity": rules.worse(existing.severity, draft.severity),
                        "version": existing.version + 1,
                    }
                )
                store.replace(conn, existing, item)
                severe = (
                    item.severity in rules.ALERT_LEVELS
                    and existing.severity not in rules.ALERT_LEVELS
                )
            by_id[item.finding_id] = item
            if severe:
                alerts.append(self._alert(item, AlertTrigger.SEVERE_FINDING, decision_id, now))
            if draft.origin is FindingOrigin.DECISION and rules.alerts_on_deny(decision, action):
                alerts.append(self._alert(item, AlertTrigger.BEFORE_DENY, decision_id, now))
        for pending in alerts:
            store.insert_alert(conn, pending)
        return tuple(by_id.values()), tuple(created), tuple(alerts)

    def _new_finding(
        self,
        draft: rules.Draft,
        fingerprint: str,
        decision: GovernanceDecision,
        action: ObservedAction,
        decision_id: str,
        now: datetime,
    ) -> Finding:
        who = decision.attribution
        return Finding(
            finding_id=new_id(FINDING_PREFIX),
            fingerprint=fingerprint,
            origin=draft.origin,
            status=FindingStatus.OPEN,
            severity=draft.severity,
            category=draft.category,
            check_key=draft.check_key,
            title=draft.title,
            session_id=decision.session_id,
            person_ref=who.person_ref,
            agent_ref=who.agent_ref,
            agent_class=who.agent_class,
            action_kind=action.kind,
            repository=action.target.get("repository", ""),
            branch=action.target.get("branch", ""),
            path=action.target.get("path", ""),
            decision_id=decision_id,
            verdict=decision.verdict,
            last_decision_id=decision_id,
            evidence_refs=rules.evidence_refs(decision_id, decision, action),
            recommendation=self._catalog.text_for(draft.origin, draft.recommendation_key),
            occurrences=1,
            first_seen=now,
            last_seen=now,
        )

    @staticmethod
    def _alert(item: Finding, trigger: AlertTrigger, decision_id: str, now: datetime) -> Alert:
        return Alert(
            alert_id=new_id(ALERT_PREFIX),
            trigger=trigger,
            finding_id=item.finding_id,
            decision_id=decision_id,
            severity=item.severity,
            title=item.title,
            person_ref=item.person_ref,
            agent_ref=item.agent_ref,
            repository=item.repository,
            branch=item.branch,
            recommendation=item.recommendation,
            created_at=now,
        )

    # --- delivery --------------------------------------------------------------------

    def _deliver(self, pending: Alert) -> Alert:
        """One delivery attempt, outside any transaction. Never raises: the outcome is
        stored on the alert, and a failure to store it is logged and leaves the alert
        pending, so `deliver_pending` sends it again."""
        failure = ""
        delivered_at: datetime | None = None
        try:
            self._sink.deliver(pending)
            delivered_at = self._clock.now()
        except Exception as exc:
            failure = type(exc).__name__
            logger.warning("findings: alert %s not delivered (%s)", pending.alert_id, failure)
        try:
            with self._engine.begin() as conn:
                return store.mark_attempt(conn, pending, delivered_at=delivered_at,
                                          failure=failure)  # fmt: skip
        except Exception as exc:
            logger.error(
                "findings: delivery state of alert %s not stored (%s)",
                pending.alert_id,
                type(exc).__name__,
            )
            return pending

    def deliver_pending(self) -> tuple[Alert, ...]:
        """Try every pending alert once more (oldest first, at most `MAX_PAGE`). Returns the
        alerts still pending afterwards."""
        with self._reading() as conn:
            pending = store.alerts_with(conn, AlertStatus.PENDING, MAX_PAGE)
        after = (self._deliver(a) for a in pending)
        return tuple(a for a in after if a.status is AlertStatus.PENDING)
