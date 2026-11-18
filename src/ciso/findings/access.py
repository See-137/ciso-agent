"""Reads and status transitions of findings, with who-may-do-what (lane brief S6.1, S6.4).

security_admin: every read and every transition. auditor: reads only. The person a
finding is about: may acknowledge it and read their own findings. Everyone is resolved
NOW through the injected resolvers; a resolver that cannot answer stops the call.
"""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from typing import Any, NoReturn

from sqlalchemy import Engine
from sqlalchemy.engine import Connection

from ciso.common.clock import Clock
from ciso.common.db import read_connection
from ciso.common.enums import ActorType, AuditOutcome
from ciso.common.errors import AuthorizationError, Conflict, FailClosed, ValidationFailed
from ciso.common.ids import new_id
from ciso.common.principal import Principal
from ciso.common.protocols import PrincipalResolver
from ciso.findings import rules, store
from ciso.findings.journal import Journal
from ciso.findings.models import (
    ACCEPT_RISK_ACTION,
    ACKNOWLEDGE_ACTION,
    DEFAULT_PAGE,
    FALSE_POSITIVE_ACTION,
    MAX_PAGE,
    READ_ACTION,
    RESOLVE_ACTION,
    TRANSITION_PREFIX,
    Alert,
    AlertStatus,
    Finding,
    FindingFilter,
    FindingStatus,
    FindingSummary,
    PersonLinkResolver,
    check_note,
    check_ref,
)


class Access:
    def __init__(
        self,
        engine: Engine,
        *,
        clock: Clock,
        journal: Journal,
        principals: PrincipalResolver,
        people: PersonLinkResolver,
    ) -> None:
        self._engine = engine
        self._clock = clock
        self._journal = journal
        self._principals = principals
        self._people = people

    @contextmanager
    def _reading(self) -> Iterator[Connection]:
        with read_connection(self._engine) as conn:
            yield conn

    # --- identity --------------------------------------------------------------------

    def _refuse(self, action: str, actor_id: str, kind: ActorType, target: str,
                reason: str) -> NoReturn:  # fmt: skip
        self._journal.best_effort(action, actor_id, kind, AuditOutcome.DENIED, target,
                                  {"reason": reason})  # fmt: skip
        raise AuthorizationError(f"not permitted: {reason}")

    def _principal(self, actor_id: str, action: str, target: str) -> Principal:
        try:
            principal = self._principals.resolve(actor_id)
        except Exception as exc:
            raise FailClosed("identity store could not be consulted") from exc
        if principal is None:
            self._refuse(action, actor_id, ActorType.ANONYMOUS, target, "unknown_actor")
        return principal

    def _person_of(self, actor_id: str) -> str | None:
        try:
            return self._people.person_ref_of(actor_id)
        except Exception as exc:
            raise FailClosed("person links could not be consulted") from exc

    # --- transitions -----------------------------------------------------------------

    def acknowledge(self, actor_id: str, finding_id: str) -> Finding:
        return self._move(actor_id, finding_id, FindingStatus.ACKNOWLEDGED, ACKNOWLEDGE_ACTION)

    def resolve(self, actor_id: str, finding_id: str) -> Finding:
        return self._move(actor_id, finding_id, FindingStatus.RESOLVED, RESOLVE_ACTION)

    def accept_risk(self, actor_id: str, finding_id: str, approval_ref: str) -> Finding:
        """Needs a reference to the approval that accepted the risk; it is recorded, not
        checked (this package does not read approvals)."""
        return self._move(actor_id, finding_id, FindingStatus.RISK_ACCEPTED,
                          ACCEPT_RISK_ACTION, approval_ref=check_ref(approval_ref))  # fmt: skip

    def mark_false_positive(self, actor_id: str, finding_id: str, reason: str) -> Finding:
        """Admin only. The reason is stored on the finding and kept out of the audit log."""
        return self._move(actor_id, finding_id, FindingStatus.FALSE_POSITIVE,
                          FALSE_POSITIVE_ACTION, reason=check_note(reason))  # fmt: skip

    def _move(
        self,
        actor_id: str,
        finding_id: str,
        target: FindingStatus,
        action: str,
        *,
        approval_ref: str | None = None,
        reason: str = "",
    ) -> Finding:
        ref = f"finding:{finding_id}"
        principal = self._principal(actor_id, action, ref)
        with self._reading() as conn:
            current = store.load(conn, finding_id)
        mine = None if rules.is_admin(principal) else self._person_of(actor_id)
        kind = principal.actor_type
        if not rules.may_transition(principal, mine, current.person_ref, target):
            self._refuse(action, actor_id, kind, ref, "not_permitted")
        details: dict[str, Any] = {"from": current.status.value, "to": target.value,
                                   "approval_ref": approval_ref}  # fmt: skip
        if target not in rules.TRANSITIONS[current.status]:
            self._journal.best_effort(action, actor_id, kind, AuditOutcome.DENIED, ref,
                                      {**details, "reason": "invalid_transition"})  # fmt: skip
            raise Conflict(f"a finding in status {current.status.value} cannot become "
                           f"{target.value}")  # fmt: skip
        self._journal.attempt(action, actor_id, kind, ref, details)
        now = self._clock.now()
        after = current.model_copy(
            update={"status": target, "status_changed_by": actor_id, "status_changed_at": now,
                    "approval_ref": approval_ref or current.approval_ref,
                    "status_reason": reason, "version": current.version + 1}
        )  # fmt: skip
        try:
            with self._engine.begin() as conn:
                store.replace(conn, current, after)
                store.insert_transition(conn, new_id(TRANSITION_PREFIX), current, after)
        except Exception as exc:
            self._journal.best_effort(action, actor_id, kind, AuditOutcome.FAILED, ref,
                                      {**details, "reason": type(exc).__name__})  # fmt: skip
            raise
        try:
            self._journal.emit(action, actor_id, kind, AuditOutcome.SUCCESS, ref, details)
        except Exception as exc:
            raise FailClosed("the finding changed but the change was not audited") from exc
        return after

    # --- reads -----------------------------------------------------------------------

    def _audited_read(self, principal: Principal, target: str, details: dict[str, Any]) -> None:
        try:
            self._journal.emit(READ_ACTION, principal.actor_id, principal.actor_type,
                               AuditOutcome.SUCCESS, target, details)  # fmt: skip
        except Exception as exc:
            raise FailClosed("the read could not be audited; nothing is returned") from exc

    def _reader(self, actor_id: str, target: str) -> Principal:
        principal = self._principal(actor_id, READ_ACTION, target)
        if not rules.may_read_all(principal):
            self._refuse(READ_ACTION, actor_id, principal.actor_type, target, "not_permitted")
        return principal

    def list(self, actor_id: str, filters: FindingFilter | None = None) -> tuple[Finding, ...]:
        """Admin or auditor. Newest `last_seen` first, at most `filters.limit`."""
        filters = filters or FindingFilter()
        principal = self._reader(actor_id, "findings")
        with self._reading() as conn:
            found = store.query(conn, filters)
        details = {"scope": "all", "count": len(found), "filters": filters.model_dump(mode="json")}
        self._audited_read(principal, "findings", details)
        return found

    def summary(self, actor_id: str, filters: FindingFilter | None = None) -> FindingSummary:
        """Admin or auditor. Counts by severity and by status (`limit` is ignored)."""
        filters = filters or FindingFilter()
        principal = self._reader(actor_id, "findings")
        with self._reading() as conn:
            result = store.summarise(conn, filters)
        details = {"scope": "summary", "filters": filters.model_dump(mode="json")}
        self._audited_read(principal, "findings", details)
        return result

    def get(self, actor_id: str, finding_id: str) -> Finding:
        """Admin or auditor, or the person the finding is about."""
        ref = f"finding:{finding_id}"
        principal = self._principal(actor_id, READ_ACTION, ref)
        with self._reading() as conn:
            item = store.load(conn, finding_id)
        if not rules.may_read_all(principal):
            mine = self._person_of(actor_id) if principal.is_human else None
            if mine is None or mine != item.person_ref:
                self._refuse(READ_ACTION, actor_id, principal.actor_type, ref, "not_permitted")
        self._audited_read(principal, ref, {"scope": "one"})
        return item

    def list_own(self, actor_id: str, filters: FindingFilter | None = None) -> tuple[Finding, ...]:
        """Findings about the person `actor_id` is linked to now. `filters.person_ref` must
        be unset: the person is never taken from the caller."""
        filters = filters or FindingFilter()
        if filters.person_ref is not None:
            raise ValidationFailed("a person-scoped read takes no person_ref")
        principal = self._principal(actor_id, READ_ACTION, "findings")
        mine = self._person_of(actor_id) if principal.is_human else None
        if mine is None:
            self._refuse(READ_ACTION, actor_id, principal.actor_type, "findings", "no_person")
        own = filters.model_copy(update={"person_ref": mine})
        with self._reading() as conn:
            found = store.query(conn, own)
        self._audited_read(principal, "findings", {"scope": "own", "count": len(found)})
        return found

    def list_alerts(
        self, actor_id: str, status: AlertStatus | None = None, limit: int = DEFAULT_PAGE
    ) -> tuple[Alert, ...]:
        """Admin or auditor. Oldest first."""
        principal = self._reader(actor_id, "alerts")
        with self._reading() as conn:
            found = store.alerts_with(conn, status, max(1, min(limit, MAX_PAGE)))
        self._audited_read(principal, "alerts", {"scope": "alerts", "count": len(found)})
        return found
