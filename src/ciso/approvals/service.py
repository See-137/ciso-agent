"""Approval service. Blueprint 8.4 step 4, 9.5, FR-025; gaps G2, G3, G12, G14, G33;
ADR-0016, ADR-0021."""

from __future__ import annotations

import logging
from collections.abc import Iterable, Mapping
from datetime import timedelta
from typing import Any

from sqlalchemy import Engine

from ciso.approvals import rules
from ciso.approvals.journal import Journal
from ciso.approvals.models import (
    APPROVE_ACTION,
    CHECK_ACTION,
    CONSUME_ACTION,
    ID_PREFIX,
    REJECT_ACTION,
    REQUEST_ACTION,
    WITHDRAW_ACTION,
    Approval,
    ApprovalConflict,
    ApprovalFault,
    ApprovalForbidden,
    ApprovalInputInvalid,
    ApprovalInvalid,
    ApprovalNotFound,
    ApprovalReason,
    ApprovalStatus,
    ApprovalUnavailable,
    AuditRecordLookup,
)
from ciso.approvals.store import ApprovalStore
from ciso.approvals.validity import Validity
from ciso.common.clock import Clock
from ciso.common.enums import ActorType, AuditOutcome, Role
from ciso.common.ids import new_id
from ciso.common.principal import Principal
from ciso.common.protocols import AuditSink, PrincipalResolver, Redactor

logger = logging.getLogger(__name__)

_UNUSED = (ApprovalStatus.PENDING, ApprovalStatus.APPROVED)


class ApprovalService:
    """Human approvals bound to one exact subject, usable once (blueprint 9.5, 8.4).

    Generic on purpose: the subject is a kind, the SHA-256 hex of what is being approved
    and a `binding` of string fields that must all match again at use (for an action: the
    envelope hash; for external inference: provider, model, purpose, request id). The
    execution broker and the external inference gateway both use this class.

    Settings. `approval_ttl=None` (the default) means nothing can be requested, approved,
    checked or consumed: `ApprovalUnavailable(TTL_UNSET)`. Rejecting, withdrawing and
    reading still work. `allow_self_approval=False` (the default, ADR-0016) refuses an
    approver who is the requester or a named party. `redactor`, when given, is applied to
    decision notes before they are stored. `audit_records`, when given, lets `check` and
    `consume` read the grant's audit record back (see "Validity").

    Who decides. `approve` / `reject` take the authenticated `Principal`. Proving that the
    caller is that person is the API layer's job, not this class's: the object is trusted
    for `actor_id` and `credential_issued_by` only, and the actor id is resolved again
    through `principals` so type and roles are today's. An object that disagrees with the
    identity store (another actor type, or a role the actor does not hold) is refused as
    `PRINCIPAL_MISMATCH`. What keeps other in-process code from calling this class with a
    made-up object is the import allowlist in `tests/architecture/`: only the execution
    broker, the external inference gateway, the approvals API router and the composition
    root may import `ciso.approvals`. The approver must resolve to an active human holding
    one of the required roles through a grant that reaches `target`.

    Validity is never stored. `check` and `consume` recompute it: approved, a grant audit
    record id present on the row, the clock not behind the stored times, not expired, not
    consumed, same subject and binding, approver still an active human with a covering
    required role, requester/party/approver rule still true under the current settings.
    With `audit_records` wired the grant record is also read back and must be a
    successful `approval.approve` of this approval by the stored approver; if the log
    cannot be read the call fails closed. WITHOUT `audit_records` only the presence of
    the id is checked: someone who can write the approval table can then forge a usable
    approval, and nothing here detects it. `consume` then takes the approval in one
    conditional UPDATE, so of any number of concurrent callers exactly one succeeds.

    Audit. Every change is: audit ATTEMPT, change in a short transaction, audit the
    result. The sink, the resolver and `audit_records` are never called inside a
    transaction. If the ATTEMPT cannot be written nothing changes (`withdraw` is the one
    exception: it only removes authority, so it goes ahead). If the result cannot be
    written the call raises `ApprovalUnavailable(AUDIT_UNAVAILABLE)` and the state is
    left on the unusable side: a new request is voided, from whatever unused state it has
    reached, and if it cannot be voided the call raises `VOID_FAILED` instead of claiming
    it was; a grant is voided (and is unusable even if voiding fails, because a grant
    counts only once its audit record id is stored on the row); a rejection stays
    rejected; a consumption stays consumed (the approval is spent and the caller must not
    act). Refusals against an existing approval are audited as DENIED; if that record
    cannot be written the refusal is still raised.

    Reads (`get`, `list_pending`) make no permission decision: the caller does.
    """

    def __init__(
        self,
        *,
        engine: Engine,
        audit: AuditSink,
        clock: Clock,
        principals: PrincipalResolver,
        approval_ttl: timedelta | None = None,
        allow_self_approval: bool = False,
        redactor: Redactor | None = None,
        audit_records: AuditRecordLookup | None = None,
    ) -> None:
        self._store = ApprovalStore(engine)
        self._journal = Journal(audit)
        self._clock = clock
        self._validity = Validity(
            clock=clock,
            principals=principals,
            ttl=rules.check_ttl(approval_ttl),
            allow_self=allow_self_approval is True,
            audit_records=audit_records,
        )
        self._redactor = redactor

    # --- reads -----------------------------------------------------------------------

    def get(self, approval_id: str) -> Approval:
        record = self._store.find(approval_id) if isinstance(approval_id, str) else None
        if record is None:
            raise ApprovalNotFound(ApprovalReason.NOT_FOUND, "no such approval")
        return record

    def list_pending(self, *, role: Role | None = None) -> tuple[Approval, ...]:
        """Pending, unexpired requests, oldest first; with `role`, only those a holder of
        that role could decide (the role is stored on the request and may approve)."""
        found = self._store.pending(self._clock.now())
        if role is None:
            return found
        return tuple(record for record in found if rules.may_list_for(record, role))

    # --- request ---------------------------------------------------------------------

    def request(
        self,
        *,
        subject_kind: str,
        subject_hash: str,
        binding: Mapping[str, str],
        requested_by: str,
        requested_by_type: ActorType,
        required_roles: Iterable[Role],
        target: Mapping[str, str | None],
        correlation_id: str = "",
        parties: Iterable[str] = (),
    ) -> Approval:
        """Open a request. The caller passes the authenticated requester, and in
        `parties` every other actor who had a hand in what is being approved (its author,
        when somebody else files it): none of them may decide it. The requester/approver
        rule is only as good as these ids; they are not resolved here."""
        kind, digest = rules.check_subject(subject_kind, subject_hash)
        actor_id, actor_type = rules.check_requester(requested_by, requested_by_type)
        roles = rules.check_roles(required_roles)
        ttl = self._validity.require_ttl()
        now = self._clock.now()
        record = Approval(
            approval_id=new_id(ID_PREFIX),
            subject_kind=kind,
            subject_hash=digest,
            binding=rules.check_binding(binding),
            requested_by=actor_id,
            requested_by_type=actor_type,
            parties=rules.check_parties(parties, actor_id),
            required_roles=roles,
            target=rules.check_target(target),
            status=ApprovalStatus.PENDING,
            requested_at=now,
            expires_at=now + ttl,
            correlation_id=rules.check_correlation(correlation_id),
        )
        extra = {"binding": dict(record.binding), "target": dict(record.target)}
        self._journal.attempt(REQUEST_ACTION, record, actor_id, actor_type, extra)
        self._store.insert(record)
        try:
            self._journal.emit(
                REQUEST_ACTION, record, actor_id, actor_type, AuditOutcome.SUCCESS, extra
            )
        except Exception as exc:
            # The row may have been approved meanwhile: void it from any unused state.
            if not self._void(record, *_UNUSED):
                raise ApprovalUnavailable(
                    ApprovalReason.VOID_FAILED,
                    "request could not be audited and could not be voided; it may be usable",
                ) from exc
            raise ApprovalUnavailable(
                ApprovalReason.AUDIT_UNAVAILABLE, "request could not be audited; it was voided"
            ) from exc
        return record

    def withdraw(self, approval_id: str, *, actor_id: str, actor_type: ActorType) -> Approval:
        """Cancel a request that will not be used (for example its caller could not
        finish filing what it belongs to). Works from pending or approved, never after
        use. Only removes authority, so it goes ahead even when the attempt cannot be
        audited; raises `AUDIT_UNAVAILABLE` afterwards if the result could not be either.
        Raises `VOID_FAILED` when nothing was cancelled."""
        actor, kind = self._caller(actor_id, actor_type)
        record = self.get(approval_id)
        try:
            self._journal.emit(WITHDRAW_ACTION, record, actor, kind, AuditOutcome.ATTEMPT, {})
        except Exception as exc:
            logger.error("approvals: withdraw attempt not audited (%s)", type(exc).__name__)
        if not self._void(record, *_UNUSED):
            self._journal.deny(
                WITHDRAW_ACTION, record, actor, kind,
                ApprovalUnavailable(ApprovalReason.VOID_FAILED, "approval could not be withdrawn"),
            )  # fmt: skip
        try:
            self._journal.emit(WITHDRAW_ACTION, record, actor, kind, AuditOutcome.SUCCESS, {})
        except Exception as exc:
            raise ApprovalUnavailable(
                ApprovalReason.AUDIT_UNAVAILABLE, "withdrawn, but the withdrawal was not audited"
            ) from exc
        return self.get(record.approval_id)

    # --- decide ----------------------------------------------------------------------

    def approve(self, approval_id: str, approver: Principal, *, note: str = "") -> Approval:
        """Grant. `approver` is the principal sign-in produced for the caller; see the
        class docstring for what is and is not trusted on it."""
        return self._decide(approval_id, approver, ApprovalStatus.APPROVED, APPROVE_ACTION, note)

    def reject(self, approval_id: str, approver: Principal, *, note: str = "") -> Approval:
        return self._decide(approval_id, approver, ApprovalStatus.REJECTED, REJECT_ACTION, note)

    def _decide(
        self,
        approval_id: str,
        approver: Principal,
        status: ApprovalStatus,
        action: str,
        note: str,
    ) -> Approval:
        text = self._clean(rules.check_note(note))
        record = self.get(approval_id)
        if not isinstance(approver, Principal):
            raise ApprovalInputInvalid(
                ApprovalReason.INVALID_ACTOR, "approver must be the authenticated principal"
            )
        claimed = rules.check_actor(approver.actor_id, ApprovalReason.INVALID_ACTOR, "approver")
        issuer = rules.check_issuer(approver.credential_issued_by)
        granting = status is ApprovalStatus.APPROVED
        resolved: Principal | None = None
        try:
            now = self._validity.open_for_decision(record, granting=granting)
            resolved = self._validity.resolve(claimed)
            why = self._validity.approver_reason(record, approver, resolved, issuer)
            if why is not None or resolved is None:
                raise ApprovalForbidden(why or ApprovalReason.APPROVER_UNKNOWN)
        except ApprovalFault as fault:
            seen = resolved.actor_type if resolved is not None else ActorType.ANONYMOUS
            self._journal.deny(action, record, claimed, seen, fault)
        roles = rules.covering_roles(record, resolved)
        self_approved = rules.is_party(record, claimed)
        extra: dict[str, Any] = {
            "decided_roles": [r.value for r in roles],
            "self_approved": self_approved,
            "credential_issued_by": issuer,
        }
        self._journal.attempt(action, record, claimed, ActorType.HUMAN, extra)
        changed = self._store.decide(
            record.approval_id, status=status, decided_by=claimed, decided_at=now,
            decided_roles=roles, note=text, self_approved=self_approved,
            credential_issuer=issuer,
        )  # fmt: skip
        if not changed:
            late = ApprovalConflict(
                ApprovalReason.ALREADY_DECIDED, "approval was decided or expired meanwhile"
            )
            self._journal.deny(action, record, claimed, ActorType.HUMAN, late)
        try:
            receipt = self._journal.emit(
                action, record, claimed, ActorType.HUMAN, AuditOutcome.SUCCESS, extra
            )
        except Exception as exc:
            state = "the request stays rejected"
            if granting:
                voided = self._void(record, ApprovalStatus.APPROVED)
                state = "it was voided" if voided else "it has no audit record and is unusable"
            raise ApprovalUnavailable(
                ApprovalReason.AUDIT_UNAVAILABLE, f"decision could not be audited; {state}"
            ) from exc
        if granting and not self._store.confirm_grant(record.approval_id, receipt.record_id):
            raise ApprovalUnavailable(
                ApprovalReason.STORE_UNAVAILABLE, "grant could not be confirmed; not usable"
            )
        return self.get(record.approval_id)

    # --- use -------------------------------------------------------------------------

    def check(
        self,
        approval_id: str,
        *,
        subject_kind: str,
        subject_hash: str,
        binding: Mapping[str, str],
        actor_id: str,
        actor_type: ActorType,
    ) -> Approval:
        """Raise unless the approval can be used for exactly this subject right now.

        Changes nothing and reserves nothing: only `consume` entitles the caller to act.
        `actor_id` / `actor_type` name the component asking, for the audit record.
        """
        return self._validate(
            CHECK_ACTION, approval_id, subject_kind, subject_hash, binding, actor_id, actor_type
        )

    def consume(
        self,
        approval_id: str,
        *,
        subject_kind: str,
        subject_hash: str,
        binding: Mapping[str, str],
        actor_id: str,
        actor_type: ActorType,
    ) -> Approval:
        """Re-verify and spend the approval. Returns only to the one caller that won it;
        act only after this returns. Any exception means: do not act."""
        record = self._validate(
            CONSUME_ACTION, approval_id, subject_kind, subject_hash, binding, actor_id, actor_type
        )
        self._journal.attempt(CONSUME_ACTION, record, actor_id, actor_type, {})
        now = self._clock.now()
        if not self._store.consume(record, consumed_by=actor_id, now=now):
            latest = self._store.find(record.approval_id)
            why = rules.state_refusal(latest, now) if latest is not None else None
            self._journal.deny(CONSUME_ACTION, record, actor_id, actor_type,
                               ApprovalInvalid(why or ApprovalReason.ALREADY_CONSUMED))  # fmt: skip
        try:
            self._journal.emit(
                CONSUME_ACTION, record, actor_id, actor_type, AuditOutcome.SUCCESS, {}
            )
        except Exception as exc:
            raise ApprovalUnavailable(
                ApprovalReason.AUDIT_UNAVAILABLE,
                "consumption could not be audited; the approval is spent, do not act",
            ) from exc
        return self.get(record.approval_id)

    def _validate(
        self,
        action: str,
        approval_id: str,
        subject_kind: str,
        subject_hash: str,
        binding: Mapping[str, str],
        actor_id: str,
        actor_type: ActorType,
    ) -> Approval:
        kind, digest = rules.check_subject(subject_kind, subject_hash)
        fields = rules.check_binding(binding)
        caller, caller_type = self._caller(actor_id, actor_type)
        record = self.get(approval_id)
        try:
            why = self._validity.use_reason(record, kind, digest, fields)
            if why is not None:
                raise ApprovalInvalid(why)
        except ApprovalFault as fault:
            self._journal.deny(action, record, caller, caller_type, fault)
        return record

    # --- internals -------------------------------------------------------------------

    @staticmethod
    def _caller(actor_id: object, actor_type: object) -> tuple[str, ActorType]:
        actor = rules.check_actor(actor_id, ApprovalReason.INVALID_ACTOR, "actor")
        if not isinstance(actor_type, ActorType):
            raise ApprovalInputInvalid(ApprovalReason.INVALID_ACTOR, "bad actor type")
        return actor, actor_type

    def _clean(self, note: str) -> str:
        """The note with secrets removed. A redactor that fails stops the decision; its
        own message is not repeated, because it could quote the note."""
        if self._redactor is None or not note:
            return note
        try:
            return self._redactor.redact(note)
        except Exception as exc:
            raise ApprovalUnavailable(
                ApprovalReason.REDACTOR_UNAVAILABLE,
                f"note could not be redacted ({type(exc).__name__}); nothing changed",
            ) from None

    def _void(self, record: Approval, *from_statuses: ApprovalStatus) -> bool:
        """True only when the row really was cancelled. The caller decides what a False
        means for what it reports."""
        try:
            changed = self._store.void(record.approval_id, *from_statuses)
        except ApprovalFault as exc:
            logger.error(
                "approvals: %s could not be voided (%s)", record.approval_id, exc.reason.value
            )
            return False
        if not changed:
            logger.error("approvals: %s was not in a state that can be voided", record.approval_id)
        return changed
