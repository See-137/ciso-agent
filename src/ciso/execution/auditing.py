"""Audit events the execution package writes (blueprint 9.4, 9.5; review findings M5, M9).

What goes into the details: reason codes, states, hashes, ids, entity references, the
exception type name of a failed step, and the fixed wording of `residual_risk`. Never the
envelope's arguments. Tool and verifier free text (`tool_detail`, `verification_detail`)
stays on the row and is not copied here; the references a tool or verifier returned are
copied only after `ciso.execution.sanitize` kept them (entity references the redactor
leaves unchanged, a bounded number).

Whose name a refusal carries: until the identity store has confirmed that the envelope's
actor exists, is active and is of the claimed type, the actor id is only what the caller
wrote. Such a refusal is audited as the broker itself, with the id in the details as
`claimed_actor_id`. After that check, refusals name the actor. The check shows the actor
is real, not that the calling component speaks for it: authenticating the caller is the
caller-facing layer's job.
"""

from __future__ import annotations

from typing import Any

from ciso.common.enums import ActorType, AuditOutcome
from ciso.common.protocols import AuditEvent
from ciso.execution.records import (
    BROKER_ACTOR_ID,
    EXECUTE_ACTION,
    ExecutionRecord,
    ExecutionRefused,
)
from ciso.policy.envelope import ActionEnvelope

_MAX_TYPE_NAME = 64


def invalid_request_event(submitted: object, refused: ExecutionRefused) -> AuditEvent:
    """`execution.execute` DENIED for something the broker could not even copy. Nothing
    from the submitted object is trusted, so only its type name is recorded."""
    name = type(submitted).__name__.encode("ascii", "replace").decode("ascii")
    return AuditEvent(
        actor_id=BROKER_ACTOR_ID,
        actor_type=ActorType.SERVICE,
        action=EXECUTE_ACTION,
        outcome=AuditOutcome.DENIED,
        details={
            "reason": refused.reason.value,
            "codes": list(refused.codes),
            "request_type": name[:_MAX_TYPE_NAME],
        },
    )


def refusal_event(
    envelope: ActionEnvelope,
    envelope_hash: str,
    refused: ExecutionRefused,
    *,
    actor_confirmed: bool,
    record: ExecutionRecord | None = None,
) -> AuditEvent:
    """`execution.execute` DENIED. In the actor's name once the identity store confirmed
    the actor, otherwise in the broker's name with the claimed id in the details.
    `record` is the row the refusal aborted, when there is one."""
    details: dict[str, Any] = {
        "reason": refused.reason.value,
        "codes": list(refused.codes),
        "operation": envelope.operation,
        "envelope_hash": envelope_hash,
        "idempotency_key": envelope.idempotency_key,
    }
    if not actor_confirmed:
        details["claimed_actor_id"] = envelope.actor_id
        details["claimed_actor_type"] = envelope.actor_type.value
    if record is not None:
        details["execution"] = record.ref
        details["state"] = record.state.value
    return AuditEvent(
        actor_id=envelope.actor_id if actor_confirmed else BROKER_ACTOR_ID,
        actor_type=envelope.actor_type if actor_confirmed else ActorType.SERVICE,
        action=EXECUTE_ACTION,
        target=envelope.target_resource,
        outcome=AuditOutcome.DENIED,
        correlation_id=envelope.request_id,
        details=details,
    )


def record_details(record: ExecutionRecord) -> dict[str, Any]:
    return {
        "execution": record.ref,
        "state": record.state.value,
        "operation": record.operation,
        "envelope_hash": record.envelope_hash,
        "idempotency_key": record.idempotency_key,
        "authority_level": int(record.authority_level),
        "policy_outcome": record.policy_outcome.value,
        "ruleset_hash": record.ruleset_hash,
        "approval": record.approval_ref,
        "tool_outcome": None if record.tool_outcome is None else record.tool_outcome.value,
        "references": list(record.references),
        "verification_matches": record.verification_matches,
        "observed": list(record.observed),
        "residual_risk": record.residual_risk,
        "error_kind": record.error_kind,
    }


def record_event(
    record: ExecutionRecord,
    outcome: AuditOutcome,
    *,
    action: str = EXECUTE_ACTION,
    as_broker: bool = False,
    **extra: Any,
) -> AuditEvent:
    """An event about one execution row. Named after the requesting actor (rows exist
    only for actors the identity store confirmed), or after the broker itself
    (`as_broker`) for recovery work nobody requested."""
    return AuditEvent(
        actor_id=BROKER_ACTOR_ID if as_broker else record.actor_id,
        actor_type=ActorType.SERVICE if as_broker else record.actor_type,
        action=action,
        target=record.target_resource,
        outcome=outcome,
        correlation_id=record.request_id,
        details={**record_details(record), **extra},
    )


def skipped_event(execution_id: str, action: str, problem: str) -> AuditEvent:
    """A row a recovery pass had to leave. Only the id and the error type name: the row
    itself could not be trusted or read."""
    return AuditEvent(
        actor_id=BROKER_ACTOR_ID,
        actor_type=ActorType.SERVICE,
        action=action,
        outcome=AuditOutcome.FAILED,
        details={"execution": f"execution:{execution_id}", "skipped": True, "problem": problem},
    )
