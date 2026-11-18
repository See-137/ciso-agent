"""Steps 5 to 7 once every gate has passed: the last kill-switch read, the one transport
call, and the closing record (blueprint 8.4; review findings H3, M2, M6).

The rule this module exists for: once the transport has been called, nothing leaves here
without a closing audit event that names the record id and says `sent: true`, and a ledger
row that is either complete or flagged `sent_unrecorded`. If the closing audit event
itself cannot be written the row is flagged and `FailClosed` is raised.

`sent: true` means "handed to the transport". After a transport error nobody knows
whether the bytes arrived; the outcome field says so.

The audit sink is never called inside a database transaction.
"""

from __future__ import annotations

import logging
from collections.abc import Mapping
from types import MappingProxyType
from typing import Any, NamedTuple

from ciso.common.clock import Clock
from ciso.common.enums import AuditOutcome
from ciso.common.errors import FailClosed
from ciso.common.ids import entity_ref
from ciso.common.protocols import Redactor
from ciso.inference.external.auditing import GateAudit
from ciso.inference.external.gates import Caller, Gates
from ciso.inference.external.ledger import ExternalLedger
from ciso.inference.external.records import (
    ACTION_TRANSMIT,
    RESULT_REF_KIND,
    ExternalGateRefused,
    ExternalResult,
    ExternalTransmissionRecord,
    ExternalTransmitFailed,
    TransmitOutcome,
)
from ciso.inference.external.transport import ExternalTransport, TransportResponse
from ciso.inference.records import UntrustedModelOutput

_LOG = logging.getLogger(__name__)


_NO_METADATA: Mapping[str, str] = MappingProxyType({})


class Answer(NamedTuple):
    outcome: TransmitOutcome
    error_type: str | None = None
    output: UntrustedModelOutput | None = None
    size: int | None = None
    metadata: Mapping[str, str] = _NO_METADATA


class Job(NamedTuple):
    """One transmission that is past every gate: the record already written as
    `attempted`, the exact bytes, and what the audit events must carry."""

    record: ExternalTransmissionRecord
    raw: bytes
    key: bytes | None
    caller: Caller
    target: str
    details: dict[str, Any]


class Courier:
    def __init__(
        self,
        *,
        ledger: ExternalLedger,
        clock: Clock,
        audit: GateAudit,
        redactor: Redactor,
        gates: Gates,
        max_response_bytes: int | None,
    ) -> None:
        self._ledger = ledger
        self._clock = clock
        self._audit = audit
        self._redactor = redactor
        self._gates = gates
        self._max_response = max_response_bytes

    def deliver(self, transport: ExternalTransport, job: Job) -> ExternalResult:
        """Read the kill switch one last time, call the transport once, close the record.

        Raises `ExternalGateRefused` (kill switch: nothing was sent, the approval stays
        spent), `ExternalTransmitFailed` (sent, no usable answer) or `FailClosed` (sent,
        and the closing record is incomplete). Never retries.
        """
        self._last_look(job)
        return self._close(job, self._call(transport, job))

    # --- before the send ---------------------------------------------------------------

    def _last_look(self, job: Job) -> None:
        """The kill switch as it is now, not as it was when the call began (finding M2).
        Between the first read and here lie database writes and audit appends."""
        stopped = self._gates.kill_switch()
        if stopped is None:
            return
        details = {**job.details, "reason": stopped.value, "sent": False}
        try:
            completed = self._ledger.complete_record(
                job.record.id, outcome=TransmitOutcome.NOT_SENT, completed_at=self._clock.now(),
                error_type=stopped.value, response_bytes=None, response_digest=None,
                response_metadata={}, result_ref=None,
            )  # fmt: skip
        except FailClosed:
            completed = False
        details["record_incomplete"] = not completed
        self._audit.emit(
            ACTION_TRANSMIT, job.caller, job.target, AuditOutcome.DENIED, details,
            job.record.correlation_id,
        )  # fmt: skip
        raise ExternalGateRefused(stopped)

    # --- the send ----------------------------------------------------------------------

    def _call(self, transport: ExternalTransport, job: Job) -> Answer:
        """Call the transport once and read the answer. Never raises, and never keeps a
        cause: an exception here could hold the payload or the answer."""
        record = job.record
        try:
            response = transport.send(
                provider_name=record.provider_name, model_name=record.model_name, payload=job.raw
            )
        except Exception as exc:
            return Answer(TransmitOutcome.TRANSPORT_ERROR, type(exc).__name__)
        try:
            return self._read(response)
        except Exception as exc:
            return Answer(TransmitOutcome.RESULT_NOT_PROCESSED, type(exc).__name__)

    def _read(self, response: object) -> Answer:
        limit = self._max_response
        try:
            checked = TransportResponse.model_validate(response.model_dump())  # type: ignore[attr-defined]
            body = checked.body
        except Exception as exc:
            return Answer(TransmitOutcome.MALFORMED_RESPONSE, type(exc).__name__)
        size = len(body)
        if limit is None or size > limit:
            return Answer(TransmitOutcome.RESPONSE_TOO_LARGE, size=size)
        try:
            text = body.decode("utf-8")
        except UnicodeDecodeError as exc:
            return Answer(TransmitOutcome.MALFORMED_RESPONSE, type(exc).__name__)
        metadata = {key: self._redactor.redact(item) for key, item in checked.metadata.items()}
        if not text.strip():
            return Answer(TransmitOutcome.EMPTY_RESPONSE, size=size, metadata=metadata)
        # Step 7: redact, wrap, and hand back. The text is never interpreted here.
        output = UntrustedModelOutput(self._redactor.redact(text))
        return Answer(TransmitOutcome.SENT, output=output, size=size, metadata=metadata)

    # --- after the send ----------------------------------------------------------------

    def _close(self, job: Job, answer: Answer) -> ExternalResult:
        record, output = job.record, answer.output
        details = {
            **job.details,
            "sent": True,
            "outcome": answer.outcome.value,
            "error_type": answer.error_type,
            "response_bytes": answer.size,
            "response_metadata_keys": sorted(answer.metadata),
        }
        try:
            digest = None if output is None or job.key is None else output.keyed_digest(job.key)
            result_ref = None if output is None else entity_ref(RESULT_REF_KIND, record.id)
            changed = self._ledger.complete_record(
                record.id, outcome=answer.outcome, completed_at=self._clock.now(),
                error_type=answer.error_type, response_bytes=answer.size,
                response_digest=digest, response_metadata=dict(answer.metadata),
                result_ref=result_ref,
            )  # fmt: skip
            if not changed:
                raise FailClosed("transmission record was not in the attempted state")
        except Exception as exc:
            flagged = self._flag(record.id, f"record_incomplete:{answer.outcome.value}")
            details = {
                **details,
                "record_incomplete": True,
                "record_flagged": flagged,
                "cause_type": type(exc).__name__,
            }
            self._emit_closing(job, AuditOutcome.FAILED, details)
            raise FailClosed(
                "the payload was handed to the transport; its record could not be completed"
            ) from exc
        details = {**details, "response_digest": digest, "result_ref": result_ref}
        closing = AuditOutcome.FAILED if output is None else AuditOutcome.SUCCESS
        self._emit_closing(job, closing, details)
        if output is None or result_ref is None or answer.size is None:
            raise ExternalTransmitFailed(answer.outcome, record.id)
        return ExternalResult(
            record_id=record.id,
            request_id=record.request_id,
            approval_ref=record.approval_ref,
            result_ref=result_ref,
            output=output,
            provider_name=record.provider_name,
            model_name=record.model_name,
            response_bytes=answer.size,
            response_digest=digest,
            response_metadata=dict(answer.metadata),
        )

    def _emit_closing(self, job: Job, outcome: AuditOutcome, details: dict[str, Any]) -> None:
        """The closing audit event. If it cannot be written the ledger row is flagged
        `sent_unrecorded` and `FailClosed` goes up: no result is returned."""
        try:
            self._audit.emit(
                ACTION_TRANSMIT, job.caller, job.target, outcome, details,
                job.record.correlation_id,
            )  # fmt: skip
        except FailClosed:
            self._flag(job.record.id, f"closing_audit_failed:{details['outcome']}")
            raise

    def _flag(self, record_id: str, note: str) -> bool:
        """Mark the row `sent_unrecorded`. True only when the row really changed; a
        failure here is logged (type name only) because the caller is already raising."""
        try:
            flagged = self._ledger.mark_unrecorded(record_id, note)
        except FailClosed as exc:
            _LOG.error(
                "external inference: record %s could not be flagged (%s)",
                record_id, type(exc.__cause__ or exc).__name__,
            )  # fmt: skip
            return False
        if not flagged:
            _LOG.error("external inference: record %s is missing; nothing flagged", record_id)
        return flagged
