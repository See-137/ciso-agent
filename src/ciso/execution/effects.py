"""The side effect and what is learned about it (blueprint 9.5; plan gap G5; FR-026;
review findings M3, M5, L1).

Runs only after the attempt is audited and stored on the row. Each step writes what it
learned to the row in its own short transaction before the next step starts:

- tool raised: `unknown_outcome` (the side effect may have happened);
- tool returned: `executed_unverified`, then an independent read decides `verified` or
  `verification_failed`. The tool's reply is recorded as a claim and never decides;
- verifier raised or is missing: the row stays unverified, says why in `error_kind`, and
  can be settled later by `ExecutionRecovery.verify`;
- level 3 and above: a raise, a reported failure or a verification mismatch calls the
  tool's rollback, ending `rolled_back` or `rollback_failed`. A rollback is the tool's
  own claim; nothing verifies it, and the residual risk says so.

Every write is conditional on the row still being in the state, and held by the run
token, of the record this code last saw. When that fails, or the store fails for any
other reason, `ExecutionStoreError` is raised and the caller (`ExecutionBroker`) decides
what the row must say; this module alone does not guarantee a true row after a crash
between two steps (start-up recovery covers that case).

Free text from a tool or verifier is made encodable, redacted and bounded before it is
stored (`ciso.execution.sanitize`), and `residual_risk` is fixed wording only. No audit
record is written here and no transaction is held across a tool call.
"""

from __future__ import annotations

from typing import Any

from ciso.common.clock import Clock
from ciso.common.enums import AuthorityLevel
from ciso.common.protocols import Redactor
from ciso.execution.records import ExecutionRecord, ExecutionState, ExecutionStoreError
from ciso.execution.sanitize import error_name, safe_refs, safe_text
from ciso.execution.store import ExecutionStore
from ciso.execution.tools import ToolCall, ToolOutcome, ToolRegistry, ToolResult

RISK_UNKNOWN = "the tool raised; the side effect may have happened and is not verified"
RISK_UNVERIFIED = "the result could not be verified independently"
RISK_SILENT = f"{RISK_UNVERIFIED}: the verifier did not answer"
RISK_MISMATCH = "the target does not show the result the tool was asked for"
RISK_ROLLED_BACK = "rolled back; the rollback is the tool's own claim and is not verified"
RISK_ROLLBACK_FAILED = "rollback did not succeed; the target may hold a partial change"


def is_reversible(record: ExecutionRecord) -> bool:
    """Level 3 and above must be rolled back when they fail or do not verify."""
    return record.authority_level >= AuthorityLevel.L3_EXECUTE


class Effects:
    def __init__(
        self, *, store: ExecutionStore, clock: Clock, registry: ToolRegistry, redactor: Redactor
    ) -> None:
        self._store = store
        self._clock = clock
        self._registry = registry
        self._redactor = redactor

    def perform(self, record: ExecutionRecord, call: ToolCall) -> ExecutionRecord:
        """Call the tool, verify, roll back where required. Returns the final row."""
        reversible = is_reversible(record)
        try:
            result = self._registry.invoke(call)
        except Exception as exc:
            kind = error_name(exc)
            if reversible:
                return self._undo(record, call, None, "the tool raised", error_kind=kind)
            return self._settle(
                record, ExecutionState.UNKNOWN_OUTCOME, error_kind=kind, residual_risk=RISK_UNKNOWN
            )
        record = self._settle(
            record,
            ExecutionState.EXECUTED_UNVERIFIED,
            tool_outcome=result.outcome,
            references=safe_refs(result.references, self._redactor),
            tool_detail=safe_text(result.detail, self._redactor),
            residual_risk=RISK_UNVERIFIED,
        )
        if reversible and result.outcome is not ToolOutcome.SUCCEEDED:
            return self._undo(record, call, result, "the tool reported failure")
        return self.confirm(record, call, result, undo_on_mismatch=reversible)

    def confirm(
        self,
        record: ExecutionRecord,
        call: ToolCall,
        result: ToolResult | None,
        *,
        undo_on_mismatch: bool,
    ) -> ExecutionRecord:
        """Read the target independently and record what it shows. Leaves the state as it
        is when the verifier cannot answer; never reports `verified` without a match that
        is exactly `True`."""
        try:
            seen = self._registry.verify(call)
        except Exception as exc:
            return self._settle(
                record, record.state, error_kind=error_name(exc), residual_risk=RISK_SILENT
            )
        facts: dict[str, Any] = {
            "verification_matches": seen.matches is True,
            "verification_detail": safe_text(seen.detail, self._redactor),
            "observed": safe_refs(seen.observed, self._redactor),
            "error_kind": "",
        }
        if seen.matches is True:
            return self._settle(record, ExecutionState.VERIFIED, residual_risk="", **facts)
        if undo_on_mismatch:
            record = self._settle(record, record.state, residual_risk=RISK_MISMATCH, **facts)
            return self._undo(record, call, result, "verification did not match")
        claimed = "" if result is None else f" (the tool reported {result.outcome.value})"
        return self._settle(
            record,
            ExecutionState.VERIFICATION_FAILED,
            residual_risk=f"{RISK_MISMATCH}{claimed}",
            **facts,
        )

    def _undo(
        self,
        record: ExecutionRecord,
        call: ToolCall,
        result: ToolResult | None,
        cause: str,
        **values: Any,
    ) -> ExecutionRecord:
        try:
            undone = self._registry.rollback(call, result)
        except Exception as exc:
            kind = error_name(exc)
            return self._settle(
                record,
                ExecutionState.ROLLBACK_FAILED,
                residual_risk=f"{cause}; {RISK_ROLLBACK_FAILED} ({kind})",
                **{**values, "error_kind": kind},
            )
        if undone.outcome is ToolOutcome.SUCCEEDED:
            return self._settle(
                record,
                ExecutionState.ROLLED_BACK,
                residual_risk=f"{cause}; {RISK_ROLLED_BACK}",
                **values,
            )
        return self._settle(
            record,
            ExecutionState.ROLLBACK_FAILED,
            residual_risk=f"{cause}; {RISK_ROLLBACK_FAILED}",
            **values,
        )

    def _settle(
        self, record: ExecutionRecord, state: ExecutionState, **values: Any
    ) -> ExecutionRecord:
        changed = self._store.change(record, self._clock.now(), state=state, **values)
        if changed is None:
            raise ExecutionStoreError(
                f"execution {record.execution_id} changed underneath; result not stored"
            )
        return changed
