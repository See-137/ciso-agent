"""Helpers for the broker, outbox and recovery tests (plan rows T2.3, T2.4).

A `World` is one process worth of collaborators around a broker: real registry, real
policy engine with the shipped ruleset, real approvals; fakes for audit, identity, kill
switch, secrets and the policy context. Import as `tests.execution.broker_world`. This
module must not import the conftest next to it (the conftest imports this).
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from datetime import datetime, timedelta
from typing import Any

from pydantic import Field
from sqlalchemy import Engine, select, update
from tests.fakes.core import FakeAudit, FakeKillSwitch, FakeRedactor, FakeSecrets

from ciso.approvals import ApprovalService
from ciso.common.clock import FixedClock
from ciso.common.enums import (
    ActorType,
    AuditOutcome,
    AuthorityLevel,
    Environment,
    FreshnessState,
    Role,
)
from ciso.common.errors import FailClosed
from ciso.common.ids import new_id
from ciso.common.principal import Principal
from ciso.common.protocols import AuditEvent, AuditReceipt, AuditSink, PrincipalResolver
from ciso.common.schemas import Model
from ciso.execution import (
    APPROVAL_SUBJECT_KIND,
    ExecutionBroker,
    ExecutionRecord,
    ExecutionRecovery,
    Tool,
    ToolCall,
    ToolOutcome,
    ToolRegistry,
    ToolResult,
    Verification,
    approval_binding,
    approval_target,
)
from ciso.execution.integrity import RowSeal
from ciso.execution.store import ExecutionStore
from ciso.execution.tables import execution_run
from ciso.policy import (
    ActionEnvelope,
    EnvelopeScope,
    EnvelopeValidator,
    OperationSpec,
    PlaybookStatus,
    PolicyDecision,
    PolicyEngine,
    Precondition,
    RollbackPlan,
    VerificationPlan,
    load_default_ruleset,
)


class NoteArgs(Model):
    note: str = Field(max_length=4000)


def _op(name: str, level: AuthorityLevel) -> OperationSpec:
    return OperationSpec(
        name=name, authority_level=level, args_model=NoteArgs, writes=True, agent_requestable=True
    )


WRITE_TOKEN_REF = "secret://write_token"
WRITE_TOKEN = "write-token-value-for-tests-5e1f"
#: The key the broker authenticates `execution_run` rows with (review finding M7).
ROW_KEY_REF = "secret://execution_row_key"
ROW_KEY = "row-key-for-tests-0123456789abcdef-0123456789"
#: A value the world's redactor knows and removes (review findings M4, M5).
SENSITIVE = "hunter2-PRIVATE-KEY-0000"
L2_OP = _op("note.write", AuthorityLevel.L2_COORDINATE)
L3_OP = _op("host.contain", AuthorityLevel.L3_EXECUTE)
L4_OP = _op("change.push", AuthorityLevel.L4_HIGH_IMPACT)
STILL_OPEN = Precondition(name="still_open", ref="finding:f1", expectation="open")


class PickyAudit(FakeAudit):
    """Fails the events `fail_if` selects; can run a probe inside `append`."""

    def __init__(self, clock: FixedClock) -> None:
        super().__init__(clock)
        self.fail_if: Callable[[AuditEvent], bool] | None = None
        self.during: Callable[[AuditEvent], None] | None = None

    def append(self, event: AuditEvent) -> AuditReceipt:
        if self.during is not None:
            self.during(event)
        if self.fail_if is not None and self.fail_if(event):
            raise FailClosed("audit path unavailable (scripted)")
        return super().append(event)

    def fail_on(self, action: str, outcome: AuditOutcome) -> None:
        self.fail_if = lambda e: e.action == action and e.outcome is outcome

    def outcomes(self, action: str) -> list[AuditOutcome]:
        return [e.outcome for e in self.find(action)]


class ScriptedTool:
    """A fake tool body. Remembers every call; run, verifier and rollback can be told
    to fail. `on_run` runs inside the tool, before it returns or raises."""

    def __init__(self) -> None:
        self.calls: list[ToolCall] = []
        self.verified: list[ToolCall] = []
        self.rolled_back: list[tuple[ToolCall, ToolResult | None]] = []
        self.checked: list[str] = []
        self.matches = True
        self.precondition_holds: Any = True
        self.outcome = ToolOutcome.SUCCEEDED
        self.run_error: Exception | None = None
        self.verify_error: Exception | None = None
        self.rollback_error: Exception | None = None
        self.check_error: Exception | None = None
        self.rollback_outcome = ToolOutcome.SUCCEEDED
        self.on_run: Callable[[ToolCall], None] | None = None
        self.on_verify: Callable[[ToolCall], None] | None = None
        self.detail = "done"
        self.verify_detail = "read back"
        self.observed: tuple[str, ...] = ("draft:d1",)
        #: When set, every entry point appends its name here (gate-order spy).
        self.trace: list[str] | None = None

    def _note(self, step: str) -> None:
        if self.trace is not None:
            self.trace.append(step)

    def run(self, call: ToolCall) -> ToolResult:
        self._note("tool")
        self.calls.append(call)
        if self.on_run is not None:
            self.on_run(call)
        if self.run_error is not None:
            raise self.run_error
        return ToolResult(outcome=self.outcome, references=("draft:d1",), detail=self.detail)

    def read_back(self, call: ToolCall) -> Verification:
        self._note("verify")
        self.verified.append(call)
        if self.on_verify is not None:
            self.on_verify(call)
        if self.verify_error is not None:
            raise self.verify_error
        return Verification(matches=self.matches, detail=self.verify_detail, observed=self.observed)

    def undo(self, call: ToolCall, result: ToolResult | None) -> ToolResult:
        self._note("rollback")
        self.rolled_back.append((call, result))
        if self.rollback_error is not None:
            raise self.rollback_error
        return ToolResult(outcome=self.rollback_outcome, detail="undo")

    def check(self, precondition: Precondition, call: ToolCall) -> bool:
        self._note("precondition")
        self.checked.append(precondition.name)
        if self.check_error is not None:
            raise self.check_error
        return self.precondition_holds  # type: ignore[no-any-return]


class FakeContext:
    """A `PolicyContext` that says yes to everything until a test flips an answer."""

    def __init__(self, clock: FixedClock) -> None:
        self._clock = clock
        self.in_scope = True
        self.channel_ok = True
        self.playbook = True
        self.fresh = True

    def is_within_scope(self, principal: Principal, envelope: ActionEnvelope) -> bool:
        return self.in_scope

    def is_channel_approved(self, channel: str) -> bool:
        return self.channel_ok

    def playbook_status(self, operation: str, scope: EnvelopeScope) -> PlaybookStatus | None:
        if not self.playbook:
            return None
        return PlaybookStatus(
            playbook_ref="playbook:p1",
            approved=True,
            enabled=True,
            expires_at=self._clock.now() + timedelta(hours=1),
        )

    def fact_freshness(self, refs: tuple[str, ...]) -> Mapping[str, FreshnessState]:
        state = FreshnessState.CURRENT if self.fresh else FreshnessState.STALE
        return dict.fromkeys(refs, state)


class PolicyTap:
    """Passes `evaluate` to the real engine. `error` makes it raise instead; `after`
    runs once the engine returned; `replace` swaps the engine's answer."""

    def __init__(self, engine: PolicyEngine) -> None:
        self._engine = engine
        self.calls = 0
        self.after: Callable[[], None] | None = None
        self.error: Exception | None = None
        self.replace: Callable[[PolicyDecision], Any] | None = None

    def evaluate(self, envelope: ActionEnvelope, context: Any) -> Any:
        self.calls += 1
        if self.error is not None:
            raise self.error
        decision = self._engine.evaluate(envelope, context)
        if self.after is not None:
            self.after()
        return decision if self.replace is None else self.replace(decision)


class World:
    def __init__(
        self,
        engine: Engine,
        clock: FixedClock,
        audit: AuditSink,
        principals: PrincipalResolver,
        system_owner: Principal,
        extra_tools: tuple[Tool, ...] = (),
    ) -> None:
        self.engine = engine
        self.clock = clock
        self.audit: Any = audit
        self.principals: Any = principals
        self.owner = system_owner.model_copy(update={"credential_issued_by": "human_idp_admin"})
        self.killswitch = FakeKillSwitch()
        self.secrets = FakeSecrets({WRITE_TOKEN_REF: WRITE_TOKEN, ROW_KEY_REF: ROW_KEY})
        self.redactor = FakeRedactor(SENSITIVE)
        self.l2, self.l3, self.l4 = ScriptedTool(), ScriptedTool(), ScriptedTool()
        self.registry = ToolRegistry([*self._tools(), *extra_tools]).seal()
        ruleset = load_default_ruleset()
        assert not ruleset.deny_all
        catalog = self.registry.catalog()
        self.validator: Any = EnvelopeValidator(
            catalog, clock, timedelta(hours=1), risk_classes=ruleset.risk_classes
        )
        self.policy: Any = PolicyTap(
            PolicyEngine(
                catalog=catalog,
                ruleset=ruleset,
                clock=clock,
                audit=audit,
                principals=principals,
                max_envelope_ttl=timedelta(hours=1),
            )
        )
        self.context = FakeContext(clock)
        self.approvals: Any = ApprovalService(
            engine=engine,
            audit=audit,
            clock=clock,
            principals=principals,
            approval_ttl=timedelta(hours=1),
        )

    def _tools(self) -> list[Tool]:
        refs = (WRITE_TOKEN_REF,)
        return [
            Tool(spec=L2_OP, run=self.l2.run, verify=self.l2.read_back, credential_refs=refs),
            Tool(
                spec=L3_OP,
                run=self.l3.run,
                verify=self.l3.read_back,
                rollback=self.l3.undo,
                credential_refs=refs,
            ),
            Tool(
                spec=L4_OP,
                run=self.l4.run,
                verify=self.l4.read_back,
                rollback=self.l4.undo,
                precondition_names=frozenset({"still_open"}),
                check_precondition=self.l4.check,
                credential_refs=refs,
            ),
        ]

    def parts(self, **overrides: Any) -> dict[str, Any]:
        args: dict[str, Any] = {
            "engine": self.engine,
            "clock": self.clock,
            "audit": self.audit,
            "principals": self.principals,
            "killswitch": self.killswitch,
            "policy": self.policy,
            "context": self.context,
            "approvals": self.approvals,
            "registry": self.registry,
            "secrets": self.secrets,
            "validator": self.validator,
            "tool_rate_limit_per_minute": 5,
            "redactor": self.redactor,
            "row_key_ref": ROW_KEY_REF,
        }
        args.update(overrides)
        return args

    def broker(self, **overrides: Any) -> ExecutionBroker:
        return ExecutionBroker(**self.parts(**overrides))

    def recovery(self, **overrides: Any) -> ExecutionRecovery:
        args: dict[str, Any] = {
            "engine": self.engine,
            "clock": self.clock,
            "audit": self.audit,
            "registry": self.registry,
            "killswitch": self.killswitch,
            "secrets": self.secrets,
            "redactor": self.redactor,
            "row_key_ref": ROW_KEY_REF,
        }
        args.update(overrides)
        return ExecutionRecovery(**args)

    def recover(
        self, started_at: datetime | None = None, **overrides: Any
    ) -> tuple[ExecutionRecord, ...]:
        """Start-up recovery as a process that started `started_at` (default: one second
        after now on the test clock, so every existing row predates it)."""
        started = started_at or self.clock.now() + timedelta(seconds=1)
        return self.recovery(**overrides).recover_in_flight(started)

    def store(self) -> ExecutionStore:
        return ExecutionStore(self.engine, RowSeal(self.secrets, ROW_KEY_REF))

    def secret_requests(self) -> list[str]:
        """Secrets asked for, without the broker's own row key."""
        return [ref for ref in self.secrets.requested if ref != ROW_KEY_REF]

    def execution_id(self, key: str = "idem-1", actor_id: str = "agent_ciso") -> str:
        with self.engine.begin() as conn:
            return str(
                conn.execute(
                    select(execution_run.c.execution_id).where(
                        execution_run.c.idempotency_key == key,
                        execution_run.c.actor_id == actor_id,
                    )
                ).scalar_one()
            )

    def row(self, key: str = "idem-1", actor_id: str = "agent_ciso") -> ExecutionRecord:
        """The stored record for a key, read the way the broker reads it."""
        found = self.broker().get(self.execution_id(key, actor_id))
        assert found is not None
        return found

    def raw(self, key: str = "idem-1") -> Any:
        """The table row as it is, with no integrity check."""
        with self.engine.begin() as conn:
            return conn.execute(
                execution_run.select().where(execution_run.c.idempotency_key == key)
            ).one()

    def tamper(self, key: str = "idem-1", **columns: Any) -> None:
        """What a database writer without the row key can do: a plain UPDATE."""
        with self.engine.begin() as conn:
            conn.execute(
                update(execution_run)
                .where(execution_run.c.idempotency_key == key)
                .values(**columns)
            )

    def force(self, key: str = "idem-1", **values: Any) -> None:
        """Change a row the way a component holding the row key would (another run, a
        recovery pass): through the store, so the row stays readable."""
        store = self.store()
        seen = store.find(self.execution_id(key))
        assert seen is not None
        assert store.change(seen, self.clock.now(), **values) is not None

    def envelope(
        self, op: OperationSpec = L2_OP, key: str = "idem-1", **overrides: Any
    ) -> ActionEnvelope:
        fields: dict[str, Any] = {
            "request_id": new_id("req"),
            "idempotency_key": key,
            "requesting_component": "orchestrator",
            "actor_id": "agent_ciso",
            "actor_type": ActorType.AGENT,
            "target_resource": "asset:a1",
            "scope": EnvelopeScope(
                resource="system:s1",
                tenant="t1",
                environment=Environment.STAGING,
                boundary="internal",
            ),
            "operation": op.name,
            "arguments": {"note": "hello"},
            "purpose": "test",
            "supporting_evidence": ("evidence:e1",),
            "risk_class": "low",
            "authority_level": op.authority_level,
            "preconditions": (STILL_OPEN,) if op is L4_OP else (),
            "expiry": self.clock.now() + timedelta(minutes=5),
            "rollback_plan": RollbackPlan(description="undo it"),
            "verification_plan": VerificationPlan(method="read", description="read it back"),
        }
        fields.update(overrides)
        return ActionEnvelope(**fields)

    def approve(self, envelope: ActionEnvelope, **overrides: Any) -> str:
        """Request and grant an approval for `envelope`, the way the API would."""
        args: dict[str, Any] = {
            "subject_kind": APPROVAL_SUBJECT_KIND,
            "subject_hash": envelope.envelope_hash(),
            "binding": approval_binding(envelope),
            "requested_by": envelope.actor_id,
            "requested_by_type": envelope.actor_type,
            "required_roles": (Role.SYSTEM_OWNER, Role.EXECUTIVE_RISK_OWNER),
            "target": approval_target(envelope),
        }
        args.update(overrides)
        made = self.approvals.request(**args)
        self.approvals.approve(made.approval_id, self.owner)
        return str(made.approval_id)

    def tool_calls(self) -> int:
        return len(self.l2.calls) + len(self.l3.calls) + len(self.l4.calls)
