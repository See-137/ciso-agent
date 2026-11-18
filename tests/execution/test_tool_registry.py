"""Tool allowlist: what may be registered, how a call is built, what a tool receives.

Blueprint 9.5 (allowlisted, typed tools; no arbitrary shell), 9.4 (rollback and
verification required for L3), FR-026.
"""

from __future__ import annotations

import os
import subprocess
from typing import Any

import pytest
from pydantic import ConfigDict
from tests.execution.conftest import (
    DraftArgs,
    EnvelopeBuilder,
    NoteArgs,
    Recorder,
    make_tool,
    spec,
)
from tests.fakes.core import FakeSecrets

from ciso.common.enums import AuthorityLevel
from ciso.common.errors import (
    AuthorizationError,
    FailClosed,
    NotFound,
    PreconditionFailed,
    ValidationFailed,
)
from ciso.common.schemas import Model
from ciso.execution import (
    InvalidToolCall,
    RollbackUnavailable,
    Tool,
    ToolCall,
    ToolErrorCode,
    ToolFault,
    ToolOutcome,
    ToolRegistry,
    ToolRejected,
    ToolResult,
    UnknownTool,
    Verification,
)
from ciso.policy import OperationCatalog, OperationSpec, Precondition

pytestmark = pytest.mark.broker

L3 = AuthorityLevel.L3_EXECUTE
L2 = AuthorityLevel.L2_COORDINATE


def rejected(registry: ToolRegistry, tool: Tool) -> ToolErrorCode:
    with pytest.raises(ToolRejected) as caught:
        registry.register(tool)
    assert tool.spec.name not in registry or caught.value.code is ToolErrorCode.DUPLICATE_NAME
    return caught.value.code


def sealed(*tools: Tool) -> ToolRegistry:
    return ToolRegistry(tools).seal()


class TestRegistration:
    def test_a_read_tool_registers_and_is_listed(self, recorder: Recorder) -> None:
        registry = ToolRegistry()
        registry.register(make_tool(recorder))
        assert registry.names() == ("note.record",)
        assert "note.record" in registry
        assert len(registry) == 1

    def test_duplicate_name_is_rejected(self, recorder: Recorder) -> None:
        registry = ToolRegistry([make_tool(recorder)])
        assert rejected(registry, make_tool(recorder)) is ToolErrorCode.DUPLICATE_NAME
        assert len(registry) == 1

    @pytest.mark.parametrize("name", ["note", "Note.record", "note.record\n", "note..x", "a.b c"])
    def test_name_must_be_dotted(self, recorder: Recorder, name: str) -> None:
        # model_construct walks around OperationSpec's own check, so this reaches the
        # registry's check. "note.record\n" is accepted by OperationSpec today.
        operation = OperationSpec.model_construct(
            name=name,
            authority_level=AuthorityLevel.L1_INVESTIGATE,
            args_model=NoteArgs,
            writes=False,
            channel_argument=None,
            protected=False,
            agent_requestable=False,
            description="",
        )
        tool = Tool.model_construct(
            spec=operation,
            run=recorder.run,
            verify=None,
            rollback=None,
            precondition_names=frozenset(),
            check_precondition=None,
            credential_refs=(),
        )
        assert rejected(ToolRegistry(), tool) is ToolErrorCode.BAD_NAME

    @pytest.mark.parametrize(
        "name", ["policy.update_rule", "killswitch.release", "audit_log.purge", "finding.suppress"]
    )
    def test_control_plane_names_are_rejected(self, recorder: Recorder, name: str) -> None:
        operation = spec(name, AuthorityLevel.L4_HIGH_IMPACT, writes=True, protected=True)
        tool = make_tool(recorder, operation, rollback=recorder.rollback)
        assert rejected(ToolRegistry(), tool) is ToolErrorCode.PROTECTED_NAME

    def test_an_l3_tool_needs_rollback_and_verification(self, recorder: Recorder) -> None:
        operation = spec("host.isolate", L3, writes=True)
        base = {"spec": operation, "run": recorder.run}
        no_rollback = Tool(**base, verify=recorder.verify)
        no_verify = Tool(**base, rollback=recorder.rollback)
        code = ToolErrorCode.ROLLBACK_AND_VERIFICATION_REQUIRED
        assert rejected(ToolRegistry(), no_rollback) is code
        assert rejected(ToolRegistry(), no_verify) is code
        registry = ToolRegistry()
        registry.register(Tool(**base, verify=recorder.verify, rollback=recorder.rollback))
        assert "host.isolate" in registry

    def test_a_non_writing_l3_tool_still_needs_both(self, recorder: Recorder) -> None:
        tool = Tool(spec=spec("host.probe", L3), run=recorder.run)
        code = ToolErrorCode.ROLLBACK_AND_VERIFICATION_REQUIRED
        assert rejected(ToolRegistry(), tool) is code

    def test_a_writing_tool_needs_verification(self, recorder: Recorder) -> None:
        operation = spec("draft.create", L2, DraftArgs, writes=True, channel_argument="channel")
        tool = Tool(spec=operation, run=recorder.run)
        assert rejected(ToolRegistry(), tool) is ToolErrorCode.VERIFICATION_REQUIRED
        registry = ToolRegistry()
        registry.register(Tool(spec=operation, run=recorder.run, verify=recorder.verify))
        assert registry.names() == ("draft.create",)

    def test_rollback_is_optional_below_l3(self, recorder: Recorder) -> None:
        operation = spec("draft.create", L2, DraftArgs, writes=True)
        registry = ToolRegistry([make_tool(recorder, operation)])
        assert registry.names() == ("draft.create",)

    def test_an_open_argument_schema_is_rejected(self, recorder: Recorder) -> None:
        class Loose(Model):
            model_config = ConfigDict(extra="allow")
            note: str

        class Thawed(Model):
            model_config = ConfigDict(frozen=False)
            note: str

        for model in (Loose, Thawed):
            operation = OperationSpec.model_construct(
                name="note.record",
                authority_level=AuthorityLevel.L1_INVESTIGATE,
                args_model=model,
                writes=False,
                channel_argument=None,
                protected=False,
                agent_requestable=False,
                description="",
            )
            tool = Tool(spec=operation, run=recorder.run)
            assert rejected(ToolRegistry(), tool) is ToolErrorCode.OPEN_ARGUMENT_SCHEMA

    def test_a_free_form_argument_field_is_rejected(self, recorder: Recorder) -> None:
        """No generic "run anything" tool: a field typed Any or object is an open door."""

        class Anything(Model):
            command: Any

        class Buried(Model):
            options: dict[str, Any]

        class Inner(Model):
            payload: object

        class Outer(Model):
            inner: Inner

        # The policy catalog runs the same closed-schema check, so such a model is now
        # refused when its operation is declared, before a tool can be built around it.
        for model in (Anything, Buried, Outer):
            with pytest.raises(ValueError, match="argument schema is not closed"):
                spec(args=model)

    def test_precondition_names_need_a_checker_and_a_plain_name(self, recorder: Recorder) -> None:
        names_only = make_tool(recorder, precondition_names=frozenset({"still_open"}))
        checker_only = make_tool(recorder, check_precondition=recorder.check)
        bad_name = make_tool(
            recorder, precondition_names=frozenset({"x; y"}), check_precondition=recorder.check
        )
        for tool in (names_only, checker_only, bad_name):
            assert rejected(ToolRegistry(), tool) is ToolErrorCode.BAD_PRECONDITIONS

    @pytest.mark.parametrize("ref", ["hunter2", "secret://Bad-Name", "https://vault/x", ""])
    def test_credentials_are_declared_as_secret_references(
        self, recorder: Recorder, ref: str
    ) -> None:
        tool = make_tool(recorder, credential_refs=(ref,))
        assert rejected(ToolRegistry(), tool) is ToolErrorCode.BAD_CREDENTIAL_REF
        registry = ToolRegistry([make_tool(recorder, credential_refs=("secret://outbox_key",))])
        assert len(registry) == 1


class TestSealing:
    def test_nothing_registers_after_seal(self, recorder: Recorder) -> None:
        registry = sealed(make_tool(recorder))
        late = make_tool(recorder, spec("note.other"))
        assert rejected(registry, late) is ToolErrorCode.REGISTRY_SEALED
        assert registry.names() == ("note.record",)
        assert registry.sealed is True

    def test_an_unsealed_registry_hands_out_no_tools(self, recorder: Recorder) -> None:
        registry = ToolRegistry([make_tool(recorder)])
        assert registry.sealed is False
        with pytest.raises(FailClosed):
            registry.get("note.record")
        assert registry.seal().get("note.record").name == "note.record"

    def test_unregistered_tool_is_a_narrow_error(self, recorder: Recorder) -> None:
        registry = sealed(make_tool(recorder))
        with pytest.raises(UnknownTool) as caught:
            registry.get("shell.run")
        assert isinstance(caught.value, NotFound)
        assert "shell.run" not in registry


class TestCatalog:
    def test_registry_produces_the_catalog_specs(self, recorder: Recorder) -> None:
        operation = spec("draft.create", L2, DraftArgs, writes=True, channel_argument="channel")
        registry = sealed(make_tool(recorder), make_tool(recorder, operation))
        assert [s.name for s in registry.operation_specs()] == ["draft.create", "note.record"]
        catalog = registry.catalog()
        assert catalog.get("draft.create") == operation
        registry.require_catalog_match(catalog)

    def test_a_tool_missing_from_the_catalog_is_a_mismatch(self, recorder: Recorder) -> None:
        registry = sealed(make_tool(recorder))
        with pytest.raises(ToolRejected) as caught:
            registry.require_catalog_match(OperationCatalog([spec("note.other")]))
        assert caught.value.code is ToolErrorCode.CATALOG_MISMATCH

    def test_a_tool_whose_spec_differs_from_the_catalog_is_a_mismatch(
        self, recorder: Recorder
    ) -> None:
        registry = sealed(make_tool(recorder))
        stronger = spec("note.record", L2)
        with pytest.raises(ToolRejected) as caught:
            registry.require_catalog_match(OperationCatalog([stronger]))
        assert caught.value.code is ToolErrorCode.CATALOG_MISMATCH


METACHARACTERS = "x; rm -rf / | cat & $(echo hi) `id` > out.txt < in\n$HOME %PATH% && || \\ \"'"


class TestCalls:
    def test_shell_metacharacters_reach_the_tool_as_inert_text(
        self,
        recorder: Recorder,
        checked: EnvelopeBuilder,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Any,
    ) -> None:
        spawned: list[Any] = []

        def refuse(*args: Any, **kwargs: Any) -> None:
            spawned.append(args)
            raise AssertionError("a process was started")

        monkeypatch.setattr(subprocess, "Popen", refuse)
        monkeypatch.setattr(os, "system", refuse)
        monkeypatch.chdir(tmp_path)
        operation = spec()
        registry = sealed(make_tool(recorder, operation))
        call = registry.call_for(checked(operation, {"note": METACHARACTERS}), FakeSecrets())
        result = registry.invoke(call)
        assert result.outcome is ToolOutcome.SUCCEEDED
        assert len(recorder.calls) == 1
        received = recorder.calls[0].arguments
        assert type(received) is NoteArgs
        assert received.note == METACHARACTERS
        assert spawned == []
        assert list(tmp_path.iterdir()) == []

    def test_extra_arguments_are_rejected_before_the_tool_runs(
        self, recorder: Recorder, checked: EnvelopeBuilder
    ) -> None:
        operation = spec()
        registry = sealed(make_tool(recorder, operation))
        with pytest.raises(InvalidToolCall) as caught:
            registry.call_for(checked(operation, {"note": "n", "command": "id"}), FakeSecrets())
        assert caught.value.code is ToolErrorCode.INVALID_ARGUMENTS
        assert isinstance(caught.value, ValidationFailed)
        assert recorder.calls == []

    def test_wrongly_typed_arguments_are_rejected(
        self, recorder: Recorder, checked: EnvelopeBuilder
    ) -> None:
        operation = spec()
        registry = sealed(make_tool(recorder, operation))
        with pytest.raises(InvalidToolCall) as caught:
            registry.call_for(checked(operation, {"note": 7}), FakeSecrets())
        assert caught.value.code is ToolErrorCode.INVALID_ARGUMENTS

    def test_arguments_are_not_coerced_between_types(
        self, recorder: Recorder, checked: EnvelopeBuilder
    ) -> None:
        class CountArgs(Model):
            count: int
            urgent: bool

        operation = spec(args=CountArgs)
        registry = sealed(make_tool(recorder, operation))
        good = registry.bind_arguments("note.record", {"count": 5, "urgent": True})
        assert good == CountArgs(count=5, urgent=True)
        for raw in ({"count": "5", "urgent": True}, {"count": 5, "urgent": 1}):
            with pytest.raises(InvalidToolCall) as caught:
                registry.call_for(checked(operation, raw), FakeSecrets())
            assert caught.value.code is ToolErrorCode.INVALID_ARGUMENTS

    def test_call_carries_the_envelope_fields_and_channel(
        self, recorder: Recorder, checked: EnvelopeBuilder
    ) -> None:
        operation = spec("draft.create", L2, DraftArgs, writes=True, channel_argument="channel")
        registry = sealed(make_tool(recorder, operation))
        envelope = checked(operation, {"channel": "sec_ops", "title": "t"})
        call = registry.call_for(envelope, FakeSecrets())
        assert call.operation == "draft.create"
        assert call.channel == "sec_ops"
        assert call.idempotency_key == "idem-1"
        assert call.request_id == envelope.envelope.request_id
        assert call.actor_id == "agent_ciso"
        assert call.target_resource == "asset:a1"
        assert call.scope == envelope.envelope.scope
        assert call.envelope_hash == envelope.envelope.envelope_hash()
        assert call.arguments == DraftArgs(channel="sec_ops", title="t")

    def test_a_checked_envelope_with_a_different_spec_is_refused(
        self, recorder: Recorder, checked: EnvelopeBuilder
    ) -> None:
        registry = sealed(make_tool(recorder))
        other = spec("note.record", L2)
        with pytest.raises(InvalidToolCall) as caught:
            registry.call_for(checked(other, {"note": "n"}), FakeSecrets())
        assert caught.value.code is ToolErrorCode.SPEC_MISMATCH

    def test_call_for_an_unregistered_operation_is_refused(
        self, recorder: Recorder, checked: EnvelopeBuilder
    ) -> None:
        registry = sealed(make_tool(recorder))
        with pytest.raises(UnknownTool):
            registry.call_for(checked(spec("shell.run"), {"note": "id"}), FakeSecrets())
        assert recorder.calls == []

    def test_invoke_refuses_arguments_of_another_model(
        self, recorder: Recorder, checked: EnvelopeBuilder
    ) -> None:
        operation = spec()
        registry = sealed(make_tool(recorder, operation))
        call = registry.call_for(checked(operation, {"note": "n"}), FakeSecrets())
        forged = call.model_copy(update={"arguments": DraftArgs(channel="c", title="t")})
        with pytest.raises(InvalidToolCall) as caught:
            registry.invoke(forged)
        assert caught.value.code is ToolErrorCode.ARGUMENT_TYPE
        assert recorder.calls == []

    def test_invoke_revalidates_arguments_built_without_validation(
        self, recorder: Recorder, checked: EnvelopeBuilder
    ) -> None:
        operation = spec()
        registry = sealed(make_tool(recorder, operation))
        call = registry.call_for(checked(operation, {"note": "n"}), FakeSecrets())
        forged = call.model_copy(update={"arguments": NoteArgs.model_construct(note=42)})
        with pytest.raises(InvalidToolCall) as caught:
            registry.invoke(forged)
        assert caught.value.code is ToolErrorCode.INVALID_ARGUMENTS
        assert recorder.calls == []

    def test_a_tool_that_returns_something_else_is_a_fault(
        self, recorder: Recorder, checked: EnvelopeBuilder
    ) -> None:
        operation = spec()
        tool = Tool(spec=operation, run=lambda call: {"ok": True})  # type: ignore[arg-type,return-value]
        registry = sealed(tool)
        call = registry.call_for(checked(operation, {"note": "n"}), FakeSecrets())
        with pytest.raises(ToolFault):
            registry.invoke(call)

    def test_a_tool_error_is_not_swallowed(
        self, recorder: Recorder, checked: EnvelopeBuilder
    ) -> None:
        def boom(call: ToolCall) -> ToolResult:
            raise RuntimeError("target went away")

        operation = spec()
        registry = sealed(Tool(spec=operation, run=boom))
        call = registry.call_for(checked(operation, {"note": "n"}), FakeSecrets())
        with pytest.raises(RuntimeError, match="target went away"):
            registry.invoke(call)


class TestCredentials:
    def test_a_tool_reaches_only_the_references_it_declared(self, checked: EnvelopeBuilder) -> None:
        seen: list[str] = []

        def run(call: ToolCall) -> ToolResult:
            seen.append(call.credentials.get("secret://outbox_key").reveal())
            with pytest.raises(AuthorizationError):
                call.credentials.get("secret://db_password")
            return ToolResult(outcome=ToolOutcome.SUCCEEDED)

        operation = spec()
        tool = Tool(spec=operation, run=run, credential_refs=("secret://outbox_key",))
        vault = FakeSecrets({"secret://outbox_key": "k1", "secret://db_password": "p1"})
        registry = sealed(tool)
        registry.invoke(registry.call_for(checked(operation, {"note": "n"}), vault))
        assert seen == ["k1"]
        assert vault.requested == ["secret://outbox_key"]


class TestVerificationAndRollback:
    def _setup(self, recorder: Recorder, checked: EnvelopeBuilder) -> tuple[ToolRegistry, ToolCall]:
        operation = spec("host.isolate", L3, writes=True)
        tool = make_tool(recorder, operation, rollback=recorder.rollback)
        registry = sealed(tool)
        envelope = checked(operation, {"note": "n"})
        return registry, registry.call_for(envelope, FakeSecrets())

    def test_verification_reads_through_the_tools_verifier(
        self, recorder: Recorder, checked: EnvelopeBuilder
    ) -> None:
        registry, call = self._setup(recorder, checked)
        assert registry.verify(call).matches is True
        recorder.matches = False
        outcome = registry.verify(call)
        assert outcome.matches is False
        assert outcome.observed == ("draft:d1",)
        assert len(recorder.verified) == 2
        assert recorder.calls == []

    def test_a_tool_without_a_verifier_cannot_be_verified(
        self, recorder: Recorder, checked: EnvelopeBuilder
    ) -> None:
        operation = spec()
        registry = sealed(make_tool(recorder, operation))
        call = registry.call_for(checked(operation, {"note": "n"}), FakeSecrets())
        with pytest.raises(FailClosed):
            registry.verify(call)

    def test_a_verifier_must_return_a_real_verification(
        self, recorder: Recorder, checked: EnvelopeBuilder
    ) -> None:
        operation = spec("draft.create", L2, writes=True)
        tool = Tool(spec=operation, run=recorder.run, verify=lambda call: True)  # type: ignore[arg-type,return-value]
        registry = sealed(tool)
        call = registry.call_for(checked(operation, {"note": "n"}), FakeSecrets())
        with pytest.raises(ToolFault):
            registry.verify(call)

    def test_a_truthy_non_boolean_is_not_a_match(self) -> None:
        with pytest.raises(ValueError, match="matches"):
            Verification(matches="yes")  # type: ignore[arg-type]
        with pytest.raises(ValueError, match="matches"):
            Verification(matches=1)  # type: ignore[arg-type]

    def test_rollback_runs_the_tools_rollback(
        self, recorder: Recorder, checked: EnvelopeBuilder
    ) -> None:
        registry, call = self._setup(recorder, checked)
        result = registry.invoke(call)
        undone = registry.rollback(call, result)
        assert undone.detail == "removed"
        assert len(recorder.rolled_back) == 1
        assert recorder.rolled_back[0][1] == result
        registry.rollback(call, None)
        assert recorder.rolled_back[1][1] is None

    def test_rollback_without_one_is_a_narrow_error(
        self, recorder: Recorder, checked: EnvelopeBuilder
    ) -> None:
        operation = spec()
        registry = sealed(make_tool(recorder, operation))
        call = registry.call_for(checked(operation, {"note": "n"}), FakeSecrets())
        with pytest.raises(RollbackUnavailable):
            registry.rollback(call, None)

    def test_a_rollback_must_return_a_real_result(
        self, recorder: Recorder, checked: EnvelopeBuilder
    ) -> None:
        def junk(call: ToolCall, result: ToolResult | None) -> ToolResult:
            return "undone"  # type: ignore[return-value]

        operation = spec()
        registry = sealed(Tool(spec=operation, run=recorder.run, rollback=junk))
        call = registry.call_for(checked(operation, {"note": "n"}), FakeSecrets())
        with pytest.raises(ToolFault):
            registry.rollback(call, None)

    def test_result_references_must_be_entity_refs(self) -> None:
        with pytest.raises(ValueError, match="entity ref"):
            ToolResult(outcome=ToolOutcome.SUCCEEDED, references=("../../etc/passwd",))


class TestPreconditions:
    def _setup(self, recorder: Recorder, checked: EnvelopeBuilder) -> tuple[ToolRegistry, ToolCall]:
        operation = spec()
        tool = make_tool(
            recorder,
            operation,
            precondition_names=frozenset({"still_open"}),
            check_precondition=recorder.check,
        )
        registry = sealed(tool)
        return registry, registry.call_for(checked(operation, {"note": "n"}), FakeSecrets())

    @staticmethod
    def _pre(name: str) -> Precondition:
        return Precondition(name=name, ref="finding:f1", expectation="open")

    def test_a_holding_precondition_passes(
        self, recorder: Recorder, checked: EnvelopeBuilder
    ) -> None:
        registry, call = self._setup(recorder, checked)
        registry.require_preconditions(call, (self._pre("still_open"),))
        assert recorder.checked == ["still_open"]

    @pytest.mark.parametrize("answer", [False, None, 1, "yes"])
    def test_anything_but_true_fails(
        self, recorder: Recorder, checked: EnvelopeBuilder, answer: Any
    ) -> None:
        registry, call = self._setup(recorder, checked)
        recorder.precondition_holds = answer
        with pytest.raises(PreconditionFailed, match="still_open"):
            registry.require_preconditions(call, (self._pre("still_open"),))

    def test_a_precondition_the_tool_cannot_check_fails(
        self, recorder: Recorder, checked: EnvelopeBuilder
    ) -> None:
        registry, call = self._setup(recorder, checked)
        with pytest.raises(PreconditionFailed, match="owner_confirmed"):
            registry.require_preconditions(call, (self._pre("owner_confirmed"),))
        assert recorder.checked == []

    def test_a_checker_that_raises_fails_closed(
        self, recorder: Recorder, checked: EnvelopeBuilder
    ) -> None:
        def broken(precondition: Precondition, call: ToolCall) -> bool:
            raise RuntimeError("source unreachable")

        operation = spec()
        tool = make_tool(
            recorder,
            operation,
            precondition_names=frozenset({"still_open"}),
            check_precondition=broken,
        )
        registry = sealed(tool)
        call = registry.call_for(checked(operation, {"note": "n"}), FakeSecrets())
        with pytest.raises(FailClosed):
            registry.require_preconditions(call, (self._pre("still_open"),))
