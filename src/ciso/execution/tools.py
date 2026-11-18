"""The tool allowlist (blueprint 5.1 #12, 9.4, 9.5; FR-026).

A tool is the only way the platform changes or queries something on behalf of an action
envelope. Each tool is bound to one registered operation (`OperationSpec`, the same
object the policy catalog holds), takes a closed argument model
(`ciso.common.closed_schema`), and comes with the means to check its own result. There is no
tool that runs a command line, and no way to add a tool once the registry is sealed.

The registry makes no policy decision. It does not look at the kill switch, approvals or
the policy engine: the broker does that before it calls `invoke`.

Arguments are data. They are validated into the tool's model and handed over as typed
fields; nothing here interprets a string, starts a process or builds a command.

What the registry trusts: nothing a caller holds. It keeps its own validated copy of
every tool, hands out copies, runs only calls it issued itself through `call_for` (each
carries a keyed seal over its fields), and validates again whatever a tool returns.

Limit: all of this is in-process Python. Code in the same process can reach the
registry's private attributes, its sealing key and closure cells by reflection. The
checks stop mistakes and ordinary callers; process isolation (ADR-0010) is the boundary
against hostile code.
"""

from __future__ import annotations

import hmac
import json
import secrets
from collections.abc import Iterable, Mapping, Sequence
from types import MappingProxyType
from typing import Any

from pydantic import BaseModel, ValidationError

from ciso.common.closed_schema import non_finite_path
from ciso.common.errors import FailClosed, PreconditionFailed
from ciso.common.schemas import Model, canonical_json, thaw
from ciso.execution.credentials_scope import CredentialAccessor, ScopedCredentials
from ciso.execution.tool_models import (
    InvalidToolCall,
    RollbackUnavailable,
    Tool,
    ToolCall,
    ToolErrorCode,
    ToolFault,
    ToolOutcome,
    ToolRejected,
    ToolResult,
    UnknownTool,
    Verification,
    rebuilt,
    spec_problem,
    tool_problem,
)
from ciso.policy.catalog import OperationCatalog, OperationSpec
from ciso.policy.envelope import CheckedEnvelope, Precondition

__all__ = [
    "CredentialAccessor",
    "InvalidToolCall",
    "RollbackUnavailable",
    "ScopedCredentials",
    "Tool",
    "ToolCall",
    "ToolErrorCode",
    "ToolFault",
    "ToolOutcome",
    "ToolRegistry",
    "ToolRejected",
    "ToolResult",
    "UnknownTool",
    "Verification",
]

#: The `ToolCall` fields the seal covers: everything but the seal and the credentials.
_SEALED_FIELDS = tuple(
    name for name in ToolCall.model_fields if name not in ("seal", "credentials")
)


def _copy(tool: Tool) -> Tool:
    """A `Tool` that shares no mutable state with `tool`."""
    return tool.model_copy(update={"spec": tool.spec.model_copy()})


def _validated[T: (ToolResult, Verification)](kind: type[T], value: object, source: str) -> T:
    """`value` validated again as exactly `kind`, as a new object. A tool can build its
    reply without validation, so an `isinstance` test alone proves nothing."""
    if type(value) is not kind:
        raise ToolFault(f"{source} did not return a {kind.__name__}")
    try:
        fields = {name: getattr(value, name) for name in kind.model_fields}
        return kind.model_validate(fields, strict=True)
    except (ValueError, AttributeError) as exc:
        raise ToolFault(f"{source} returned an invalid {kind.__name__}") from exc


class ToolRegistry:
    """The allowlist. Register, then `seal()`; only a sealed registry hands out tools."""

    def __init__(self, tools: Iterable[Tool] = ()) -> None:
        self._tools: Mapping[str, Tool] = {}
        self._sealed = False
        self._key = secrets.token_bytes(32)
        for tool in tools:
            self.register(tool)

    def register(self, tool: Tool) -> None:
        """Add a tool or raise `ToolRejected` with a `ToolErrorCode`.

        `tool` must be exactly a `Tool` holding exactly an `OperationSpec`. It is
        validated again and the registry stores that new copy, so nothing the caller
        still holds is what later runs."""
        if self._sealed:
            raise ToolRejected(ToolErrorCode.REGISTRY_SEALED, "the tool registry is sealed")
        if type(tool) is not Tool or type(getattr(tool, "spec", None)) is not OperationSpec:
            raise ToolRejected(ToolErrorCode.NOT_A_TOOL, "only a Tool with an OperationSpec")
        problem = spec_problem(tool.spec)
        if problem is not None:
            raise ToolRejected(*problem)
        try:
            own = rebuilt(tool)
        except (ValueError, AttributeError) as exc:
            raise ToolRejected(
                ToolErrorCode.INVALID_TOOL, "the tool does not hold valid fields"
            ) from exc
        problem = tool_problem(own)
        if problem is not None:
            raise ToolRejected(*problem)
        if own.name in self._tools:
            raise ToolRejected(ToolErrorCode.DUPLICATE_NAME, f"duplicate tool: {own.name!r}")
        self._tools = {**self._tools, own.name: own}

    def seal(self) -> ToolRegistry:
        """Close the registry for good. Returns itself."""
        self._tools = MappingProxyType(dict(self._tools))
        self._sealed = True
        return self

    @property
    def sealed(self) -> bool:
        return self._sealed

    def names(self) -> tuple[str, ...]:
        return tuple(sorted(self._tools))

    def __contains__(self, name: object) -> bool:
        return name in self._tools

    def __len__(self) -> int:
        return len(self._tools)

    def operation_specs(self) -> tuple[OperationSpec, ...]:
        """Copies of the specs to put in the policy catalog, sorted by name."""
        return tuple(self._tools[name].spec.model_copy() for name in self.names())

    def catalog(self) -> OperationCatalog:
        """A catalog holding exactly this registry's operations."""
        return OperationCatalog(self.operation_specs())

    def require_catalog_match(self, catalog: OperationCatalog) -> None:
        """Raise unless every tool is in `catalog` with an identical spec. The catalog
        may hold more operations than there are tools."""
        for name in self.names():
            if catalog.get(name) != self._tools[name].spec:
                raise ToolRejected(
                    ToolErrorCode.CATALOG_MISMATCH,
                    f"tool {name!r} is missing from the catalog or differs from it",
                )

    def get(self, name: str) -> Tool:
        """A copy of the tool for an operation: changing it changes nothing here.
        `UnknownTool` if absent, `FailClosed` if the registry is not sealed."""
        return _copy(self._stored(name))

    def _stored(self, name: str) -> Tool:
        if not self._sealed:
            raise FailClosed("the tool registry is not sealed; no tool may be used yet")
        tool = self._tools.get(name)
        if tool is None:
            raise UnknownTool(f"no tool is registered for {name!r}")
        return tool

    def bind_arguments(self, name: str, arguments: Mapping[str, Any] | Model) -> Model:
        """Validate raw arguments into the tool's model. Strict types, no extra fields,
        no NaN or infinity."""
        model = self._stored(name).spec.args_model
        try:
            if isinstance(arguments, BaseModel):
                # JSON has no NaN or infinity: dumping would turn one into `null`, which
                # an optional field would then accept as "not given".
                where = non_finite_path(arguments)
                raw = arguments.model_dump_json(warnings=False)
            else:
                where = None
                raw = json.dumps(thaw(arguments))
            bound = model.model_validate_json(raw, strict=True)
        except ValidationError as exc:
            fields = sorted({".".join(map(str, err["loc"])) for err in exc.errors()})
            raise InvalidToolCall(
                ToolErrorCode.INVALID_ARGUMENTS, f"arguments fail the schema at: {fields}"
            ) from exc
        except (TypeError, ValueError) as exc:
            raise InvalidToolCall(
                ToolErrorCode.INVALID_ARGUMENTS, "arguments cannot be encoded as JSON"
            ) from exc
        where = where or non_finite_path(bound)
        if where is not None:
            raise InvalidToolCall(
                ToolErrorCode.NON_FINITE_NUMBER, f"{where} is not a finite number"
            )
        return bound

    def call_for(self, checked: CheckedEnvelope, credentials: CredentialAccessor) -> ToolCall:
        """Issue the call for a validated envelope. The arguments are validated again
        here from the envelope itself, so the tool never depends on the caller's copy.
        This is the only way to obtain a call that `invoke`, `verify`, `rollback` and
        `require_preconditions` accept."""
        envelope = checked.envelope
        tool = self._stored(envelope.operation)
        if checked.spec != tool.spec:
            raise InvalidToolCall(
                ToolErrorCode.SPEC_MISMATCH,
                f"the envelope was checked against a different spec for {tool.name!r}",
            )
        arguments = self.bind_arguments(tool.name, envelope.arguments)
        channel = tool.spec.channel_argument
        call = ToolCall(
            operation=tool.name,
            request_id=envelope.request_id,
            idempotency_key=envelope.idempotency_key,
            actor_id=envelope.actor_id,
            target_resource=envelope.target_resource,
            scope=envelope.scope,
            envelope_hash=envelope.envelope_hash(),
            arguments=arguments,
            channel=None if channel is None else str(getattr(arguments, channel)),
            credentials=credentials,
        )
        return call.model_copy(update={"seal": self._seal(call)})

    def _seal(self, call: ToolCall) -> str:
        """Keyed hash over the identifying fields of a call. The key never leaves this
        registry, so only a call it issued carries a seal it can reproduce."""
        body = {name: getattr(call, name) for name in _SEALED_FIELDS}
        body["scope"] = call.scope.model_dump(mode="json")
        body["arguments"] = call.arguments.model_dump(mode="json")
        return hmac.new(self._key, canonical_json(body).encode("utf-8"), "sha256").hexdigest()

    def _issued(self, call: ToolCall) -> bool:
        """True only when the call's seal is this registry's seal for its fields. A call
        whose fields cannot even be read as a call's fields was not issued here."""
        try:
            return hmac.compare_digest(call.seal.encode("utf-8"), self._seal(call).encode("utf-8"))
        except Exception:
            return False

    def _prepared(self, call: ToolCall) -> tuple[Tool, ToolCall]:
        """The stored tool for a call this registry issued, and the call as the tool
        gets it: arguments validated again, credentials narrowed to what it declared."""
        if type(call) is not ToolCall:
            raise InvalidToolCall(ToolErrorCode.NOT_ISSUED, "not a call this registry issued")
        tool = self._stored(call.operation)
        if type(call.arguments) is not tool.spec.args_model:
            raise InvalidToolCall(
                ToolErrorCode.ARGUMENT_TYPE, f"arguments are not {tool.spec.args_model.__name__}"
            )
        arguments = self.bind_arguments(tool.name, call.arguments)
        if not self._issued(call):
            raise InvalidToolCall(ToolErrorCode.NOT_ISSUED, "not a call this registry issued")
        scoped = ScopedCredentials(call.credentials, tool.credential_refs)
        return tool, call.model_copy(update={"arguments": arguments, "credentials": scoped})

    def invoke(self, call: ToolCall) -> ToolResult:
        """Run the tool. An exception from the tool is passed on unchanged: the caller
        must then treat the outcome as unknown, because the side effect may have
        happened. `ToolFault` when the tool returns anything but a valid `ToolResult`."""
        tool, prepared = self._prepared(call)
        return _validated(ToolResult, tool.run(prepared), f"tool {tool.name!r}")

    def verify(self, call: ToolCall) -> Verification:
        """Read the target independently of the tool's reply. `FailClosed` when the tool
        has no verifier: an unverifiable result is never reported as verified. The
        answer is validated again; compare it with `matches is True`."""
        tool, prepared = self._prepared(call)
        if tool.verify is None:
            raise FailClosed(f"tool {tool.name!r} has no verification")
        return _validated(Verification, tool.verify(prepared), f"verifier of {tool.name!r}")

    def rollback(self, call: ToolCall, result: ToolResult | None) -> ToolResult:
        """Undo the call. `result` is what `invoke` returned, or None if it never did."""
        tool, prepared = self._prepared(call)
        if tool.rollback is None:
            raise RollbackUnavailable(f"tool {tool.name!r} has no rollback")
        return _validated(ToolResult, tool.rollback(prepared, result), f"rollback of {tool.name!r}")

    def require_preconditions(self, call: ToolCall, preconditions: Sequence[Precondition]) -> None:
        """Raise `PreconditionFailed` naming every precondition that does not hold now.

        A name the tool cannot check counts as not holding, and so does a name the tool
        requires that the envelope left out. A checker that raises is `FailClosed`
        (blueprint 9.5: checks that are unavailable stop a write).
        """
        tool, prepared = self._prepared(call)
        supplied = {precondition.name for precondition in preconditions}
        failed: list[str] = sorted(tool.required_preconditions - supplied)
        for precondition in preconditions:
            if precondition.name not in tool.precondition_names or tool.check_precondition is None:
                failed.append(precondition.name)
                continue
            try:
                holds = tool.check_precondition(precondition, prepared)
            except Exception as exc:
                raise FailClosed(
                    f"precondition {precondition.name!r} could not be checked"
                ) from exc
            if holds is not True:
                failed.append(precondition.name)
        if failed:
            raise PreconditionFailed(f"preconditions do not hold: {sorted(failed)}")
