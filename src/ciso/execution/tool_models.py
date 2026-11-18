"""The data a tool is described by, is handed and hands back, and the rules a tool must
meet to be registered (blueprint 9.4, 9.5; FR-026). `ciso.execution.tools` holds the
registry that applies them.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from enum import StrEnum
from typing import Any

from pydantic import ConfigDict, field_validator

from ciso.common.closed_schema import schema_problem
from ciso.common.enums import AuthorityLevel
from ciso.common.errors import CisoError, NotFound, ValidationFailed
from ciso.common.ids import EntityRef
from ciso.common.schemas import Model
from ciso.execution.credentials_scope import CredentialAccessor
from ciso.policy.catalog import OperationSpec, is_protected_name
from ciso.policy.envelope import EnvelopeScope, Precondition

_NAME_RE = re.compile(r"[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+")
_PRECONDITION_RE = re.compile(r"[a-z][a-z0-9_]{0,63}")
_SECRET_REF_RE = re.compile(r"secret://[a-z0-9_]+")


class ToolErrorCode(StrEnum):
    """Why a registration or a call was refused. Values are a wire format."""

    BAD_NAME = "bad_name"
    DUPLICATE_NAME = "duplicate_name"
    PROTECTED_NAME = "protected_name"
    OPEN_ARGUMENT_SCHEMA = "open_argument_schema"
    VERIFICATION_REQUIRED = "verification_required"
    ROLLBACK_AND_VERIFICATION_REQUIRED = "rollback_and_verification_required"
    BAD_PRECONDITIONS = "bad_preconditions"
    BAD_CREDENTIAL_REF = "bad_credential_ref"
    NOT_A_TOOL = "not_a_tool"
    INVALID_TOOL = "invalid_tool"
    REGISTRY_SEALED = "registry_sealed"
    CATALOG_MISMATCH = "catalog_mismatch"
    SPEC_MISMATCH = "spec_mismatch"
    INVALID_ARGUMENTS = "invalid_arguments"
    NON_FINITE_NUMBER = "non_finite_number"
    ARGUMENT_TYPE = "argument_type"
    NOT_ISSUED = "not_issued"


class ToolRejected(ValidationFailed):
    """A tool may not be registered, or the registry does not fit the catalog."""

    def __init__(self, code: ToolErrorCode, detail: str) -> None:
        super().__init__(detail)
        self.code = code
        self.detail = detail


class InvalidToolCall(ValidationFailed):
    """A call does not fit the tool it names, or the registry did not issue it. The tool
    was not run."""

    def __init__(self, code: ToolErrorCode, detail: str) -> None:
        super().__init__(detail)
        self.code = code
        self.detail = detail


class UnknownTool(NotFound):
    """No tool is registered under this operation name."""


class ToolFault(CisoError):
    """A tool, verifier or rollback returned something other than a valid object of its
    declared type."""


class RollbackUnavailable(CisoError):
    """The tool has no rollback."""


class ToolOutcome(StrEnum):
    SUCCEEDED = "succeeded"
    FAILED = "failed"


def _entity_refs(value: tuple[str, ...]) -> tuple[str, ...]:
    for item in value:
        EntityRef.parse(item)
    return value


class ToolResult(Model):
    """What a tool says happened. A claim, not a fact: see `Verification`."""

    outcome: ToolOutcome
    references: tuple[str, ...] = ()
    detail: str = ""

    @field_validator("references")
    @classmethod
    def _refs(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        return _entity_refs(value)


class Verification(Model):
    """What an independent read of the target shows (blueprint 9.5). `matches` must be a
    real boolean; `observed` are entity references the verifier read, not ones the tool
    gave. Compare with `matches is True`."""

    model_config = ConfigDict(strict=True)

    matches: bool
    detail: str = ""
    observed: tuple[str, ...] = ()

    @field_validator("observed")
    @classmethod
    def _observed(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        return _entity_refs(value)


class ToolCall(Model):
    """Everything a tool is given. Issued only by `ToolRegistry.call_for`.

    `arguments` is an instance of the tool's own argument model. `channel` is the value
    of the operation's channel argument, or None. `seal` is the registry's keyed hash
    over every other field except `credentials`: the registry runs only a call whose
    seal it can reproduce, so a copy with a changed channel, actor or target is refused.
    `credentials` is the accessor the caller supplied; the tool itself receives a
    `ScopedCredentials` that resolves only the references it declared.
    """

    model_config = ConfigDict(arbitrary_types_allowed=True)

    operation: str
    request_id: str
    idempotency_key: str
    actor_id: str
    target_resource: str
    scope: EnvelopeScope
    envelope_hash: str
    arguments: Model
    channel: str | None = None
    credentials: CredentialAccessor
    seal: str = ""


class Tool(Model):
    """One allowlisted tool.

    `spec` is the operation it carries out: name, authority level, closed argument model,
    whether it writes, and the argument naming the channel it needs, if any.
    `verify` must read the target itself; it is not given the tool's reply.
    `rollback` gets the earlier result, or None when the outcome is unknown.
    `check_precondition` answers for the names in `precondition_names`; only exactly
    `True` counts as "still holds". `required_preconditions` (a subset of those names)
    must each be present in the envelope: leaving one out refuses the call.

    The registry keeps its own validated copy, so changing a `Tool` after registering it,
    or one returned by `ToolRegistry.get`, has no effect on what runs.
    """

    spec: OperationSpec
    run: Callable[[ToolCall], ToolResult]
    verify: Callable[[ToolCall], Verification] | None = None
    rollback: Callable[[ToolCall, ToolResult | None], ToolResult] | None = None
    precondition_names: frozenset[str] = frozenset()
    required_preconditions: frozenset[str] = frozenset()
    check_precondition: Callable[[Precondition, ToolCall], bool] | None = None
    credential_refs: tuple[str, ...] = ()

    @property
    def name(self) -> str:
        return self.spec.name


Problem = tuple[ToolErrorCode, str]


def spec_problem(spec: Any) -> Problem | None:
    """Checks that need nothing but the name, the protected flag and the argument model.
    Safe to run on a spec that was built without validation."""
    name = getattr(spec, "name", None)
    if not isinstance(name, str) or not _NAME_RE.fullmatch(name):
        return ToolErrorCode.BAD_NAME, "a tool name is dotted lower-case, like 'draft.create'"
    if getattr(spec, "protected", True) or is_protected_name(name):
        return ToolErrorCode.PROTECTED_NAME, f"{name!r} is a control-plane operation"
    schema = schema_problem(getattr(spec, "args_model", None))
    if schema is not None:
        return ToolErrorCode.OPEN_ARGUMENT_SCHEMA, schema
    return None


def rebuilt(tool: Tool) -> Tool:
    """A new `Tool` with every validator run again and no container shared with `tool`.
    Raises `ValueError` or `AttributeError` when `tool` does not hold valid fields."""
    spec = OperationSpec.model_validate(
        {name: getattr(tool.spec, name) for name in OperationSpec.model_fields}
    )
    fields = {name: getattr(tool, name) for name in Tool.model_fields}
    return Tool.model_validate({**fields, "spec": spec})


def tool_problem(tool: Tool) -> Problem | None:
    """Checks on a validated tool: what its level, its writes and its declarations need."""
    spec = tool.spec
    name = spec.name
    if spec.authority_level >= AuthorityLevel.L3_EXECUTE and (
        tool.rollback is None or tool.verify is None
    ):
        return (
            ToolErrorCode.ROLLBACK_AND_VERIFICATION_REQUIRED,
            f"{name!r} is level 3 or above and needs both rollback and verification",
        )
    if spec.writes and tool.verify is None:
        return ToolErrorCode.VERIFICATION_REQUIRED, f"{name!r} writes and needs verification"
    if bool(tool.precondition_names) != (tool.check_precondition is not None) or not all(
        _PRECONDITION_RE.fullmatch(item) for item in tool.precondition_names
    ):
        return (
            ToolErrorCode.BAD_PRECONDITIONS,
            "precondition names need a checker, a checker needs names, names are plain words",
        )
    if not tool.required_preconditions <= tool.precondition_names:
        return (
            ToolErrorCode.BAD_PRECONDITIONS,
            "a required precondition must be one the tool can check",
        )
    if not all(_SECRET_REF_RE.fullmatch(ref) for ref in tool.credential_refs):
        return ToolErrorCode.BAD_CREDENTIAL_REF, "credentials are declared as secret://<name>"
    return None
