"""What a write adapter to a real system must provide. No adapter exists in this build.

Blueprint 13.1: `execute_action` is "not available in read connectors. Write-capable
adapters are separate, policy-gated and allowlisted." Blueprint 19.1: keep read
integrations separate from write adapters. Blueprint 9.5: separate read and write
credentials, and a result is verified against the target, never inferred from the reply.

An adapter is driven only by the execution broker, after policy, approval and the kill
switch have been checked there. It decides nothing itself. It imports only
`ciso.common`, so it cannot reach policy, inference or orchestration code.
"""

from __future__ import annotations

import re
from enum import StrEnum
from typing import Protocol

from pydantic import ConfigDict, ValidationError, field_validator

from ciso.common.closed_schema import non_finite_path, schema_problem
from ciso.common.enums import AuthorityLevel
from ciso.common.errors import ValidationFailed
from ciso.common.ids import EntityRef
from ciso.common.protocols import RevealableSecret
from ciso.common.schemas import Model
from ciso.write_adapters.protected import is_protected_name

_OPERATION_RE = re.compile(r"[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+")
_ADAPTER_ID_RE = re.compile(r"[a-z][a-z0-9_]{1,62}")
_SECRET_REF_RE = re.compile(r"secret://[a-z0-9_]+")
_KEY_RE = re.compile(r"[A-Za-z0-9._:-]{1,128}")


class AdapterOperation(Model):
    """One registered operation an adapter can apply, and the authority level it needs.

    `args_model` is a closed schema by the same allowlist the tool registry applies
    (`ciso.common.closed_schema`): a frozen `Model` subclass that forbids extra fields
    and whose fields, all the way down, are bounded typed values. `name` may not be a
    control-plane operation (`ciso.write_adapters.protected`).
    """

    name: str
    authority_level: AuthorityLevel
    args_model: type[Model]
    reversible: bool

    @field_validator("name")
    @classmethod
    def _name(cls, value: str) -> str:
        if not _OPERATION_RE.fullmatch(value):
            raise ValueError("an operation name is dotted lower-case")
        if is_protected_name(value):
            raise ValueError("a write adapter may not declare a control-plane operation")
        return value

    @field_validator("args_model")
    @classmethod
    def _closed(cls, value: type[Model]) -> type[Model]:
        problem = schema_problem(value)
        if problem is not None:
            raise ValueError(f"argument schema is not closed: {problem}")
        return value


class AdapterManifest(Model):
    """What an adapter declares about itself before it is ever called.

    `credential_refs` are `secret://<name>` references to WRITE credentials. They are
    separate from any read connector's credentials and are never the values themselves.
    """

    adapter_id: str
    operations: tuple[AdapterOperation, ...]
    credential_refs: tuple[str, ...]

    @field_validator("adapter_id")
    @classmethod
    def _id(cls, value: str) -> str:
        if not _ADAPTER_ID_RE.fullmatch(value):
            raise ValueError("bad adapter id")
        return value

    @field_validator("operations")
    @classmethod
    def _operations(cls, value: tuple[AdapterOperation, ...]) -> tuple[AdapterOperation, ...]:
        names = [operation.name for operation in value]
        if not names or len(set(names)) != len(names):
            raise ValueError("an adapter declares at least one operation, each once")
        return value

    @field_validator("credential_refs")
    @classmethod
    def _refs(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if not all(_SECRET_REF_RE.fullmatch(ref) for ref in value):
            raise ValueError("credentials are declared as secret://<name> references")
        return value

    def operation(self, name: str) -> AdapterOperation | None:
        return next((item for item in self.operations if item.name == name), None)

    def validate_request(self, request: WriteRequest) -> Model:
        """The request's arguments, validated again as the declared operation's
        `args_model`. `ValidationFailed` when the operation is not declared here, the
        arguments are another model, or they do not pass that model strictly. The broker
        calls this before `apply`, `verify` or `rollback`; `WriteRequest` alone does not
        tie its `arguments` to anything."""
        if type(request) is not WriteRequest:
            raise ValidationFailed("only a WriteRequest can be validated")
        declared = self.operation(request.operation)
        if declared is None:
            raise ValidationFailed(f"operation {request.operation!r} is not declared")
        model = declared.args_model
        if type(request.arguments) is not model:
            raise ValidationFailed(f"arguments are not {model.__name__}")
        where = non_finite_path(request.arguments)
        if where is not None:
            raise ValidationFailed(f"{where} is not a finite number")
        try:
            raw = request.arguments.model_dump_json(warnings=False)
            return model.model_validate_json(raw, strict=True)
        except ValidationError as exc:
            fields = sorted({".".join(map(str, err["loc"])) for err in exc.errors()})
            raise ValidationFailed(f"arguments fail the schema at: {fields}") from exc


class WriteRequest(Model):
    """One application of a registered operation. `arguments` must be an instance of the
    operation's `args_model`; nothing in this class checks that, so run the request
    through `AdapterManifest.validate_request` first. The same `idempotency_key` must
    never apply twice."""

    request_id: str
    idempotency_key: str
    operation: str
    target_resource: str
    arguments: Model

    @field_validator("idempotency_key")
    @classmethod
    def _key(cls, value: str) -> str:
        if not _KEY_RE.fullmatch(value):
            raise ValueError("bad idempotency key")
        return value

    @field_validator("operation")
    @classmethod
    def _operation(cls, value: str) -> str:
        if not _OPERATION_RE.fullmatch(value):
            raise ValueError("an operation name is dotted lower-case")
        return value

    @field_validator("target_resource")
    @classmethod
    def _target(cls, value: str) -> str:
        EntityRef.parse(value)
        return value


class WriteOutcome(StrEnum):
    APPLIED = "applied"
    FAILED = "failed"
    ROLLED_BACK = "rolled_back"


class WriteReceipt(Model):
    """What the adapter says happened. A claim until `verify` confirms it."""

    outcome: WriteOutcome
    references: tuple[str, ...] = ()
    detail: str = ""


class WriteVerification(Model):
    """What a fresh read of the target shows. `matches` must be a real boolean."""

    model_config = ConfigDict(strict=True)

    matches: bool
    detail: str = ""
    observed: tuple[str, ...] = ()


class CredentialSource(Protocol):
    def get(self, ref: str) -> RevealableSecret:
        """Resolve a declared `secret://` reference, or raise. Supplied by the broker,
        which checks the kill switch before every resolution."""
        ...


class WriteAdapter(Protocol):
    """The contract. Implementing it for a real system needs an approved ADR first."""

    def manifest(self) -> AdapterManifest:
        """Operations, authority levels and credential references. No side effects."""
        ...

    def apply(self, request: WriteRequest, credentials: CredentialSource) -> WriteReceipt:
        """Carry out the operation once. A repeat of the same idempotency key returns
        the earlier receipt and changes nothing."""
        ...

    def verify(self, request: WriteRequest, credentials: CredentialSource) -> WriteVerification:
        """Read the target system again and say whether it shows the requested state.
        Must not rely on anything `apply` returned."""
        ...

    def rollback(
        self, request: WriteRequest, receipt: WriteReceipt | None, credentials: CredentialSource
    ) -> WriteReceipt:
        """Reverse the operation. `receipt` is None when the outcome of `apply` is
        unknown. Raise if the operation is not reversible."""
        ...
