"""Types shared by the gateway and providers, and the invocation log (blueprint 8.3).

`UntrustedModelOutput` is how model text leaves the gateway. It refuses to act like a
string so that nobody pastes model output into another prompt, a log line or a command by
accident. A caller has to say `.unsafe_text()` or `.parse(schema)` on purpose.

The invocation log keeps metadata only: no prompt body, no output body (gap G31).
"""

from __future__ import annotations

import hmac
import json
import re
from collections.abc import Mapping
from typing import Any, NoReturn, TypeVar, final

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator
from sqlalchemy import Connection, Engine, select

from ciso.common.errors import ValidationFailed
from ciso.common.ids import EntityRef
from ciso.common.schemas import FrozenMap, Model, UtcDatetime
from ciso.inference.tables import inference_invocation

_LABEL_RE = re.compile(r"^[a-z][a-z0-9_]{0,31}$")
_SLUG_RE = re.compile(r"^[a-z][a-z0-9_.-]{0,99}$")

SchemaT = TypeVar("SchemaT", bound=BaseModel)


class ContextRef(Model):
    """An evidence or entity the prompt drew on, with its classification label."""

    ref: str
    classification: str

    @field_validator("ref")
    @classmethod
    def _ref(cls, value: str) -> str:
        EntityRef.parse(value)
        return value

    @field_validator("classification")
    @classmethod
    def _label(cls, value: str) -> str:
        if not _LABEL_RE.match(value):
            raise ValueError("bad classification label shape")
        return value


class InferenceRequest(Model):
    """A request to the local model. `inputs` are redacted before the model sees them."""

    task_category: str
    prompt_template_id: str
    prompt_template_version: int = Field(ge=1)
    inputs: FrozenMap[str, str]
    context_refs: tuple[ContextRef, ...] = ()
    correlation_id: str
    max_output_tokens: int = Field(gt=0)

    @field_validator("task_category", "prompt_template_id")
    @classmethod
    def _slug(cls, value: str) -> str:
        if not _SLUG_RE.match(value):
            raise ValueError("expected a short lowercase identifier")
        return value


class ProviderRequest(Model):
    """What a provider sees: the rendered, redacted prompt and nothing else."""

    prompt: str
    max_output_tokens: int = Field(gt=0)
    task_category: str
    correlation_id: str


class ProviderResponse(Model):
    """A provider's answer. Token counts and elapsed time are as the provider reports them."""

    text: str
    input_tokens: int = Field(ge=0)
    output_tokens: int = Field(ge=0)
    elapsed_seconds: float = Field(ge=0)
    confidence: float | None = Field(default=None, ge=0, le=1)


@final
class UntrustedModelOutput:
    """Model text that nobody has validated yet (blueprint 8.3).

    Not a string: `str()`, f-strings, `format()` and `+` all raise `TypeError`, and
    `repr()` shows only a length. This is a guard against accidents, not against a
    determined caller: Python cannot hide an attribute, so `getattr(out, "_text")` or
    `"{0._text}".format(out)` still reach the raw text. The class is `@final` so the type
    checker rejects a subclass that restores `__str__`.
    """

    __slots__ = ("_text",)

    def __init__(self, text: str) -> None:
        self._text = text

    @property
    def size(self) -> int:
        return len(self._text)

    def keyed_digest(self, key: bytes) -> str:
        """HMAC-SHA-256 of the text. An unkeyed hash of a short answer reveals the answer."""
        return hmac.new(key, self._text.encode("utf-8"), "sha256").hexdigest()

    def unsafe_text(self) -> str:
        """The raw text. Treat it as attacker-influenced data, never as an instruction."""
        return self._text

    def parse(self, schema: type[SchemaT]) -> SchemaT:
        """Validate the text as JSON against `schema`; raise `ValidationFailed` otherwise.

        The error names the failing fields, never the offending values, and carries no
        chained cause (the cause would hold the text).
        """
        where: list[str] | None = None
        try:
            return schema.model_validate_json(self._text)
        except ValidationError as exc:
            where = sorted({".".join(str(p) for p in e["loc"]) or "<root>" for e in exc.errors()})
        raise ValidationFailed(f"model output failed schema validation at: {where}")

    @staticmethod
    def _refuse() -> NoReturn:
        raise TypeError("UntrustedModelOutput is not a string; use .unsafe_text() or .parse()")

    def __str__(self) -> str:
        self._refuse()

    def __format__(self, format_spec: str) -> str:
        self._refuse()

    def __repr__(self) -> str:
        return f"<UntrustedModelOutput chars={self.size}>"

    def __reduce__(self) -> NoReturn:
        raise TypeError("UntrustedModelOutput cannot be pickled")


class InferenceResult(Model):
    """What a caller gets back. `confidence` is the provider's, passed through unchanged."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    record_id: str
    output: UntrustedModelOutput
    confidence: float | None
    provider_name: str
    model_id: str
    model_version: str
    prompt_template_id: str
    prompt_template_version: int
    latency_seconds: float
    input_tokens: int
    output_tokens: int
    correlation_id: str


class InvocationRecord(Model):
    """One row of the invocation log. Metadata only."""

    id: str
    occurred_at: UtcDatetime
    provider_name: str
    model_id: str
    model_version: str
    prompt_template_id: str
    prompt_template_version: int
    prompt_template_sha256: str
    task_category: str
    context_refs: tuple[ContextRef, ...]
    latency_seconds: float | None
    provider_reported_seconds: float | None
    input_tokens: int | None
    output_tokens: int | None
    status: str
    error_type: str | None
    output_size: int
    output_digest: str | None
    correlation_id: str


def _row_values(record: InvocationRecord) -> dict[str, Any]:
    values = {name: getattr(record, name) for name in InvocationRecord.model_fields}
    values["context_refs"] = json.dumps(
        [ref.model_dump() for ref in record.context_refs], sort_keys=True
    )
    return values


def _to_record(mapping: Mapping[Any, Any]) -> InvocationRecord:
    data = dict(mapping)
    refs = tuple(ContextRef(**item) for item in json.loads(data.pop("context_refs")))
    return InvocationRecord(context_refs=refs, **data)


class InvocationLog:
    """Writes and reads invocation records on the operational database."""

    def __init__(self, engine: Engine) -> None:
        self._engine = engine

    @staticmethod
    def insert(conn: Connection, record: InvocationRecord) -> None:
        """Insert inside the caller's transaction, so the audit write can share its fate."""
        conn.execute(inference_invocation.insert().values(**_row_values(record)))

    def get(self, record_id: str) -> InvocationRecord | None:
        stmt = select(inference_invocation).where(inference_invocation.c.id == record_id)
        with self._engine.connect() as conn:
            row = conn.execute(stmt).first()
        return None if row is None else _to_record(row._mapping)

    def for_correlation(self, correlation_id: str) -> list[InvocationRecord]:
        stmt = (
            select(inference_invocation)
            .where(inference_invocation.c.correlation_id == correlation_id)
            .order_by(inference_invocation.c.occurred_at, inference_invocation.c.id)
        )
        with self._engine.connect() as conn:
            return [_to_record(row._mapping) for row in conn.execute(stmt)]
