"""Registered operations. There is no free-text command anywhere (blueprint 9.4, 9.5).

An operation is known only if it is in the catalog. The catalog, not the requester, says
what authority level an operation needs, whether it writes, whether an agent or service
may request it at all, and whether it changes the control plane.
"""

from __future__ import annotations

import re
from collections.abc import Iterable

from pydantic import field_validator, model_validator

from ciso.common.closed_schema import schema_problem
from ciso.common.enums import AuthorityLevel
from ciso.common.errors import ValidationFailed

# The protected families and suppression verbs live in `ciso.common.protected`; they are
# re-exported here under the names this module always had.
from ciso.common.protected import PROTECTED_FAMILIES, SUPPRESSION_VERBS, is_protected_name
from ciso.common.schemas import Model

_NAME_RE = re.compile(r"^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+$")

__all__ = [
    "PROTECTED_FAMILIES",
    "SUPPRESSION_VERBS",
    "OperationCatalog",
    "OperationSpec",
    "is_protected_name",
]


class OperationSpec(Model):
    """One registered operation.

    `args_model` is a closed schema by the allowlist in `ciso.common.closed_schema` (the
    same check the tool registry and the write-adapter contract apply): a frozen `Model`
    subclass that forbids extra fields and whose fields are bounded typed values. When
    `channel_argument` is set the operation sends something somewhere, and that argument
    names the channel the engine checks against the approved-channel list (G13).
    `agent_requestable` must be set for an agent or service to request the operation at
    all; it defaults to False and is refused on a protected operation.
    """

    name: str
    authority_level: AuthorityLevel
    args_model: type[Model]
    writes: bool = False
    channel_argument: str | None = None
    protected: bool = False
    agent_requestable: bool = False
    description: str = ""

    @field_validator("name")
    @classmethod
    def _name(cls, value: str) -> str:
        if not _NAME_RE.fullmatch(value):
            raise ValueError(f"bad operation name: {value!r}")
        return value

    @field_validator("args_model")
    @classmethod
    def _closed(cls, value: type[Model]) -> type[Model]:
        problem = schema_problem(value)
        if problem is not None:
            raise ValueError(f"argument schema is not closed: {problem}")
        return value

    @model_validator(mode="after")
    def _consistent(self) -> OperationSpec:
        if is_protected_name(self.name) and not self.protected:
            raise ValueError(f"{self.name!r} is a control-plane name and must be protected")
        if self.protected and not self.writes:
            raise ValueError("a protected operation is always a write")
        if self.protected and self.agent_requestable:
            raise ValueError("a protected operation cannot be agent_requestable")
        if self.channel_argument is not None:
            field = self.args_model.model_fields.get(self.channel_argument)
            if field is None or field.annotation is not str:
                raise ValueError(
                    f"channel argument {self.channel_argument!r} must be a str field of "
                    "the argument schema"
                )
        return self

    @property
    def needs_channel(self) -> bool:
        return self.channel_argument is not None


class OperationCatalog:
    """Immutable set of registered operations, keyed by name."""

    def __init__(self, specs: Iterable[OperationSpec]) -> None:
        by_name: dict[str, OperationSpec] = {}
        for spec in specs:
            if spec.name in by_name:
                raise ValidationFailed(f"duplicate operation: {spec.name!r}")
            by_name[spec.name] = spec
        self._specs = by_name

    def get(self, name: str) -> OperationSpec | None:
        return self._specs.get(name)

    def names(self) -> tuple[str, ...]:
        return tuple(sorted(self._specs))

    def __contains__(self, name: object) -> bool:
        return name in self._specs

    def __len__(self) -> int:
        return len(self._specs)
