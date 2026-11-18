"""What counts as a closed argument schema (blueprint 9.4 "typed action and validated
arguments; no free-form command execution", 9.5 "allowlisted and typed").

An ALLOWLIST: a field type is accepted only when it is one of the shapes named here, and
everything else is refused. Accepted, recursively:

- `bool`, `int`, `float` (non-finite values are refused when arguments are bound);
- `str` with a `max_length`;
- an `Enum` subclass; `Literal[...]` of `str`, `int`, `bool` or `None`;
- `UtcDatetime`, the UTC-validated datetime from `ciso.common.schemas` (a plain
  `datetime` or `date` is refused: nothing in `ciso.common` validates one);
- a frozen `Model` subclass that forbids extra fields and itself passes this check;
- `tuple[T, ...]` and `frozenset[T]` of an accepted `T`, with a `max_length`;
- `T | None` and unions of accepted types.

Type aliases and `Annotated` are resolved first. Refused: bare or parameterised `dict`,
`Mapping`, `list`, `set`; `Any`; `object`; JSON-value aliases; `bytes`; `TypedDict`;
dataclasses; callables; any other class; any annotation or validator that runs before or
instead of type validation, since that is another way to spell "anything".

The one copy. The tool registry (`ciso.execution`), the write-adapter contract
(`ciso.write_adapters`) and the policy catalog (`ciso.policy.catalog.OperationSpec`) all
apply this check, so an operation cannot be open in one place and closed in another.
Uses pydantic and the standard library only.
"""

from __future__ import annotations

from enum import Enum
from typing import Annotated, Any, Literal, TypeAliasType, Union, get_args, get_origin

from pydantic import AfterValidator, BaseModel
from pydantic.fields import FieldInfo

from ciso.common.clock import ensure_utc
from ciso.common.schemas import Model, UtcDatetime

_UNION_TYPE = type(int | None)
_NONE_TYPE = type(None)
_NUMBERS = (bool, int, float)
_LITERAL_TYPES = (str, int, bool, _NONE_TYPE)
_INFINITY = float("inf")
#: The class behind `UtcDatetime`; accepted only together with its UTC validator.
_UTC_TYPE = get_args(UtcDatetime)[0]
#: Entry points a schema class may not replace: each one decides what input is accepted.
_FIXED_ENTRY_POINTS = ("__get_pydantic_core_schema__", "model_validate", "model_validate_json")
#: Constraint classes from the validation library that only narrow a value.
_NARROWING = frozenset({"Strict", "StringConstraints"})
_GENERAL_KEYS = frozenset({"pattern", "strict"})


def schema_problem(model: Any, seen: frozenset[Any] = frozenset()) -> str | None:
    """Why `model` is not a closed argument schema, or None when it is."""
    if not (isinstance(model, type) and issubclass(model, Model)):
        return "argument schema must be a Model subclass"
    config = model.model_config
    if config.get("extra") != "forbid" or config.get("frozen") is not True:
        return f"{model.__name__} must forbid extra fields and be frozen"
    hooked = _hook_problem(model)
    if hooked is not None:
        return f"{model.__name__} {hooked}"
    inside = seen | {model}
    for name, field in model.model_fields.items():
        problem = _type_problem(field.annotation, tuple(field.metadata), inside)
        if problem is not None:
            return f"{model.__name__}.{name}: {problem}"
    return None


def non_finite_path(value: Any, path: str = "") -> str | None:
    """Where a bound argument value holds NaN or an infinity, or None when it holds none.
    Such a number does not equal itself or survive a JSON round trip, so comparing or
    re-validating the arguments would misbehave."""
    if isinstance(value, float):
        return (path or "value") if value != value or abs(value) == _INFINITY else None
    if isinstance(value, BaseModel):
        items: list[tuple[str, Any]] = [
            (f"{path}.{name}" if path else name, getattr(value, name, None))
            for name in type(value).model_fields
        ]
    elif isinstance(value, tuple | frozenset):
        items = [(f"{path}[]", item) for item in value]
    else:
        return None
    for where, item in items:
        found = non_finite_path(item, where)
        if found is not None:
            return found
    return None


def _hook_problem(model: type[BaseModel]) -> str | None:
    """A validator that sees the raw input, or a replaced entry point, opens the schema."""
    for name in _FIXED_ENTRY_POINTS:
        if getattr(getattr(model, name), "__func__", None) is not getattr(BaseModel, name).__func__:
            return f"replaces {name}"
    decorators = model.__pydantic_decorators__
    if decorators.validators or decorators.root_validators:
        return "uses a legacy validator"
    for group in (decorators.field_validators, decorators.model_validators):
        for hook in group.values():
            if hook.info.mode != "after":
                return f"has a {hook.info.mode!r} validator, which sees unvalidated input"
    return None


def _flat(metadata: tuple[Any, ...]) -> list[Any]:
    """Annotation metadata with any field description replaced by what it carries."""
    out: list[Any] = []
    for item in metadata:
        if isinstance(item, FieldInfo):
            out.extend(_flat(tuple(item.metadata)))
        else:
            out.append(item)
    return out


def _metadata_problem(metadata: list[Any]) -> str | None:
    for item in metadata:
        kind = type(item)
        if isinstance(item, AfterValidator):
            continue
        if getattr(item, "strict", None) is False:
            return "strict=False lets other types in"
        if kind.__module__ == "annotated_types":
            continue
        if kind.__module__ == "pydantic.types" and kind.__name__ in _NARROWING:
            continue
        if kind.__name__ == "_PydanticGeneralMetadata" and set(vars(item)) <= _GENERAL_KEYS:
            continue
        return f"{kind.__name__} is not an allowed annotation"
    return None


def _bounded(metadata: list[Any]) -> bool:
    return any(type(getattr(item, "max_length", None)) is int for item in metadata)


def _utc_validated(metadata: list[Any]) -> bool:
    return any(isinstance(item, AfterValidator) and item.func is ensure_utc for item in metadata)


def _type_problem(annotation: Any, metadata: tuple[Any, ...], seen: frozenset[Any]) -> str | None:
    """Why this annotation is not on the allowlist, or None when it is."""
    alias = annotation if isinstance(annotation, TypeAliasType) else get_origin(annotation)
    if isinstance(alias, TypeAliasType):
        if alias in seen:
            return "a type alias that refers to itself"
        return _type_problem(alias.__value__, metadata, seen | {alias})
    if alias is Annotated:
        return _type_problem(annotation.__origin__, (*metadata, *annotation.__metadata__), seen)
    flat = _flat(metadata)
    refused = _metadata_problem(flat)
    if refused is not None:
        return refused
    if alias is Union or alias is _UNION_TYPE:
        members = [member for member in get_args(annotation) if member is not _NONE_TYPE]
        carried = metadata if len(members) == 1 else ()
        problems = (_type_problem(member, carried, seen) for member in members)
        return next((problem for problem in problems if problem is not None), None)
    if alias is Literal:
        if all(type(value) in _LITERAL_TYPES for value in get_args(annotation)):
            return None
        return "a Literal of something other than str, int, bool or None"
    if alias is tuple or alias is frozenset:
        return _collection_problem(annotation, alias, flat, seen)
    if alias is not None:
        return f"{getattr(alias, '__name__', alias)}[...] is not an allowed container"
    return _plain_problem(annotation, flat, seen)


def _collection_problem(
    annotation: Any, origin: Any, metadata: list[Any], seen: frozenset[Any]
) -> str | None:
    args = get_args(annotation)
    if origin is tuple and (len(args) != 2 or args[1] is not Ellipsis):
        return "a tuple must be tuple[T, ...]"
    if not _bounded(metadata):
        return f"a {origin.__name__} needs a max_length"
    return _type_problem(args[0], (), seen)


def _plain_problem(annotation: Any, metadata: list[Any], seen: frozenset[Any]) -> str | None:
    if annotation is _NONE_TYPE or any(annotation is number for number in _NUMBERS):
        return None
    if annotation is str:
        return None if _bounded(metadata) else "a str needs a max_length"
    if annotation is _UTC_TYPE:
        return None if _utc_validated(metadata) else "a datetime must be the UTC-validated type"
    if isinstance(annotation, type) and issubclass(annotation, Enum):
        return None
    if isinstance(annotation, type) and issubclass(annotation, Model):
        return None if annotation in seen else schema_problem(annotation, seen)
    return f"{getattr(annotation, '__name__', annotation)!r} is not an allowed argument type"
