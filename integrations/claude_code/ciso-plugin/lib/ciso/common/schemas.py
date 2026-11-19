"""Pydantic base and canonical serialisation used for hashing."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from datetime import datetime
from types import MappingProxyType
from typing import Annotated, Any

from pydantic import AfterValidator, BaseModel, ConfigDict, PlainSerializer

from ciso.common.clock import ensure_utc


class Model(BaseModel):
    """Immutable, closed schema. Unknown fields are an error, not a silent drop."""

    model_config = ConfigDict(extra="forbid", frozen=True, validate_default=True)


#: A datetime that must carry a timezone and is normalised to UTC.
UtcDatetime = Annotated[datetime, AfterValidator(ensure_utc)]


def deep_freeze(value: Any) -> Any:
    """Return a copy in which every dict is a read-only mapping and every list a tuple.

    A frozen model stops its fields being reassigned, but a dict or list held in a field
    can still be changed in place. Fields that carry authority (scopes, the arguments an
    approval binds to) go through this so nobody holding the object can widen it.
    """
    if isinstance(value, Mapping):
        return MappingProxyType({key: deep_freeze(item) for key, item in value.items()})
    if isinstance(value, list | tuple):
        return tuple(deep_freeze(item) for item in value)
    if isinstance(value, set | frozenset):
        return frozenset(value)
    return value


def thaw(value: Any) -> Any:
    """The plain dict/list form of a frozen value, for serialisation."""
    if isinstance(value, Mapping):
        return {key: thaw(item) for key, item in value.items()}
    if isinstance(value, tuple | list):
        return [thaw(item) for item in value]
    if isinstance(value, set | frozenset):
        return sorted(value)
    return value


#: A mapping field that cannot be changed in place after validation.
type FrozenMap[K, V] = Annotated[
    Mapping[K, V], AfterValidator(deep_freeze), PlainSerializer(thaw, return_type=dict[Any, Any])
]

#: A JSON-shaped value (dicts, lists, scalars) that cannot be changed in place.
FrozenJson = Annotated[Any, AfterValidator(deep_freeze), PlainSerializer(thaw)]


def canonical_json(value: Any) -> str:
    """Deterministic JSON: sorted keys, no whitespace, models dumped in JSON mode."""
    if isinstance(value, BaseModel):
        value = value.model_dump(mode="json")
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str)


def sha256_hex(data: bytes | str) -> str:
    raw = data.encode("utf-8") if isinstance(data, str) else data
    return hashlib.sha256(raw).hexdigest()


def content_hash(value: Any) -> str:
    """Hash of the canonical JSON form. Used to bind approvals to an exact payload."""
    return sha256_hex(canonical_json(value))
