"""Pydantic base and canonical serialisation used for hashing."""

from __future__ import annotations

import hashlib
import json
from datetime import datetime
from typing import Annotated, Any

from pydantic import AfterValidator, BaseModel, ConfigDict

from ciso.common.clock import ensure_utc


class Model(BaseModel):
    """Immutable, closed schema. Unknown fields are an error, not a silent drop."""

    model_config = ConfigDict(extra="forbid", frozen=True, validate_default=True)


#: A datetime that must carry a timezone and is normalised to UTC.
UtcDatetime = Annotated[datetime, AfterValidator(ensure_utc)]


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
