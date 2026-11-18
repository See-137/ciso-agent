"""Load a ruleset from JSON. Any failure gives a deny-all ruleset, never an exception.

Failures covered: missing or unreadable file, bytes that are not UTF-8, malformed JSON,
pathological nesting, a key repeated inside one JSON object (which plain parsing would
silently resolve to the last value), a schema violation, an unknown key, a duplicate rule
id, and any unexpected error. The reason is on `RuleSet.deny_reason`.

A leading UTF-8 byte order mark is stripped (Windows tools write one); the content hash
is computed over the parsed document, so it is the same with or without the mark.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

from pydantic import ValidationError

from ciso.common.schemas import content_hash
from ciso.policy.rules import RuleSet, RuleSetDocument

logger = logging.getLogger(__name__)

DEFAULT_RULESET_PATH = Path(__file__).resolve().parent / "rulesets" / "default.json"

_BOM = "﻿"


class _DuplicateKey(ValueError):
    pass


def _no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise _DuplicateKey(f"duplicate key {key!r} in a JSON object")
        result[key] = value
    return result


def _deny(path: Path, reason: str) -> RuleSet:
    logger.error("policy ruleset %s refused, engine is deny-all: %s", path.name, reason)
    return RuleSet.deny_everything(reason)


def _read_text(path: Path) -> str:
    raw = path.read_bytes()
    text = raw.decode("utf-8")
    return text.removeprefix(_BOM)


def _parse(path: Path) -> RuleSet:
    try:
        text = _read_text(path)
    except OSError as exc:
        return _deny(path, f"cannot read ruleset file: {type(exc).__name__}")
    except UnicodeDecodeError:
        return _deny(path, "ruleset file is not valid UTF-8")
    try:
        parsed = json.loads(text, object_pairs_hook=_no_duplicates)
    except _DuplicateKey as exc:
        return _deny(path, str(exc))
    except RecursionError:
        return _deny(path, "ruleset JSON nests too deeply")
    except ValueError as exc:
        return _deny(path, f"malformed JSON: {exc}")
    try:
        document = RuleSetDocument.model_validate_json(text, strict=True)
    except ValidationError as exc:
        problems = "; ".join(
            f"{'.'.join(map(str, err['loc']))}: {err['msg']}" for err in exc.errors()
        )
        return _deny(path, f"schema violation: {problems}")
    return RuleSet.from_document(document, content_hash(parsed))


def load_ruleset(path: Path) -> RuleSet:
    """Read and validate `path`. Returns a deny-all ruleset if anything is wrong."""
    try:
        return _parse(path)
    except Exception as exc:
        return _deny(path, f"unexpected error while loading: {type(exc).__name__}")


def load_default_ruleset() -> RuleSet:
    """The ruleset shipped with the package (blueprint 9.2)."""
    return load_ruleset(DEFAULT_RULESET_PATH)
