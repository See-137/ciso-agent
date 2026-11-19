"""Load a governance ruleset from JSON. Any failure gives a deny-all ruleset, never an
exception.

Covered: missing or unreadable file, bytes that are not UTF-8, malformed JSON, nesting
too deep, a key repeated inside one object, a schema violation, an unknown key, and any
unexpected error. A leading byte order mark is stripped; the content hash is computed over
the parsed document, so it is the same with or without the mark.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

from pydantic import ValidationError

from ciso.common.schemas import content_hash, sha256_hex
from ciso.governance.rules import GovernanceRuleSet, RuleSetDocument

logger = logging.getLogger(__name__)

DEFAULT_RULESET_PATH = Path(__file__).resolve().parent / "rulesets" / "default.json"
#: The hash a deny-all ruleset reports (the decision contract needs one).
DENY_ALL_HASH = sha256_hex("governance-ruleset:deny-all")
#: Largest ruleset file read.
MAX_RULESET_BYTES = 1_000_000

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


def deny_all(reason: str) -> GovernanceRuleSet:
    return GovernanceRuleSet(
        version="deny-all",
        content_hash=DENY_ALL_HASH,
        document=None,
        deny_all=True,
        deny_reason=reason or "ruleset unavailable",
    )


def _deny(path: Path, reason: str) -> GovernanceRuleSet:
    logger.error("governance ruleset %s refused, engine is deny-all: %s", path.name, reason)
    return deny_all(reason)


def parse_ruleset(text: str, origin: Path) -> GovernanceRuleSet:
    """Validate ruleset text. Returns deny-all on any problem."""
    text = text.removeprefix(_BOM)
    try:
        parsed = json.loads(text, object_pairs_hook=_no_duplicates)
    except _DuplicateKey as exc:
        return _deny(origin, str(exc))
    except RecursionError:
        return _deny(origin, "ruleset JSON nests too deeply")
    except ValueError as exc:
        return _deny(origin, f"malformed JSON: {exc}")
    try:
        document = RuleSetDocument.model_validate_json(text, strict=True)
    except ValidationError as exc:
        problems = "; ".join(
            f"{'.'.join(map(str, err['loc']))}: {err['msg']}" for err in exc.errors()
        )
        return _deny(origin, f"schema violation: {problems}")
    return GovernanceRuleSet(
        version=document.version, content_hash=content_hash(parsed), document=document
    )


def load_ruleset(path: Path) -> GovernanceRuleSet:
    """Read and validate `path`. Returns a deny-all ruleset if anything is wrong."""
    try:
        raw = path.read_bytes()
        if len(raw) > MAX_RULESET_BYTES:
            return _deny(path, "ruleset file is too large")
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError:
            return _deny(path, "ruleset file is not valid UTF-8")
        return parse_ruleset(text, path)
    except OSError as exc:
        return _deny(path, f"cannot read ruleset file: {type(exc).__name__}")
    except Exception as exc:
        return _deny(path, f"unexpected error while loading: {type(exc).__name__}")


def load_default_ruleset() -> GovernanceRuleSet:
    """The provisional ruleset shipped with the package."""
    return load_ruleset(DEFAULT_RULESET_PATH)
