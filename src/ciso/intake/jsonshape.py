"""Bounds on JSON-shaped input: only JSON types, bounded nesting, bounded encoded size.

The decision API hands the intake an already parsed object; the central gate hands it raw
bytes. Both pass through here so a deeply nested or non-JSON value is refused with a reason
code instead of failing somewhere later with an error that quotes the input.
"""

from __future__ import annotations

import json
import math
from typing import Any

from ciso.intake.errors import RefusalCode, refuse


def check_json_value(value: Any, *, max_depth: int, code: RefusalCode) -> None:
    """Refuse anything that is not plain JSON (dict with str keys, list, str, int, finite
    float, bool, None) or nests deeper than `max_depth`. Iterative: no recursion limit."""
    stack: list[tuple[Any, int]] = [(value, 0)]
    while stack:
        item, depth = stack.pop()
        if depth > max_depth:
            raise refuse(code)
        if isinstance(item, dict):
            if not all(isinstance(key, str) for key in item):
                raise refuse(code)
            stack.extend((child, depth + 1) for child in item.values())
        elif isinstance(item, list):
            stack.extend((child, depth + 1) for child in item)
        elif isinstance(item, float):
            if not math.isfinite(item):
                raise refuse(code)
        elif item is not None and not isinstance(item, str | int | bool):
            raise refuse(code)


def encoded_size(value: Any) -> int:
    """Bytes of the compact UTF-8 JSON encoding. Call after `check_json_value`."""
    text = json.dumps(value, ensure_ascii=False, separators=(",", ":"))
    return len(text.encode("utf-8", errors="surrogatepass"))


def _no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    keys = [key for key, _ in pairs]
    if len(set(keys)) != len(keys):
        raise ValueError("duplicate key")
    return dict(pairs)


def _no_constants(_name: str) -> Any:
    raise ValueError("non-finite number")


def loads_strict(body: bytes, *, max_depth: int, code: RefusalCode) -> Any:
    """Parse UTF-8 JSON, refusing duplicate keys, NaN/Infinity and deep nesting."""
    try:
        text = body.decode("utf-8")
        value = json.loads(text, object_pairs_hook=_no_duplicates, parse_constant=_no_constants)
    except (ValueError, RecursionError):
        raise refuse(code) from None
    check_json_value(value, max_depth=max_depth, code=code)
    return value
