"""Making text a tool, a verifier or a rollback handed back safe to store and to audit
(blueprint 9.5 "do not infer success from a tool response"; review findings M3, M5).

Whatever a tool returns is a claim written by code that talked to a target the platform
does not trust. Before any of it reaches an `execution_run` row or an audit record it is:

- made encodable: a character that cannot be written as UTF-8 (a lone surrogate) becomes
  `?`, so the database driver cannot raise after the side effect has happened;
- passed through the `Redactor`; if the redactor cannot answer, the text is replaced by a
  fixed marker, never stored as it came;
- cut to a fixed length.

References are kept only when they are entity references the redactor leaves unchanged,
and at most `MAX_REFERENCES` of them.

The numbers here are structural bounds on stored text, not safety parameters an operator
tunes: they exist so one reply cannot grow a row or an audit record without limit.
"""

from __future__ import annotations

from ciso.common.errors import ValidationFailed
from ciso.common.ids import EntityRef
from ciso.common.protocols import Redactor

#: Longest tool or verifier free text kept on a row. Structural bound.
MAX_DETAIL = 500
#: Most references kept from one reply (`references`, `observed`). Structural bound.
MAX_REFERENCES = 32
#: Longest exception type name kept in `error_kind` (the column is 96 wide).
MAX_ERROR_KIND = 96
#: How much of a reply the redactor is shown. Structural bound on the work done per
#: reply; it is far above `MAX_DETAIL` so a secret cannot straddle the final cut.
MAX_RAW_TEXT = 16_384
#: Stored in place of text the redactor could not process.
WITHHELD = "[withheld: redaction unavailable]"


def encodable(text: str) -> str:
    """`text` with every character UTF-8 cannot encode replaced by `?`."""
    return text.encode("utf-8", "replace").decode("utf-8")


def safe_text(text: object, redactor: Redactor) -> str:
    """Tool-supplied free text, safe to store: encodable, redacted, bounded."""
    if not isinstance(text, str):
        return ""
    try:
        cleaned = redactor.redact(encodable(text[:MAX_RAW_TEXT]))
    except Exception:
        return WITHHELD
    if not isinstance(cleaned, str):
        return WITHHELD
    return encodable(cleaned)[:MAX_DETAIL]


def safe_refs(values: object, redactor: Redactor) -> tuple[str, ...]:
    """The entity references among `values` that carry nothing the redactor would
    remove, at most `MAX_REFERENCES`. Anything else is dropped; if the redactor cannot
    answer, every reference is dropped."""
    if not isinstance(values, tuple | list):
        return ()
    kept: list[str] = []
    for item in values:
        if len(kept) == MAX_REFERENCES:
            break
        if not isinstance(item, str):
            continue
        try:
            unchanged = redactor.redact(item) == item
        except Exception:
            return ()
        if not unchanged:
            continue
        try:
            EntityRef.parse(item)
        except ValidationFailed:
            continue
        kept.append(item)
    return tuple(kept)


def error_name(exc: BaseException) -> str:
    """The exception's type name, never its message, bounded and encodable."""
    return encodable(type(exc).__name__)[:MAX_ERROR_KIND]
