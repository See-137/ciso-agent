"""Redaction of secret values and token-shaped strings from text, structures and log records.

Blueprint 11.1 and 13.4: secrets are redacted from all logs and model contexts. FR-031:
recorded events carry metadata, not raw content. The patterns are generic shapes (bearer
and authorization headers, JWTs, PEM private keys, key-like assignments); none names a
vendor or product.
"""

from __future__ import annotations

import copy
import logging
import re
import threading
from typing import Any, Final

from ciso.common.errors import ValidationFailed
from ciso.common.protocols import Redactor

#: What every redacted span becomes. It is never itself treated as a secret.
REDACTION_MARKER: Final = "[REDACTED]"

#: Values shorter than this are not registered for substring matching: replacing a short
#: string everywhere would shred ordinary text. Keep short secrets away from logs.
MIN_REGISTERED_LENGTH: Final = 8

_M = re.escape(REDACTION_MARKER)

_PEM = re.compile(
    r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----"
    r"(?:[\s\S]*?-----END [A-Z0-9 ]*PRIVATE KEY-----|[\s\S]*\Z)"
)
_JWT = re.compile(r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*")
# A bearer token is at least 8 characters and holds a digit or symbol, so prose such as
# "the bearer of this note" is left alone. Header values are also caught by _AUTH_HEADER.
_BEARER = re.compile(
    r"\b(?P<pre>bearer\s+)(?=[A-Za-z]*[0-9\-._~+/])[A-Za-z0-9\-._~+/]{8,}=*", re.IGNORECASE
)
_AUTH_HEADER = re.compile(
    r"\b(?P<pre>authorization[\"']?\s*[:=]\s*[\"']?)"
    rf"(?P<val>{_M}|[^\r\n,;\"']*[^\s,;\"'])",
    re.IGNORECASE,
)
_KEY_WORDS = (
    r"api[_-]?key|apikey|secret[_-]?key|private[_-]?key|access[_-]?key"
    r"|password|passwd|secret|token"
)
_ASSIGNMENT = re.compile(
    rf"(?P<pre>(?P<q>[\"']?)\b[A-Za-z0-9_.\-]*?(?:{_KEY_WORDS})(?P=q)\s*[:=]\s*)"
    rf"(?P<val>{_M}|\"(?:[^\"\\]|\\.)+\"|'[^']+'|\[?[^\s,;&'\"}}\[\]]+\]?)",
    re.IGNORECASE,
)


def _sub_value(match: re.Match[str]) -> str:
    value = match.group("val")
    if value[:1] in {'"', "'"} and value[-1:] == value[:1] and len(value) >= 2:
        replacement = value[0] + REDACTION_MARKER + value[0]
    else:
        replacement = REDACTION_MARKER
    return match.group("pre") + replacement


def _overlaps_marker(value: str) -> bool:
    """True if the value could match across, inside or around an existing marker."""
    if value in REDACTION_MARKER or REDACTION_MARKER in value:
        return True
    size = min(len(value), len(REDACTION_MARKER))
    return any(
        REDACTION_MARKER[-k:] == value[:k] or REDACTION_MARKER[:k] == value[-k:]
        for k in range(1, size + 1)
    )


def _merged_spans(text: str, values: tuple[str, ...]) -> list[tuple[int, int]]:
    spans: list[tuple[int, int]] = []
    for value in values:
        start = text.find(value)
        while start != -1:
            spans.append((start, start + len(value)))
            start = text.find(value, start + 1)
    spans.sort()
    merged: list[tuple[int, int]] = []
    for start, end in spans:
        if merged and start <= merged[-1][1]:
            merged[-1] = (merged[-1][0], max(merged[-1][1], end))
        else:
            merged.append((start, end))
    return merged


class SecretRedactor:
    """Scrubs registered secret values and token-shaped strings. Safe to share across threads.

    Overlapping or nested registered values are removed as one span, so no fragment of
    either survives. `redact` is idempotent and never rewrites the marker.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._values: tuple[str, ...] = ()

    @property
    def marker(self) -> str:
        return REDACTION_MARKER

    def register(self, value: str) -> bool:
        """Add a known secret value. Returns True if it will be redacted from now on.

        Returns False, and registers nothing, for values shorter than
        MIN_REGISTERED_LENGTH (8) characters, whitespace-only values, and values that are
        or overlap the redaction marker. Such values are not scrubbed by substring match.
        """
        if not isinstance(value, str):
            raise ValidationFailed("only string values can be registered for redaction")
        if len(value) < MIN_REGISTERED_LENGTH or not value.strip() or _overlaps_marker(value):
            return False
        with self._lock:
            if value not in self._values:
                ordered = sorted((*self._values, value), key=len, reverse=True)
                self._values = tuple(ordered)
        return True

    def redact(self, text: str) -> str:
        """Return `text` with registered values and token shapes replaced by the marker."""
        if not isinstance(text, str):
            raise ValidationFailed("redact() takes a string; use redact_value() for structures")
        values = self._values  # one atomic read: a consistent snapshot
        spans = _merged_spans(text, values)
        if spans:
            parts: list[str] = []
            cursor = 0
            for start, end in spans:
                parts.append(text[cursor:start])
                parts.append(REDACTION_MARKER)
                cursor = end
            parts.append(text[cursor:])
            text = "".join(parts)
        text = _PEM.sub(REDACTION_MARKER, text)
        text = _JWT.sub(REDACTION_MARKER, text)
        text = _BEARER.sub(lambda m: m.group("pre") + REDACTION_MARKER, text)
        text = _AUTH_HEADER.sub(lambda m: m.group("pre") + REDACTION_MARKER, text)
        return _ASSIGNMENT.sub(_sub_value, text)

    def redact_value(self, value: Any) -> Any:
        """Redact strings inside dicts (keys and values), lists, tuples, sets and strings.

        Returns a new value; the input is not changed. Other scalars pass through. If two
        dict keys redact to the same marker, the later entry wins in the copy.
        """
        if isinstance(value, str):
            return self.redact(value)
        if isinstance(value, dict):
            return {self.redact_value(k): self.redact_value(v) for k, v in value.items()}
        if isinstance(value, list):
            return [self.redact_value(item) for item in value]
        if isinstance(value, tuple):
            return tuple(self.redact_value(item) for item in value)
        if isinstance(value, frozenset):
            return frozenset(self.redact_value(item) for item in value)
        if isinstance(value, set):
            return {self.redact_value(item) for item in value}
        return value


class RedactingLogFilter(logging.Filter):
    """Logging filter that returns a redacted copy of each record (Python 3.12+ semantics).

    The message is formatted with its args first and the result redacted, so secrets in
    any argument type are caught. A record whose format does not match its args is not
    allowed to fail: its message and args are rendered and redacted separately. Exception
    and stack text are formatted and redacted; `exc_info` is cleared on the copy so no
    later handler re-renders the raw exception. Attach it to handlers.
    """

    def __init__(self, redactor: Redactor) -> None:
        super().__init__()
        self._redactor = redactor
        self._formatter = logging.Formatter()

    def filter(self, record: logging.LogRecord) -> logging.LogRecord:
        new = copy.copy(record)
        new.msg = self._redactor.redact(self._render(record))
        new.args = None
        if record.exc_info:
            new.exc_text = self._formatter.formatException(record.exc_info)
        if new.exc_text:
            new.exc_text = self._redactor.redact(new.exc_text)
        new.exc_info = None
        if record.stack_info:
            new.stack_info = self._redactor.redact(record.stack_info)
        return new

    @staticmethod
    def _render(record: logging.LogRecord) -> str:
        try:
            return record.getMessage()
        except (TypeError, ValueError, KeyError):
            return f"{record.msg!s} | args={record.args!r}"
