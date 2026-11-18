"""Secret detection: token shapes, key-like assignments and long high-entropy values.

Line by line, deterministic, no model. A finding names the rule and the line and column;
it never carries the value. Obvious placeholders (`<token>`, `xxxx`, `changeme`, `${VAR}`,
`os.environ[...]`, `secret://` references) are not reported.

The shapes are generic: each names a token format, not a provider. They overlap the
vault's redaction shapes (`ciso.vault.redact`) on purpose and are kept here because a
detector needs the value's span and placeholder check, which redaction does not expose.
"""

from __future__ import annotations

import math
import re
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import PurePosixPath
from typing import Final

from ciso.common.activity import Severity
from ciso.inspection._collect import Collector, location
from ciso.inspection.rules import Rule

#: A value shorter than this after a key-like name is not reported (quoted, bare).
MIN_QUOTED_VALUE: Final = 4
MIN_BARE_VALUE: Final = 6
#: The high-entropy check: shortest value and the Shannon entropy floor in bits per char.
HIGH_ENTROPY_MIN_LENGTH: Final = 24
HIGH_ENTROPY_MIN_BITS: Final = 4.0

_CATEGORY = "secret"
_ROTATE = "Remove the value, rotate the credential and load it from the secret store"

PRIVATE_KEY = Rule(
    "secret.private_key",
    _CATEGORY,
    Severity.CRITICAL,
    "Private key block",
    "Remove the key, treat it as exposed and issue a new one; keep keys in the secret store",
)
CLOUD_ACCESS_KEY = Rule(
    "secret.cloud_access_key",
    _CATEGORY,
    Severity.HIGH,
    "Cloud access key id",
    _ROTATE,
)
JWT = Rule("secret.jwt", _CATEGORY, Severity.HIGH, "Signed web token", _ROTATE)
BEARER = Rule(
    "secret.bearer_token",
    _CATEGORY,
    Severity.HIGH,
    "Bearer or basic authorization credential",
    _ROTATE,
)
SERVICE_TOKEN = Rule(
    "secret.service_token",
    _CATEGORY,
    Severity.HIGH,
    "Service access token with a known token prefix",
    _ROTATE,
)
CONNECTION_STRING = Rule(
    "secret.connection_string",
    _CATEGORY,
    Severity.HIGH,
    "Connection string with an embedded password",
    "Remove the password from the connection string and load it from the secret store",
)
ASSIGNMENT = Rule(
    "secret.assignment",
    _CATEGORY,
    Severity.HIGH,
    "Password, secret or token assigned a literal value",
    _ROTATE,
)
HIGH_ENTROPY = Rule(
    "secret.high_entropy",
    _CATEGORY,
    Severity.MEDIUM,
    "Long random-looking value assigned in code or configuration",
    "If this is a credential, remove it, rotate it and load it from the secret store",
)


@dataclass(frozen=True, slots=True)
class _Shape:
    rule: Rule
    pattern: re.Pattern[str]


# Token shapes. A group named `val` marks the value; otherwise the whole match is it.
_SHAPES: Final[tuple[_Shape, ...]] = (
    _Shape(
        PRIVATE_KEY,
        re.compile(r"-----BEGIN (?:[A-Z0-9]{1,16} ){0,3}PRIVATE KEY(?: BLOCK)?-----"),
    ),
    _Shape(
        CLOUD_ACCESS_KEY,
        re.compile(
            r"(?<![A-Z0-9])(?:AKIA|ASIA|AGPA|AIDA|AROA|ANPA|ANVA|AIPA)[A-Z0-9]{16}(?![A-Z0-9])"
        ),
    ),
    _Shape(
        JWT,
        re.compile(
            r"(?<![\w-])eyJ[A-Za-z0-9_-]{8,4096}\.eyJ[A-Za-z0-9_-]{4,4096}\.[A-Za-z0-9_-]{8,4096}"
        ),
    ),
    _Shape(
        BEARER,
        re.compile(
            r"(?i)\b(?:bearer|basic)\s+(?P<val>(?=[A-Za-z]{0,512}[0-9\-._~+/])"
            r"[A-Za-z0-9\-._~+/]{16,4096}=*)"
        ),
    ),
    _Shape(
        SERVICE_TOKEN,
        re.compile(
            r"(?<![A-Za-z0-9_-])(?:"
            r"gh[pousr]_[A-Za-z0-9]{36,255}"
            r"|github_pat_[A-Za-z0-9_]{50,255}"
            r"|glpat-[A-Za-z0-9_-]{20,64}"
            r"|xox[abposr]-[A-Za-z0-9-]{10,255}"
            r"|(?:sk|rk)_live_[A-Za-z0-9]{20,255}"
            r"|sk-(?:[a-z]{2,12}-)?[A-Za-z0-9_-]{32,255}"
            r"|AIza[0-9A-Za-z_-]{35}"
            r"|npm_[A-Za-z0-9]{36}"
            r"|pypi-[A-Za-z0-9_-]{50,255}"
            r"|SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}"
            r"|hf_[A-Za-z0-9]{34,64}"
            r"|dop_v1_[a-f0-9]{64}"
            r"|shp(?:at|ss|ca|pa)_[a-fA-F0-9]{32}"
            r")(?![A-Za-z0-9_-])"
        ),
    ),
    _Shape(
        CONNECTION_STRING,
        re.compile(
            r"\b[a-zA-Z][a-zA-Z0-9+.-]{1,20}://[^\s:/@'\"]{1,256}:(?P<val>[^\s@/'\"]{1,256})@"
        ),
    ),
)

_KEY_WORDS = (
    r"password|passwd|passphrase|secret|token|api[_-]?key|apikey|access[_-]?key"
    r"|private[_-]?key|client[_-]?secret|credentials?"
)
_ASSIGNMENT = re.compile(
    rf"(?i)(?<![A-Za-z0-9])(?P<key>[A-Za-z0-9_.-]{{0,64}}?(?:{_KEY_WORDS}))(?![A-Za-z0-9])"
    r"[\"']?\s*(?:=>|:=|[:=])(?!=)\s*"
    r"(?P<val>\$\{[^}\n]{0,256}\}|\"[^\"\n]{0,512}\"|'[^'\n]{0,512}'|`[^`\n]{0,512}`|[^\s,;'\"`)}\]]{1,512})"
)
_ENTROPY_CANDIDATE = re.compile(
    r"(?P<key>[A-Za-z_][A-Za-z0-9_.-]{0,63})[\"']?\s*(?:=>|:=|[:=])(?!=)\s*[\"'`]?"
    r"(?P<val>[A-Za-z0-9+/=_-]{24,512})"
)
_ENTROPY_KEY_EXEMPT = re.compile(
    r"(?i).{0,64}(?:hash|sha\d*|checksum|digest|integrity|commit|etag|revision|uuid|guid"
    r"|nonce|(?:^|[_.-])id)"
)

_PLACEHOLDER_WHOLE = re.compile(
    r"(?i)<[^<>]{0,256}>"
    r"|\$\{[^}]{0,256}\}|\$\(.{0,256}\)|\$[A-Za-z_][A-Za-z0-9_]{0,127}"
    r"|\{\{.{0,256}\}\}|%\([^)]{0,64}\)s|%[A-Za-z_][A-Za-z0-9_]{0,63}%"
    r"|[x*.#_-]{3,512}"
    r"|change[_-]?me|change[_-]?it|(?:your|my)[_-].{0,256}"
    r"|(?:os\.environ|os\.getenv|getenv|process\.env|environ|env)\b.{0,256}"
    r"|secret://.{0,256}"
    r"|none|null|nil|undefined|true|false|empty|redacted|\[redacted\]"
)
_PLACEHOLDER_PART = re.compile(
    r"(?i)example|dummy|placeholder|sample|fake|redacted|x{4}|\*{3}|(.)\1{7}"
)
_TYPE_NAMES: Final = frozenset(
    {"string", "secretstr", "optional", "required", "boolean", "number", "bytes", "object"}
)
_CODE_SUFFIXES: Final = frozenset(
    {
        ".py", ".pyi", ".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx", ".go", ".java", ".kt",
        ".rb", ".cs", ".php", ".rs", ".swift", ".scala", ".c", ".h", ".cpp", ".hpp", ".m",
    }
)  # fmt: skip
_CODE_REFERENCE = re.compile(r"[A-Za-z_][\w]*(?:\.[A-Za-z_]\w*)+|.*[(\[].*")


def is_placeholder(value: str) -> bool:
    """True for values that are obviously not a real secret."""
    stripped = value.strip()
    if not stripped:
        return True
    return bool(_PLACEHOLDER_WHOLE.fullmatch(stripped) or _PLACEHOLDER_PART.search(stripped))


def shannon_entropy(value: str) -> float:
    """Bits per character of `value`'s own character distribution."""
    if not value:
        return 0.0
    size = len(value)
    counts: dict[str, int] = {}
    for ch in value:
        counts[ch] = counts.get(ch, 0) + 1
    return -sum((n / size) * math.log2(n / size) for n in counts.values())


def _is_code_path(path: str) -> bool:
    return PurePosixPath(path.replace("\\", "/").lower()).suffix in _CODE_SUFFIXES


def _overlaps(span: tuple[int, int], taken: list[tuple[int, int]]) -> bool:
    return any(span[0] < end and start < span[1] for start, end in taken)


def _value_span(match: re.Match[str]) -> tuple[int, int]:
    return match.span("val") if "val" in match.groupdict() else match.span()


def _literal_value(raw: str, *, code_file: bool) -> str | None:
    """The literal a key-like name is given, or None when it is not a literal secret."""
    if raw[:1] in {'"', "'", "`"}:
        inner = raw[1:-1]
        return inner if len(inner) >= MIN_QUOTED_VALUE else None
    if code_file or len(raw) < MIN_BARE_VALUE or raw.isdigit():
        return None
    if raw.lower() in _TYPE_NAMES or _CODE_REFERENCE.fullmatch(raw):
        return None
    return raw


def scan_secrets(lines: Iterable[tuple[int, str]], path: str, out: Collector) -> None:
    """Add a finding for each secret on the given (line number, text) pairs."""
    code_file = _is_code_path(path)
    for number, text in lines:
        taken: list[tuple[int, int]] = []
        for shape in _SHAPES:
            for match in shape.pattern.finditer(text):
                span = _value_span(match)
                if is_placeholder(text[span[0] : span[1]]) or _overlaps(span, taken):
                    continue
                taken.append(span)
                out.add(shape.rule, location(path, number, match.start() + 1))
        for match in _ASSIGNMENT.finditer(text):
            span = match.span("val")
            value = _literal_value(match.group("val"), code_file=code_file)
            if value is None or is_placeholder(value) or _overlaps(span, taken):
                continue
            taken.append(span)
            out.add(ASSIGNMENT, location(path, number, match.start() + 1))
        for match in _ENTROPY_CANDIDATE.finditer(text):
            span = match.span("val")
            value = match.group("val")
            if _overlaps(span, taken) or not _random_looking(value):
                continue
            if _ENTROPY_KEY_EXEMPT.fullmatch(match.group("key")) or is_placeholder(value):
                continue
            taken.append(span)
            out.add(HIGH_ENTROPY, location(path, number, match.start() + 1))


def _random_looking(value: str) -> bool:
    mixed = (
        any(c.isupper() for c in value)
        and any(c.islower() for c in value)
        and any(c.isdigit() for c in value)
    )
    return (
        mixed
        and len(value) >= HIGH_ENTROPY_MIN_LENGTH
        and shannon_entropy(value) >= HIGH_ENTROPY_MIN_BITS
    )


SECRET_RULES: Final[tuple[Rule, ...]] = (
    *(shape.rule for shape in _SHAPES),
    ASSIGNMENT,
    HIGH_ENTROPY,
)
