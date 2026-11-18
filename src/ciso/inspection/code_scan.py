"""Risky code patterns in new or changed lines.

Table-driven: each entry is a rule (id, category, severity, fixed remediation) and a line
pattern, optionally with a second pattern the same line must also match. Only the lines
handed in are checked; for a diff that is the added lines, so code that was already there
is not reported again. Patterns are bounded so a hostile line cannot make matching slow.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Final

from ciso.common.activity import Severity
from ciso.inspection._collect import Collector, location
from ciso.inspection.rules import Rule

_CODE = "code_risk"


@dataclass(frozen=True, slots=True)
class _LineRule:
    rule: Rule
    pattern: re.Pattern[str]
    also: re.Pattern[str] | None = None


def _rule(rule_id: str, severity: Severity, title: str, remediation: str) -> Rule:
    return Rule(rule_id, _CODE, severity, title, remediation)


TLS_DISABLED = _rule(
    "code.tls_verify_disabled",
    Severity.HIGH,
    "TLS certificate or host name verification switched off",
    "Keep verification on; add the internal certificate authority to the trust store",
)
DYNAMIC_EVAL = _rule(
    "code.dynamic_eval",
    Severity.HIGH,
    "Text evaluated as code",
    "Parse the input with a safe parser (for example a literal or JSON parser) instead",
)
SHELL_INJECTION = _rule(
    "code.shell_injection",
    Severity.HIGH,
    "Shell command built from formatted text",
    "Pass the command as an argument list without a shell, and never format input into it",
)
SQL_FORMATTING = _rule(
    "code.sql_string_format",
    Severity.HIGH,
    "SQL statement built by string formatting",
    "Use bound query parameters instead of formatting values into SQL",
)
UNSAFE_DESERIALIZE = _rule(
    "code.unsafe_deserialization",
    Severity.HIGH,
    "Unsafe deserialisation that can run code",
    "Use a data-only format or the safe loader; never deserialise untrusted bytes this way",
)
HARDCODED_IP = _rule(
    "code.hardcoded_ip",
    Severity.MEDIUM,
    "Network call to a hard-coded IP address",
    "Read the endpoint from configuration so it can be reviewed and changed",
)
HARDCODED_URL = _rule(
    "code.hardcoded_url",
    Severity.LOW,
    "Network call to a hard-coded host",
    "Read the endpoint from configuration so it can be reviewed and changed",
)
CORS_WILDCARD = _rule(
    "code.cors_wildcard",
    Severity.MEDIUM,
    "Cross-origin access opened to every origin",
    "List the allowed origins explicitly",
)
DEBUG_ENABLED = _rule(
    "code.debug_enabled",
    Severity.MEDIUM,
    "Debug mode switched on",
    "Keep debug mode off outside local development; read it from configuration",
)
WORLD_WRITABLE = _rule(
    "code.world_writable",
    Severity.HIGH,
    "Permissions opened to everyone",
    "Grant the narrowest permissions the file needs, never write access for all users",
)
PIPE_TO_SHELL = _rule(
    "code.pipe_to_shell",
    Severity.HIGH,
    "Downloaded script piped straight into an interpreter",
    "Download to a file, verify its checksum or signature, review it, then run it",
)
LINT_SUPPRESSED = _rule(
    "code.security_lint_suppressed",
    Severity.MEDIUM,
    "Security lint or scanner suppressed",
    "Fix the reported issue instead of suppressing it, or record a reviewed exception",
)

_FORMATTED = re.compile(
    r"\bf[\"']|\.format\(|[\"']\s{0,8}%\s{0,8}[\w(]|[\"']\s{0,8}\+|\+\s{0,8}[\"']|`[^`]{0,512}\$\{"
)
_SQL = r"(?:select\s[^\"'`]{0,256}?\sfrom|insert\s+into|update\s+\w{1,64}\s+set|delete\s+from)"
_LOOPBACK = r"(?!(?:localhost|127\.0\.0\.1|\[::1\]|0\.0\.0\.0)\b)"
_NET_CALL = (
    r"\b(?:get|post|put|patch|delete|head|request|fetch|urlopen|connect|create_connection"
    r"|Request|axios|open)\s{0,4}\(\s{0,4}[\"'`]"
)

_LINE_RULES: Final[tuple[_LineRule, ...]] = (
    _LineRule(
        TLS_DISABLED,
        re.compile(
            r"\bverify\s{0,4}=\s{0,4}False\b|_create_unverified_context|\bCERT_NONE\b"
            r"|check_hostname\s{0,4}=\s{0,4}False|rejectUnauthorized[\"']?\s{0,4}:\s{0,4}false"
            r"|NODE_TLS_REJECT_UNAUTHORIZED[\"']?\s{0,4}[=:]\s{0,4}[\"']?0"
            r"|InsecureSkipVerify\s{0,4}:\s{0,4}true|--no-check-certificate"
            r"|(?i:\bcurl\b[^|;&\n]{0,512}\s(?:-k|--insecure)\b)"
            r"|(?i:http\.sslverify[\s=\"']{1,8}false)|(?i:strict-ssl[\s=:\"']{1,8}false)"
        ),
    ),
    _LineRule(
        DYNAMIC_EVAL,
        re.compile(r"(?<![.\w])(?:eval|exec)\s{0,4}\((?!\s{0,4}[\"'])|\bnew\s+Function\s*\("),
    ),
    _LineRule(
        SHELL_INJECTION,
        re.compile(r"\bshell\s{0,4}=\s{0,4}True\b|\bos\.(?:system|popen)\s{0,4}\("),
        _FORMATTED,
    ),
    _LineRule(
        SHELL_INJECTION,
        re.compile(r"\b(?:child_process\.)?exec(?:Sync)?\s{0,4}\(\s{0,4}`[^`]{0,512}\$\{"),
    ),
    _LineRule(
        SQL_FORMATTING,
        re.compile(
            rf"(?i)\bf[\"'][^\"']{{0,512}}?{_SQL}[^\"']{{0,512}}?\{{"
            rf"|[\"'][^\"']{{0,512}}?{_SQL}[^\"']{{0,512}}?[\"']\s{{0,8}}(?:%\s{{0,8}}[\w(]|\+|\.format\()"
            rf"|`[^`]{{0,512}}?{_SQL}[^`]{{0,512}}?\$\{{"
        ),
    ),
    _LineRule(
        UNSAFE_DESERIALIZE,
        re.compile(
            r"\b(?:c?pickle|dill|marshal|jsonpickle)\.(?:loads?|decode|Unpickler)\s{0,4}\("
            r"|\byaml\.unsafe_load\s{0,4}\(|\byaml\.load\s{0,4}\((?![^)]{0,512}SafeLoader)"
            r"|\bshelve\.open\s{0,4}\(|\bObjectInputStream\s{0,4}\(|\bBinaryFormatter\b"
        ),
    ),
    _LineRule(
        HARDCODED_IP,
        re.compile(rf"{_NET_CALL}(?:[a-z]{{2,8}}://)?{_LOOPBACK}(?:\d{{1,3}}\.){{3}}\d{{1,3}}\b"),
    ),
    _LineRule(
        HARDCODED_URL,
        re.compile(rf"{_NET_CALL}(?:https?|wss?|ftp)://{_LOOPBACK}(?!(?:\d{{1,3}}\.){{3}})"),
    ),
    _LineRule(
        CORS_WILDCARD,
        re.compile(
            r"(?i)access-control-allow-origin[\"']?\s{0,4}[:,=]\s{0,4}[\"']\*[\"']"
            r"|allow_origins\s{0,4}=\s{0,4}\[\s{0,4}[\"']\*[\"']"
            r"|\borigins?[\"']?\s{0,4}[:=]\s{0,4}[\"']\*[\"']"
            r"|cors_(?:origin_)?allow_all(?:_origins)?\s{0,4}=\s{0,4}true"
        ),
    ),
    _LineRule(
        DEBUG_ENABLED,
        re.compile(
            r"(?<![\w.])(?:DEBUG|debug)[\"']?\s{0,4}[:=]\s{0,4}(?:True|true|1|[\"']true[\"'])\b"
            r"|\bFLASK_DEBUG\s{0,4}=\s{0,4}[\"']?1|\bapp\.run\([^)]{0,512}debug\s{0,4}=\s{0,4}True"
        ),
    ),
    _LineRule(
        WORLD_WRITABLE,
        re.compile(
            r"\bchmod\s+(?:-[A-Za-z]{1,4}\s+){0,3}(?:0?777|a\+rwx|o\+w|a\+w)\b"
            r"|\bchmod\s{0,4}\([^)]{0,512}0o?777\s{0,4}\)"
        ),
    ),
    _LineRule(
        PIPE_TO_SHELL,
        re.compile(
            r"(?i)\b(?:curl|wget)\b[^|;&\n]{0,512}\|\s{0,4}(?:sudo\s+(?:-\S+\s+){0,3})?"
            r"(?:ba|z|da|k|fi)?sh\b"
            r"|\b(?:curl|wget)\b[^|;&\n]{0,512}\|\s{0,4}(?:sudo\s+)?(?:python3?|perl|ruby|node)\b"
            r"|\b(?:iwr|irm|invoke-webrequest|invoke-restmethod)\b[^|\n]{0,512}\|\s{0,4}(?:iex|invoke-expression)\b"
            r"|\b(?:sh|bash)\s+-c\s+[\"']?\$\((?:curl|wget)\b"
        ),
    ),
    _LineRule(
        LINT_SUPPRESSED,
        re.compile(
            r"#\s{0,4}nosec\b|//\s{0,4}NOSONAR\b|#\s{0,4}noqa\s{0,4}:\s{0,4}[^\n]{0,64}\bS\d{3}"
            r"|//\s{0,4}nolint\s{0,4}:\s{0,4}[^\n]{0,64}\bgosec"
            r"|eslint-disable(?:-next-line|-line)?\s{1,8}[^\n]{0,256}"
            r"(?:security|no-eval|no-implied-eval|no-new-func|no-unsanitized|detect-)"
            r"|eslint-disable(?:-next-line|-line)?\s{0,8}(?:\*/)?\s{0,8}$"
            r"|@SuppressWarnings\(\s{0,4}[\"'](?:security|find-sec-bugs)"
            r"|pylint:\s{0,4}disable\s{0,4}=[^\n]{0,256}(?:eval-used|exec-used)"
        ),
    ),
)


def scan_code(lines: Iterable[tuple[int, str]], path: str, out: Collector) -> None:
    """Add a finding for each risky pattern on the given (line number, text) pairs.

    One finding per rule per line: a line with two TLS switches is one finding.
    """
    for number, text in lines:
        seen: set[str] = set()
        for entry in _LINE_RULES:
            if entry.rule.rule_id in seen:
                continue
            match = entry.pattern.search(text)
            if match is None or (entry.also is not None and not entry.also.search(text)):
                continue
            seen.add(entry.rule.rule_id)
            out.add(entry.rule, location(path, number, match.start() + 1))


CODE_RULES: Final[tuple[Rule, ...]] = tuple(dict.fromkeys(entry.rule for entry in _LINE_RULES))
