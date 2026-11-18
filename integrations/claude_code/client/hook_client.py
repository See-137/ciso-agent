#!/usr/bin/env python3
"""Hook client for the company's AI-governance service (component C2).

Claude Code runs this script as a command hook. It reads the hook's JSON from stdin,
adds what it can read on the machine (operating-system account, host name, surface),
sends it to the governance service, and turns the answer into the hook output that the
Claude Code hooks reference documents (https://code.claude.com/docs/en/hooks.md).

Usage: ``hook_client.py decide`` or ``hook_client.py report``.

decide  POST /v1/governance/decide before an action. ``deny`` and ``ask`` become the
        event's documented decision fields; ``allow`` prints nothing, so the normal
        permission flow still applies. ANY failure exits 2 with a fixed message, which
        blocks PreToolUse and UserPromptSubmit (the hook also sets onFailure "block").
report  POST /v1/activity after something happened. Never blocks: one retry, then a
        local log line and exit 0.

Configuration comes only from environment variables that the managed policy pack sets
through the managed settings ``env`` block (managed values override the user's shell):

    AIGOV_SERVICE_URL              base URL; https, or http to localhost/127.0.0.1 only
    AIGOV_DEVICE_TOKEN_FILE        path of the file holding the device token
    AIGOV_DECIDE_TIMEOUT_SECONDS   network timeout in decide mode (no default: unset blocks)
    AIGOV_REPORT_TIMEOUT_SECONDS   network timeout in report mode (no default: unset drops)
    AIGOV_CA_BUNDLE                optional CA bundle (PEM) to verify the service
    AIGOV_SURFACE                  optional surface label, default "cli"
    AIGOV_LOG_FILE                 optional local log path

The device token is read from a file, never from the environment (the environment
reaches every command the agent runs), and is never printed or logged.

Standard library only. Targets Python 3.10 and later.
"""

from __future__ import annotations

import getpass
import json
import math
import os
import re
import socket
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import IO, Any, Protocol

# --- structural bounds (sizes and counts, not tunable safety parameters) -------------

#: The decision API's request cap (docs/skill/decision-api.md).
MAX_REQUEST_BYTES = 256 * 1024
MAX_RESPONSE_BYTES = 64 * 1024
MAX_TOKEN_BYTES = 4096
MAX_MESSAGE_CHARS = 1000
#: Upper bound accepted for a configured network timeout, in seconds.
MAX_TIMEOUT_SECONDS = 600.0

DECIDE_PATH = "/v1/governance/decide"
ACTIVITY_PATH = "/v1/activity"
REQUEST_FORMAT = "assistant_hook_v1"
DEFAULT_SURFACE = "cli"

BLOCK_MESSAGE = (
    "Blocked: the company AI-governance check could not be completed. "
    "Nothing was run. Ask your IT or security contact if this continues."
)
GENERIC_REFUSAL = "Refused by the company AI-governance policy."

ENV_URL = "AIGOV_SERVICE_URL"
ENV_TOKEN_FILE = "AIGOV_DEVICE_TOKEN_FILE"  # noqa: S105 - a variable name, not a secret
ENV_DECIDE_TIMEOUT = "AIGOV_DECIDE_TIMEOUT_SECONDS"
ENV_REPORT_TIMEOUT = "AIGOV_REPORT_TIMEOUT_SECONDS"
ENV_CA_BUNDLE = "AIGOV_CA_BUNDLE"
ENV_SURFACE = "AIGOV_SURFACE"
ENV_LOG_FILE = "AIGOV_LOG_FILE"

LOOPBACK_HOSTS = frozenset({"localhost", "127.0.0.1"})
VERDICTS = frozenset({"allow", "deny", "ask"})
DECIDE_EVENTS = frozenset({"PreToolUse", "UserPromptSubmit", "SessionStart"})

_TOKEN_RE = re.compile(r"[A-Za-z0-9._~+/=-]+")
_EVENT_RE = re.compile(r"[A-Za-z]{1,64}")
_DECISION_ID_RE = re.compile(r"[A-Za-z0-9_.:-]{1,128}")
_SURFACE_RE = re.compile(r"[a-z][a-z0-9_-]{0,31}")
_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f-\x9f]")
_ANSI_RE = re.compile(r"\x1b\[[0-9;?]*[ -/]*[@-~]")


class ClientError(Exception):
    """A failure with a short code that is safe to write to the local log."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


@dataclass(frozen=True)
class HttpResponse:
    status: int
    body: bytes


class Transport(Protocol):
    """Sends one POST. Raises on connection, TLS or timeout errors."""

    def post(
        self,
        url: str,
        body: bytes,
        headers: Mapping[str, str],
        timeout: float,
        context: ssl.SSLContext | None,
    ) -> HttpResponse: ...


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """A redirect could carry the bearer token to another host: refuse every one."""

    def redirect_request(self, *args: Any, **kwargs: Any) -> None:
        return None


class UrllibTransport:
    """The real transport: urllib, certificate verification, no redirects."""

    def post(
        self,
        url: str,
        body: bytes,
        headers: Mapping[str, str],
        timeout: float,
        context: ssl.SSLContext | None,
    ) -> HttpResponse:
        handlers: list[Any] = [_NoRedirect()]
        if context is not None:
            handlers.append(urllib.request.HTTPSHandler(context=context))
        opener = urllib.request.build_opener(*handlers)
        request = urllib.request.Request(url, data=body, headers=dict(headers), method="POST")  # noqa: S310 - scheme checked in validate_service_url
        try:
            with opener.open(request, timeout=timeout) as response:
                return HttpResponse(int(response.status), response.read(MAX_RESPONSE_BYTES + 1))
        except urllib.error.HTTPError as error:
            with error:
                return HttpResponse(int(error.code), error.read(MAX_RESPONSE_BYTES + 1))


@dataclass(frozen=True)
class ClientConfig:
    service_url: str
    token: str
    timeout: float
    context: ssl.SSLContext | None
    surface: str

    def __repr__(self) -> str:  # never show the token
        return f"ClientConfig(service_url={self.service_url!r}, timeout={self.timeout})"


@dataclass(frozen=True)
class Verdict:
    verdict: str
    decision_id: str
    message: str


@dataclass(frozen=True)
class HookOutput:
    exit_code: int
    stdout: str = ""
    stderr: str = ""


# --- configuration ---------------------------------------------------------------------


def validate_service_url(raw: str) -> str:
    """Return the base URL without a trailing slash, or raise.

    https is required; plain http only to localhost or 127.0.0.1. No credentials, query
    or fragment in the URL.
    """
    parsed = urllib.parse.urlsplit(raw.strip())
    if parsed.scheme not in ("https", "http") or not parsed.hostname:
        raise ClientError("bad_url")
    if parsed.username is not None or parsed.password is not None:
        raise ClientError("bad_url")
    if parsed.query or parsed.fragment:
        raise ClientError("bad_url")
    if parsed.scheme == "http" and parsed.hostname not in LOOPBACK_HOSTS:
        raise ClientError("plain_http_refused")
    return urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, parsed.path.rstrip("/"), "", ""))


def parse_timeout(raw: str | None) -> float:
    if raw is None:
        raise ClientError("no_timeout")
    try:
        value = float(raw)
    except ValueError as error:
        raise ClientError("bad_timeout") from error
    if not math.isfinite(value) or value <= 0 or value > MAX_TIMEOUT_SECONDS:
        raise ClientError("bad_timeout")
    return value


def read_token(path_text: str | None) -> str:
    if not path_text:
        raise ClientError("no_token_file")
    try:
        with Path(path_text).open("rb") as handle:
            data = handle.read(MAX_TOKEN_BYTES + 1)
    except OSError as error:
        raise ClientError("token_unreadable") from error
    if len(data) > MAX_TOKEN_BYTES:
        raise ClientError("token_too_large")
    try:
        token = data.decode("ascii").strip()
    except UnicodeDecodeError as error:
        raise ClientError("token_invalid") from error
    if not _TOKEN_RE.fullmatch(token):
        raise ClientError("token_invalid")
    return token


def tls_context(url: str, ca_bundle: str | None) -> ssl.SSLContext | None:
    if not url.startswith("https://"):
        return None
    if ca_bundle:
        if not Path(ca_bundle).is_file():
            raise ClientError("ca_bundle_missing")
        return ssl.create_default_context(cafile=ca_bundle)
    return ssl.create_default_context()


def load_config(environ: Mapping[str, str], timeout_variable: str) -> ClientConfig:
    raw_url = environ.get(ENV_URL)
    if not raw_url:
        raise ClientError("no_service_url")
    url = validate_service_url(raw_url)
    timeout = parse_timeout(environ.get(timeout_variable))
    token = read_token(environ.get(ENV_TOKEN_FILE))
    context = tls_context(url, environ.get(ENV_CA_BUNDLE))
    surface = environ.get(ENV_SURFACE, DEFAULT_SURFACE)
    if not _SURFACE_RE.fullmatch(surface):
        surface = DEFAULT_SURFACE
    return ClientConfig(url, token, timeout, context, surface)


# --- request ---------------------------------------------------------------------------


def os_account_claim(
    environ: Mapping[str, str], is_windows: bool, getuser: Callable[[], str]
) -> dict[str, Any] | None:
    """The logged-in operating-system account, as read on this machine. Never verified.

    Windows: ``DOMAIN\\user`` from USERDOMAIN and USERNAME. Elsewhere: the account name
    from the password database (``getuser``). The service decides what it is worth.
    """
    subject = ""
    if is_windows:
        user = environ.get("USERNAME", "")
        domain = environ.get("USERDOMAIN", "")
        subject = f"{domain}\\{user}" if domain and user else user
    if not subject:
        try:
            subject = getuser()
        except (OSError, KeyError, ImportError):
            return None
    if not subject:
        return None
    return {"kind": "os_account", "subject": subject, "verified": False}


def posix_or_env_user() -> str:
    """Account name from the password database where it exists, else getpass."""
    if sys.platform != "win32":
        import pwd

        try:
            return str(pwd.getpwuid(os.getuid()).pw_name)
        except KeyError:
            pass
    return getpass.getuser()


def parse_hook_input(raw: bytes) -> dict[str, Any]:
    try:
        payload = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as error:
        raise ClientError("bad_hook_input") from error
    if not isinstance(payload, dict):
        raise ClientError("bad_hook_input")
    event = payload.get("hook_event_name")
    if not isinstance(event, str) or not _EVENT_RE.fullmatch(event):
        raise ClientError("bad_hook_event")
    return payload


def build_body(
    payload: dict[str, Any], config: ClientConfig, device: str, claim: dict[str, Any] | None
) -> bytes:
    body = {
        "format": REQUEST_FORMAT,
        "event": payload["hook_event_name"],
        "surface": config.surface,
        "device": device,
        "claims": [claim] if claim else [],
        "payload": payload,
    }
    data = json.dumps(body, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    if len(data) > MAX_REQUEST_BYTES:
        raise ClientError("too_large")
    return data


def headers_for(config: ClientConfig) -> dict[str, str]:
    return {
        "Authorization": "Bearer " + config.token,
        "Content-Type": "application/json",
        "Accept": "application/json",
    }


# --- response --------------------------------------------------------------------------


def clean_message(text: str) -> str:
    text = _ANSI_RE.sub("", text)
    text = _CONTROL_RE.sub(" ", text)
    return " ".join(text.split())[:MAX_MESSAGE_CHARS]


def parse_verdict(response: HttpResponse) -> Verdict:
    if response.status != 200:
        raise ClientError(f"status_{response.status}")
    if len(response.body) > MAX_RESPONSE_BYTES:
        raise ClientError("response_too_large")
    try:
        data = json.loads(response.body.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as error:
        raise ClientError("malformed_response") from error
    if not isinstance(data, dict):
        raise ClientError("malformed_response")
    verdict = data.get("verdict")
    decision_id = data.get("decision_id")
    message = data.get("message", "")
    if verdict not in VERDICTS:
        raise ClientError("unknown_verdict")
    if not isinstance(decision_id, str) or not _DECISION_ID_RE.fullmatch(decision_id):
        raise ClientError("bad_decision_id")
    if not isinstance(message, str):
        raise ClientError("malformed_response")
    return Verdict(str(verdict), decision_id, clean_message(message))


def refusal_text(verdict: Verdict) -> str:
    message = verdict.message or GENERIC_REFUSAL
    return f"{message} (AI-governance decision {verdict.decision_id})"


def render(event: str, verdict: Verdict) -> HookOutput:
    """Map a verdict to the output the hooks reference documents for ``event``."""
    if event not in DECIDE_EVENTS:
        raise ClientError("event_not_decidable")
    if verdict.verdict == "allow":
        return HookOutput(0)
    text = refusal_text(verdict)
    output: dict[str, Any]
    if event == "PreToolUse":
        output = {
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": verdict.verdict,
                "permissionDecisionReason": text,
            }
        }
    elif event == "UserPromptSubmit":
        # A prompt cannot be held for a person, so "ask" blocks it with the reason.
        output = {
            "decision": "block",
            "reason": text,
            "hookSpecificOutput": {
                "hookEventName": "UserPromptSubmit",
                "suppressOriginalPrompt": True,
            },
        }
    else:
        # SessionStart has no decision field; continue:false stops processing.
        output = {"continue": False, "stopReason": text}
    return HookOutput(0, json.dumps(output))


def block_output(event: str | None) -> HookOutput:
    stdout = ""
    if event == "SessionStart":
        # Measured 2026-11-18 (2.1.316, -p): this did not stop the session; the prompt
        # and tool hooks still block. Kept because the docs describe it as a stop.
        stdout = json.dumps({"continue": False, "stopReason": BLOCK_MESSAGE})
    elif event == "UserPromptSubmit":
        # Documented to apply with exit 2: keeps the prompt text out of the block message.
        stdout = json.dumps(
            {
                "hookSpecificOutput": {
                    "hookEventName": "UserPromptSubmit",
                    "suppressOriginalPrompt": True,
                }
            }
        )
    return HookOutput(2, stdout, BLOCK_MESSAGE + "\n")


# --- local log -------------------------------------------------------------------------


def log_line(environ: Mapping[str, str], mode: str, event: str, outcome: str) -> None:
    """Append one line: time, mode, event, outcome code. Never content, never the token.

    A log that cannot be written must not change the hook's outcome, so write errors
    are dropped here on purpose.
    """
    path_text = environ.get(ENV_LOG_FILE) or str(
        Path(environ.get("CLAUDE_PLUGIN_DATA") or os.environ.get("TEMP", "/tmp")) / "aigov-hook.log"  # noqa: S108
    )
    stamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    line = f"{stamp} mode={mode} event={event or '-'} outcome={outcome}\n"
    try:
        with Path(path_text).open("a", encoding="utf-8") as handle:
            handle.write(line)
    except OSError:
        return


# --- modes -----------------------------------------------------------------------------


@dataclass(frozen=True)
class Machine:
    hostname: Callable[[], str]
    is_windows: bool
    getuser: Callable[[], str]


def _prepare(
    raw: bytes, environ: Mapping[str, str], timeout_variable: str, machine: Machine
) -> tuple[dict[str, Any], ClientConfig, bytes]:
    payload = parse_hook_input(raw)
    config = load_config(environ, timeout_variable)
    claim = os_account_claim(environ, machine.is_windows, machine.getuser)
    body = build_body(payload, config, machine.hostname(), claim)
    return payload, config, body


def run_decide(
    raw: bytes, environ: Mapping[str, str], transport: Transport, machine: Machine
) -> HookOutput:
    event: str | None = None
    try:
        payload, config, body = _prepare(raw, environ, ENV_DECIDE_TIMEOUT, machine)
        event = str(payload["hook_event_name"])
        response = transport.post(
            config.service_url + DECIDE_PATH,
            body,
            headers_for(config),
            config.timeout,
            config.context,
        )
        return render(event, parse_verdict(response))
    except ClientError as error:
        log_line(environ, "decide", event or "-", error.code)
    except Exception as error:
        log_line(environ, "decide", event or "-", type(error).__name__)
    return block_output(event)


def run_report(
    raw: bytes, environ: Mapping[str, str], transport: Transport, machine: Machine
) -> HookOutput:
    event = "-"
    try:
        payload, config, body = _prepare(raw, environ, ENV_REPORT_TIMEOUT, machine)
        event = str(payload["hook_event_name"])
    except ClientError as error:
        log_line(environ, "report", event, "dropped:" + error.code)
        return HookOutput(0)
    url = config.service_url + ACTIVITY_PATH
    last = "unknown"
    for _attempt in range(2):  # the contract allows one retry
        try:
            response = transport.post(
                url, body, headers_for(config), config.timeout, config.context
            )
        except Exception as error:
            last = type(error).__name__
            continue
        if response.status == 202:
            return HookOutput(0)
        last = f"status_{response.status}"
    log_line(environ, "report", event, "dropped:" + last)
    return HookOutput(0)


def main(
    argv: list[str],
    *,
    stdin: IO[bytes],
    stdout: IO[str],
    stderr: IO[str],
    environ: Mapping[str, str],
    transport: Transport,
    hostname: Callable[[], str] = socket.gethostname,
    is_windows: bool = sys.platform == "win32",
    getuser: Callable[[], str] = posix_or_env_user,
) -> int:
    mode = argv[1] if len(argv) == 2 else ""
    machine = Machine(hostname, is_windows, getuser)
    if mode == "report":
        result = run_report(stdin.read(), environ, transport, machine)
    elif mode == "decide":
        result = run_decide(stdin.read(), environ, transport, machine)
    else:
        result = block_output(None)
    stdout.write(result.stdout)
    stderr.write(result.stderr)
    stdout.flush()
    stderr.flush()
    return result.exit_code


if __name__ == "__main__":
    sys.exit(
        main(
            sys.argv,
            stdin=sys.stdin.buffer,
            stdout=sys.stdout,
            stderr=sys.stderr,
            environ=os.environ,
            transport=UrllibTransport(),
        )
    )
