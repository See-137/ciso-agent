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
        A PreToolUse ``deny`` that carries ``needs_change`` (a push or commit whose
        change must be scanned first) is followed here: the client builds the change
        with git in the hook's working directory, uploads it to POST /v1/changes and
        asks decide again with ``change_id`` and ``change_head``; that second answer is
        the one applied. Any failure on the way blocks. The whole run stays inside the
        configured hook deadline.
report  POST /v1/activity after something happened. Never blocks: one retry, then a
        local log line and exit 0.

Configuration (review C1). Nothing that decides where the client connects, whom it
trusts or which git it runs comes from the environment: the environment is the
engineer's (their shell, ``setx``, a wrapper) and reaches every command the agent runs.
The client reads ONE JSON file at a fixed path next to itself, ``aigov-client.json`` in
the admin-owned install directory, and refuses to run (decide blocks, report drops) when
that file is missing, malformed, or writable by the user running the hook
(``user_can_write``: best effort per operating system, see its docstring). Keys, all
required (``CONFIG_KEYS``)::

    service_url              https URL (plain http only to localhost/127.0.0.1)
    ca_bundle                absolute path of the PEM bundle that verifies the service;
                             the ONLY trust anchors used (null only for loopback http)
    token_file               absolute path of the file holding the device token
    decide_timeout_seconds   network timeout in decide mode
    report_timeout_seconds   network timeout in report mode
    hook_deadline_seconds    the client's whole time budget, below the hook's timeout
    git_path                 absolute path of the admin-installed git (pre-push)
    git_hooks_dir            the empty hooks directory the managed env names (pre-push:
                             the hook's GIT_* variables must be exactly the pack's)
    surface                  surface label, for example "cli"
    log_file                 absolute path of the local log (no content is logged)

No proxy is ever used (an explicit empty proxy handler: neither ``HTTPS_PROXY`` nor the
Windows registry proxy), and the TLS context loads the configured bundle only (never
``SSL_CERT_FILE``, ``SSL_CERT_DIR`` or the system store). The device token is read from
its file and is never printed or logged.

Standard library only. Targets Python 3.10 and later.
"""

from __future__ import annotations

import base64
import contextlib
import getpass
import json
import math
import os
import re
import socket
import ssl
import stat
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import IO, Any, Protocol

# --- structural bounds (sizes and counts, not tunable safety parameters) -------------

#: The decision API's request cap (docs/skill/decision-api.md).
MAX_REQUEST_BYTES = 256 * 1024
MAX_RESPONSE_BYTES = 64 * 1024
MAX_TOKEN_BYTES = 4096
MAX_CONFIG_BYTES = 16 * 1024
MAX_MESSAGE_CHARS = 1000
#: Upper bound accepted for a configured timeout or deadline, in seconds.
MAX_TIMEOUT_SECONDS = 600.0

#: Pre-push bounds. The bundle bound is the sandbox's archive bound (32 MiB); the request
#: cap equals the service's `MAX_CHANGE_BODY_BYTES` (a test pins the two together).
MAX_BUNDLE_BYTES = 32 * 1024 * 1024
MAX_DIFF_BYTES = 4 * 1024 * 1024
MAX_CHANGE_COMMITS = 1000
MAX_CHANGE_REQUEST_BYTES = ((MAX_BUNDLE_BYTES + MAX_DIFF_BYTES + 2) // 3) * 4 + 128 * 1024
MAX_GIT_OUTPUT_BYTES = MAX_DIFF_BYTES
#: Most approved bases the service lists for one repository and branch.
MAX_BASES = 64
MAX_REPOSITORY_CHARS = 512
#: Longest any single git step may take, inside the deadline.
GIT_STEP_SECONDS = 10.0
#: Kept back from the deadline for printing the answer; a step needs at least MIN_STEP.
DEADLINE_MARGIN_SECONDS = 0.5
MIN_STEP_SECONDS = 0.2

DECIDE_PATH = "/v1/governance/decide"
CHANGES_PATH = "/v1/changes"
BASES_PATH = "/v1/changes/bases"
ACTIVITY_PATH = "/v1/activity"
REQUEST_FORMAT = "assistant_hook_v1"

CONFIG_FILE_NAME = "aigov-client.json"
#: The one configuration file: next to this script, in the admin-owned install directory.
DEFAULT_CONFIG_PATH = Path(__file__).resolve().parent / CONFIG_FILE_NAME
CONFIG_KEYS = frozenset(
    {
        "service_url",
        "ca_bundle",
        "token_file",
        "decide_timeout_seconds",
        "report_timeout_seconds",
        "hook_deadline_seconds",
        "git_path",
        "surface",
        "log_file",
        "git_hooks_dir",
    }
)

BLOCK_MESSAGE = (
    "Blocked: the company AI-governance check could not be completed. "
    "Nothing was run. Ask your IT or security contact if this continues."
)
GENERIC_REFUSAL = "Refused by the company AI-governance policy."
PREPUSH_BLOCK_MESSAGE = (
    "Blocked: this push or commit could not be prepared for its pre-push scan, so it was "
    "stopped. Push one branch at a time with a plain git command, or ask your IT or "
    "security contact if this continues."
)
#: Fixed messages for pre-push refusals the engineer can act on (by ClientError code).
PREPUSH_MESSAGES = {
    "push_config": (
        "Blocked: this repository's git configuration changes where or how pushed data "
        "goes (a push URL, receive-pack, ssh command, pushInsteadOf, push refspec or "
        "mirror setting, or a git transport variable), so the pushed commits cannot be "
        "tied to the scanned ones. The agent may not push here; push it yourself."
    ),
    "too_many_unscanned": (
        "Blocked: this push carries more than 1000 commits that the company AI-governance "
        "service has not scanned before, so it cannot be scanned in one go. Push it "
        "yourself, or ask your IT or security contact."
    ),
    "device_busy": (
        "Held: another push from this machine is still being scanned. Retry this push "
        "in a minute; only one push per machine is scanned at a time."
    ),
    "shallow_repository": (
        "Blocked: this is a shallow clone, so its history cannot be scanned completely. "
        "Fetch the full history (git fetch --unshallow) or push it yourself."
    ),
}

LOOPBACK_HOSTS = frozenset({"localhost", "127.0.0.1"})
VERDICTS = frozenset({"allow", "deny", "ask"})
DECIDE_EVENTS = frozenset({"PreToolUse", "UserPromptSubmit", "SessionStart"})

_TOKEN_RE = re.compile(r"[A-Za-z0-9._~+/=-]+")
_EVENT_RE = re.compile(r"[A-Za-z]{1,64}")
_DECISION_ID_RE = re.compile(r"[A-Za-z0-9_.:-]{1,128}")
_SURFACE_RE = re.compile(r"[a-z][a-z0-9_-]{0,31}")
_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f-\x9f]")
_ANSI_RE = re.compile(r"\x1b\[[0-9;?]*[ -/]*[@-~]")
_COMMIT_RE = re.compile(r"[0-9a-f]{40}|[0-9a-f]{64}")
_REF_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._/-]{0,199}")
_REMOTE_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}")
_CHANGE_ID_RE = re.compile(r"chg_[0-9A-HJKMNP-TV-Z]{26}")
_URL_USERINFO_RE = re.compile(r"^([A-Za-z][A-Za-z0-9+.-]*://)[^/@]*@")
#: Windows `FILE_ATTRIBUTE_READONLY` (the user can clear it, so it proves nothing).
_READONLY_ATTRIBUTE = 0x1
#: Environment variables that change how the agent's own `git push` transports data.
#: The git configuration the managed pack's ``env`` gives the agent's own git (review H2,
#: queue Q16), in index order: ``GIT_CONFIG_KEY_n`` / ``GIT_CONFIG_VALUE_n``. None is the
#: admin-owned empty hooks directory, named by the configuration file's ``git_hooks_dir``.
#: ``managed/check_pack.py`` keeps the same table (a test pins the two together).
MANAGED_GIT_CONFIG: tuple[tuple[str, str | None], ...] = (
    ("core.hooksPath", None),
    ("safe.bareRepository", "explicit"),
    ("push.recurseSubmodules", "no"),
    ("protocol.ext.allow", "never"),
)


def managed_git_env(hooks_dir: str) -> dict[str, str]:
    """Exactly the ``GIT_*`` variables the managed pack sets, for this machine."""
    env = {"GIT_CONFIG_COUNT": str(len(MANAGED_GIT_CONFIG))}
    for index, (key, value) in enumerate(MANAGED_GIT_CONFIG):
        env[f"GIT_CONFIG_KEY_{index}"] = key
        env[f"GIT_CONFIG_VALUE_{index}"] = hooks_dir if value is None else value
    return env


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


def make_opener(context: ssl.SSLContext | None) -> urllib.request.OpenerDirector:
    """No proxy (an explicit empty handler, so urllib never reads ``*_PROXY`` or the
    registry), no redirects, and the given TLS context."""
    handlers: list[Any] = [urllib.request.ProxyHandler({}), _NoRedirect()]
    if context is not None:
        handlers.append(urllib.request.HTTPSHandler(context=context))
    return urllib.request.build_opener(*handlers)


class UrllibTransport:
    """The real transport: urllib, certificate verification, no proxy, no redirects."""

    def post(
        self,
        url: str,
        body: bytes,
        headers: Mapping[str, str],
        timeout: float,
        context: ssl.SSLContext | None,
    ) -> HttpResponse:
        opener = make_opener(context)
        request = urllib.request.Request(url, data=body, headers=dict(headers), method="POST")  # noqa: S310 - scheme checked in validate_service_url
        try:
            with opener.open(request, timeout=timeout) as response:
                return HttpResponse(int(response.status), response.read(MAX_RESPONSE_BYTES + 1))
        except urllib.error.HTTPError as error:
            with error:
                return HttpResponse(int(error.code), error.read(MAX_RESPONSE_BYTES + 1))


@dataclass(frozen=True)
class FileConfig:
    """The parsed configuration file. Paths are checked when they are used."""

    service_url: str
    ca_bundle: str | None
    token_file: str
    decide_timeout: float
    report_timeout: float
    hook_deadline: float
    git_path: str
    surface: str
    log_file: str
    git_hooks_dir: str


@dataclass(frozen=True)
class ClientConfig:
    service_url: str
    token: str
    timeout: float
    context: ssl.SSLContext | None
    surface: str
    git_path: str
    hook_deadline: float
    git_hooks_dir: str

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


def _windows_probe(path: Path) -> bool:
    """True unless both probes are refused by the operating system.

    Checks: (1) the file can be opened for appending (nothing is written, so neither the
    content nor the modification time changes); (2) a new file can be created in its
    directory (an exclusive create of a random name, removed at once). Cannot check:
    whether the user may change the ACL or take ownership (WRITE_DAC, WRITE_OWNER),
    whether a parent directory can be renamed, or a file the read-only attribute
    protects (that attribute is the user's to clear, so it counts as writable here).
    """
    try:
        attributes = int(getattr(os.stat(path), "st_file_attributes", 0))
    except OSError:
        return True
    if attributes & _READONLY_ATTRIBUTE:
        return True
    try:
        with path.open("ab"):
            return True
    except PermissionError:
        pass
    except OSError:
        return True
    probe = path.parent / f".aigov-probe-{uuid.uuid4().hex}"
    try:
        handle = os.open(probe, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
    except PermissionError:
        return False
    except OSError:
        return True
    os.close(handle)
    with contextlib.suppress(OSError):
        probe.unlink()
    return True


def _posix_writable(path: Path) -> bool:
    """True when the current user can write the file or its directory, or when the file
    or any directory above it is owned by the user (who could change its mode) or is
    writable by group or others (who may include the user)."""
    if os.access(path, os.W_OK) or os.access(path.parent, os.W_OK):
        return True
    me = os.geteuid() if hasattr(os, "geteuid") else -1
    for item in (path, *path.parents):
        try:
            info = os.stat(item)
        except OSError:
            return True
        if (me != 0 and info.st_uid == me) or info.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
            return True
    return False


def user_can_write(path: Path) -> bool:
    """Best effort: True when the user running the hook could change or replace `path`.

    POSIX: `os.access` on the file and its directory, then the owner and the group/other
    write bits of the file and every directory up to `/`. Windows: two probes the
    operating system answers from the real ACL (see `_windows_probe`). An error counts as
    writable (fail closed).
    """
    if sys.platform == "win32":
        return _windows_probe(path)
    return _posix_writable(path)


Writable = Callable[[Path], bool]


def _number(value: Any, code: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ClientError(code)
    number = float(value)
    if not math.isfinite(number) or number <= 0 or number > MAX_TIMEOUT_SECONDS:
        raise ClientError(code)
    return number


def _absolute_text(value: Any, code: str) -> str:
    if not isinstance(value, str) or not value or not Path(value).is_absolute():
        raise ClientError(code)
    return value


def read_file_config(path: Path, writable: Writable) -> FileConfig:
    """The configuration file, or ClientError. See the module docstring."""
    try:
        with path.open("rb") as handle:
            data = handle.read(MAX_CONFIG_BYTES + 1)
    except OSError as error:
        raise ClientError("no_config_file") from error
    if writable(path):
        raise ClientError("config_writable")
    if len(data) > MAX_CONFIG_BYTES:
        raise ClientError("bad_config")
    try:
        raw = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as error:
        raise ClientError("bad_config") from error
    if not isinstance(raw, dict) or set(raw) != CONFIG_KEYS:
        raise ClientError("bad_config")
    surface = raw["surface"]
    if not isinstance(surface, str) or not _SURFACE_RE.fullmatch(surface):
        raise ClientError("bad_config")
    ca_bundle = raw["ca_bundle"]
    if ca_bundle is not None:
        ca_bundle = _absolute_text(ca_bundle, "bad_config")
    return FileConfig(
        service_url=validate_service_url(raw["service_url"]),
        ca_bundle=ca_bundle,
        token_file=_absolute_text(raw["token_file"], "bad_config"),
        decide_timeout=_number(raw["decide_timeout_seconds"], "bad_timeout"),
        report_timeout=_number(raw["report_timeout_seconds"], "bad_timeout"),
        hook_deadline=_number(raw["hook_deadline_seconds"], "bad_timeout"),
        git_path=_absolute_text(raw["git_path"], "bad_config"),
        surface=surface,
        log_file=_absolute_text(raw["log_file"], "bad_config"),
        git_hooks_dir=_absolute_text(raw["git_hooks_dir"], "bad_config"),
    )


def validate_service_url(raw: Any) -> str:
    """Return the base URL without a trailing slash, or raise.

    https is required; plain http only to localhost or 127.0.0.1. No credentials, query
    or fragment in the URL.
    """
    if not isinstance(raw, str):
        raise ClientError("bad_url")
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


def tls_context(url: str, ca_bundle: str | None, writable: Writable) -> ssl.SSLContext | None:
    """The configured bundle and nothing else: no system store, no ``SSL_CERT_FILE`` or
    ``SSL_CERT_DIR`` (``load_default_certs`` and ``set_default_verify_paths`` are never
    called). A bundle the user can write is refused like a missing one."""
    if not url.startswith("https://"):
        return None
    if not ca_bundle or not Path(ca_bundle).is_file():
        raise ClientError("ca_bundle_missing")
    if writable(Path(ca_bundle)):
        raise ClientError("ca_bundle_writable")
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.check_hostname = True
    context.verify_mode = ssl.CERT_REQUIRED
    try:
        context.load_verify_locations(cafile=ca_bundle)
    except (OSError, ssl.SSLError) as error:
        raise ClientError("ca_bundle_invalid") from error
    return context


def load_config(file: FileConfig, timeout: float, writable: Writable) -> ClientConfig:
    token = read_token(file.token_file)
    context = tls_context(file.service_url, file.ca_bundle, writable)
    return ClientConfig(
        file.service_url,
        token,
        timeout,
        context,
        file.surface,
        file.git_path,
        file.hook_deadline,
        file.git_hooks_dir,
    )


# --- request ---------------------------------------------------------------------------


def os_account_claim(
    environ: Mapping[str, str], is_windows: bool, getuser: Callable[[], str]
) -> dict[str, Any] | None:
    """The logged-in operating-system account, as read on this machine. Never verified.

    Windows: ``DOMAIN\\user`` from USERDOMAIN and USERNAME. Elsewhere: the account name
    from the password database (``getuser``). The service decides what it is worth: it
    counts only through the device's assignments (review H4).
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
    payload: dict[str, Any],
    config: ClientConfig,
    device: str,
    claim: dict[str, Any] | None,
    report_id: str,
) -> bytes:
    """The envelope. `report_id` is made once per hook run and reused on its retry and on
    the second decide (queue Q12)."""
    body = {
        "format": REQUEST_FORMAT,
        "event": payload["hook_event_name"],
        "surface": config.surface,
        "device": device,
        "claims": [claim] if claim else [],
        "report_id": report_id,
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


def block_output(event: str | None, message: str = BLOCK_MESSAGE) -> HookOutput:
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
    return HookOutput(2, stdout, message + "\n")


# --- local log -------------------------------------------------------------------------


def log_line(path_text: str | None, mode: str, event: str, outcome: str) -> None:
    """Append one line: time, mode, event, outcome code. Never content, never the token.

    Only the configured log file is used; before the configuration is read there is no
    log. A log that cannot be written must not change the hook's outcome, so write errors
    are dropped here on purpose.
    """
    if not path_text:
        return
    stamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    line = f"{stamp} mode={mode} event={event or '-'} outcome={outcome}\n"
    try:
        with Path(path_text).open("a", encoding="utf-8") as handle:
            handle.write(line)
    except OSError:
        return


# --- pre-push change upload (docs/skill/decision-api.md, "Pre-push change upload") -----


@dataclass(frozen=True)
class GitResult:
    returncode: int
    stdout: bytes


class GitRunner(Protocol):
    """Runs git with a fixed argv list (never a shell) in ``cwd``. Raises ClientError on
    a timeout or when git cannot be started."""

    def run(
        self, argv: list[str], cwd: str, timeout: float, env: Mapping[str, str]
    ) -> GitResult: ...


class SubprocessGitRunner:
    """The real runner: ``shell=False``, stdin closed, stderr dropped, stdout through a
    temporary file read back with a cap, killed at the timeout."""

    def run(self, argv: list[str], cwd: str, timeout: float, env: Mapping[str, str]) -> GitResult:
        with tempfile.TemporaryFile() as out:
            try:
                done = subprocess.run(  # noqa: S603 - fixed argv list, absolute git, no shell
                    argv,
                    cwd=cwd,
                    env=dict(env),
                    stdin=subprocess.DEVNULL,
                    stdout=out,
                    stderr=subprocess.DEVNULL,
                    timeout=timeout,
                    shell=False,
                    check=False,
                )
            except subprocess.TimeoutExpired as error:
                raise ClientError("git_timeout") from error
            except OSError as error:
                raise ClientError("git_unavailable") from error
            out.seek(0)
            return GitResult(done.returncode, out.read(MAX_GIT_OUTPUT_BYTES + 1))


class Budget:
    """The hook's own deadline, measured from the start of the run. Every step gets at
    most what is left minus a margin; a step that would not fit blocks instead."""

    def __init__(self, seconds: float, monotonic: Callable[[], float], start: float) -> None:
        self._end = start + seconds
        self._now = monotonic

    def timeout(self, limit: float) -> float:
        left = self._end - self._now() - DEADLINE_MARGIN_SECONDS
        if left < MIN_STEP_SECONDS:
            raise ClientError("deadline")
        return min(limit, left)


@dataclass(frozen=True)
class NeedsChange:
    kind: str
    remote: str | None
    branch: str | None
    source: str | None


def parse_needs_change(response: HttpResponse) -> NeedsChange | None:
    """The ``needs_change`` of a decide answer (already validated by parse_verdict)."""
    data = json.loads(response.body.decode("utf-8"))
    raw = data.get("needs_change")
    if raw is None:
        return None
    if not isinstance(raw, dict) or set(raw) - {"kind", "remote", "branch", "source"}:
        raise ClientError("bad_needs_change")
    kind = raw.get("kind")
    if kind not in ("push", "commit"):
        raise ClientError("bad_needs_change")
    names = [raw.get(key) for key in ("remote", "branch", "source")]
    for name in names:
        if name is not None and not (isinstance(name, str) and _REF_RE.fullmatch(name)):
            raise ClientError("bad_needs_change")
    if names[0] is not None and not _REMOTE_RE.fullmatch(names[0]):
        raise ClientError("bad_needs_change")
    return NeedsChange(str(kind), names[0], names[1], names[2])


#: Options that make the client's git show exactly the objects and lines being pushed
#: (review M3): no replace refs, no relative or prefix-less diff, no external diff, no
#: rename or copy shortcuts (every added line is printed), and no program the repository
#: names (fsmonitor, hooks, protocols).
GIT_SAFE_OPTIONS = (
    "--no-pager", "--no-optional-locks", "--no-replace-objects",
    "-c", "core.fsmonitor=false", "-c", "diff.external=", "-c", "protocol.allow=never",
    "-c", "diff.relative=false", "-c", "diff.noprefix=false", "-c", "diff.mnemonicPrefix=false",
    "-c", "diff.renames=false", "-c", "core.quotePath=true",
)  # fmt: skip
#: Configuration the hook's environment may add for the agent's own git (read back when
#: the effective push configuration is checked).
_CONFIG_ENV_RE = re.compile(
    r"GIT_CONFIG_(COUNT|KEY_\d+|VALUE_\d+|PARAMETERS|GLOBAL|SYSTEM|NOSYSTEM)"
)


class Git:
    """git in the hook's working directory, with options that keep the repository's own
    configuration from running programs or changing what the diff and bundle show.

    Two environments: `isolated` (no system or global configuration, no replace objects)
    for everything that builds the change, and `effective` (what the agent's own `git
    push` will see: system, global, repository and environment configuration) for the
    push configuration check only.
    """

    def __init__(
        self,
        runner: GitRunner,
        executable: str,
        cwd: str,
        budget: Budget,
        environ: Mapping[str, str],
        scratch: str,
    ) -> None:
        self._runner = runner
        self._cwd = cwd
        self._budget = budget
        nohooks = str(Path(scratch) / "no-hooks")
        self._prefix = [executable, *GIT_SAFE_OPTIONS, "-c", "core.hooksPath=" + nohooks]
        base = {k: v for k, v in environ.items() if not k.upper().startswith("GIT_")}
        base.update({"GIT_TERMINAL_PROMPT": "0", "GIT_OPTIONAL_LOCKS": "0", "LC_ALL": "C"})
        empty = Path(scratch) / "empty-gitconfig"
        empty.write_bytes(b"")
        self.env = {
            **base,
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": str(empty),
            "GIT_NO_REPLACE_OBJECTS": "1",
        }
        passed = {k: v for k, v in environ.items() if _CONFIG_ENV_RE.fullmatch(k.upper())}
        self.effective_env = {**base, **passed}

    def raw(self, *args: str, cwd: str | None = None, effective: bool = False) -> GitResult:
        argv = [*self._prefix, *args]
        timeout = self._budget.timeout(GIT_STEP_SECONDS)
        env = self.effective_env if effective else self.env
        return self._runner.run(argv, cwd or self._cwd, timeout, env)

    def out(self, *args: str, code: str, cwd: str | None = None, effective: bool = False) -> str:
        result = self.raw(*args, cwd=cwd, effective=effective)
        if result.returncode != 0 or len(result.stdout) > MAX_GIT_OUTPUT_BYTES:
            raise ClientError(code)
        return result.stdout.decode("utf-8", errors="replace").strip()

    def commit_of(self, ref: str) -> str | None:
        result = self.raw("rev-parse", "--verify", "--quiet", "--end-of-options", ref + "^{commit}")
        text = result.stdout.decode("ascii", errors="replace").strip()
        if result.returncode != 0 or not _COMMIT_RE.fullmatch(text):
            return None
        return text


def check_git_environment(environ: Mapping[str, str], hooks_dir: str) -> None:
    """Refuse (``push_config``) unless the hook's ``GIT_*`` variables are exactly the ones
    the managed pack sets (``managed_git_env``): any other one (``GIT_DIR``,
    ``GIT_SSH_COMMAND``, ``GIT_EXEC_PATH``, ``GIT_CONFIG_GLOBAL``, an extra
    ``GIT_CONFIG_KEY_n``...) or a changed or missing value changes what the agent's own
    `git push` does, so the pushed commits could differ from the scanned ones."""
    found = {k.upper(): v for k, v in environ.items() if k.upper().startswith("GIT_")}
    if found != managed_git_env(hooks_dir):
        raise ClientError("push_config")


def check_push_config(git: Git, remote: str, environ: Mapping[str, str]) -> None:
    """Refuse (``push_config``) when the configuration the agent's `git push` will read
    changes where or how the pushed data goes (reviews H2, Q17): `remote.<r>.pushurl`,
    `.receivepack`, `.push`, `.mirror`, `core.sshCommand`, any `url.*.pushInsteadOf`, or
    a transport variable in the hook's environment."""
    pattern = (
        r"^(remote\." + re.escape(remote) + r"\.(pushurl|receivepack|push|mirror)"
        r"|core\.sshcommand|url\..*\.pushinsteadof)$"
    )
    result = git.raw("config", "--get-regexp", pattern, effective=True)
    if result.returncode == 0:
        raise ClientError("push_config")
    if result.returncode != 1:
        raise ClientError("config_unreadable")


def repository_url(git: Git, remote: str) -> str:
    """The push URL of `remote` as git resolves it, without any `user[:password]@`."""
    url = git.out("remote", "get-url", "--push", remote, code="no_remote_url", effective=True)
    url = _URL_USERINFO_RE.sub(r"\1", url)
    if not url or len(url) > MAX_REPOSITORY_CHARS or _CONTROL_RE.search(url):
        raise ClientError("no_remote_url")
    return url


def fetch_bases(
    config: ClientConfig, ctx: PrepushContext, repository: str, branch: str
) -> list[str]:
    """The heads the service has approved for this repository and branch (review H1)."""
    body = json.dumps({"repository": repository, "branch": branch}).encode("utf-8")
    response = ctx.transport.post(
        config.service_url + BASES_PATH, body, headers_for(config),
        ctx.budget.timeout(config.timeout), config.context,
    )  # fmt: skip
    if response.status != 200 or len(response.body) > MAX_RESPONSE_BYTES:
        raise ClientError(f"bases_status_{response.status}")
    try:
        bases = json.loads(response.body.decode("utf-8")).get("bases")
    except (UnicodeDecodeError, ValueError, AttributeError) as error:
        raise ClientError("bad_bases") from error
    if not isinstance(bases, list) or len(bases) > MAX_BASES:
        raise ClientError("bad_bases")
    if not all(isinstance(b, str) and _COMMIT_RE.fullmatch(b) for b in bases):
        raise ClientError("bad_bases")
    return bases


def choose_base(git: Git, bases: list[str], head: str) -> str | None:
    """The first approved base that is a commit here and an ancestor of `head`; None
    (scan from the root) when there is none. Local remote-tracking refs play no part."""
    for base in bases:
        if base == head or git.commit_of(base) is None:
            continue
        result = git.raw("merge-base", "--is-ancestor", base, head)
        if result.returncode == 0:
            return base
        if result.returncode != 1:
            raise ClientError("merge_base_failed")
    return None


def _bundle(git: Git, tmp: str, head: str) -> bytes:
    """A complete, cloneable bundle whose HEAD is the pushed commit, built in a scratch
    bare repository that borrows the objects (the sandbox clones it and needs a HEAD)."""
    objects = git.out(
        "rev-parse", "--path-format=absolute", "--git-path", "objects", code="git_dir"
    )
    bare = str(Path(tmp) / "b.git")
    git.out("init", "--bare", "-q", "--template=", bare, code="bundle", cwd=tmp)
    alternates = Path(bare) / "objects" / "info"
    alternates.mkdir(parents=True, exist_ok=True)
    # Bytes, not text: a text write on Windows ends the line with CR LF, and git then
    # reads a path that ends in CR (measured in the real run).
    (alternates / "alternates").write_bytes(objects.encode("utf-8") + b"\n")
    scratch = ("--git-dir=" + bare,)
    git.out(*scratch, "update-ref", "refs/heads/aigov", head, code="bundle", cwd=tmp)
    git.out(*scratch, "symbolic-ref", "HEAD", "refs/heads/aigov", code="bundle", cwd=tmp)
    target = str(Path(tmp) / "change.bundle")
    git.out(*scratch, "bundle", "create", "-q", target, "HEAD", "refs/heads/aigov",
            code="bundle", cwd=tmp)  # fmt: skip
    with Path(target).open("rb") as handle:
        data = handle.read(MAX_BUNDLE_BYTES + 1)
    if len(data) > MAX_BUNDLE_BYTES:
        raise ClientError("bundle_too_large")
    return data


def _diff(git: Git, top: str, *args: str) -> bytes:
    """`git diff` from the repository's top level, so a relative diff cannot hide files
    outside the hook's directory."""
    result = git.raw(
        "diff", "--no-ext-diff", "--no-textconv", "--no-color", "--no-renames", *args, cwd=top
    )
    if result.returncode != 0:
        raise ClientError("diff_failed")
    if len(result.stdout) > MAX_DIFF_BYTES:
        raise ClientError("diff_too_large")
    return result.stdout


def _top(git: Git) -> str:
    top = git.out("rev-parse", "--show-toplevel", code="no_toplevel")
    if not top or not Path(top).is_absolute() or not Path(top).is_dir():
        raise ClientError("no_toplevel")
    return top


def _commit_change(git: Git, top: str) -> dict[str, Any]:
    tree = git.out("write-tree", code="write_tree")
    if not _COMMIT_RE.fullmatch(tree):
        raise ClientError("write_tree")
    diff = _diff(git, top, "--cached")
    return {"kind": "commit", "head": tree, "base": git.commit_of("HEAD"),
            "diff_b64": base64.b64encode(diff).decode("ascii")}  # fmt: skip


def _range(git: Git, base: str | None, head: str) -> list[str]:
    """`rev-list base..head`, or the whole history of `head` when there is no base."""
    span = f"{base}..{head}" if base is not None else head
    listed = git.out("rev-list", f"--max-count={MAX_CHANGE_COMMITS + 1}", span,
                     code="rev_list").split()  # fmt: skip
    if not listed:
        raise ClientError("nothing_to_push")
    if not all(_COMMIT_RE.fullmatch(c) for c in listed):
        raise ClientError("rev_list")
    if len(listed) > MAX_CHANGE_COMMITS:
        raise ClientError("too_many_commits" if base is not None else "too_many_unscanned")
    return listed


def build_change(
    git: Git,
    needs: NeedsChange,
    tmp: str,
    bases: Callable[[str, str], list[str]],
    environ: Mapping[str, str],
    hooks_dir: str,
) -> dict[str, Any]:
    """The upload body (without session_id) for ``needs``. Any failure raises.

    `bases(repository, branch)` asks the service for its approved heads."""
    if needs.kind == "commit":
        return _commit_change(git, _top(git))
    if needs.remote is None or needs.branch is None:
        # Only a push that names its remote and branch is scanned: without them,
        # configuration (push.default, remote.<name>.push, .mirror) decides what is sent.
        raise ClientError("push_names_no_branch")
    top = _top(git)
    check_git_environment(environ, hooks_dir)
    check_push_config(git, needs.remote, environ)
    if git.out("rev-parse", "--is-shallow-repository", code="git_dir") != "false":
        raise ClientError("shallow_repository")
    ref = "HEAD" if needs.source is None else "refs/heads/" + needs.source
    head = git.commit_of(ref)
    if head is None:
        raise ClientError("no_source_commit")
    repository = repository_url(git, needs.remote)
    base = choose_base(git, bases(repository, needs.branch), head)
    listed = _range(git, base, head)
    if base is None:
        empty = git.out("hash-object", "-t", "tree", "--stdin", code="empty_tree")
        if not _COMMIT_RE.fullmatch(empty):
            raise ClientError("empty_tree")
        diff = _diff(git, top, empty, head)
    else:
        diff = _diff(git, top, base, head)
    return {
        "kind": "push", "repository": repository, "remote": needs.remote,
        "branch": needs.branch, "source": needs.source,
        "head": head, "base": base, "commits": listed,
        "diff_b64": base64.b64encode(diff).decode("ascii"),
        "bundle_b64": base64.b64encode(_bundle(git, tmp, head)).decode("ascii"),
    }  # fmt: skip


@dataclass(frozen=True)
class PrepushContext:
    environ: Mapping[str, str]
    transport: Transport
    runner: GitRunner
    budget: Budget


def git_executable(path: str, writable: Writable) -> str:
    """The admin-installed git named by the configuration file: absolute, a file, and not
    writable by the user. A bare ``git`` would be looked up in PATH or the agent's
    working directory."""
    if not path or not Path(path).is_absolute() or not Path(path).is_file():
        raise ClientError("no_git_path")
    if writable(Path(path)):
        raise ClientError("git_writable")
    return path


def hook_cwd(payload: Mapping[str, Any]) -> str:
    cwd = payload.get("cwd")
    if not isinstance(cwd, str) or not Path(cwd).is_absolute() or not Path(cwd).is_dir():
        raise ClientError("bad_cwd")
    return cwd


def upload_change(
    payload: Mapping[str, Any],
    config: ClientConfig,
    needs: NeedsChange,
    ctx: PrepushContext,
    writable: Writable,
) -> tuple[str, str]:
    """Build and upload the change; returns (change_id, head)."""
    executable = git_executable(config.git_path, writable)
    cwd = hook_cwd(payload)
    with tempfile.TemporaryDirectory(prefix="aigov-") as tmp:
        git = Git(ctx.runner, executable, cwd, ctx.budget, ctx.environ, tmp)

        def bases(repository: str, branch: str) -> list[str]:
            return fetch_bases(config, ctx, repository, branch)

        change = build_change(git, needs, tmp, bases, ctx.environ, config.git_hooks_dir)
    body = json.dumps(
        {"session_id": payload.get("session_id"), **change}, separators=(",", ":")
    ).encode("utf-8")
    if len(body) > MAX_CHANGE_REQUEST_BYTES:
        raise ClientError("change_too_large")
    response = ctx.transport.post(
        config.service_url + CHANGES_PATH, body, headers_for(config),
        ctx.budget.timeout(config.timeout), config.context,
    )  # fmt: skip
    if response.status == 409 and _error_code(response) == "device_busy":
        raise ClientError("device_busy")
    if response.status != 201 or len(response.body) > MAX_RESPONSE_BYTES:
        raise ClientError(f"upload_status_{response.status}")
    try:
        change_id = json.loads(response.body.decode("utf-8")).get("change_id")
    except (UnicodeDecodeError, ValueError, AttributeError) as error:
        raise ClientError("bad_upload_answer") from error
    if not isinstance(change_id, str) or not _CHANGE_ID_RE.fullmatch(change_id):
        raise ClientError("bad_upload_answer")
    return change_id, str(change["head"])


def _error_code(response: HttpResponse) -> str | None:
    if len(response.body) > MAX_RESPONSE_BYTES:
        return None
    try:
        data = json.loads(response.body.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        return None
    code = data.get("error") if isinstance(data, dict) else None
    return code if isinstance(code, str) else None


def decide_with_change(
    payload: Mapping[str, Any],
    config: ClientConfig,
    body: bytes,
    needs: NeedsChange,
    ctx: PrepushContext,
    writable: Writable,
) -> Verdict:
    """Upload the change, then ask decide again with it attached (same report_id)."""
    change_id, head = upload_change(payload, config, needs, ctx, writable)
    request = json.loads(body.decode("utf-8"))
    request.update({"change_id": change_id, "change_head": head})
    again = json.dumps(request, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    if len(again) > MAX_REQUEST_BYTES:
        raise ClientError("too_large")
    response = ctx.transport.post(
        config.service_url + DECIDE_PATH, again, headers_for(config),
        ctx.budget.timeout(config.timeout), config.context,
    )  # fmt: skip
    return parse_verdict(response)


# --- modes -----------------------------------------------------------------------------


@dataclass(frozen=True)
class Machine:
    hostname: Callable[[], str]
    is_windows: bool
    getuser: Callable[[], str]
    config_path: Path
    writable: Writable


def _prepare(
    raw: bytes, environ: Mapping[str, str], mode: str, machine: Machine, logs: list[str]
) -> tuple[dict[str, Any], ClientConfig, bytes]:
    file = read_file_config(machine.config_path, machine.writable)
    logs.append(file.log_file)
    payload = parse_hook_input(raw)
    timeout = file.decide_timeout if mode == "decide" else file.report_timeout
    config = load_config(file, timeout, machine.writable)
    claim = os_account_claim(environ, machine.is_windows, machine.getuser)
    body = build_body(payload, config, machine.hostname(), claim, uuid.uuid4().hex)
    return payload, config, body


@dataclass(frozen=True)
class Clocked:
    """The git runner and the monotonic clock the pre-push step uses (seams for tests)."""

    runner: GitRunner
    monotonic: Callable[[], float]
    start: float


def run_decide(
    raw: bytes,
    environ: Mapping[str, str],
    transport: Transport,
    machine: Machine,
    clocked: Clocked | None = None,
) -> HookOutput:
    event: str | None = None
    prepush = False
    logs: list[str] = []
    try:
        payload, config, body = _prepare(raw, environ, "decide", machine, logs)
        event = str(payload["hook_event_name"])
        response = transport.post(
            config.service_url + DECIDE_PATH,
            body,
            headers_for(config),
            config.timeout,
            config.context,
        )
        verdict = parse_verdict(response)
        needs = parse_needs_change(response) if verdict.verdict == "deny" else None
        if needs is not None and event == "PreToolUse":
            prepush = True
            if clocked is None:
                raise ClientError("no_git_runner")
            budget = Budget(config.hook_deadline, clocked.monotonic, clocked.start)
            ctx = PrepushContext(environ, transport, clocked.runner, budget)
            verdict = decide_with_change(payload, config, body, needs, ctx, machine.writable)
        return render(event, verdict)
    except ClientError as error:
        log_line(_last(logs), "decide", event or "-", ("prepush:" if prepush else "") + error.code)
        if prepush and error.code in PREPUSH_MESSAGES:
            return block_output(event, PREPUSH_MESSAGES[error.code])
    except Exception as error:
        log_line(_last(logs), "decide", event or "-", type(error).__name__)
    return block_output(event, PREPUSH_BLOCK_MESSAGE if prepush else BLOCK_MESSAGE)


def _last(logs: list[str]) -> str | None:
    return logs[-1] if logs else None


def run_report(
    raw: bytes, environ: Mapping[str, str], transport: Transport, machine: Machine
) -> HookOutput:
    event = "-"
    logs: list[str] = []
    try:
        payload, config, body = _prepare(raw, environ, "report", machine, logs)
        event = str(payload["hook_event_name"])
    except ClientError as error:
        log_line(_last(logs), "report", event, "dropped:" + error.code)
        return HookOutput(0)
    url = config.service_url + ACTIVITY_PATH
    last = "unknown"
    for _attempt in range(2):  # the contract allows one retry, with the same report_id
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
    log_line(_last(logs), "report", event, "dropped:" + last)
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
    isolated: bool = bool(sys.flags.isolated),
    git_runner: GitRunner | None = None,
    monotonic: Callable[[], float] = time.monotonic,
    config_path: Path = DEFAULT_CONFIG_PATH,
    writable: Writable = user_can_write,
) -> int:
    """Run one hook. Unless the interpreter runs isolated (`python -I`: no PYTHONPATH,
    PYTHONSTARTUP, user site or script-directory imports a user could plant), nothing is
    sent: decide mode blocks and report mode drops the record. `environ` supplies only
    the operating-system account claim and the base environment of git; `config_path`
    and `writable` are seams for tests."""
    start = monotonic()
    mode = argv[1] if len(argv) == 2 else ""
    machine = Machine(hostname, is_windows, getuser, config_path, writable)
    clocked = Clocked(git_runner or SubprocessGitRunner(), monotonic, start)
    if not isolated:
        stdin.read()
        result = HookOutput(0) if mode == "report" else block_output(None)
    elif mode == "report":
        result = run_report(stdin.read(), environ, transport, machine)
    elif mode == "decide":
        result = run_decide(stdin.read(), environ, transport, machine, clocked)
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
