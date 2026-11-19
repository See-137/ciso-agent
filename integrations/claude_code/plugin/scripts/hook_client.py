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
        the one applied. Any failure on the way blocks. The whole run stays inside
        AIGOV_HOOK_DEADLINE_SECONDS.
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
    AIGOV_GIT_PATH                 absolute path of the admin-installed git (pre-push;
                                   unset: a push or commit that needs a scan blocks)
    AIGOV_HOOK_DEADLINE_SECONDS    the client's whole time budget, below the hook's own
                                   timeout (pre-push; unset: such a push blocks)

The device token is read from a file, never from the environment (the environment
reaches every command the agent runs), and is never printed or logged.

Standard library only. Targets Python 3.10 and later.
"""

from __future__ import annotations

import base64
import getpass
import json
import math
import os
import re
import socket
import ssl
import subprocess
import sys
import tempfile
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

#: Pre-push bounds. The bundle bound is the sandbox's archive bound (32 MiB); the request
#: cap equals the service's `MAX_CHANGE_BODY_BYTES` (a test pins the two together).
MAX_BUNDLE_BYTES = 32 * 1024 * 1024
MAX_DIFF_BYTES = 4 * 1024 * 1024
MAX_CHANGE_COMMITS = 1000
MAX_CHANGE_REQUEST_BYTES = ((MAX_BUNDLE_BYTES + MAX_DIFF_BYTES + 2) // 3) * 4 + 128 * 1024
MAX_GIT_OUTPUT_BYTES = MAX_DIFF_BYTES
#: Longest any single git step may take, inside the deadline.
GIT_STEP_SECONDS = 10.0
#: Kept back from the deadline for printing the answer; a step needs at least MIN_STEP.
DEADLINE_MARGIN_SECONDS = 0.5
MIN_STEP_SECONDS = 0.2

DECIDE_PATH = "/v1/governance/decide"
CHANGES_PATH = "/v1/changes"
ACTIVITY_PATH = "/v1/activity"
REQUEST_FORMAT = "assistant_hook_v1"
DEFAULT_SURFACE = "cli"

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

ENV_URL = "AIGOV_SERVICE_URL"
ENV_TOKEN_FILE = "AIGOV_DEVICE_TOKEN_FILE"  # noqa: S105 - a variable name, not a secret
ENV_DECIDE_TIMEOUT = "AIGOV_DECIDE_TIMEOUT_SECONDS"
ENV_REPORT_TIMEOUT = "AIGOV_REPORT_TIMEOUT_SECONDS"
ENV_CA_BUNDLE = "AIGOV_CA_BUNDLE"
ENV_SURFACE = "AIGOV_SURFACE"
ENV_LOG_FILE = "AIGOV_LOG_FILE"
ENV_GIT = "AIGOV_GIT_PATH"
ENV_DEADLINE = "AIGOV_HOOK_DEADLINE_SECONDS"

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


class Git:
    """git in the hook's working directory, with options that keep the repository's own
    configuration from running programs (fsmonitor, external diff, textconv, hooks)."""

    def __init__(
        self,
        runner: GitRunner,
        executable: str,
        cwd: str,
        budget: Budget,
        environ: Mapping[str, str],
        nohooks: str,
    ) -> None:
        self._runner = runner
        self._cwd = cwd
        self._budget = budget
        self._prefix = [
            executable, "--no-pager", "--no-optional-locks",
            "-c", "core.fsmonitor=false", "-c", "core.hooksPath=" + nohooks,
            "-c", "diff.external=", "-c", "protocol.allow=never",
        ]  # fmt: skip
        self.env = {k: v for k, v in environ.items() if not k.upper().startswith("GIT_")}
        self.env.update({"GIT_TERMINAL_PROMPT": "0", "GIT_OPTIONAL_LOCKS": "0", "LC_ALL": "C"})

    def raw(self, *args: str, cwd: str | None = None) -> GitResult:
        argv = [*self._prefix, *args]
        timeout = self._budget.timeout(GIT_STEP_SECONDS)
        return self._runner.run(argv, cwd or self._cwd, timeout, self.env)

    def out(self, *args: str, code: str, cwd: str | None = None) -> str:
        result = self.raw(*args, cwd=cwd)
        if result.returncode != 0 or len(result.stdout) > MAX_GIT_OUTPUT_BYTES:
            raise ClientError(code)
        return result.stdout.decode("utf-8", errors="replace").strip()

    def commit_of(self, ref: str) -> str | None:
        result = self.raw("rev-parse", "--verify", "--quiet", "--end-of-options", ref + "^{commit}")
        text = result.stdout.decode("ascii", errors="replace").strip()
        if result.returncode != 0 or not _COMMIT_RE.fullmatch(text):
            return None
        return text


def _base(git: Git, needs: NeedsChange, head: str) -> str:
    """Where the pushed range starts: the merge base with the remote branch, else with
    the remote's default branch."""
    candidates = [f"refs/remotes/{needs.remote}/{needs.branch}"]
    candidates += [f"refs/remotes/{needs.remote}/{name}" for name in ("HEAD", "main", "master")]
    for ref in candidates:
        if git.commit_of(ref) is None:
            continue
        base = git.out("merge-base", head, ref, code="no_merge_base")
        if _COMMIT_RE.fullmatch(base):
            return base
    raise ClientError("no_base")


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


def _diff(git: Git, *args: str) -> bytes:
    result = git.raw("diff", "--no-ext-diff", "--no-textconv", "--no-color", *args)
    if result.returncode != 0:
        raise ClientError("diff_failed")
    if len(result.stdout) > MAX_DIFF_BYTES:
        raise ClientError("diff_too_large")
    return result.stdout


def build_change(git: Git, needs: NeedsChange, tmp: str) -> dict[str, Any]:
    """The upload body (without session_id) for ``needs``. Any failure raises."""
    if needs.kind == "commit":
        tree = git.out("write-tree", code="write_tree")
        if not _COMMIT_RE.fullmatch(tree):
            raise ClientError("write_tree")
        diff = _diff(git, "--cached")
        return {"kind": "commit", "head": tree, "base": git.commit_of("HEAD"),
                "diff_b64": base64.b64encode(diff).decode("ascii")}  # fmt: skip
    if needs.remote is None or needs.branch is None:
        # Only a push that names its remote and branch is scanned: without them,
        # configuration (push.default, remote.<name>.push, .mirror) decides what is sent.
        raise ClientError("push_names_no_branch")
    ref = "HEAD" if needs.source is None else "refs/heads/" + needs.source
    head = git.commit_of(ref)
    if head is None:
        raise ClientError("no_source_commit")
    base = _base(git, needs, head)
    listed = git.out("rev-list", f"--max-count={MAX_CHANGE_COMMITS + 1}", f"{base}..{head}",
                     code="rev_list").split()  # fmt: skip
    if not listed:
        raise ClientError("nothing_to_push")
    if len(listed) > MAX_CHANGE_COMMITS or not all(_COMMIT_RE.fullmatch(c) for c in listed):
        raise ClientError("too_many_commits")
    return {
        "kind": "push", "remote": needs.remote, "branch": needs.branch, "source": needs.source,
        "head": head, "base": base, "commits": listed,
        "diff_b64": base64.b64encode(_diff(git, base, head)).decode("ascii"),
        "bundle_b64": base64.b64encode(_bundle(git, tmp, head)).decode("ascii"),
    }  # fmt: skip


@dataclass(frozen=True)
class PrepushContext:
    environ: Mapping[str, str]
    transport: Transport
    runner: GitRunner
    budget: Budget


def git_executable(environ: Mapping[str, str]) -> str:
    """The admin-installed git named by the managed environment: absolute, a file. A bare
    ``git`` would be looked up in PATH or the agent's working directory."""
    path = environ.get(ENV_GIT)
    if not path or not Path(path).is_absolute() or not Path(path).is_file():
        raise ClientError("no_git_path")
    return path


def hook_cwd(payload: Mapping[str, Any]) -> str:
    cwd = payload.get("cwd")
    if not isinstance(cwd, str) or not Path(cwd).is_absolute() or not Path(cwd).is_dir():
        raise ClientError("bad_cwd")
    return cwd


def upload_change(
    payload: Mapping[str, Any], config: ClientConfig, needs: NeedsChange, ctx: PrepushContext
) -> tuple[str, str]:
    """Build and upload the change; returns (change_id, head)."""
    executable = git_executable(ctx.environ)
    cwd = hook_cwd(payload)
    with tempfile.TemporaryDirectory(prefix="aigov-") as tmp:
        nohooks = str(Path(tmp) / "no-hooks")
        git = Git(ctx.runner, executable, cwd, ctx.budget, ctx.environ, nohooks)
        change = build_change(git, needs, tmp)
    body = json.dumps(
        {"session_id": payload.get("session_id"), **change}, separators=(",", ":")
    ).encode("utf-8")
    if len(body) > MAX_CHANGE_REQUEST_BYTES:
        raise ClientError("change_too_large")
    response = ctx.transport.post(
        config.service_url + CHANGES_PATH, body, headers_for(config),
        ctx.budget.timeout(config.timeout), config.context,
    )  # fmt: skip
    if response.status != 201 or len(response.body) > MAX_RESPONSE_BYTES:
        raise ClientError(f"upload_status_{response.status}")
    try:
        change_id = json.loads(response.body.decode("utf-8")).get("change_id")
    except (UnicodeDecodeError, ValueError, AttributeError) as error:
        raise ClientError("bad_upload_answer") from error
    if not isinstance(change_id, str) or not _CHANGE_ID_RE.fullmatch(change_id):
        raise ClientError("bad_upload_answer")
    return change_id, str(change["head"])


def decide_with_change(
    payload: Mapping[str, Any],
    config: ClientConfig,
    body: bytes,
    needs: NeedsChange,
    ctx: PrepushContext,
) -> Verdict:
    """Upload the change, then ask decide again with it attached."""
    change_id, head = upload_change(payload, config, needs, ctx)
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


def _prepare(
    raw: bytes, environ: Mapping[str, str], timeout_variable: str, machine: Machine
) -> tuple[dict[str, Any], ClientConfig, bytes]:
    payload = parse_hook_input(raw)
    config = load_config(environ, timeout_variable)
    claim = os_account_claim(environ, machine.is_windows, machine.getuser)
    body = build_body(payload, config, machine.hostname(), claim)
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
        verdict = parse_verdict(response)
        needs = parse_needs_change(response) if verdict.verdict == "deny" else None
        if needs is not None and event == "PreToolUse":
            prepush = True
            if clocked is None:
                raise ClientError("no_git_runner")
            seconds = parse_timeout(environ.get(ENV_DEADLINE))
            budget = Budget(seconds, clocked.monotonic, clocked.start)
            ctx = PrepushContext(environ, transport, clocked.runner, budget)
            verdict = decide_with_change(payload, config, body, needs, ctx)
        return render(event, verdict)
    except ClientError as error:
        log_line(environ, "decide", event or "-", ("prepush:" if prepush else "") + error.code)
    except Exception as error:
        log_line(environ, "decide", event or "-", type(error).__name__)
    return block_output(event, PREPUSH_BLOCK_MESSAGE if prepush else BLOCK_MESSAGE)


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
    isolated: bool = bool(sys.flags.isolated),
    git_runner: GitRunner | None = None,
    monotonic: Callable[[], float] = time.monotonic,
) -> int:
    """Run one hook. Unless the interpreter runs isolated (`python -I`: no PYTHONPATH,
    PYTHONSTARTUP, user site or script-directory imports a user could plant), nothing is
    sent: decide mode blocks and report mode drops the record with a log line."""
    start = monotonic()
    mode = argv[1] if len(argv) == 2 else ""
    machine = Machine(hostname, is_windows, getuser)
    clocked = Clocked(git_runner or SubprocessGitRunner(), monotonic, start)
    if not isolated:
        stdin.read()
        log_line(environ, mode or "unknown", "", "refused:not_isolated")
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
