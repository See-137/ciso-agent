"""Client of the sandbox service (component C5): `POST /v1/jobs` with a git bundle.

This is the ONLY module in `src` that talks to a network (`tests/architecture`,
`NETWORK_ALLOWLIST`). It sends one change to the sandbox and returns the report as
parsed JSON; turning the report into findings is `ciso.inspection.from_sandbox_report`.

- URL, token reference and timeout come from `governance.sandbox_url`,
  `governance.sandbox_token_ref` and `governance.sandbox_timeout_seconds`; any of them
  unset, a token that does not resolve or is shorter than the sandbox's own minimum, or
  a URL that is not https (or plain http to a loopback host) refuses with `FailClosed`
  before anything is sent.
- The job carries the pushed `head`, the `commits` of the range and the `base_ref` (an
  approved head, or None: the whole history); the sandbox checks all three against the
  bundle and reports the head it scanned (reviews M2, H1).
- 429 (the sandbox runs one job at a time) is `SandboxBusy`: the worker tries the same
  job again later without spending a queue attempt (review L3).
- Redirects are refused: a redirect could carry the bearer token to another host.
- The answer is read with a hard cap (`MAX_REPORT_BYTES`); anything but a 200 with a
  JSON object is `SandboxUnavailable` with a short code (never the body, never the
  token). The caller (the worker) retries through the job queue.
"""

from __future__ import annotations

import base64
import json
from collections.abc import Mapping, Sequence
from typing import Any, Final

import httpx

from ciso.app.change_models import SandboxInput
from ciso.app.governance_settings import check_sandbox_url
from ciso.common.errors import CisoError, FailClosed
from ciso.common.protocols import SecretResolver

JOBS_PATH: Final = "/v1/jobs"
#: Largest report read: the inspection's own report bound plus envelope room.
MAX_REPORT_BYTES: Final = 1_048_576 + 64 * 1024
#: The sandbox service refuses shorter tokens (`services/sandbox/README.md`).
MIN_TOKEN_CHARS: Final = 16


class SandboxUnavailable(CisoError):
    """The sandbox did not return a usable report. `code` is safe to log."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


class SandboxBusy(SandboxUnavailable):
    """The sandbox is running another job (429). Not a failure of this job."""


class SandboxClient:
    def __init__(
        self,
        *,
        url: str | None,
        token_ref: str | None,
        secrets: SecretResolver,
        timeout_seconds: float | None,
        transport: httpx.BaseTransport | None = None,
    ) -> None:
        """`transport` is a seam for tests (`httpx.MockTransport`); production passes none."""
        self._url = url
        self._token_ref = token_ref
        self._secrets = secrets
        self._timeout = timeout_seconds
        self._transport = transport

    def __repr__(self) -> str:
        return f"SandboxClient(url={self._url!r})"

    def run(self, item: SandboxInput, checks: Sequence[str]) -> Mapping[str, Any]:
        """Send one bundle job and return the report. See the module docstring."""
        url, token, timeout = self._ready()
        if not checks:
            raise FailClosed("no sandbox checks are configured")
        body = {
            "job_id": item.change_id,
            "archive_format": "git_bundle",
            "archive_b64": base64.b64encode(item.bundle).decode("ascii"),
            "base_ref": item.base,
            "head": item.head,
            "commits": list(item.commits),
            "checks": list(checks),
        }
        headers = {"Authorization": "Bearer " + token, "Accept": "application/json"}
        try:
            with (
                httpx.Client(
                    transport=self._transport, timeout=timeout, follow_redirects=False
                ) as client,
                client.stream("POST", url + JOBS_PATH, json=body, headers=headers) as response,
            ):
                if response.status_code == 429:
                    raise SandboxBusy("status_429")
                if response.status_code != 200:
                    raise SandboxUnavailable(f"status_{response.status_code}")
                raw = _read_capped(response)
        except httpx.HTTPError as exc:
            raise SandboxUnavailable(type(exc).__name__) from None
        try:
            report = json.loads(raw)
        except ValueError:
            raise SandboxUnavailable("malformed_report") from None
        if not isinstance(report, dict):
            raise SandboxUnavailable("malformed_report")
        return report

    def _ready(self) -> tuple[str, str, float]:
        if self._url is None or self._token_ref is None or self._timeout is None:
            raise FailClosed("the sandbox client is not configured")
        try:
            url = check_sandbox_url(self._url).rstrip("/")
        except ValueError as exc:
            raise FailClosed("the sandbox URL is not allowed") from exc
        try:
            token = self._secrets.get(self._token_ref).reveal()
        except CisoError as exc:
            raise FailClosed("the sandbox token does not resolve") from exc
        if len(token) < MIN_TOKEN_CHARS:
            raise FailClosed("the sandbox token is too short")
        return url, token, self._timeout


def _read_capped(response: httpx.Response) -> bytes:
    chunks: list[bytes] = []
    size = 0
    for chunk in response.iter_bytes():
        size += len(chunk)
        if size > MAX_REPORT_BYTES:
            raise SandboxUnavailable("report_too_large")
        chunks.append(chunk)
    return b"".join(chunks)
