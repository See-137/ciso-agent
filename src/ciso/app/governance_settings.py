"""Settings of the AI-activity governance services (docs/skill/spec-draft.md, C3 and C4).

Every value is unset by default, and unset means the part that needs it refuses:

- `ruleset_path`: a deployment ruleset. The governance loader treats a ruleset file as
  complete (it never merges two files), so a deployment ruleset REPLACES the packaged
  default; ship it as a full copy of the default plus the deployment's additions
  (`config/governance-ruleset.provisional.json` is one). Unset: the packaged default. A
  file that does not load makes the engine deny everything, and readiness says so.
- `required_sandbox_checks`: the sandbox check ids every change must pass. Unset: no
  sandbox result is ever complete (`ciso.inspection.Inspector`), so pushes are refused.
- `central_gate_secret_ref`, `central_gate_tolerance_seconds`,
  `central_gate_replay_capacity`: the central gate endpoint's signing secret reference,
  timestamp window and replay memory size. Any of them unset: every delivery is denied.
- the pre-push path (`ciso.app.changes`, `ciso.app.sandbox_client`,
  `ciso.app.sandbox_worker`): `change_key_ref` (AES-GCM key for changes at rest) and
  `change_retention_seconds` (how long a stored change is kept; unset: uploads refuse);
  `sandbox_url`, `sandbox_token_ref`, `sandbox_timeout_seconds` (the sandbox service; any
  unset: the sandbox client refuses) and `worker_poll_seconds` (the worker's idle wait;
  unset: the worker does not start). Retries are the job queue's own
  (`safety.queue_max_attempts`, `queue_backoff_*`); the sandbox timeout must stay below
  `safety.queue_lease_seconds`, and readiness says so when it does not.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Annotated, Final

from pydantic import Field, field_validator

from ciso.common.schemas import Model

_CHECK_ID = re.compile(r"[a-z][a-z0-9_.-]{0,47}")
_LOOPBACK: Final = frozenset({"127.0.0.1", "::1", "localhost"})

#: The pre-push path's settings, each unset by default and named in readiness while unset.
CHANGE_SETTING_NAMES: Final = (
    "change_key_ref",
    "change_retention_seconds",
    "sandbox_url",
    "sandbox_token_ref",
    "sandbox_timeout_seconds",
    "worker_poll_seconds",
)

Positive = Annotated[float, Field(gt=0, allow_inf_nan=False)]


_URL_RE: Final = re.compile(
    r"(?P<scheme>https?)://(?P<host>[A-Za-z0-9](?:[A-Za-z0-9.-]{0,252}))(?::(?P<port>[0-9]{1,5}))?"
    r"(?P<path>/[A-Za-z0-9._~/-]*)?"
)


def check_sandbox_url(value: str) -> str:
    """https, or plain http to a loopback host only; no credentials, query or fragment.

    A plain pattern (no URL library: `urllib` is a network module under the architecture
    rule): scheme, host name or IPv4 address, optional port and path, nothing else.
    """
    match = _URL_RE.fullmatch(value)
    if match is None:
        raise ValueError("sandbox_url must be http(s)://host[:port][/path] with nothing else")
    if match["scheme"] == "http" and match["host"] not in _LOOPBACK:
        raise ValueError("plain http is allowed to a loopback sandbox only")
    return value


class GovernanceSettings(Model):
    ruleset_path: Path | None = None
    required_sandbox_checks: tuple[str, ...] | None = None
    central_gate_secret_ref: str | None = None
    #: Accepted during a rotation, next to the current one. Unset: none.
    central_gate_previous_secret_ref: str | None = None
    central_gate_tolerance_seconds: Annotated[int, Field(gt=0, strict=True)] | None = None
    central_gate_replay_capacity: Annotated[int, Field(gt=0, strict=True)] | None = None
    change_key_ref: str | None = None
    change_retention_seconds: Annotated[int, Field(gt=0, strict=True)] | None = None
    sandbox_url: str | None = None
    sandbox_token_ref: str | None = None
    sandbox_timeout_seconds: Positive | None = None
    worker_poll_seconds: Positive | None = None

    @field_validator(
        "central_gate_secret_ref",
        "central_gate_previous_secret_ref",
        "change_key_ref",
        "sandbox_token_ref",
    )
    @classmethod
    def _reference(cls, value: str | None) -> str | None:
        if value is not None and not value.startswith("secret://"):
            raise ValueError("a key or token setting must be a secret:// reference")
        return value

    @field_validator("sandbox_url")
    @classmethod
    def _url(cls, value: str | None) -> str | None:
        return None if value is None else check_sandbox_url(value)

    @field_validator("required_sandbox_checks")
    @classmethod
    def _check_ids(cls, value: tuple[str, ...] | None) -> tuple[str, ...] | None:
        for check_id in value or ():
            if not _CHECK_ID.fullmatch(check_id):
                raise ValueError("required sandbox check ids must be short ids")
        return value

    def unset(self) -> tuple[str, ...]:
        """Readiness entries for every value this build runs without."""
        names = (
            "required_sandbox_checks",
            "central_gate_secret_ref",
            "central_gate_tolerance_seconds",
            "central_gate_replay_capacity",
            *CHANGE_SETTING_NAMES,
        )
        return tuple(f"governance.{name}" for name in names if getattr(self, name) is None)
