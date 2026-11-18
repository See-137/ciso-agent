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
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Annotated

from pydantic import Field, field_validator

from ciso.common.schemas import Model

_CHECK_ID = re.compile(r"[a-z][a-z0-9_.-]{0,47}")


class GovernanceSettings(Model):
    ruleset_path: Path | None = None
    required_sandbox_checks: tuple[str, ...] | None = None
    central_gate_secret_ref: str | None = None
    #: Accepted during a rotation, next to the current one. Unset: none.
    central_gate_previous_secret_ref: str | None = None
    central_gate_tolerance_seconds: Annotated[int, Field(gt=0, strict=True)] | None = None
    central_gate_replay_capacity: Annotated[int, Field(gt=0, strict=True)] | None = None

    @field_validator("central_gate_secret_ref", "central_gate_previous_secret_ref")
    @classmethod
    def _reference(cls, value: str | None) -> str | None:
        if value is not None and not value.startswith("secret://"):
            raise ValueError("the central gate secret must be a secret:// reference")
        return value

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
        )
        return tuple(f"governance.{name}" for name in names if getattr(self, name) is None)
