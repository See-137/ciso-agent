"""Sandbox service (component C5): runs secret and code scanners and a project's tests on a
change, in isolated containers, and returns a report in the fixed format.

Lives outside `src` because it creates processes; nothing in `src` imports it. See
`README.md` in this directory for what must be provided before it can run for real.
"""

from services.sandbox.backend import (
    Backend,
    BackendHealth,
    ContainerSpec,
    IsolationUnavailable,
    RunOutcome,
)
from services.sandbox.job import ArchiveFormat, CheckId, Job, ProjectType
from services.sandbox.report import CheckReport, Report, validate_wire
from services.sandbox.runner import JobRunner, RunnerHealth
from services.sandbox.settings import SandboxImages, SandboxLimits, SandboxSettings, SettingsUnset

__all__ = [
    "ArchiveFormat",
    "Backend",
    "BackendHealth",
    "CheckId",
    "CheckReport",
    "ContainerSpec",
    "IsolationUnavailable",
    "Job",
    "JobRunner",
    "ProjectType",
    "Report",
    "RunOutcome",
    "RunnerHealth",
    "SandboxImages",
    "SandboxLimits",
    "SandboxSettings",
    "SettingsUnset",
    "validate_wire",
]
