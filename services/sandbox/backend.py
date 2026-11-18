"""The isolation backend interface. The runner never runs code except through a `Backend`.

A backend runs one container from a `ContainerSpec` and reports how it ended. It must
enforce every isolation property the spec implies (no network, read-only root, bounded
work dir, non-root user, no capabilities, no privilege gain, process/CPU/memory limits,
wall-clock kill, output cap, removal afterwards) or refuse to run. There is no "local"
backend: with no backend the job fails closed.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import Protocol, runtime_checkable

from services.sandbox.settings import ResolvedLimits

from ciso.common.errors import FailClosed


class IsolationUnavailable(FailClosed):
    """The backend cannot provide isolation, so nothing runs."""


@dataclass(frozen=True)
class ContainerSpec:
    """One isolated run.

    `script` is a fixed shell script (a module constant, never built from job data); the
    job's data reaches the container only as `stdin` (a tar or a bundle) and as `command`
    words passed as positional arguments (`sh -c script sandbox <command...>`).
    """

    name: str
    image: str
    script: str
    command: tuple[str, ...]
    env: tuple[tuple[str, str], ...]
    stdin: bytes = field(repr=False)
    limits: ResolvedLimits
    timeout_seconds: float
    max_output_bytes: int


@dataclass(frozen=True)
class RunOutcome:
    """How a container ended. `exit_code` is None when it was killed by the backend."""

    exit_code: int | None
    stdout: bytes = field(repr=False)
    timed_out: bool
    output_exceeded: bool


@dataclass(frozen=True)
class BackendHealth:
    usable: bool
    reasons: tuple[str, ...]


@runtime_checkable
class Backend(Protocol):
    def probe(self, images: Sequence[str]) -> BackendHealth:
        """Whether the runtime answers and every given image is present locally."""
        ...

    def run(self, spec: ContainerSpec) -> RunOutcome:
        """Run one container under full isolation, or raise `IsolationUnavailable`."""
        ...
