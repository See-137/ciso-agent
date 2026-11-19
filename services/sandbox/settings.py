"""Sandbox settings. Every numeric limit and every image has no default: unset means refuse.

Spec section 6 rule 4 (numeric safety settings have no defaults) and the C5 lane brief:
limits are per job (wall time) or per container (CPU, memory, output, processes, work-dir
size); images are pinned by digest and never pulled by this service.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Annotated, Any

from pydantic import AfterValidator, BeforeValidator, Field

from ciso.common.errors import FailClosed
from ciso.common.schemas import Model

#: An image reference pinned by content digest. Tags alone are refused.
IMAGE_RE = re.compile(r"[a-z0-9][a-z0-9._/:-]{0,254}@sha256:[0-9a-f]{64}")
#: A path inside a scanner image (rules baked into the image). No `..`, no spaces.
IMAGE_PATH_RE = re.compile(r"/(?:[A-Za-z0-9_][A-Za-z0-9._-]{0,127}/?){1,16}")
#: Docker refuses less than 6 MiB of memory for a container.
MIN_MEMORY_BYTES = 6 * 1024 * 1024

LIMIT_NAMES = (
    "wall_time_seconds",
    "cpus",
    "memory_bytes",
    "output_bytes",
    "pids",
    "work_tmpfs_bytes",
)


class SettingsUnset(FailClosed):
    """A setting the job needs has no value, so the job refuses (fails closed)."""

    def __init__(self, names: tuple[str, ...]) -> None:
        self.names = names
        super().__init__("settings unset: " + ", ".join(names))


def _no_bool(value: Any) -> Any:
    if isinstance(value, bool):
        raise ValueError("a boolean is not a number")
    return value


def _image(value: str) -> str:
    if not IMAGE_RE.fullmatch(value):
        raise ValueError("image must be pinned by digest: name@sha256:<64 hex>")
    return value


def _image_path(value: str) -> str:
    if not IMAGE_PATH_RE.fullmatch(value) or ".." in value.split("/"):
        raise ValueError("path inside the image must be absolute and plain")
    return value


type PositiveFloat = Annotated[float, BeforeValidator(_no_bool), Field(gt=0)]
type PositiveInt = Annotated[int, Field(gt=0, strict=True)]
type Image = Annotated[str, AfterValidator(_image)]
type ImagePath = Annotated[str, AfterValidator(_image_path)]


@dataclass(frozen=True)
class ResolvedLimits:
    """Limits with every value present. Only `SandboxLimits.resolve` builds one."""

    wall_time_seconds: float
    cpus: float
    memory_bytes: int
    output_bytes: int
    pids: int
    work_tmpfs_bytes: int


class SandboxLimits(Model):
    """Per-job wall time; per-container CPU, memory, stdout size, process count, work dir."""

    wall_time_seconds: PositiveFloat | None = None
    cpus: PositiveFloat | None = None
    memory_bytes: Annotated[int, Field(ge=MIN_MEMORY_BYTES, strict=True)] | None = None
    output_bytes: PositiveInt | None = None
    pids: PositiveInt | None = None
    work_tmpfs_bytes: PositiveInt | None = None

    def resolve(self) -> ResolvedLimits:
        """All limits, or `SettingsUnset` naming every one that is missing."""
        missing = tuple(name for name in LIMIT_NAMES if getattr(self, name) is None)
        if missing:
            raise SettingsUnset(missing)
        return ResolvedLimits(**{name: getattr(self, name) for name in LIMIT_NAMES})


class SandboxImages(Model):
    """Container images (pinned by digest) and scanner files inside them.

    The scanners never take configuration from the repository they scan (review H3):
    `gitleaks_config` is required (with no `--config`, gitleaks would load the target's
    own `.gitleaks.toml`); `gitleaks_ignore_file` names an EMPTY file baked into the image,
    passed as `--gitleaks-ignore-path` so the repository's `.gitleaksignore` is never read;
    `semgrep_config` is required (semgrep has no built-in rules and fetching registry
    rules would need the network). `git` is required for every bundle job: it verifies
    the bundle's head and range before anything else runs.
    """

    python_tests: Image | None = None
    node_tests: Image | None = None
    go_tests: Image | None = None
    gitleaks: Image | None = None
    semgrep: Image | None = None
    git: Image | None = None
    semgrep_config: ImagePath | None = None
    gitleaks_config: ImagePath | None = None
    gitleaks_ignore_file: ImagePath | None = None

    def configured(self) -> tuple[str, ...]:
        """Every configured image, in field order, without duplicates."""
        found: list[str] = []
        for name in ("python_tests", "node_tests", "go_tests", "gitleaks", "semgrep", "git"):
            value = getattr(self, name)
            if value is not None and value not in found:
                found.append(value)
        return tuple(found)

    def missing(self) -> tuple[str, ...]:
        """Required entries that are unset."""
        required = (
            "python_tests",
            "node_tests",
            "go_tests",
            "gitleaks",
            "semgrep",
            "git",
            "semgrep_config",
            "gitleaks_config",
            "gitleaks_ignore_file",
        )
        return tuple(name for name in required if getattr(self, name) is None)


class SandboxSettings(Model):
    """Everything the runner needs. `docker_cli` is the absolute path of the docker client."""

    limits: SandboxLimits = Field(default_factory=SandboxLimits)
    images: SandboxImages = Field(default_factory=SandboxImages)
    docker_cli: Annotated[str, Field(min_length=1, max_length=512)] | None = None
