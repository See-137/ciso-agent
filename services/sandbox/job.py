"""The job the governance service sends, and the fixed allowlist of test commands.

A job carries the change as a tar archive of the working tree or as a git bundle, the base
commit for the diff (bundles only: a tree has no history), and which checks to run. The
test command is never taken from the job: it is chosen from `TEST_COMMANDS` by the project
type detected from files at the root of the tree.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping
from enum import StrEnum
from types import MappingProxyType
from typing import Annotated, Final

from pydantic import AfterValidator, Field, model_validator

from ciso.common.schemas import Model

#: Largest archive or bundle accepted, in bytes. Structural bound, not a tunable.
MAX_ARCHIVE_BYTES: Final = 32 * 1024 * 1024

JOB_ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}")
#: A full commit id (SHA-1 or SHA-256). Names like `main` or `HEAD~1` are refused.
COMMIT_RE = re.compile(r"[0-9a-f]{40}|[0-9a-f]{64}")


class ArchiveFormat(StrEnum):
    TAR = "tar"
    GIT_BUNDLE = "git_bundle"


class CheckId(StrEnum):
    SECRETS = "secrets"
    CODE = "code"
    TESTS = "tests"


class ProjectType(StrEnum):
    PYTHON = "python"
    NODE = "node"
    GO = "go"
    NONE = "none"


#: Root-level files that mark a project type, in priority order (first match wins).
PROJECT_MARKERS: Final = (
    (ProjectType.PYTHON, ("pyproject.toml", "setup.py", "setup.cfg", "pytest.ini", "tox.ini")),
    (ProjectType.NODE, ("package.json",)),
    (ProjectType.GO, ("go.mod",)),
)

#: The only test commands the sandbox ever runs. `-p no:terminal` leaves stdout to the
#: JUnit XML report; pytest docs: https://docs.pytest.org/en/stable/how-to/output.html
TEST_COMMANDS: Final[Mapping[ProjectType, tuple[str, ...]]] = MappingProxyType(
    {
        ProjectType.PYTHON: (
            "python",
            "-m",
            "pytest",
            "-p",
            "no:cacheprovider",
            "-p",
            "no:terminal",
            "--junitxml=/dev/stdout",
        ),
        ProjectType.NODE: ("npm", "test"),
        ProjectType.GO: ("go", "test", "-json", "./..."),
    }
)


def _job_id(value: str) -> str:
    if not JOB_ID_RE.fullmatch(value):
        raise ValueError("job_id must be 1-64 of letters, digits, '_', '.', '-'")
    return value


def _commit(value: str) -> str:
    if not COMMIT_RE.fullmatch(value):
        raise ValueError("base_ref must be a full lowercase commit id")
    return value


class Job(Model):
    """One sandbox job. `archive` stays out of `repr`."""

    job_id: Annotated[str, AfterValidator(_job_id)]
    archive_format: ArchiveFormat
    archive: Annotated[bytes, Field(min_length=1, max_length=MAX_ARCHIVE_BYTES)] = Field(repr=False)
    base_ref: Annotated[str, AfterValidator(_commit)] | None = None
    checks: Annotated[tuple[CheckId, ...], Field(min_length=1, max_length=len(CheckId))]

    @model_validator(mode="after")
    def _consistent(self) -> Job:
        if len(set(self.checks)) != len(self.checks):
            raise ValueError("each check may be requested once")
        if self.base_ref is not None and self.archive_format is ArchiveFormat.TAR:
            raise ValueError("base_ref needs history: send a git bundle, not a tar archive")
        return self


def detect_project(paths: Iterable[str]) -> ProjectType:
    """The project type from root-level marker files; `NONE` when there is no marker."""
    root = {path for path in paths if "/" not in path}
    for project, markers in PROJECT_MARKERS:
        if root.intersection(markers):
            return project
    return ProjectType.NONE
