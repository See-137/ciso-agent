"""A bundle job and a fake backend that answers the range verification, for the bundle tests.

The verification container (command word `verify`) answers like the real script: the HEAD
it cloned on the first line, then `git rev-list` of the range. `FakeRepo` holds what the
"bundle" really contains, so a test can make it disagree with what the job states.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field

from services.sandbox.backend import ContainerSpec, RunOutcome
from services.sandbox.job import ArchiveFormat, CheckId, Job
from tests.services.sandbox.support import FakeBackend, outcome

HEAD = "1" * 40
OLDER = "2" * 40
BASE = "3" * 40
BUNDLE = b"# v2 git bundle\n" + HEAD.encode() + b" HEAD\n\nPACK"


def bundle_job(
    checks: tuple[CheckId, ...] = (CheckId.SECRETS, CheckId.CODE, CheckId.TESTS),
    *,
    base_ref: str | None = BASE,
    head: str = HEAD,
    commits: tuple[str, ...] = (HEAD, OLDER),
) -> Job:
    return Job(
        job_id="job-b",
        archive_format=ArchiveFormat.GIT_BUNDLE,
        archive=BUNDLE,
        base_ref=base_ref,
        head=head,
        commits=commits,
        checks=checks,
    )


@dataclass
class FakeRepo:
    """What the bundle really holds: its HEAD, the commits above `ancestor`, and whether
    `ancestor` is an ancestor of HEAD (the verify script exits 1 otherwise)."""

    head: str = HEAD
    above_base: tuple[str, ...] = (HEAD, OLDER)
    whole: tuple[str, ...] = (HEAD, OLDER, BASE)
    base_is_ancestor: bool = True
    exit_code: int = 0
    verifications: list[ContainerSpec] = field(default_factory=list)

    def __call__(self, spec: ContainerSpec) -> RunOutcome:
        self.verifications.append(spec)
        base = spec.command[1]
        if self.exit_code != 0:
            return outcome(self.exit_code, b"")
        if base and not self.base_is_ancestor:
            return outcome(1, (self.head + "\n").encode())
        listed = self.above_base if base else self.whole
        return outcome(0, "\n".join((self.head, *listed)).encode() + b"\n")


def backend_for(
    repo: FakeRepo, extra: dict[str, RunOutcome | Callable[[ContainerSpec], RunOutcome]]
) -> FakeBackend:
    return FakeBackend(outcomes={"verify": repo, **extra})
