"""Before anything runs on a bundle: is it the change the job says it is? (review M2, H1)

A git container clones the bundle and prints its HEAD, then (with a base) checks that the
base is an ancestor of HEAD inside the bundle and lists `base..HEAD`, or (without one)
lists the whole history. The runner accepts the bundle only when HEAD is the job's
`head` and the listed commits are exactly the job's `commits` (as a set, at most
`MAX_JOB_COMMITS`). Anything else, including a git failure, is a mismatch: no scanner and
no test runs, and the report names no head.

The governance service picks the base (an approved head, or none) and the client lists
the commits; this check is what makes "scanned" mean "these commits, below this head".
"""

from __future__ import annotations

import logging
from typing import Final

from services.sandbox.backend import Backend, ContainerSpec, RunOutcome
from services.sandbox.job import MAX_JOB_COMMITS, Job
from services.sandbox.settings import ResolvedLimits

from ciso.common.ids import new_id

logger = logging.getLogger(__name__)

#: Clone the streamed bundle, print HEAD, check ancestry and list the range. `$2` is the
#: base (empty: none); it is a validated commit id passed as a positional argument.
VERIFY_SCRIPT: Final = (
    "set -eu; mkdir -p /work/tmp; cat > /work/tmp/in.bundle; "
    "git clone -q --no-checkout /work/tmp/in.bundle /work/src; cd /work/src; "
    "git rev-parse HEAD; "
    'if [ -n "$2" ]; then git merge-base --is-ancestor "$2" HEAD; '
    f'git rev-list --max-count={MAX_JOB_COMMITS + 1} "$2..HEAD"; '
    f"else git rev-list --max-count={MAX_JOB_COMMITS + 1} HEAD; fi"
)
#: Room for HEAD plus one line more than the cap of 64-character ids.
VERIFY_OUTPUT_BYTES: Final = (MAX_JOB_COMMITS + 2) * 65 + 1024
_ENV: Final = (("HOME", "/work"), ("TMPDIR", "/work/tmp"), ("LANG", "C.UTF-8"))


def range_matches(job: Job, outcome: RunOutcome | None) -> bool:
    """True when the verification run shows exactly the job's head and commits."""
    if outcome is None or outcome.exit_code != 0 or outcome.timed_out or outcome.output_exceeded:
        return False
    try:
        lines = outcome.stdout.decode("ascii").split()
    except UnicodeDecodeError:
        return False
    if not lines or lines[0] != job.head or job.commits is None:
        return False
    listed = lines[1:]
    # `job.commits` holds at most MAX_JOB_COMMITS distinct ids (the job validator), so a
    # distinct list equal to it as a set is within the cap; the script lists one more than
    # the cap, so a longer range always differs.
    if len(set(listed)) != len(listed):
        return False
    return set(listed) == set(job.commits)


def verify_bundle(
    job: Job,
    backend: Backend,
    git_image: str,
    limits: ResolvedLimits,
    remaining_seconds: float,
) -> bool:
    """Run the verification container; True only for a bundle that matches the job."""
    if remaining_seconds <= 0:
        return False
    spec = ContainerSpec(
        name=new_id("sbx"),
        image=git_image,
        script=VERIFY_SCRIPT,
        command=("verify", job.base_ref or ""),
        env=_ENV,
        stdin=job.archive,
        limits=limits,
        timeout_seconds=remaining_seconds,
        max_output_bytes=VERIFY_OUTPUT_BYTES,
    )
    try:
        outcome = backend.run(spec)
    except Exception as exc:
        logger.error("bundle verification run raised %s", type(exc).__name__)
        outcome = None
    matched = range_matches(job, outcome)
    if not matched:
        logger.warning("job %s: bundle does not match its stated head and commits", job.job_id)
    return matched
