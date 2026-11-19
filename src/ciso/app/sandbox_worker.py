"""The sandbox worker: runs uploaded pushes through the sandbox service (spec C5, step 4).

Run it as its own process, next to the API, from the repository root:

    python -m ciso.app.sandbox_worker --config config/provisional-settings.json

It builds the same container as the API (same data directory and databases), then
loops: lease one `governance.sandbox_change` job from the durable queue, decrypt the
change's bundle, send it to the sandbox (`ciso.app.sandbox_client`, the only network
module), turn the report into an `InspectionResult` (`from_sandbox_report` with
`governance.required_sandbox_checks`) and store it, then complete the job. A failed send
goes back to the queue (`fail`: backoff, then dead-letter at
`safety.queue_max_attempts`); when the queue gives up, the change is recorded as failed,
so `decide` answers "not inspected" instead of "pending" for ever.

Restart-safe through the queue's leases: a worker that dies mid-job leaves the job
leased; once the lease expires another worker takes it. A job whose change already has
its report (the worker died after storing it) is completed without a second send. Each
loop also deletes the files of changes whose retention has ended (`ChangeService.purge`).

Refuses to start (`FailClosed`) while `governance.worker_poll_seconds` or
`governance.required_sandbox_checks` is unset, or while the sandbox timeout is not below
the queue lease (a job would be taken over while it still runs).
"""

from __future__ import annotations

import argparse
import logging
import threading
from collections.abc import Mapping, Sequence
from typing import Any, Protocol

from ciso.app.change_models import SANDBOX_JOB_KIND
from ciso.app.changes import ChangeService
from ciso.app.sandbox_client import SandboxClient
from ciso.common.errors import CisoError, FailClosed, NotFound
from ciso.common.ids import new_id
from ciso.inspection import Inspector
from ciso.workflows import Job, JobQueue, JobState

logger = logging.getLogger(__name__)


class SandboxRunner(Protocol):
    def run(
        self, job_id: str, bundle: bytes, base_ref: str, checks: Sequence[str]
    ) -> Mapping[str, Any]: ...


class SandboxWorker:
    def __init__(
        self,
        *,
        queue: JobQueue,
        changes: ChangeService,
        client: SandboxRunner,
        inspector: Inspector,
        required_checks: Sequence[str] | None,
        worker_id: str,
        poll_seconds: float | None,
        timeout_seconds: float | None = None,
        lease_seconds: float | None = None,
    ) -> None:
        self._queue = queue
        self._changes = changes
        self._client = client
        self._inspector = inspector
        self._checks = tuple(required_checks) if required_checks else ()
        self._worker = worker_id
        self._poll = poll_seconds
        self._timeout = timeout_seconds
        self._lease = lease_seconds

    def missing(self) -> tuple[str, ...]:
        """What keeps the worker from starting; empty when it can run."""
        found: list[str] = []
        if self._poll is None:
            found.append("governance.worker_poll_seconds")
        if not self._checks:
            found.append("governance.required_sandbox_checks")
        if self._timeout is not None and self._lease is not None and self._timeout >= self._lease:
            found.append("governance.sandbox_timeout_seconds (not below the queue lease)")
        return tuple(found)

    def run_forever(self, stop: threading.Event) -> None:
        """Work until `stop` is set. Waits `poll_seconds` when there is nothing to do."""
        missing = self.missing()
        if missing or self._poll is None:
            raise FailClosed("sandbox worker not configured: " + ", ".join(missing))
        while not stop.is_set():
            try:
                busy = self.run_once()
            except CisoError as exc:
                logger.error("sandbox worker: loop step failed (%s)", type(exc).__name__)
                busy = False
            if not busy:
                stop.wait(self._poll)

    def run_once(self) -> bool:
        """Purge expired files, then handle at most one job. True when a job was handled."""
        self._changes.purge()
        job = self._queue.lease([SANDBOX_JOB_KIND], self._worker)
        if job is None:
            return False
        self._handle(job)
        return True

    def _handle(self, job: Job) -> None:
        change_id = str(job.payload.get("change_id", ""))
        if self._changes.has_finished(change_id):
            logger.info("sandbox worker: %s already has its report", change_id)
            self._queue.complete(job.job_id, self._worker, attempt=job.attempts)
            return
        try:
            item = self._changes.load_for_sandbox(change_id)
            report = self._client.run(change_id, item.bundle, item.base, self._checks)
        except (CisoError, OSError) as exc:
            logger.warning("sandbox worker: %s not sent (%s)", change_id, type(exc).__name__)
            self._failed(job, change_id, exc)
            return
        result = self._inspector.from_sandbox_report(report, action_id=change_id)
        try:
            self._changes.record_report(change_id, result)
        except NotFound:
            logger.info("sandbox worker: %s already has its report", change_id)
        self._queue.complete(job.job_id, self._worker, attempt=job.attempts)

    def _failed(self, job: Job, change_id: str, error: BaseException) -> None:
        after = self._queue.fail(job.job_id, self._worker, error, attempt=job.attempts)
        if after.state is JobState.DEAD:
            try:
                self._changes.record_failure(change_id)
            except NotFound:
                logger.info("sandbox worker: %s already finished", change_id)


def build_worker(container: Any) -> SandboxWorker:
    """The worker for a built `Container` (see `main`)."""
    settings = container.settings
    gov = settings.governance
    client = SandboxClient(
        url=gov.sandbox_url,
        token_ref=gov.sandbox_token_ref,
        secrets=container.secret_store,
        timeout_seconds=gov.sandbox_timeout_seconds,
    )
    return SandboxWorker(
        queue=container.queue,
        changes=container.governance.changes,
        client=client,
        inspector=container.governance.inspector,
        required_checks=gov.required_sandbox_checks,
        worker_id=new_id("wrk"),
        poll_seconds=gov.worker_poll_seconds,
        timeout_seconds=gov.sandbox_timeout_seconds,
        lease_seconds=settings.safety.queue_lease_seconds,
    )


def main(argv: Sequence[str] | None = None) -> int:
    from ciso.app.container import build_container
    from ciso.app.settings import load_settings

    parser = argparse.ArgumentParser(prog="python -m ciso.app.sandbox_worker")
    parser.add_argument("--config", required=True, help="settings JSON file")
    args = parser.parse_args(argv)
    stop = threading.Event()
    with build_container(load_settings(args.config), logger_names=(__name__,)) as container:
        worker = build_worker(container)
        missing = worker.missing()
        if missing:
            logger.error("sandbox worker not started; missing: %s", ", ".join(missing))
            return 2
        logger.info("sandbox worker started")
        try:
            worker.run_forever(stop)
        except KeyboardInterrupt:
            stop.set()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
