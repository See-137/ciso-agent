"""The sandbox worker: leases a change's job from the durable queue, sends the bundle to
the sandbox (fake client here), stores the report; retries through the queue, records a
failure when the queue gives up, and survives a restart through lease expiry."""

from __future__ import annotations

import threading
from collections.abc import Iterator, Mapping, Sequence
from pathlib import Path
from typing import Any

import pytest
from tests.app.change_helpers import (
    DEVICE,
    HEAD,
    SESSION,
    ChangeWorld,
    build_changes,
    push_upload,
)

from ciso.app.change_models import SANDBOX_JOB_KIND, ChangeState
from ciso.app.change_shape import ChangeKind, ChangeShape
from ciso.app.sandbox_client import SandboxUnavailable
from ciso.app.sandbox_worker import SandboxWorker
from ciso.common.errors import FailClosed
from ciso.inspection import Inspector
from ciso.workflows import JobState

pytestmark = pytest.mark.unit

CHECKS = ("secrets", "code", "tests")
SHAPE = ChangeShape(kind=ChangeKind.PUSH, remote="origin", branch="feature", source="feature")


def report(job_id: str, failed_tests: int = 0) -> dict[str, Any]:
    tests = {"passed": 3, "failed": failed_tests, "errors": 0}
    return {
        "job_id": job_id,
        "checks": [
            {"check_id": "secrets", "status": "passed"},
            {"check_id": "code", "status": "passed"},
            {"check_id": "tests", "status": "failed" if failed_tests else "passed", "tests": tests},
        ],
    }


class FakeSandbox:
    def __init__(self, *answers: Any) -> None:
        self.answers = list(answers)
        self.calls: list[tuple[str, bytes, str, tuple[str, ...]]] = []

    def run(
        self, job_id: str, bundle: bytes, base_ref: str, checks: Sequence[str]
    ) -> Mapping[str, Any]:
        self.calls.append((job_id, bundle, base_ref, tuple(checks)))
        answer = self.answers.pop(0)
        if isinstance(answer, BaseException):
            raise answer
        if callable(answer):
            return answer(job_id)  # type: ignore[no-any-return]
        return answer  # type: ignore[no-any-return]


@pytest.fixture
def world(tmp_path: Path) -> Iterator[ChangeWorld]:
    built = build_changes(tmp_path)
    yield built
    built.engine.dispose()


def _worker(
    world: ChangeWorld, sandbox: FakeSandbox, name: str = "w1", **changes: Any
) -> SandboxWorker:
    args: dict[str, Any] = {
        "queue": world.queue,
        "changes": world.service,
        "client": sandbox,
        "inspector": Inspector(required_sandbox_checks=CHECKS),
        "required_checks": CHECKS,
        "worker_id": name,
        "poll_seconds": 0.01,
    }
    args.update(changes)
    return SandboxWorker(**args)


def _state(world: ChangeWorld, change_id: str) -> Any:
    return world.service.resolve(
        change_id, device_actor_id=DEVICE, session_id=SESSION, shape=SHAPE, head=HEAD
    )


def test_a_clean_report_completes_the_change(world: ChangeWorld) -> None:
    receipt = world.service.submit(push_upload(), device_actor_id=DEVICE)
    sandbox = FakeSandbox(report)
    assert _worker(world, sandbox).run_once() is True
    resolved = _state(world, receipt.change_id)
    assert resolved.state is ChangeState.DONE
    assert resolved.sandbox.complete
    assert not resolved.sandbox.findings
    assert sandbox.calls[0][0] == receipt.change_id
    assert sandbox.calls[0][3] == CHECKS
    assert world.queue.stats().counts[JobState.DONE] == 1
    assert _worker(world, sandbox).run_once() is False  # nothing left


def test_failed_tests_are_a_finding(world: ChangeWorld) -> None:
    receipt = world.service.submit(push_upload(), device_actor_id=DEVICE)
    _worker(world, FakeSandbox(lambda j: report(j, failed_tests=2))).run_once()
    resolved = _state(world, receipt.change_id)
    assert [f.check_id for f in resolved.sandbox.findings] == ["sandbox.test_failure"]


def test_an_unavailable_sandbox_is_retried_then_recorded_as_failed(world: ChangeWorld) -> None:
    receipt = world.service.submit(push_upload(), device_actor_id=DEVICE)
    worker = _worker(world, FakeSandbox(SandboxUnavailable("status_503"), SandboxUnavailable("x")))
    worker.run_once()
    assert _state(world, receipt.change_id).state is ChangeState.PENDING  # retry is queued
    world.clock.advance(seconds=5)
    worker.run_once()  # second and last attempt (max_attempts=2)
    assert _state(world, receipt.change_id).state is ChangeState.FAILED
    assert world.queue.stats().counts[JobState.DEAD] == 1


def test_a_restart_mid_job_is_picked_up_after_the_lease_expires(world: ChangeWorld) -> None:
    receipt = world.service.submit(push_upload(), device_actor_id=DEVICE)
    crashed = world.queue.lease([SANDBOX_JOB_KIND], "w-crashed")  # leased, then the process died
    assert crashed is not None
    sandbox = FakeSandbox(report)
    assert _worker(world, sandbox, "w2").run_once() is False  # still leased
    world.clock.advance(seconds=61)
    assert _worker(world, sandbox, "w2").run_once() is True
    assert _state(world, receipt.change_id).state is ChangeState.DONE


def test_a_job_whose_report_is_already_in_is_just_completed(world: ChangeWorld) -> None:
    receipt = world.service.submit(push_upload(), device_actor_id=DEVICE)
    inspector = Inspector(required_sandbox_checks=CHECKS)
    world.service.record_report(
        receipt.change_id, inspector.from_sandbox_report(report("x"), action_id=receipt.change_id)
    )
    sandbox = FakeSandbox()
    assert _worker(world, sandbox).run_once() is True
    assert sandbox.calls == []
    assert world.queue.stats().counts[JobState.DONE] == 1


@pytest.mark.parametrize(
    "changes", [{"poll_seconds": None}, {"required_checks": None}, {"required_checks": ()}]
)
def test_unset_settings_refuse_to_start(world: ChangeWorld, changes: dict[str, Any]) -> None:
    worker = _worker(world, FakeSandbox(), **changes)
    stopped = threading.Event()
    stopped.set()  # bounded: a guard that is switched off returns instead of looping
    with pytest.raises(FailClosed):
        worker.run_forever(stopped)
    assert worker.missing()


def test_run_forever_stops_when_asked(world: ChangeWorld) -> None:
    world.service.submit(push_upload(), device_actor_id=DEVICE)
    stop = threading.Event()
    sandbox = FakeSandbox(report)
    worker = _worker(world, sandbox)
    thread = threading.Thread(target=worker.run_forever, args=(stop,))
    thread.start()
    for _ in range(500):
        if sandbox.calls:
            break
        stop.wait(0.01)
    stop.set()
    thread.join(timeout=5)
    assert not thread.is_alive()
    assert len(sandbox.calls) == 1
