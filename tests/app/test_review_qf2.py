"""Fix round QF2 on the pre-push path: the adversarial review of the skill service
(docs/reviews/skill-service-adversarial.md, H1 M1 M2 L1 L2 L3 L6) and the pre-push lane's
leftovers, each reproduced on the change store and the sandbox worker."""

from __future__ import annotations

import base64
from collections.abc import Iterator, Mapping, Sequence
from datetime import timedelta
from pathlib import Path
from typing import Any

import httpx
import pytest
from tests.app.change_helpers import (
    DEVICE,
    HEAD,
    REPOSITORY,
    SESSION,
    ChangeWorld,
    build_changes,
    bundle_for,
    commit_upload,
    push_upload,
    sha,
)
from tests.fakes.core import FakeSecrets

from ciso.app.change_models import (
    ChangeRefusal,
    ChangeRefused,
    ChangeState,
    DeviceBusy,
    SandboxInput,
    UploadRefusal,
    UploadRefused,
    normalize_repository,
)
from ciso.app.change_shape import ChangeKind, ChangeShape
from ciso.app.sandbox_client import SandboxBusy, SandboxClient
from ciso.app.sandbox_worker import SandboxWorker
from ciso.common.enums import KillCapability
from ciso.common.errors import FailClosed, ValidationFailed
from ciso.inspection import Inspector
from ciso.workflows import JobState

pytestmark = pytest.mark.unit

CHECKS = ("secrets", "code", "tests")
SHAPE = ChangeShape(kind=ChangeKind.PUSH, remote="origin", branch="feature", source="feature")
OTHER = sha("other-head")


def report(job_id: str, head: str | None = HEAD) -> dict[str, Any]:
    body: dict[str, Any] = {
        "job_id": job_id,
        "checks": [
            {"check_id": "secrets", "status": "passed"},
            {"check_id": "code", "status": "passed"},
            {"check_id": "tests", "status": "passed", "tests": {"passed": 1}},
        ],
    }
    if head is not None:
        body["head"] = head
    return body


class FakeSandbox:
    def __init__(self, *answers: Any) -> None:
        self.answers = list(answers)
        self.items: list[SandboxInput] = []

    def run(self, item: SandboxInput, checks: Sequence[str]) -> Mapping[str, Any]:
        self.items.append(item)
        answer = self.answers.pop(0)
        if isinstance(answer, BaseException):
            raise answer
        if callable(answer):
            return answer(item.change_id)  # type: ignore[no-any-return]
        return answer  # type: ignore[no-any-return]


@pytest.fixture
def world(tmp_path: Path) -> Iterator[ChangeWorld]:
    built = build_changes(tmp_path)
    yield built
    built.engine.dispose()


def worker(world: ChangeWorld, sandbox: FakeSandbox) -> SandboxWorker:
    return SandboxWorker(
        queue=world.queue,
        changes=world.service,
        client=sandbox,
        inspector=Inspector(required_sandbox_checks=CHECKS),
        required_checks=CHECKS,
        worker_id="w1",
        poll_seconds=1.0,
    )


def submit(world: ChangeWorld, device: str = DEVICE, **changes: Any) -> str:
    return world.service.submit(push_upload(**changes), device_actor_id=device).change_id


def state(world: ChangeWorld, change_id: str) -> ChangeState:
    row = world.service._row(change_id)
    return ChangeState(row.state)


# --- M2: the bundle's tip, the commit list and the stated head agree ---------------------


@pytest.mark.parametrize(
    "bundle",
    [
        bundle_for(OTHER),
        bundle_for(HEAD, extra=b"-" + OTHER.encode() + b" prerequisite\n"),
        b"# v2 git bundle\n" + HEAD.encode() + b" HEAD\n\nPACK",
        b"# v2 git bundle\n" + HEAD.encode() + b" HEAD\n" + HEAD.encode() + b" refs/heads/x\n\nP",
        b"# v2 git bundle\n" + HEAD.encode() + b" HEAD\n" + HEAD.encode() + b" refs/heads/aigov\n",
    ],
    ids=["other-tip", "prerequisite", "no-aigov-ref", "extra-ref", "no-end-of-header"],
)
def test_a_bundle_whose_tip_is_not_the_stated_head_is_refused(
    world: ChangeWorld, bundle: bytes
) -> None:
    with pytest.raises(ValidationFailed):
        submit(world, bundle_b64=base64.b64encode(bundle).decode())


def test_a_v3_bundle_with_capabilities_naming_the_head_is_accepted(world: ChangeWorld) -> None:
    refs = f"{HEAD} HEAD\n{HEAD} refs/heads/aigov\n".encode()
    bundle = b"# v3 git bundle\n@object-format=sha1\n" + refs + b"\nPACK"
    assert submit(world, bundle_b64=base64.b64encode(bundle).decode()).startswith("chg_")


# --- H1 / Q18: the scan base must be a head the service approved -------------------------


def test_a_base_the_service_never_approved_is_refused(world: ChangeWorld) -> None:
    with pytest.raises(UploadRefused) as info:
        submit(world, base=sha("forged-tracking-ref"), commits=[HEAD])
    assert info.value.reason is UploadRefusal.BASE_NOT_APPROVED


def test_no_base_scans_from_the_root_and_an_approved_head_becomes_a_base(
    world: ChangeWorld,
) -> None:
    first = submit(world)
    assert world.service.load_for_sandbox(first).base is None
    world.service.record_report(first, Inspector(required_sandbox_checks=CHECKS).
                                from_sandbox_report(report(first, None), action_id=first))  # fmt: skip
    resolved = world.service.resolve(
        first, device_actor_id=DEVICE, session_id=SESSION, shape=SHAPE, head=HEAD
    )
    world.service.record_approved(resolved, decision_id="dec_X")
    assert world.service.approved_bases(REPOSITORY, "feature") == (HEAD,)
    # the same repository spelt another way, and only for that branch
    assert world.service.approved_bases("ssh://git@GIT.example.test/team/app", "feature") == (HEAD,)
    assert world.service.approved_bases(REPOSITORY, "main") == ()
    newer = sha("newer")
    later = submit(
        world, head=newer, base=HEAD, commits=[newer],
        bundle_b64=base64.b64encode(bundle_for(newer)).decode(),
    )  # fmt: skip
    assert world.service.load_for_sandbox(later).base == HEAD


@pytest.mark.parametrize(
    ("raw", "key"),
    [
        ("https://user:pw@Git.Example.test/Team/App.git/", "git.example.test/team/app"),
        ("git@git.example.test:team/app.git", "git.example.test/team/app"),
        ("ssh://git@git.example.test:2222/team/app", "git.example.test/team/app"),
        ("C:\\work\\remote.git", "file:c:/work/remote"),
        ("file:///srv/git/remote.git", "file:/srv/git/remote"),
    ],
)
def test_repositories_are_normalised(raw: str, key: str) -> None:
    assert normalize_repository(raw) == key


@pytest.mark.parametrize("raw", ["", " https://x/y", "https://x/y z", "a\nb", "x" * 600])
def test_a_bad_repository_is_refused(raw: str) -> None:
    with pytest.raises(ValueError):
        normalize_repository(raw)


def test_a_push_without_a_repository_is_refused(world: ChangeWorld) -> None:
    with pytest.raises(ValidationFailed):
        submit(world, repository=None)
    with pytest.raises(ValidationFailed):
        world.service.submit(commit_upload(repository=REPOSITORY), device_actor_id=DEVICE)


# --- M1: uploads and the worker stop while WRITES is blocked -----------------------------


def test_an_upload_is_refused_while_writes_are_blocked(world: ChangeWorld) -> None:
    world.killswitch.blocked.add(KillCapability.WRITES)
    with pytest.raises(FailClosed):
        submit(world)
    assert not list(world.store_dir.glob("*.bin")) if world.store_dir.exists() else True


def test_an_unreadable_kill_switch_refuses_the_upload(world: ChangeWorld) -> None:
    world.killswitch.broken = True
    with pytest.raises(FailClosed):
        submit(world)


def test_the_worker_idles_while_writes_are_blocked(world: ChangeWorld) -> None:
    change_id = submit(world)
    sandbox = FakeSandbox(report)
    world.killswitch.blocked.add(KillCapability.WRITES)
    assert worker(world, sandbox).run_once() is False
    assert sandbox.items == []
    assert world.queue.stats().counts.get(JobState.PENDING) == 1
    world.killswitch.blocked.clear()
    assert worker(world, sandbox).run_once() is True
    assert state(world, change_id) is ChangeState.DONE


# --- M2 / L1: the report must name this change and the head the service holds ------------


@pytest.mark.parametrize(
    "answer",
    [
        lambda job: report("some-other-job"),
        lambda job: report(job, head=None),
        lambda job: report(job, head=OTHER),
    ],
    ids=["other-job-id", "no-head", "other-head"],
)
def test_a_report_for_another_job_or_head_refuses_the_change(
    world: ChangeWorld, answer: Any
) -> None:
    change_id = submit(world)
    assert worker(world, FakeSandbox(answer)).run_once() is True
    assert state(world, change_id) is ChangeState.REFUSED
    with pytest.raises(ChangeRefused) as info:
        world.service.resolve(change_id, device_actor_id=DEVICE, session_id=SESSION,
                              shape=SHAPE, head=HEAD)  # fmt: skip
    assert info.value.code is ChangeRefusal.SANDBOX_MISMATCH


def test_the_worker_sends_the_head_commits_and_base(world: ChangeWorld) -> None:
    change_id = submit(world)
    sandbox = FakeSandbox(report)
    worker(world, sandbox).run_once()
    item = sandbox.items[0]
    assert (item.head, item.commits, item.base) == (HEAD, (HEAD,), None)
    assert state(world, change_id) is ChangeState.DONE


# --- L2: a failed change is not sticky; any error stays inside the job --------------------


def test_an_identical_upload_after_a_failure_is_scanned_again(world: ChangeWorld) -> None:
    first = submit(world)
    world.service.record_failure(first)
    again = world.service.submit(push_upload(), device_actor_id=DEVICE)
    assert again.created is True and again.change_id != first
    assert state(world, again.change_id) is ChangeState.PENDING


def test_an_unexpected_error_fails_the_job_instead_of_stopping_the_worker(
    world: ChangeWorld,
) -> None:
    submit(world)
    assert worker(world, FakeSandbox(RuntimeError("boom"))).run_once() is True
    assert world.queue.stats().counts.get(JobState.PENDING) == 1  # retried later


# --- L3: one queued job per device; a busy sandbox costs no attempt ----------------------


def test_a_device_has_at_most_one_pending_push(world: ChangeWorld) -> None:
    first = submit(world)
    other = sha("second")
    second = {"head": other, "commits": [other],
              "bundle_b64": base64.b64encode(bundle_for(other)).decode()}  # fmt: skip
    with pytest.raises(DeviceBusy):
        submit(world, **second)
    assert submit(world, device="svc_device_2", **second).startswith("chg_")
    assert world.service.submit(push_upload(), device_actor_id=DEVICE).change_id == first
    world.service.record_failure(first)
    assert submit(world, **second).startswith("chg_")


def test_a_busy_sandbox_is_retried_on_the_same_lease(world: ChangeWorld) -> None:
    change_id = submit(world)
    sandbox = FakeSandbox(SandboxBusy("status_429"), SandboxBusy("status_429"), report)
    run = worker(world, sandbox)
    for _ in range(3):
        world.clock.advance(timedelta(seconds=1))
        assert run.run_once() is True
    assert state(world, change_id) is ChangeState.DONE
    job = world.queue.enqueue("governance.sandbox_change", {"change_id": change_id},
                              source="governance.changes", event_id=change_id).job  # fmt: skip
    assert job.attempts == 1


# --- L6: no file without its row ---------------------------------------------------------


def test_a_failed_insert_leaves_no_orphaned_file(
    world: ChangeWorld, monkeypatch: pytest.MonkeyPatch
) -> None:
    def broken(*args: Any, **kwargs: Any) -> None:
        raise RuntimeError("database gone")

    monkeypatch.setattr(world.service, "_insert", broken)
    with pytest.raises(RuntimeError):
        submit(world)
    assert world.store_dir.exists()
    assert list(world.store_dir.iterdir()) == []


# --- leftovers ---------------------------------------------------------------------------


def test_a_deduplicated_upload_is_audited(world: ChangeWorld) -> None:
    first = submit(world)
    world.service.submit(push_upload(), device_actor_id=DEVICE)
    records = world.audit.find("governance.change.submit")
    assert [r.details.get("deduplicated") for r in records] == [None, None, True]
    assert records[-1].target == first


def test_a_job_dead_lettered_by_lease_expiry_fails_its_change(world: ChangeWorld) -> None:
    change_id = submit(world)
    for _ in range(2):  # the helper queue allows 2 attempts, 60 s leases
        assert world.queue.lease(["governance.sandbox_change"], "dead-worker") is not None
        world.clock.advance(timedelta(seconds=61))
    assert world.queue.lease(["governance.sandbox_change"], "dead-worker") is None
    assert state(world, change_id) is ChangeState.PENDING
    worker(world, FakeSandbox()).run_once()
    assert state(world, change_id) is ChangeState.FAILED


# --- the sandbox client: head, commits, base; 429 is busy ---------------------------------


def _client(handler: Any) -> SandboxClient:
    return SandboxClient(
        url="https://sandbox.example.test",
        token_ref="secret://t",
        secrets=FakeSecrets({"secret://t": "sandbox-token-0123456789"}),
        timeout_seconds=5.0,
        transport=httpx.MockTransport(handler),
    )


def test_the_client_sends_head_and_commits_and_reads_429_as_busy() -> None:
    seen: list[dict[str, Any]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        import json

        seen.append(json.loads(request.content))
        return httpx.Response(429 if len(seen) > 1 else 200, json={"job_id": "chg_1"})

    item = SandboxInput(change_id="chg_1", bundle=b"b", base=None, head=HEAD, commits=(HEAD,))
    _client(handler).run(item, CHECKS)
    assert (seen[0]["head"], seen[0]["commits"], seen[0]["base_ref"]) == (HEAD, [HEAD], None)
    with pytest.raises(SandboxBusy):
        _client(handler).run(item, CHECKS)
