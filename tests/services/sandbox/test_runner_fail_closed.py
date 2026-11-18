"""No isolation, no run: every way the sandbox cannot isolate ends in `error`, never a run."""

from __future__ import annotations

from collections.abc import Sequence

import pytest
from services.sandbox.backend import BackendHealth
from services.sandbox.job import ArchiveFormat, CheckId, Job
from services.sandbox.runner import JobRunner
from services.sandbox.settings import SandboxImages, SandboxLimits, SandboxSettings
from tests.services.sandbox.support import FakeBackend, tar_of

from ciso.common.clock import FixedClock

pytestmark = pytest.mark.resilience

ALL = (CheckId.SECRETS, CheckId.CODE, CheckId.TESTS)


def tar_job(checks: tuple[CheckId, ...] = ALL) -> Job:
    return Job(
        job_id="job-1",
        archive_format=ArchiveFormat.TAR,
        archive=tar_of({"pyproject.toml": b"[project]\n", "t/test_a.py": b"def test(): pass\n"}),
        checks=checks,
    )


def rules(report_wire: dict[str, object]) -> list[tuple[str, str, str]]:
    checks = report_wire["checks"]
    assert isinstance(checks, list)
    return [
        (c["check_id"], c["status"], c["findings"][0]["rule"] if c["findings"] else "")
        for c in checks
    ]


def test_no_backend_fails_closed(settings: SandboxSettings, clock: FixedClock) -> None:
    report = JobRunner(None, settings, clock).run(tar_job()).to_wire()
    assert rules(report) == [
        ("secrets", "error", "sandbox.isolation_unavailable"),
        ("code", "error", "sandbox.isolation_unavailable"),
        ("tests", "error", "sandbox.isolation_unavailable"),
    ]
    messages = {c["findings"][0]["message"] for c in report["checks"]}
    assert messages == {"no isolation backend is configured"}


def test_unusable_backend_fails_closed_without_running(
    settings: SandboxSettings, clock: FixedClock
) -> None:
    backend = FakeBackend(usable=False)
    report = JobRunner(backend, settings, clock).run(tar_job()).to_wire()
    assert {r[2] for r in rules(report)} == {"sandbox.isolation_unavailable"}
    assert backend.specs == []
    assert len(backend.probes) == 1


def test_probe_exception_fails_closed(settings: SandboxSettings, clock: FixedClock) -> None:
    class Broken(FakeBackend):
        def probe(self, images: Sequence[str]) -> BackendHealth:
            raise OSError("daemon gone")

    backend = Broken()
    report = JobRunner(backend, settings, clock).run(tar_job()).to_wire()
    assert {r[2] for r in rules(report)} == {"sandbox.isolation_unavailable"}
    assert backend.specs == []


def test_unset_limits_refuse_before_anything_runs(
    images: SandboxImages, clock: FixedClock, backend: FakeBackend
) -> None:
    settings = SandboxSettings(limits=SandboxLimits(), images=images, docker_cli="/d")
    report = JobRunner(backend, settings, clock).run(tar_job()).to_wire()
    assert {r[1:] for r in rules(report)} == {("error", "sandbox.settings_unset")}
    assert backend.specs == []
    assert backend.probes == []


def test_unset_scanner_image_refuses_that_check_only(
    settings: SandboxSettings, clock: FixedClock, backend: FakeBackend
) -> None:
    images = settings.images.model_copy(update={"gitleaks": None})
    partial = settings.model_copy(update={"images": images})
    report = JobRunner(backend, partial, clock).run(tar_job()).to_wire()
    assert rules(report)[0] == ("secrets", "error", "sandbox.settings_unset")
    assert [s.command[0] for s in backend.specs] == ["semgrep", "python"]


def test_unset_semgrep_rules_refuse_code_check(
    settings: SandboxSettings, clock: FixedClock, backend: FakeBackend
) -> None:
    images = settings.images.model_copy(update={"semgrep_config": None})
    partial = settings.model_copy(update={"images": images})
    report = JobRunner(backend, partial, clock).run(tar_job((CheckId.CODE,))).to_wire()
    assert rules(report) == [("code", "error", "sandbox.settings_unset")]
    assert backend.specs == []


def test_rejected_archive_runs_nothing(
    settings: SandboxSettings, clock: FixedClock, backend: FakeBackend
) -> None:
    bad = Job(job_id="job-1", archive_format=ArchiveFormat.TAR, archive=b"PK\x03\x04", checks=ALL)
    report = JobRunner(backend, settings, clock).run(bad).to_wire()
    assert {r[1:] for r in rules(report)} == {("error", "sandbox.archive_rejected")}
    assert backend.specs == []


def test_backend_exception_is_an_error_not_a_pass(
    settings: SandboxSettings, clock: FixedClock
) -> None:
    backend = FakeBackend(raise_on_run=OSError("exec failed"))
    report = JobRunner(backend, settings, clock).run(tar_job()).to_wire()
    assert {r[1:] for r in rules(report)} == {("error", "sandbox.backend_failure")}


def test_wall_time_is_shared_by_the_whole_job(settings: SandboxSettings, clock: FixedClock) -> None:
    def slow(spec: object) -> object:
        clock.advance(seconds=200)
        from tests.services.sandbox.support import outcome

        return outcome(0, b"[]")

    backend = FakeBackend(outcomes={"gitleaks": slow})  # type: ignore[dict-item]
    report = JobRunner(backend, settings, clock).run(tar_job()).to_wire()
    assert rules(report)[1:] == [
        ("code", "error", "sandbox.wall_time_exceeded"),
        ("tests", "error", "sandbox.wall_time_exceeded"),
    ]
    assert len(backend.specs) == 1
    assert backend.specs[0].timeout_seconds == 120.0


def test_each_container_gets_only_the_remaining_time(
    settings: SandboxSettings, clock: FixedClock
) -> None:
    def thirty(spec: object) -> object:
        clock.advance(seconds=30)
        from tests.services.sandbox.support import outcome

        return outcome(0, b"[]")

    backend = FakeBackend(outcomes={"gitleaks": thirty})  # type: ignore[dict-item]
    JobRunner(backend, settings, clock).run(tar_job((CheckId.SECRETS, CheckId.CODE)))
    assert [s.timeout_seconds for s in backend.specs] == [120.0, 90.0]


def test_bundle_without_git_image_refuses(
    settings: SandboxSettings, clock: FixedClock, backend: FakeBackend
) -> None:
    images = settings.images.model_copy(update={"git": None})
    partial = settings.model_copy(update={"images": images})
    bundle = Job(
        job_id="job-1",
        archive_format=ArchiveFormat.GIT_BUNDLE,
        archive=b"# v2 git bundle\nabc refs/heads/main\n\nPACK",
        checks=(CheckId.TESTS,),
    )
    report = JobRunner(backend, partial, clock).run(bundle).to_wire()
    assert rules(report) == [("tests", "error", "sandbox.settings_unset")]
    assert backend.specs == []
