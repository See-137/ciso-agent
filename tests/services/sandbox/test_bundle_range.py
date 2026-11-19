"""Review M2 and H1, sandbox side: before anything runs on a bundle, a git container checks
that the bundle's HEAD is the stated head, that the base is an ancestor inside the bundle,
and that the range holds exactly the stated commits. Any mismatch: every check `error`
`sandbox.range_mismatch`, nothing else runs, and the report names no head."""

from __future__ import annotations

import pytest
from pydantic import ValidationError
from services.sandbox.job import MAX_JOB_COMMITS, ArchiveFormat, CheckId, Job
from services.sandbox.report import validate_wire
from services.sandbox.runner import BUNDLE_SCRIPT, TAR_SCRIPT, JobRunner
from services.sandbox.settings import SandboxSettings
from services.sandbox.verify import VERIFY_SCRIPT
from tests.services.sandbox.bundle_support import (
    BASE,
    BUNDLE,
    HEAD,
    OLDER,
    FakeRepo,
    backend_for,
    bundle_job,
)
from tests.services.sandbox.support import fixture_bytes, image, outcome, tar_of

from ciso.common.clock import FixedClock

pytestmark = pytest.mark.unit

PY_TREE = {"pyproject.toml": b"[project]\n", "tests/test_a.py": b"def test_a(): pass\n"}
SCANNERS = {
    "gitleaks": outcome(0, b"[]"),
    "semgrep": outcome(0, fixture_bytes("semgrep_report.json")),
    "git": outcome(0, tar_of(PY_TREE)),
}


def run(settings: SandboxSettings, clock: FixedClock, repo: FakeRepo, job: Job) -> tuple:  # type: ignore[type-arg]
    backend = backend_for(repo, dict(SCANNERS))
    report = JobRunner(backend, settings, clock).run(job).to_wire()
    validate_wire(report)
    return report, backend


def mismatch(report: dict[str, object]) -> bool:
    checks = report["checks"]
    assert isinstance(checks, list)
    return all(
        c["status"] == "error" and c["findings"][0]["rule"] == "sandbox.range_mismatch"
        for c in checks
    )


def test_a_matching_bundle_is_scanned_and_reports_its_head(
    settings: SandboxSettings, clock: FixedClock
) -> None:
    repo = FakeRepo()
    report, backend = run(settings, clock, repo, bundle_job())
    assert report["head"] == HEAD
    verify = repo.verifications[0]
    assert backend.specs[0] is verify
    assert verify.image == image("git")
    assert verify.script == VERIFY_SCRIPT
    assert verify.command == ("verify", BASE)
    assert verify.stdin == BUNDLE
    assert [c["check_id"] for c in report["checks"]] == ["secrets", "code", "tests"]
    assert not mismatch(report)


def test_with_no_base_the_whole_history_is_the_range(
    settings: SandboxSettings, clock: FixedClock
) -> None:
    repo = FakeRepo(whole=(HEAD, OLDER))
    report, _ = run(settings, clock, repo, bundle_job(base_ref=None))
    assert repo.verifications[0].command == ("verify", "")
    assert report["head"] == HEAD
    assert not mismatch(report)


@pytest.mark.parametrize(
    "repo",
    [
        pytest.param(FakeRepo(head=OLDER), id="bundle-head-differs"),
        pytest.param(FakeRepo(base_is_ancestor=False), id="base-not-an-ancestor"),
        pytest.param(FakeRepo(above_base=(HEAD,)), id="fewer-commits-than-stated"),
        pytest.param(FakeRepo(above_base=(HEAD, OLDER, BASE)), id="more-commits-than-stated"),
        pytest.param(FakeRepo(above_base=(HEAD, "4" * 40)), id="other-commits"),
        pytest.param(FakeRepo(exit_code=128), id="clone-or-git-failed"),
    ],
)
def test_any_disagreement_is_a_range_mismatch_and_nothing_runs(
    settings: SandboxSettings, clock: FixedClock, repo: FakeRepo
) -> None:
    report, backend = run(settings, clock, repo, bundle_job())
    assert mismatch(report)
    assert report["head"] is None
    assert backend.specs == repo.verifications  # no scanner, no export, no test


def test_more_than_the_commit_cap_is_a_mismatch(
    settings: SandboxSettings, clock: FixedClock
) -> None:
    many = tuple(f"{n:040x}" for n in range(1, MAX_JOB_COMMITS + 2))
    repo = FakeRepo(head=many[0], whole=many)
    job = bundle_job(base_ref=None, head=many[0], commits=many[:MAX_JOB_COMMITS])
    report, backend = run(settings, clock, repo, job)
    assert mismatch(report)
    assert backend.specs == repo.verifications


def test_the_mismatch_message_echoes_nothing(settings: SandboxSettings, clock: FixedClock) -> None:
    report, _ = run(settings, clock, FakeRepo(head=OLDER), bundle_job())
    text = str(report)
    assert OLDER not in text
    assert HEAD not in text


def test_every_bundle_container_asserts_the_verified_head(
    settings: SandboxSettings, clock: FixedClock
) -> None:
    repo = FakeRepo()
    _, backend = run(settings, clock, repo, bundle_job())
    after = backend.specs[1:]
    bundle_specs = [s for s in after if s.script == BUNDLE_SCRIPT]
    assert len(bundle_specs) == 4  # export for tests, gitleaks git + dir, semgrep
    for spec in bundle_specs:
        assert dict(spec.env)["SANDBOX_HEAD"] == HEAD
    assert 'test "$(git rev-parse HEAD)" = "$SANDBOX_HEAD"' in BUNDLE_SCRIPT
    assert BUNDLE_SCRIPT.index("SANDBOX_HEAD") < BUNDLE_SCRIPT.index('exec "$@"')
    assert [s.script for s in after if s.script != BUNDLE_SCRIPT] == [TAR_SCRIPT]


def test_verify_script_checks_ancestry_and_lists_the_range() -> None:
    assert "git rev-parse HEAD" in VERIFY_SCRIPT
    assert 'git merge-base --is-ancestor "$2" HEAD' in VERIFY_SCRIPT
    assert "--max-count=" in VERIFY_SCRIPT
    assert "set -eu" in VERIFY_SCRIPT
    assert "{" not in VERIFY_SCRIPT


def test_a_bundle_job_without_the_git_image_refuses_every_check(
    settings: SandboxSettings, clock: FixedClock
) -> None:
    images = settings.images.model_copy(update={"git": None})
    partial = settings.model_copy(update={"images": images})
    backend = backend_for(FakeRepo(), dict(SCANNERS))
    report = JobRunner(backend, partial, clock).run(bundle_job()).to_wire()
    assert {(c["status"], c["findings"][0]["rule"]) for c in report["checks"]} == {
        ("error", "sandbox.settings_unset")
    }
    assert backend.specs == []
    assert report["head"] is None


def test_a_tar_job_reports_no_head(settings: SandboxSettings, clock: FixedClock) -> None:
    backend = backend_for(FakeRepo(), dict(SCANNERS))
    job = Job(
        job_id="t", archive_format=ArchiveFormat.TAR, archive=tar_of(PY_TREE),
        checks=(CheckId.SECRETS,),
    )  # fmt: skip
    assert JobRunner(backend, settings, clock).run(job).to_wire()["head"] is None


@pytest.mark.parametrize(
    "overrides",
    [
        {"head": None},
        {"commits": None},
        {"commits": ()},
        {"commits": (OLDER, HEAD)},  # head must come first
        {"commits": (HEAD, HEAD)},
        {"commits": (HEAD, "main")},
        {"head": "A" * 40, "commits": ("A" * 40,)},
        {"commits": tuple(f"{n:040x}" for n in range(1, MAX_JOB_COMMITS + 2))},
    ],
)
def test_bundle_jobs_need_a_head_and_a_bounded_commit_list(overrides: dict[str, object]) -> None:
    values: dict[str, object] = {
        "job_id": "j",
        "archive_format": ArchiveFormat.GIT_BUNDLE,
        "archive": BUNDLE,
        "head": HEAD,
        "commits": (HEAD, OLDER),
        "checks": (CheckId.SECRETS,),
    }
    values.update(overrides)
    with pytest.raises(ValidationError):
        Job(**values)


def test_tar_jobs_refuse_a_head_or_commits() -> None:
    for extra in ({"head": HEAD}, {"commits": (HEAD,)}):
        with pytest.raises(ValidationError):
            Job(
                job_id="j", archive_format=ArchiveFormat.TAR, archive=b"x",
                checks=(CheckId.SECRETS,), **extra,
            )  # fmt: skip


def test_commit_cap_is_a_thousand() -> None:
    assert MAX_JOB_COMMITS == 1000


def test_a_failed_verification_run_never_matches_even_with_the_right_output() -> None:
    from services.sandbox.verify import range_matches

    job = bundle_job()
    right = "\n".join((HEAD, HEAD, OLDER)).encode()
    assert range_matches(job, outcome(0, right)) is True
    assert range_matches(job, outcome(1, right)) is False
    assert range_matches(job, outcome(0, right, timed_out=True)) is False
    assert range_matches(job, outcome(0, right, exceeded=True)) is False
    assert range_matches(job, None) is False
    repeated = "\n".join((HEAD, HEAD, OLDER, OLDER)).encode()
    assert range_matches(job, outcome(0, repeated)) is False
