"""What the runner asks the backend to run, and the report it returns."""

from __future__ import annotations

import io
import json
import tarfile

import pytest
from services.sandbox.job import ArchiveFormat, CheckId, Job
from services.sandbox.report import validate_wire
from services.sandbox.runner import BUNDLE_SCRIPT, TAR_SCRIPT, JobRunner
from services.sandbox.settings import SandboxSettings
from tests.services.sandbox.support import FakeBackend, fixture_bytes, image, outcome, tar_of

from ciso.common.clock import FixedClock

pytestmark = pytest.mark.unit

SHA = "0123456789abcdef0123456789abcdef01234567"
ALL = (CheckId.SECRETS, CheckId.CODE, CheckId.TESTS)
PY_TREE = {"pyproject.toml": b"[project]\n", "tests/test_a.py": b"def test_a(): pass\n"}
BUNDLE = b"# v2 git bundle\n" + SHA.encode() + b" refs/heads/main\n\nPACK"


def tar_job(files: dict[str, bytes] = PY_TREE, checks: tuple[CheckId, ...] = ALL) -> Job:
    return Job(
        job_id="job-1", archive_format=ArchiveFormat.TAR, archive=tar_of(files), checks=checks
    )


def names_in(tar_bytes: bytes) -> set[str]:
    with tarfile.open(fileobj=io.BytesIO(tar_bytes), mode="r:") as tf:
        return {m.name for m in tf.getmembers() if m.isfile()}


@pytest.fixture
def good_backend() -> FakeBackend:
    return FakeBackend(
        outcomes={
            "gitleaks": outcome(0, fixture_bytes("gitleaks_report.json")),
            "semgrep": outcome(0, fixture_bytes("semgrep_report.json")),
            "python": outcome(1, fixture_bytes("pytest_junit_failed.xml")),
            "git": outcome(0, tar_of(PY_TREE)),
        }
    )


def test_tar_job_runs_three_isolated_containers(
    settings: SandboxSettings, clock: FixedClock, good_backend: FakeBackend
) -> None:
    report = JobRunner(good_backend, settings, clock).run(tar_job()).to_wire()
    validate_wire(report)
    assert report["job_id"] == "job-1"
    assert [(c["check_id"], c["status"]) for c in report["checks"]] == [
        ("secrets", "failed"),
        ("code", "failed"),
        ("tests", "failed"),
    ]
    assert report["checks"][2]["tests"] == {"passed": 2, "failed": 1, "errors": 1}
    images = [s.image for s in good_backend.specs]
    assert images == [image("gitleaks"), image("semgrep"), image("python-tests")]
    assert good_backend.probes == [(image("gitleaks"), image("semgrep"), image("python-tests"))]


def test_tar_job_streams_a_rebuilt_archive_not_the_original(
    settings: SandboxSettings, clock: FixedClock, good_backend: FakeBackend
) -> None:
    job = tar_job()
    JobRunner(good_backend, settings, clock).run(job)
    for spec in good_backend.specs:
        assert spec.script == TAR_SCRIPT
        assert spec.stdin != job.archive
        assert names_in(spec.stdin) == set(PY_TREE)


def test_container_specs_carry_limits_names_and_fixed_env(
    settings: SandboxSettings, clock: FixedClock, good_backend: FakeBackend
) -> None:
    JobRunner(good_backend, settings, clock).run(tar_job())
    resolved = settings.limits.resolve()
    names = [s.name for s in good_backend.specs]
    assert len(set(names)) == 3
    for spec in good_backend.specs:
        assert spec.limits == resolved
        assert spec.max_output_bytes == resolved.output_bytes
        env = dict(spec.env)
        assert env["HOME"] == "/work"
        assert all(not value.startswith("$") for value in env.values())


def test_scanner_commands_for_a_working_tree(
    settings: SandboxSettings, clock: FixedClock, good_backend: FakeBackend
) -> None:
    JobRunner(good_backend, settings, clock).run(tar_job())
    gitleaks, semgrep, tests = (s.command for s in good_backend.specs)
    assert gitleaks[:3] == ("gitleaks", "dir", ".")
    for flag in ("--redact", "--no-banner"):
        assert flag in gitleaks
    assert gitleaks[gitleaks.index("--report-format") + 1] == "json"
    assert gitleaks[gitleaks.index("--report-path") + 1] == "-"
    assert gitleaks[gitleaks.index("--exit-code") + 1] == "0"
    assert semgrep[:3] == ("semgrep", "scan", "--json")
    assert semgrep[semgrep.index("--config") + 1] == "/rules/semgrep"
    assert semgrep[semgrep.index("--metrics") + 1] == "off"
    assert "--disable-version-check" in semgrep
    assert "--baseline-commit" not in semgrep
    assert tests[:3] == ("python", "-m", "pytest")


def test_gitleaks_custom_rules_are_passed_when_configured(
    settings: SandboxSettings, clock: FixedClock, good_backend: FakeBackend
) -> None:
    images = settings.images.model_copy(update={"gitleaks_config": "/rules/gitleaks.toml"})
    configured = settings.model_copy(update={"images": images})
    JobRunner(good_backend, configured, clock).run(tar_job(checks=(CheckId.SECRETS,)))
    command = good_backend.specs[0].command
    assert command[command.index("--config") + 1] == "/rules/gitleaks.toml"


@pytest.mark.parametrize(
    ("files", "command", "image_name"),
    [
        ({"package.json": b"{}"}, ("npm", "test"), "node-tests"),
        ({"go.mod": b"module x\n"}, ("go", "test", "-json", "./..."), "go-tests"),
    ],
)
def test_test_command_follows_the_detected_project(
    settings: SandboxSettings,
    clock: FixedClock,
    files: dict[str, bytes],
    command: tuple[str, ...],
    image_name: str,
) -> None:
    backend = FakeBackend()
    JobRunner(backend, settings, clock).run(tar_job(files, (CheckId.TESTS,)))
    assert backend.specs[0].command == command
    assert backend.specs[0].image == image(image_name)


def test_no_project_means_tests_skipped_without_a_container(
    settings: SandboxSettings, clock: FixedClock
) -> None:
    backend = FakeBackend()
    report = JobRunner(backend, settings, clock).run(
        tar_job({"README.md": b"hi"}, (CheckId.TESTS,))
    )
    check = report.to_wire()["checks"][0]
    assert check["status"] == "skipped"
    assert check["findings"][0]["rule"] == "sandbox.no_test_project"
    assert backend.specs == []


def test_bundle_job_scans_history_and_tests_the_head_tree(
    settings: SandboxSettings, clock: FixedClock, good_backend: FakeBackend
) -> None:
    job = Job(
        job_id="job-2",
        archive_format=ArchiveFormat.GIT_BUNDLE,
        archive=BUNDLE,
        base_ref=SHA,
        checks=ALL,
    )
    report = JobRunner(good_backend, settings, clock).run(job).to_wire()
    validate_wire(report)
    prepare, gitleaks, semgrep, tests = good_backend.specs
    assert prepare.image == image("git")
    assert prepare.command == ("git", "archive", "--format=tar", "HEAD")
    assert prepare.script == BUNDLE_SCRIPT
    assert prepare.stdin == BUNDLE
    assert gitleaks.script == semgrep.script == BUNDLE_SCRIPT
    assert gitleaks.stdin == semgrep.stdin == BUNDLE
    assert gitleaks.command[:3] == ("gitleaks", "git", ".")
    assert gitleaks.command[gitleaks.command.index("--log-opts") + 1] == f"{SHA}..HEAD"
    assert semgrep.command[semgrep.command.index("--baseline-commit") + 1] == SHA
    assert tests.script == TAR_SCRIPT
    assert names_in(tests.stdin) == set(PY_TREE)
    assert [c["status"] for c in report["checks"]] == ["failed", "failed", "failed"]


def test_bundle_without_base_scans_whole_history(
    settings: SandboxSettings, clock: FixedClock, good_backend: FakeBackend
) -> None:
    job = Job(
        job_id="job-2",
        archive_format=ArchiveFormat.GIT_BUNDLE,
        archive=BUNDLE,
        checks=(CheckId.SECRETS, CheckId.CODE),
    )
    JobRunner(good_backend, settings, clock).run(job)
    gitleaks, semgrep = good_backend.specs
    assert "--log-opts" not in gitleaks.command
    assert "--baseline-commit" not in semgrep.command


def test_bundle_prepare_failure_fails_tests_closed(
    settings: SandboxSettings, clock: FixedClock
) -> None:
    backend = FakeBackend(outcomes={"git": outcome(128, b"")})
    job = Job(
        job_id="job-2",
        archive_format=ArchiveFormat.GIT_BUNDLE,
        archive=BUNDLE,
        checks=(CheckId.TESTS,),
    )
    check = JobRunner(backend, settings, clock).run(job).to_wire()["checks"][0]
    assert (check["status"], check["findings"][0]["rule"]) == ("error", "sandbox.prepare_failed")


def test_bundle_prepare_output_goes_through_the_same_archive_defenses(
    settings: SandboxSettings, clock: FixedClock
) -> None:
    from tests.services.sandbox.support import tar_with

    hostile = tar_with([(tarfile.TarInfo("../x"), b"")])
    backend = FakeBackend(outcomes={"git": outcome(0, hostile)})
    job = Job(
        job_id="job-2",
        archive_format=ArchiveFormat.GIT_BUNDLE,
        archive=BUNDLE,
        checks=(CheckId.TESTS,),
    )
    check = JobRunner(backend, settings, clock).run(job).to_wire()["checks"][0]
    assert (check["status"], check["findings"][0]["rule"]) == ("error", "sandbox.archive_rejected")
    assert len(backend.specs) == 1


def test_report_is_json_serialisable_and_has_no_extra_keys(
    settings: SandboxSettings, clock: FixedClock, good_backend: FakeBackend
) -> None:
    report = JobRunner(good_backend, settings, clock).run(tar_job()).to_wire()
    text = json.dumps(report)
    assert json.loads(text) == report


def test_scripts_take_no_job_data() -> None:
    for script in (TAR_SCRIPT, BUNDLE_SCRIPT):
        assert '"$@"' in script
        assert "{" not in script


def test_health_reports_missing_settings(clock: FixedClock) -> None:
    runner = JobRunner(FakeBackend(), SandboxSettings(), clock)
    health = runner.health()
    assert not health.usable
    assert "limits" in health.missing
    assert "gitleaks" in health.missing


def test_health_usable_when_everything_answers(
    settings: SandboxSettings, clock: FixedClock
) -> None:
    backend = FakeBackend()
    health = JobRunner(backend, settings, clock).health()
    assert health.usable
    assert health.missing == ()
    assert health.backend_reasons == ()
    assert set(backend.probes[0]) == {
        image(n) for n in ("python-tests", "node-tests", "go-tests", "gitleaks", "semgrep", "git")
    }


def test_health_with_no_backend(settings: SandboxSettings, clock: FixedClock) -> None:
    health = JobRunner(None, settings, clock).health()
    assert not health.usable
    assert health.backend_reasons == ("no_backend",)
