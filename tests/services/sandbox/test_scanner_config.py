"""Review H3: the scanners never take configuration from the repository they scan.

- gitleaks always gets the image's config (required; no fallback to the target's
  `.gitleaks.toml` or built-in rules), an empty ignore file from the image (never the
  repository's `.gitleaksignore`), and `--ignore-gitleaks-allow` (inline allow comments
  are not honoured). A bundle is scanned twice: history (`git` mode) and the checked-out
  tree (`dir` mode), merged into one `secrets` check.
- semgrep runs with `--disable-nosem` and `--x-ignore-semgrepignore-files`.
- The fixed scripts neutralise `.gitattributes` for git (`* diff` in `.git/info/attributes`,
  which outranks every attribute file in the tree) and move the scanners' own files out of
  the scanned directory before anything runs.

A repository's files cannot reach any command line: the commands below are built before
the code is opened and take nothing from it.
"""

from __future__ import annotations

import pytest
from services.sandbox.job import ArchiveFormat, CheckId, Job
from services.sandbox.report import CheckReport, Status, finding, merge_checks, validate_wire
from services.sandbox.runner import BUNDLE_SCRIPT, TAR_SCRIPT, JobRunner
from services.sandbox.settings import SandboxImages, SandboxSettings
from tests.services.sandbox.bundle_support import FakeRepo, backend_for, bundle_job
from tests.services.sandbox.support import FakeBackend, fixture_bytes, image, outcome, tar_of

from ciso.common.activity import Severity
from ciso.common.clock import FixedClock

pytestmark = pytest.mark.unit

# Repository files a hostile change could plant (built from fragments: no real secret).
ALLOW_COMMENT = b"token = 'x'  # gitleaks" + b":allow\n"
PLANTED = {
    "pyproject.toml": b"[project]\n",
    ".gitleaks.toml": b"[allowlist]\npaths = ['.*']\n",
    ".gitleaksignore": b"fingerprint:all\n",
    ".semgrepignore": b"*\n",
    ".gitattributes": b"* -diff\n",
    "app.py": ALLOW_COMMENT + b"x = 1  # nosemgrep\n",
}


def tar_job(files: dict[str, bytes], checks: tuple[CheckId, ...]) -> Job:
    return Job(job_id="j", archive_format=ArchiveFormat.TAR, archive=tar_of(files), checks=checks)


def commands(backend: FakeBackend, word: str) -> list[tuple[str, ...]]:
    return [s.command for s in backend.specs if s.command[0] == word]


def value(command: tuple[str, ...], flag: str) -> str:
    return command[command.index(flag) + 1]


def test_gitleaks_uses_only_the_images_config_and_empty_ignore_file(
    settings: SandboxSettings, clock: FixedClock
) -> None:
    clean = FakeBackend()
    planted = FakeBackend()
    JobRunner(clean, settings, clock).run(tar_job({"a.py": b"x"}, (CheckId.SECRETS,)))
    JobRunner(planted, settings, clock).run(tar_job(PLANTED, (CheckId.SECRETS,)))
    (command,) = commands(planted, "gitleaks")
    assert commands(clean, "gitleaks") == [command]  # the repository changed nothing
    assert value(command, "--config") == "/rules/gitleaks.toml"
    assert value(command, "--gitleaks-ignore-path") == "/rules/empty.gitleaksignore"
    assert "--ignore-gitleaks-allow" in command


def test_semgrep_ignores_nosem_comments_and_semgrepignore_files(
    settings: SandboxSettings, clock: FixedClock
) -> None:
    backend = FakeBackend()
    JobRunner(backend, settings, clock).run(tar_job(PLANTED, (CheckId.CODE,)))
    (command,) = commands(backend, "semgrep")
    assert "--disable-nosem" in command
    assert "--x-ignore-semgrepignore-files" in command
    assert "--enable-nosem" not in command


@pytest.mark.parametrize("name", ["gitleaks_config", "gitleaks_ignore_file"])
def test_a_secrets_check_without_its_fixed_config_is_an_error_and_runs_nothing(
    settings: SandboxSettings, clock: FixedClock, name: str
) -> None:
    images = settings.images.model_copy(update={name: None})
    partial = settings.model_copy(update={"images": images})
    backend = FakeBackend()
    report = JobRunner(backend, partial, clock).run(tar_job(PLANTED, (CheckId.SECRETS,)))
    check = report.to_wire()["checks"][0]
    assert (check["status"], check["findings"][0]["rule"]) == ("error", "sandbox.settings_unset")
    assert commands(backend, "gitleaks") == []


def test_both_gitleaks_settings_are_required_for_health() -> None:
    missing = SandboxImages().missing()
    assert "gitleaks_config" in missing
    assert "gitleaks_ignore_file" in missing


def test_a_bundle_is_scanned_as_history_and_as_the_checked_out_tree(
    settings: SandboxSettings, clock: FixedClock
) -> None:
    backend = backend_for(FakeRepo(), {})
    report = JobRunner(backend, settings, clock).run(bundle_job((CheckId.SECRETS,)))
    history, tree = commands(backend, "gitleaks")
    assert history[:3] == ("gitleaks", "git", ".")
    assert tree[:3] == ("gitleaks", "dir", ".")
    for command in (history, tree):
        assert value(command, "--config") == "/rules/gitleaks.toml"
        assert value(command, "--gitleaks-ignore-path") == "/rules/empty.gitleaksignore"
        assert "--ignore-gitleaks-allow" in command
    assert [c.check_id for c in report.checks] == ["secrets"]


def test_a_secret_found_only_in_the_tree_fails_the_one_secrets_check(
    settings: SandboxSettings, clock: FixedClock
) -> None:
    def gitleaks(spec: object) -> object:
        mode = spec.command[1]  # type: ignore[attr-defined]
        return outcome(0, fixture_bytes("gitleaks_report.json") if mode == "dir" else b"[]")

    backend = backend_for(FakeRepo(), {"gitleaks": gitleaks})  # type: ignore[dict-item]
    wire = JobRunner(backend, settings, clock).run(bundle_job((CheckId.SECRETS,))).to_wire()
    validate_wire(wire)
    (check,) = wire["checks"]
    assert check["check_id"] == "secrets"
    assert check["status"] == "failed"
    assert check["findings"]


def test_scripts_neutralise_repository_attributes_and_scanner_files() -> None:
    assert "printf '* diff -export-ignore -export-subst\\n' > .git/info/attributes" in (
        BUNDLE_SCRIPT
    )
    for script in (BUNDLE_SCRIPT, TAR_SCRIPT):
        for name in (".gitleaks.toml", ".gitleaksignore", ".semgrepignore"):
            assert name in script
        assert 'mv -f -- "$f" "/work/tmp/inert$f"' in script
        assert script.index("/work/tmp/inert") < script.index('exec "$@"')
    assert BUNDLE_SCRIPT.index("info/attributes") < BUNDLE_SCRIPT.index('exec "$@"')


def test_container_env_is_fixed_and_names_no_scanner_config(
    settings: SandboxSettings, clock: FixedClock
) -> None:
    backend = backend_for(FakeRepo(), {})
    JobRunner(backend, settings, clock).run(bundle_job())
    for spec in backend.specs:
        names = {key for key, _ in spec.env}
        assert not any(n.startswith(("GITLEAKS", "SEMGREP")) for n in names)


def _check(status: Status, *rules: str) -> CheckReport:
    found = tuple(finding(r, "secret", Severity.HIGH, "m", "p", 1) for r in rules)
    return CheckReport(check_id="secrets", status=status, findings=found)


@pytest.mark.parametrize(
    ("a", "b", "worst"),
    [
        (Status.PASSED, Status.FAILED, Status.FAILED),
        (Status.FAILED, Status.ERROR, Status.ERROR),
        (Status.ERROR, Status.PASSED, Status.ERROR),
        (Status.SKIPPED, Status.PASSED, Status.PASSED),
        (Status.PASSED, Status.PASSED, Status.PASSED),
    ],
)
def test_merging_keeps_the_worst_status(a: Status, b: Status, worst: Status) -> None:
    assert merge_checks(_check(a), _check(b)).status is worst
    assert merge_checks(_check(b), _check(a)).status is worst


def test_merging_combines_and_deduplicates_findings() -> None:
    merged = merge_checks(_check(Status.FAILED, "r1", "r2"), _check(Status.FAILED, "r2", "r3"))
    assert [f.rule for f in merged.findings] == ["r1", "r2", "r3"]


def test_merging_caps_findings_and_says_so() -> None:
    from services.sandbox.report import MAX_FINDINGS_PER_CHECK

    many = [f"r{n}" for n in range(MAX_FINDINGS_PER_CHECK)]
    merged = merge_checks(_check(Status.FAILED, *many), _check(Status.FAILED, "extra", "more"))
    assert len(merged.findings) == MAX_FINDINGS_PER_CHECK
    assert merged.findings[-1].rule == "sandbox.findings_truncated"


def test_images_fixture_names_the_fixed_files(settings: SandboxSettings) -> None:
    assert settings.images.gitleaks == image("gitleaks")
    assert settings.images.gitleaks_config == "/rules/gitleaks.toml"
