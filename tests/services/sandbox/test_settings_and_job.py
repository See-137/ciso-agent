"""Settings refuse when unset; the job model is bounded; test commands come from an allowlist."""

from __future__ import annotations

import pytest
from pydantic import ValidationError
from services.sandbox.job import (
    TEST_COMMANDS,
    ArchiveFormat,
    CheckId,
    Job,
    ProjectType,
    detect_project,
)
from services.sandbox.settings import SandboxImages, SandboxLimits, SettingsUnset
from tests.services.sandbox.support import image

from services.sandbox import job as job_module

pytestmark = pytest.mark.unit

SHA = "0123456789abcdef0123456789abcdef01234567"
HEAD = "fedcba9876543210fedcba9876543210fedcba98"


def test_limits_default_to_unset_and_refuse() -> None:
    with pytest.raises(SettingsUnset) as caught:
        SandboxLimits().resolve()
    assert caught.value.names == (
        "wall_time_seconds",
        "cpus",
        "memory_bytes",
        "output_bytes",
        "pids",
        "work_tmpfs_bytes",
    )


@pytest.mark.parametrize(
    "name",
    ["wall_time_seconds", "cpus", "memory_bytes", "output_bytes", "pids", "work_tmpfs_bytes"],
)
def test_each_unset_limit_refuses(limits: SandboxLimits, name: str) -> None:
    partial = limits.model_copy(update={name: None})
    with pytest.raises(SettingsUnset) as caught:
        partial.resolve()
    assert caught.value.names == (name,)


def test_resolved_limits_carry_the_values(limits: SandboxLimits) -> None:
    resolved = limits.resolve()
    assert resolved.pids == 128
    assert resolved.cpus == 1.5


@pytest.mark.parametrize(
    ("name", "value"),
    [("cpus", 0), ("memory_bytes", 1024), ("pids", -1), ("output_bytes", True), ("pids", 1.5)],
)
def test_limits_reject_nonsense(name: str, value: object) -> None:
    with pytest.raises(ValidationError):
        SandboxLimits(**{name: value})


@pytest.mark.parametrize(
    "value",
    [
        "python:3.13",
        "registry.invalid/python:3.13",
        "registry.invalid/python@sha256:abc",
        "registry.invalid/python@sha256:" + "A" * 64,
        image("x") + " --privileged",
    ],
)
def test_images_must_be_pinned_by_digest(value: str) -> None:
    with pytest.raises(ValidationError):
        SandboxImages(gitleaks=value)


def test_image_paths_must_be_absolute_and_plain() -> None:
    SandboxImages(semgrep_config="/rules/semgrep.yml")
    for bad in ("rules.yml", "/rules/../etc", "/rules/a b", "p/default", "https://x.invalid/r"):
        with pytest.raises(ValidationError):
            SandboxImages(semgrep_config=bad)


def test_images_default_to_unset() -> None:
    images = SandboxImages()
    assert images.configured() == ()
    assert set(images.missing()) == {
        "python_tests",
        "node_tests",
        "go_tests",
        "gitleaks",
        "semgrep",
        "git",
        "semgrep_config",
        "gitleaks_config",
        "gitleaks_ignore_file",
    }


def job(**overrides: object) -> Job:
    values: dict[str, object] = {
        "job_id": "job-1",
        "archive_format": ArchiveFormat.TAR,
        "archive": b"data",
        "checks": (CheckId.SECRETS,),
    }
    values.update(overrides)
    return Job(**values)


@pytest.mark.parametrize("job_id", ["", "-x", "a b", "a/b", "x" * 65, "job\n1", "ü"])
def test_job_id_is_strict(job_id: str) -> None:
    with pytest.raises(ValidationError):
        job(job_id=job_id)


def test_job_needs_at_least_one_distinct_check() -> None:
    with pytest.raises(ValidationError):
        job(checks=())
    with pytest.raises(ValidationError):
        job(checks=(CheckId.SECRETS, CheckId.SECRETS))
    with pytest.raises(ValidationError):
        job(checks=("shell",))


def test_archive_size_is_bounded(monkeypatch: pytest.MonkeyPatch) -> None:
    assert job_module.MAX_ARCHIVE_BYTES > 0
    with pytest.raises(ValidationError):
        job(archive=b"")
    with pytest.raises(ValidationError):
        job(archive=b"x" * (job_module.MAX_ARCHIVE_BYTES + 1))


def test_base_ref_must_be_a_full_commit_id_and_needs_history() -> None:
    bundle = {"archive_format": ArchiveFormat.GIT_BUNDLE, "head": HEAD, "commits": (HEAD,)}
    assert job(**bundle, base_ref=SHA).base_ref == SHA
    for bad in ("main", "HEAD~1", SHA[:-1], SHA.upper(), f"{SHA};rm -rf /", f"--{SHA}"):
        with pytest.raises(ValidationError):
            job(**bundle, base_ref=bad)
    with pytest.raises(ValidationError, match="history"):
        job(archive_format=ArchiveFormat.TAR, base_ref=SHA)


def test_job_repr_hides_archive() -> None:
    assert "PLANTEDARCHIVE" not in repr(job(archive=b"PLANTEDARCHIVE"))


@pytest.mark.parametrize(
    ("paths", "expected"),
    [
        (("pyproject.toml", "src/a.py"), ProjectType.PYTHON),
        (("setup.py",), ProjectType.PYTHON),
        (("pytest.ini",), ProjectType.PYTHON),
        (("package.json", "index.js"), ProjectType.NODE),
        (("go.mod", "main.go"), ProjectType.GO),
        (("README.md", "sub/package.json", "sub/go.mod"), ProjectType.NONE),
        (("pyproject.toml", "package.json"), ProjectType.PYTHON),
        ((), ProjectType.NONE),
    ],
)
def test_project_detection_reads_root_markers_only(
    paths: tuple[str, ...], expected: ProjectType
) -> None:
    assert detect_project(paths) is expected


def test_test_commands_are_a_fixed_allowlist() -> None:
    assert set(TEST_COMMANDS) == {ProjectType.PYTHON, ProjectType.NODE, ProjectType.GO}
    assert TEST_COMMANDS[ProjectType.PYTHON][:3] == ("python", "-m", "pytest")
    assert TEST_COMMANDS[ProjectType.NODE] == ("npm", "test")
    assert TEST_COMMANDS[ProjectType.GO] == ("go", "test", "-json", "./...")
    with pytest.raises(TypeError):
        TEST_COMMANDS[ProjectType.NONE] = ("sh",)  # type: ignore[index]
