"""Real containers. Skipped unless the owner has provided a runtime and pinned images.

Run (Git Bash, repo root), after filling a settings file as in services/sandbox/README.md:

    export CISO_SANDBOX_CONFIG=/path/to/sandbox-settings.json
    uv run pytest tests/services/sandbox/test_real_container.py

The planted "secret" below is assembled at run time from harmless pieces so this file
itself does not trip a secret scanner.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest
from services.sandbox.docker import DockerBackend
from services.sandbox.job import ArchiveFormat, CheckId, Job
from services.sandbox.process import SubprocessRunner, minimal_env
from services.sandbox.report import validate_wire
from services.sandbox.runner import JobRunner
from services.sandbox.serve import load_config
from tests.services.sandbox.support import tar_of

from ciso.common.clock import SystemClock

pytestmark = pytest.mark.resilience

CONFIG_ENV = "CISO_SANDBOX_CONFIG"

ISOLATION_TESTS = b"""
import os, socket, pathlib

def test_runs_as_non_root():
    assert os.getuid() != 0

def test_no_network():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(3)
    try:
        assert s.connect_ex(("1.1.1.1", 443)) != 0
    finally:
        s.close()

def test_root_filesystem_is_read_only():
    try:
        pathlib.Path("/usr/sandbox-write-probe").write_text("x")
    except OSError:
        return
    raise AssertionError("root filesystem is writable")

def test_no_host_environment():
    assert "CISO_SANDBOX_CONFIG" not in os.environ

def test_planted_failure():
    assert 1 == 2
"""


def _runner() -> JobRunner:
    path = os.environ.get(CONFIG_ENV)
    if not path:
        pytest.skip(f"{CONFIG_ENV} is not set: no container runtime or pinned images provided")
    config = load_config(Path(path))
    backend = DockerBackend(SubprocessRunner(minimal_env()), config.settings.docker_cli)
    runner = JobRunner(backend, config.settings, SystemClock())
    health = runner.health()
    if not health.usable:
        pytest.skip(
            f"sandbox not usable: missing={health.missing} backend={health.backend_reasons}"
        )
    return runner


def test_planted_secret_and_failing_test_are_caught_in_isolation() -> None:
    runner = _runner()
    key = "AKIA" + "Q" * 4 + "Z7" + "X" * 10
    files = {
        "pyproject.toml": b'[project]\nname = "probe"\nversion = "0"\n',
        "app/settings.py": f'AWS_ACCESS_KEY_ID = "{key}"\n'.encode(),
        "tests/test_isolation.py": ISOLATION_TESTS,
    }
    job = Job(
        job_id="real-1",
        archive_format=ArchiveFormat.TAR,
        archive=tar_of(files),
        checks=(CheckId.SECRETS, CheckId.TESTS),
    )
    report = runner.run(job).to_wire()
    validate_wire(report)
    secrets, tests = report["checks"]
    assert secrets["status"] == "failed", secrets
    assert any(f["path"] == "app/settings.py" for f in secrets["findings"])
    assert key not in str(report)
    assert tests["status"] == "failed", tests
    assert tests["tests"] == {"passed": 4, "failed": 1, "errors": 0}
