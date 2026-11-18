"""Fixtures for the sandbox service tests. Doubles live in `support.py`."""

from __future__ import annotations

import pytest
from services.sandbox.settings import SandboxImages, SandboxLimits, SandboxSettings
from tests.services.sandbox.support import (
    FakeBackend,
    FakeProcessRunner,
    image,
)


@pytest.fixture
def limits() -> SandboxLimits:
    return SandboxLimits(
        wall_time_seconds=120.0,
        cpus=1.5,
        memory_bytes=512 * 1024 * 1024,
        output_bytes=1024 * 1024,
        pids=128,
        work_tmpfs_bytes=256 * 1024 * 1024,
    )


@pytest.fixture
def images() -> SandboxImages:
    return SandboxImages(
        python_tests=image("python-tests"),
        node_tests=image("node-tests"),
        go_tests=image("go-tests"),
        gitleaks=image("gitleaks"),
        semgrep=image("semgrep"),
        git=image("git"),
        semgrep_config="/rules/semgrep",
    )


@pytest.fixture
def settings(limits: SandboxLimits, images: SandboxImages) -> SandboxSettings:
    return SandboxSettings(limits=limits, images=images, docker_cli="/usr/bin/docker")


@pytest.fixture
def fake_process() -> FakeProcessRunner:
    return FakeProcessRunner()


@pytest.fixture
def backend() -> FakeBackend:
    return FakeBackend()
