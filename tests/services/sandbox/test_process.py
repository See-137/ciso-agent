"""The real process runner bounds time and output and gives the child a minimal environment.

These start a Python child process (this interpreter), never a container.
"""

from __future__ import annotations

import sys

import pytest
from services.sandbox.process import SubprocessRunner, minimal_env

pytestmark = pytest.mark.resilience

PY = sys.executable


def runner() -> SubprocessRunner:
    return SubprocessRunner(minimal_env())


def test_stdin_reaches_the_child_and_stdout_comes_back() -> None:
    code = "import sys; sys.stdout.buffer.write(sys.stdin.buffer.read()[::-1])"
    result = runner().run(
        [PY, "-I", "-c", code], stdin=b"abc", timeout_seconds=30, max_output_bytes=100
    )
    assert (result.exit_code, result.stdout) == (0, b"cba")
    assert not result.timed_out
    assert not result.output_exceeded


def test_exit_code_is_reported() -> None:
    result = runner().run(
        [PY, "-I", "-c", "raise SystemExit(7)"], stdin=b"", timeout_seconds=30, max_output_bytes=10
    )
    assert result.exit_code == 7


def test_wall_time_kills_the_child() -> None:
    result = runner().run(
        [PY, "-I", "-c", "import time; time.sleep(60)"],
        stdin=b"",
        timeout_seconds=1,
        max_output_bytes=10,
    )
    assert result.timed_out
    assert result.exit_code is None


def test_output_cap_kills_the_child() -> None:
    code = "import sys\nwhile True: sys.stdout.write('x' * 65536); sys.stdout.flush()"
    result = runner().run(
        [PY, "-I", "-c", code], stdin=b"", timeout_seconds=30, max_output_bytes=100_000
    )
    assert result.output_exceeded
    assert not result.timed_out
    assert result.exit_code is None
    assert len(result.stdout) <= 100_000


def test_child_does_not_see_host_variables(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("CISO_SANDBOX_PLANTED", "leak")
    monkeypatch.setenv("DOCKER_HOST", "npipe:////./pipe/docker_engine")
    env = minimal_env()
    assert "CISO_SANDBOX_PLANTED" not in env
    assert env["DOCKER_HOST"] == "npipe:////./pipe/docker_engine"
    code = "import os, sys; sys.stdout.write(os.environ.get('CISO_SANDBOX_PLANTED', 'absent'))"
    result = SubprocessRunner(env).run(
        [PY, "-I", "-c", code], stdin=b"", timeout_seconds=30, max_output_bytes=100
    )
    assert result.stdout == b"absent"


def test_child_that_ignores_stdin_does_not_hang() -> None:
    result = runner().run(
        [PY, "-I", "-c", "pass"],
        stdin=b"x" * (4 * 1024 * 1024),
        timeout_seconds=30,
        max_output_bytes=10,
    )
    assert result.exit_code == 0


def test_large_stderr_is_drained_not_kept() -> None:
    code = "import sys; sys.stderr.write('e' * (2 * 1024 * 1024)); sys.stdout.write('ok')"
    result = runner().run(
        [PY, "-I", "-c", code], stdin=b"", timeout_seconds=10, max_output_bytes=100
    )
    assert not result.timed_out
    assert (result.exit_code, result.stdout) == (0, b"ok")
