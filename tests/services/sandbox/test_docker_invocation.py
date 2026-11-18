"""The exact `docker run` invocation: every isolation flag, limits, cleanup, fail closed.

One test per isolation flag, so removing any single flag from the builder turns a named
test red.
"""

from __future__ import annotations

from itertools import pairwise

import pytest
from services.sandbox.backend import ContainerSpec
from services.sandbox.docker import (
    SANDBOX_USER,
    WORK_DIR,
    DockerBackend,
    build_run_argv,
)
from services.sandbox.process import ProcessResult
from services.sandbox.settings import SandboxLimits
from tests.services.sandbox.support import FakeProcessRunner, image

pytestmark = pytest.mark.resilience

DOCKER = "/usr/bin/docker"


def spec(limits: SandboxLimits, **overrides: object) -> ContainerSpec:
    values: dict[str, object] = {
        "name": "sbx_TESTNAME",
        "image": image("python-tests"),
        "script": 'set -eu; exec "$@"',
        "command": ("python", "-m", "pytest"),
        "env": (("HOME", "/work"),),
        "stdin": b"payload",
        "limits": limits.resolve(),
        "timeout_seconds": 30.0,
        "max_output_bytes": 4096,
    }
    values.update(overrides)
    return ContainerSpec(**values)  # type: ignore[arg-type]


def pairs(argv: tuple[str, ...]) -> list[tuple[str, str]]:
    """Adjacent (option, value) pairs before the image name."""
    head = argv[: argv.index(image("python-tests"))]
    return list(pairwise(head))


@pytest.fixture
def argv(limits: SandboxLimits) -> tuple[str, ...]:
    return build_run_argv(DOCKER, spec(limits))


def test_network_none(argv: tuple[str, ...]) -> None:
    assert ("--network", "none") in pairs(argv)


def test_read_only_root(argv: tuple[str, ...]) -> None:
    assert "--read-only" in argv


def test_work_dir_is_size_limited_tmpfs(argv: tuple[str, ...], limits: SandboxLimits) -> None:
    tmpfs = [v for k, v in pairs(argv) if k == "--tmpfs"]
    assert tmpfs == [f"{WORK_DIR}:rw,exec,nosuid,nodev,size={limits.work_tmpfs_bytes},mode=1777"]


def test_non_root_user(argv: tuple[str, ...]) -> None:
    assert ("--user", SANDBOX_USER) in pairs(argv)
    uid = SANDBOX_USER.split(":")[0]
    assert uid != "0"
    assert uid.isdigit()


def test_cap_drop_all(argv: tuple[str, ...]) -> None:
    assert ("--cap-drop", "ALL") in pairs(argv)


def test_no_new_privileges(argv: tuple[str, ...]) -> None:
    assert ("--security-opt", "no-new-privileges") in pairs(argv)


def test_pids_limit(argv: tuple[str, ...], limits: SandboxLimits) -> None:
    assert ("--pids-limit", str(limits.pids)) in pairs(argv)


def test_cpu_limit(argv: tuple[str, ...]) -> None:
    assert ("--cpus", "1.5") in pairs(argv)


def test_memory_limit_and_no_swap(argv: tuple[str, ...], limits: SandboxLimits) -> None:
    assert ("--memory", f"{limits.memory_bytes}b") in pairs(argv)
    assert ("--memory-swap", f"{limits.memory_bytes}b") in pairs(argv)


def test_container_removed_afterwards(argv: tuple[str, ...]) -> None:
    assert "--rm" in argv


def test_never_pulls(argv: tuple[str, ...]) -> None:
    assert ("--pull", "never") in pairs(argv)


def test_private_ipc_and_no_log_copy(argv: tuple[str, ...]) -> None:
    assert ("--ipc", "none") in pairs(argv)
    assert ("--log-driver", "none") in pairs(argv)


def test_code_arrives_on_stdin_not_by_mount(argv: tuple[str, ...]) -> None:
    assert "-i" in argv
    forbidden = {"-v", "--volume", "--mount", "--volumes-from", "--privileged", "--env-file"}
    assert not forbidden & set(argv)
    assert not any(a.startswith(("--volume=", "--mount=", "-v=")) for a in argv)
    assert not any(a.startswith("--network=") or a == "--net" for a in argv)


def test_no_host_env_passthrough(argv: tuple[str, ...]) -> None:
    envs = [v for k, v in pairs(argv) if k in {"--env", "-e"}]
    assert envs == ["HOME=/work"]
    assert all("=" in v for v in envs)


def test_env_without_value_is_refused(limits: SandboxLimits) -> None:
    with pytest.raises(ValueError, match="env"):
        build_run_argv(DOCKER, spec(limits, env=(("HOME", ""),)))
    with pytest.raises(ValueError, match="env"):
        build_run_argv(DOCKER, spec(limits, env=(("BAD NAME", "x"),)))


def test_image_must_be_pinned_by_digest(limits: SandboxLimits) -> None:
    with pytest.raises(ValueError, match="digest"):
        build_run_argv(DOCKER, spec(limits, image="registry.invalid/python:latest"))


def test_entrypoint_is_shell_with_fixed_script_and_command_as_arguments(
    argv: tuple[str, ...],
) -> None:
    at = argv.index(image("python-tests"))
    assert argv[at + 1 :] == ("-c", 'set -eu; exec "$@"', "sandbox", "python", "-m", "pytest")
    assert ("--entrypoint", "/bin/sh") in pairs(argv)
    assert argv[:4] == (DOCKER, "run", "--rm", "-i")


def test_image_is_the_last_option(argv: tuple[str, ...]) -> None:
    at = argv.index(image("python-tests"))
    assert all(not a.startswith("-") for a in argv[at : at + 1])
    assert argv.count(image("python-tests")) == 1


def test_run_passes_stdin_timeout_and_output_cap(limits: SandboxLimits) -> None:
    runner = FakeProcessRunner()
    DockerBackend(runner, DOCKER).run(spec(limits))
    call = runner.calls[0]
    assert call.argv[1] == "run"
    assert call.stdin == b"payload"
    assert call.timeout_seconds == 30.0
    assert call.max_output_bytes == 4096


def test_wall_clock_kill_and_forced_removal(limits: SandboxLimits) -> None:
    def respond(argv: tuple[str, ...]) -> ProcessResult:
        timed_out = argv[1] == "run"
        return ProcessResult(
            exit_code=None if timed_out else 0,
            stdout=b"",
            timed_out=timed_out,
            output_exceeded=False,
        )

    runner = FakeProcessRunner(respond=respond)
    result = DockerBackend(runner, DOCKER).run(spec(limits))
    assert result.timed_out
    assert result.exit_code is None
    verbs = [c.argv[1:3] for c in runner.calls]
    assert verbs[1:] == [("kill", "sbx_TESTNAME"), ("rm", "-f")]
    assert runner.calls[2].argv[-1] == "sbx_TESTNAME"


def test_output_cap_also_kills_and_removes(limits: SandboxLimits) -> None:
    def respond(argv: tuple[str, ...]) -> ProcessResult:
        over = argv[1] == "run"
        return ProcessResult(exit_code=None, stdout=b"", timed_out=False, output_exceeded=over)

    runner = FakeProcessRunner(respond=respond)
    result = DockerBackend(runner, DOCKER).run(spec(limits))
    assert result.output_exceeded
    assert [c.argv[1] for c in runner.calls] == ["run", "kill", "rm"]


def test_clean_exit_does_not_kill(limits: SandboxLimits) -> None:
    runner = FakeProcessRunner()
    result = DockerBackend(runner, DOCKER).run(spec(limits))
    assert result.exit_code == 0
    assert [c.argv[1] for c in runner.calls] == ["run"]


def test_no_docker_cli_is_unusable_and_refuses_to_run(limits: SandboxLimits) -> None:
    runner = FakeProcessRunner()
    backend = DockerBackend(runner, None)
    health = backend.probe([image("git")])
    assert not health.usable
    assert "docker_cli_unset" in health.reasons
    with pytest.raises(Exception, match="docker"):
        backend.run(spec(limits))
    assert runner.calls == []


def test_probe_reports_unreachable_daemon() -> None:
    def respond(argv: tuple[str, ...]) -> ProcessResult:
        return ProcessResult(exit_code=1, stdout=b"", timed_out=False, output_exceeded=False)

    health = DockerBackend(FakeProcessRunner(respond=respond), DOCKER).probe([image("git")])
    assert not health.usable
    assert health.reasons == ("runtime_unreachable",)


def test_probe_reports_missing_image() -> None:
    def respond(argv: tuple[str, ...]) -> ProcessResult:
        code = 1 if argv[1:3] == ("image", "inspect") else 0
        return ProcessResult(exit_code=code, stdout=b"", timed_out=False, output_exceeded=False)

    runner = FakeProcessRunner(respond=respond)
    health = DockerBackend(runner, DOCKER).probe([image("git")])
    assert not health.usable
    assert health.reasons == ("image_missing",)
    assert ("image", "inspect") in [c.argv[1:3] for c in runner.calls]


def test_probe_usable_when_daemon_and_images_answer() -> None:
    runner = FakeProcessRunner()
    health = DockerBackend(runner, DOCKER).probe([image("git"), image("semgrep")])
    assert health.usable
    assert health.reasons == ()
    assert [c.argv[1] for c in runner.calls] == ["version", "image", "image"]
