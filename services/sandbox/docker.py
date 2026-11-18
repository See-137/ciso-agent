"""Docker (or any docker-CLI-compatible OCI runtime) as the isolation backend.

`build_run_argv` is the single place the container invocation is written. Every isolation
property is a flag here and each one has its own test in
`tests/services/sandbox/test_docker_invocation.py`:

    <docker> run --rm -i --name <name> --pull never
      --network none --read-only
      --tmpfs /work:rw,exec,nosuid,nodev,size=<work_tmpfs_bytes>,mode=1777
      --user 65534:65534 --cap-drop ALL --security-opt no-new-privileges
      --pids-limit <pids> --cpus <cpus> --memory <bytes>b --memory-swap <bytes>b
      --ipc none --log-driver none --workdir /work --entrypoint /bin/sh
      --env K=V ... <image@sha256:...> -c <fixed script> sandbox <command...>

The code is streamed on stdin (`-i`) into the tmpfs work dir; nothing on the host is
mounted. A run that outlives its time or output budget is killed with `docker kill` and
removed with `docker rm -f` (the client process dying does not stop a container).
"""

from __future__ import annotations

import logging
import re
from collections.abc import Sequence
from typing import Final

from services.sandbox.backend import BackendHealth, ContainerSpec, IsolationUnavailable, RunOutcome
from services.sandbox.process import ProcessRunner
from services.sandbox.settings import IMAGE_RE

logger = logging.getLogger(__name__)

#: The container user: `nobody`. Never root.
SANDBOX_USER: Final = "65534:65534"
#: The only writable path inside the container (a size-limited tmpfs).
WORK_DIR: Final = "/work"
#: Seconds allowed for the short control commands (version, image inspect, kill, rm).
CONTROL_TIMEOUT_SECONDS: Final = 30.0
_CONTROL_OUTPUT_BYTES: Final = 64 * 1024
_ENV_NAME_RE = re.compile(r"[A-Z][A-Z0-9_]{0,63}")
_NAME_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}")


def _cpus(value: float) -> str:
    return f"{value:.3f}".rstrip("0").rstrip(".")


def build_run_argv(docker_cli: str, spec: ContainerSpec) -> tuple[str, ...]:
    """The exact `docker run` argv for one isolated container. Raises `ValueError` for an
    unpinned image, a bad container name or an env entry without a literal value."""
    if not IMAGE_RE.fullmatch(spec.image):
        raise ValueError("image must be pinned by digest")
    if not _NAME_RE.fullmatch(spec.name):
        raise ValueError("bad container name")
    env_args: list[str] = []
    for key, value in spec.env:
        if not _ENV_NAME_RE.fullmatch(key) or not value or "\n" in value:
            raise ValueError("env entries need a plain name and a literal value")
        env_args += ["--env", f"{key}={value}"]
    lim = spec.limits
    return (
        docker_cli,
        "run",
        "--rm",
        "-i",
        "--name",
        spec.name,
        "--pull",
        "never",
        "--network",
        "none",
        "--read-only",
        "--tmpfs",
        f"{WORK_DIR}:rw,exec,nosuid,nodev,size={lim.work_tmpfs_bytes},mode=1777",
        "--user",
        SANDBOX_USER,
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges",
        "--pids-limit",
        str(lim.pids),
        "--cpus",
        _cpus(lim.cpus),
        "--memory",
        f"{lim.memory_bytes}b",
        "--memory-swap",
        f"{lim.memory_bytes}b",
        "--ipc",
        "none",
        "--log-driver",
        "none",
        "--workdir",
        WORK_DIR,
        "--entrypoint",
        "/bin/sh",
        *env_args,
        spec.image,
        "-c",
        spec.script,
        "sandbox",
        *spec.command,
    )


class DockerBackend:
    """A `Backend` that drives the docker CLI through a `ProcessRunner`.

    With no `docker_cli` configured it is unusable and refuses every run.
    """

    def __init__(self, runner: ProcessRunner, docker_cli: str | None) -> None:
        self._runner = runner
        self._cli = docker_cli

    def _control(self, *args: str) -> int | None:
        assert self._cli is not None
        result = self._runner.run(
            (self._cli, *args),
            stdin=b"",
            timeout_seconds=CONTROL_TIMEOUT_SECONDS,
            max_output_bytes=_CONTROL_OUTPUT_BYTES,
        )
        return None if result.timed_out or result.output_exceeded else result.exit_code

    def probe(self, images: Sequence[str]) -> BackendHealth:
        if self._cli is None:
            return BackendHealth(usable=False, reasons=("docker_cli_unset",))
        if self._control("version", "--format", "{{.Server.Version}}") != 0:
            return BackendHealth(usable=False, reasons=("runtime_unreachable",))
        for image in images:
            if self._control("image", "inspect", "--format", "{{.Id}}", image) != 0:
                return BackendHealth(usable=False, reasons=("image_missing",))
        return BackendHealth(usable=True, reasons=())

    def run(self, spec: ContainerSpec) -> RunOutcome:
        if self._cli is None:
            raise IsolationUnavailable("no docker client configured")
        result = self._runner.run(
            build_run_argv(self._cli, spec),
            stdin=spec.stdin,
            timeout_seconds=spec.timeout_seconds,
            max_output_bytes=spec.max_output_bytes,
        )
        if result.timed_out or result.output_exceeded:
            self._destroy(spec.name)
        return RunOutcome(
            exit_code=result.exit_code,
            stdout=result.stdout,
            timed_out=result.timed_out,
            output_exceeded=result.output_exceeded,
        )

    def _destroy(self, name: str) -> None:
        """Kill and remove a container that outlived its budget. A failure is logged with
        the container name so an operator can remove it; the job is already an error."""
        if self._control("kill", name) != 0:
            logger.warning("docker kill did not confirm for container %s", name)
        if self._control("rm", "-f", name) != 0:
            logger.error("docker rm -f failed for container %s: remove it by hand", name)
