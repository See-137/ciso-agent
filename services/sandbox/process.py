"""Starting the container runtime's client process, with a time limit and an output cap.

This is the only module in the repository's services that creates processes, and it only
ever runs the configured container client (see `docker.py`). The child gets a minimal,
allowlisted environment: the variables the client needs to find its daemon and config,
nothing else from the host.
"""

from __future__ import annotations

import logging
import os
import subprocess
import threading
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import IO, Final, Protocol

logger = logging.getLogger(__name__)

#: Host variables the container client may see. Everything else is dropped.
CLIENT_ENV_ALLOWLIST: Final = (
    "PATH",
    "SystemRoot",
    "SYSTEMROOT",
    "USERPROFILE",
    "HOME",
    "TEMP",
    "TMP",
    "DOCKER_HOST",
    "DOCKER_CONTEXT",
    "DOCKER_CONFIG",
    "DOCKER_CERT_PATH",
    "DOCKER_TLS_VERIFY",
)
_CHUNK: Final = 64 * 1024
#: Seconds to wait for reader threads after the process has ended or been killed.
_JOIN_SECONDS: Final = 10.0


@dataclass(frozen=True)
class ProcessResult:
    """`exit_code` is None when this runner killed the process (time or output cap)."""

    exit_code: int | None
    stdout: bytes = field(repr=False)
    timed_out: bool
    output_exceeded: bool


class ProcessRunner(Protocol):
    def run(
        self,
        argv: Sequence[str],
        *,
        stdin: bytes,
        timeout_seconds: float,
        max_output_bytes: int,
    ) -> ProcessResult: ...


def minimal_env(source: Mapping[str, str] | None = None) -> dict[str, str]:
    """The allowlisted subset of `source` (default: this process's environment)."""
    env = os.environ if source is None else source
    return {name: env[name] for name in CLIENT_ENV_ALLOWLIST if name in env}


class _Collector:
    """Reads a stream to the end, keeping at most `cap` bytes; calls `on_over` once."""

    def __init__(self, stream: IO[bytes], cap: int, on_over: threading.Event) -> None:
        self.chunks: list[bytes] = []
        self.size = 0
        self._stream = stream
        self._cap = cap
        self._over = on_over

    def __call__(self) -> None:
        while chunk := self._stream.read(_CHUNK):
            if self.size + len(chunk) > self._cap:
                self._over.set()
                break
            self.size += len(chunk)
            self.chunks.append(chunk)


class _Drain:
    """Reads a stream to the end and keeps only the byte count, so a chatty child never
    blocks on a full pipe. Stderr may hold scanner text (even secrets): it is not kept."""

    def __init__(self, stream: IO[bytes]) -> None:
        self.size = 0
        self._stream = stream

    def __call__(self) -> None:
        while chunk := self._stream.read(_CHUNK):
            self.size += len(chunk)


class SubprocessRunner:
    """Runs a client command with no shell, a minimal environment and hard bounds."""

    def __init__(self, env: Mapping[str, str]) -> None:
        self._env = dict(env)

    def run(
        self,
        argv: Sequence[str],
        *,
        stdin: bytes,
        timeout_seconds: float,
        max_output_bytes: int,
    ) -> ProcessResult:
        proc = subprocess.Popen(  # noqa: S603 - fixed argv, no shell, see module docstring
            list(argv),
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=self._env,
            shell=False,
        )
        if proc.stdin is None or proc.stdout is None or proc.stderr is None:
            proc.kill()
            raise RuntimeError("process pipes were not created")
        over = threading.Event()
        out = _Collector(proc.stdout, max_output_bytes, over)
        err = _Drain(proc.stderr)
        threads = [
            threading.Thread(target=out, daemon=True),
            threading.Thread(target=err, daemon=True),
            threading.Thread(target=_feed, args=(proc.stdin, stdin), daemon=True),
        ]
        for thread in threads:
            thread.start()
        timed_out = self._wait(proc, timeout_seconds, over)
        for thread in threads:
            thread.join(_JOIN_SECONDS)
        for stream in (proc.stdout, proc.stderr):
            stream.close()
        exceeded = over.is_set()
        killed = timed_out or exceeded
        if err.size:
            logger.debug("client wrote %d bytes to stderr (not kept)", err.size)
        return ProcessResult(
            exit_code=None if killed else proc.returncode,
            stdout=b"".join(out.chunks),
            timed_out=timed_out,
            output_exceeded=exceeded,
        )

    @staticmethod
    def _wait(proc: subprocess.Popen[bytes], timeout: float, over: threading.Event) -> bool:
        """Wait for exit; kill on output overflow or timeout. True when it timed out."""
        step = 0.05
        waited = 0.0
        while True:
            try:
                proc.wait(timeout=step)
                return False
            except subprocess.TimeoutExpired:
                waited += step
            if over.is_set():
                proc.kill()
                proc.wait()
                return False
            if waited >= timeout:
                proc.kill()
                proc.wait()
                return True


def _feed(pipe: IO[bytes], data: bytes) -> None:
    """Write stdin, then close it. A child that exits early closes the pipe; that is not
    an error here because the exit code decides the outcome."""
    try:
        pipe.write(data)
    except (BrokenPipeError, OSError) as exc:
        logger.debug("child closed stdin early: %s", type(exc).__name__)
    finally:
        try:
            pipe.close()
        except OSError as exc:
            logger.debug("closing stdin failed: %s", type(exc).__name__)
