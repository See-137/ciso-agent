"""Test doubles and archive builders for the sandbox service tests."""

from __future__ import annotations

import io
import tarfile
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from pathlib import Path

from services.sandbox.backend import BackendHealth, ContainerSpec, RunOutcome
from services.sandbox.process import ProcessResult

FIXTURES = Path(__file__).resolve().parent / "fixtures"

DIGEST = "sha256:" + "a" * 64


def image(name: str) -> str:
    return f"registry.invalid/{name}@{DIGEST}"


@dataclass
class Call:
    argv: tuple[str, ...]
    stdin: bytes
    timeout_seconds: float
    max_output_bytes: int


@dataclass
class FakeProcessRunner:
    """Records every argv. `respond` picks the result for a call; default: exit 0, no output."""

    respond: Callable[[tuple[str, ...]], ProcessResult] | None = None
    calls: list[Call] = field(default_factory=list)

    def run(
        self,
        argv: Sequence[str],
        *,
        stdin: bytes,
        timeout_seconds: float,
        max_output_bytes: int,
    ) -> ProcessResult:
        call = Call(tuple(argv), stdin, timeout_seconds, max_output_bytes)
        self.calls.append(call)
        if self.respond is not None:
            return self.respond(call.argv)
        return ProcessResult(exit_code=0, stdout=b"", timed_out=False, output_exceeded=False)


@dataclass
class FakeBackend:
    """A `Backend` that records each container spec and answers from `outcomes`.

    `outcomes` maps the first word of the container command (`gitleaks`, `semgrep`, `python`,
    `npm`, `go`, `git`) to an outcome or a callable producing one.
    """

    outcomes: dict[str, RunOutcome | Callable[[ContainerSpec], RunOutcome]] = field(
        default_factory=dict
    )
    usable: bool = True
    specs: list[ContainerSpec] = field(default_factory=list)
    probes: list[tuple[str, ...]] = field(default_factory=list)
    raise_on_run: Exception | None = None

    def probe(self, images: Sequence[str]) -> BackendHealth:
        self.probes.append(tuple(images))
        if self.usable:
            return BackendHealth(usable=True, reasons=())
        return BackendHealth(usable=False, reasons=("runtime_unreachable",))

    def run(self, spec: ContainerSpec) -> RunOutcome:
        self.specs.append(spec)
        if self.raise_on_run is not None:
            raise self.raise_on_run
        answer = self.outcomes.get(spec.command[0])
        if answer is None:
            return outcome(0, b"")
        return answer(spec) if callable(answer) else answer


def outcome(
    exit_code: int | None, stdout: bytes, *, timed_out: bool = False, exceeded: bool = False
) -> RunOutcome:
    return RunOutcome(
        exit_code=exit_code, stdout=stdout, timed_out=timed_out, output_exceeded=exceeded
    )


def tar_of(files: dict[str, bytes], *, gz: bool = False) -> bytes:
    """A well-formed tar archive of regular files."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz" if gz else "w") as tf:
        for name, data in files.items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            info.mode = 0o644
            tf.addfile(info, io.BytesIO(data))
    return buf.getvalue()


def tar_with(infos: list[tuple[tarfile.TarInfo, bytes | None]]) -> bytes:
    """A tar archive from hand-made members, for planting hostile entries."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w", format=tarfile.GNU_FORMAT) as tf:
        for info, data in infos:
            tf.addfile(info, io.BytesIO(data) if data is not None else None)
    return buf.getvalue()


def fixture_bytes(name: str) -> bytes:
    return (FIXTURES / name).read_bytes()
