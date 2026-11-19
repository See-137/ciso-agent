"""git, run so the repository being inspected cannot run programs or change the output.

Every call: a fixed argv list (never a shell), stdin closed, stderr dropped, stdout read
back through a temporary file with a cap, a per-step timeout. Options that keep the
repository's (and the user's) configuration from running programs or reshaping output:
`--no-replace-objects`, fsmonitor off, hooks pointed at a directory that does not exist,
no external diff, `--no-textconv` on every diff, implicit bare repositories refused
(`safe.bareRepository=explicit`), diff prefixes and relative mode fixed, colour off.
Every `GIT_*` variable of the hook's environment is dropped (the managed git hardening
is meant for the agent's own git; this git sets its own). Local steps refuse every
transport (`protocol.allow=never`, which also stops lazy fetches of a partial clone);
the one network step (`ls_remote`) only refuses the `ext` transport.
"""

from __future__ import annotations

import os
import subprocess
import tempfile
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Final

#: Seconds one git step may take.
GIT_STEP_SECONDS: Final = 15.0
#: Largest output read from one git step.
MAX_GIT_OUTPUT_BYTES: Final = 64 * 1024 * 1024

_HARDENING: Final = (
    "-c",
    "core.fsmonitor=false",
    "-c",
    "diff.external=",
    "-c",
    "safe.bareRepository=explicit",
    "-c",
    "diff.relative=false",
    "-c",
    "diff.noprefix=false",
    "-c",
    "diff.mnemonicPrefix=false",
    "-c",
    "diff.srcPrefix=a/",
    "-c",
    "diff.dstPrefix=b/",
    "-c",
    "diff.renames=false",
    "-c",
    "color.ui=false",
    "-c",
    "log.showSignature=false",
    "-c",
    "log.showRoot=true",
    "-c",
    "core.quotePath=true",
)


class GitError(Exception):
    """A git step failed. `code` is a fixed word; nothing from git's output."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


@dataclass(frozen=True)
class GitResult:
    returncode: int
    stdout: bytes


def clean_env(environ: Mapping[str, str]) -> dict[str, str]:
    env = {k: v for k, v in environ.items() if not k.upper().startswith("GIT_")}
    env.update(
        {
            "GIT_TERMINAL_PROMPT": "0",
            "GIT_OPTIONAL_LOCKS": "0",
            "GIT_NO_LAZY_FETCH": "1",
            "LC_ALL": "C",
        }
    )
    return env


@dataclass(frozen=True)
class SafeGit:
    executable: str
    cwd: str
    no_hooks_dir: str
    environ: Mapping[str, str] = field(default_factory=lambda: dict(os.environ))

    def _argv(self, args: Sequence[str], *, network: bool) -> list[str]:
        protocol = ("-c", "protocol.ext.allow=never") if network else ("-c", "protocol.allow=never")
        return [
            self.executable,
            "--no-pager",
            "--no-replace-objects",
            *_HARDENING,
            "-c",
            "core.hooksPath=" + self.no_hooks_dir,
            *protocol,
            *args,
        ]

    def run(self, *args: str, network: bool = False, cwd: str | None = None) -> GitResult:
        argv = self._argv(args, network=network)
        flags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
        with tempfile.TemporaryFile() as out:
            try:
                done = subprocess.run(  # noqa: S603 - fixed argv list, absolute git, no shell
                    argv,
                    cwd=cwd or self.cwd,
                    env=clean_env(self.environ),
                    stdin=subprocess.DEVNULL,
                    stdout=out,
                    stderr=subprocess.DEVNULL,
                    timeout=GIT_STEP_SECONDS,
                    shell=False,
                    check=False,
                    creationflags=flags,
                )
            except subprocess.TimeoutExpired as error:
                raise GitError("git_timeout") from error
            except OSError as error:
                raise GitError("git_unavailable") from error
            out.seek(0)
            data = out.read(MAX_GIT_OUTPUT_BYTES + 1)
        if len(data) > MAX_GIT_OUTPUT_BYTES:
            raise GitError("git_output_too_large")
        return GitResult(done.returncode, data)

    def out(self, *args: str, code: str, network: bool = False, cwd: str | None = None) -> str:
        result = self.run(*args, network=network, cwd=cwd)
        if result.returncode != 0:
            raise GitError(code)
        return result.stdout.decode("utf-8", errors="replace").strip()

    def at(self, cwd: str) -> SafeGit:
        return SafeGit(self.executable, cwd, self.no_hooks_dir, self.environ)


def no_hooks_dir(data: Path) -> str:
    """A hooks path that never exists, inside the plugin's own data directory."""
    return str(data / "no-hooks-dir-never-created")
