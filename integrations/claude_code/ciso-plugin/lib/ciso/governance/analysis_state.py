"""State one analysis of one parsed command carries, shared by the analyzer's parts.

`ciso.governance.analysis.Analyzer` is assembled from this base and two mixins
(`analysis_paths.PathChecks`, `analysis_code.CodeRunners`); the abstract methods here are
implemented by the assembled class.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, NamedTuple

from ciso.common.paths import NormalisedPath
from ciso.governance.classes import CommandClass as C
from ciso.governance.lexer_types import Dialect, Script, Stage, Word

if TYPE_CHECKING:
    from ciso.governance.commands import ClassifierConfig


class Seen(NamedTuple):
    network: bool = False
    decoder: bool = False
    stdin_exec: bool = False

    def __or__(self, other: object) -> Seen:
        if not isinstance(other, Seen):
            return NotImplemented
        return Seen(
            self.network or other.network,
            self.decoder or other.decoder,
            self.stdin_exec or other.stdin_exec,
        )


class AnalyzerState:
    """Mutable state of one analysis. Never shared between commands."""

    def __init__(self, config: ClassifierConfig) -> None:
        self.cfg = config
        self.classes: set[C] = set()
        self.branches: set[str] = set()
        self.downloaded: set[str] = set()
        self.executed: set[str] = set()
        self.read_only = True
        self.depth = 0
        self.dialect = Dialect.POSIX
        #: Where relative paths are, relative to where the command started.
        self.cwd = NormalisedPath(())
        #: A directory change happened earlier in the line.
        self.moved = False
        #: Code is built at run time (a script block from text, a variable as a command).
        self.computed = False
        #: A push names no destination branch.
        self.unknown_branch = False

    def script(self, script: Script) -> Seen:
        raise NotImplementedError

    def nested(self, text: str, dialect: Dialect) -> Seen:
        raise NotImplementedError

    def program(self, name: str, args: list[Word], stage: Stage, position: int) -> Seen:
        raise NotImplementedError

    def path(self, text: str, *, writes: bool, strict: bool = False) -> None:
        raise NotImplementedError
