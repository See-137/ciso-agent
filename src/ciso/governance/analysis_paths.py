"""Path and credential checks of the analyzer (review H1, H2, M1).

Every dangerous-path decision goes through `ciso.common.paths`: the text is normalised
(case, both separators, `.`/`..`, trailing dots and spaces, stream suffixes, short names,
home directory spellings) and matched with "could these meet", so a glob, an alias of a
name or a directory change cannot hide a sensitive file.

`strict` decides what unknown text means. Where an argument is a file the program opens
(a reader's operands, a file writer's operands, a redirect target), a variable may hold
any path and matches every pattern, and after a directory change to an unknown place a
relative name may be anywhere. Elsewhere (a git refspec, a commit message, interpreter
arguments) unknown text matches nothing, so `git commit -m "$msg"` is not a file write.
"""

from __future__ import annotations

import re

from ciso.common.paths import (
    UNKNOWN_LOCATION,
    NormalisedPath,
    join_paths,
    may_match,
    normalise_path,
)
from ciso.governance import programs as p
from ciso.governance.analysis_state import AnalyzerState
from ciso.governance.classes import CommandClass as C
from ciso.governance.danger_paths import (
    GIT_CONFIG_PATHS,
    GIT_HOOK_PATHS,
    PRIVILEGE_PATHS,
    TAMPER_PATHS,
)
from ciso.governance.lexer_types import DYN, Word

#: Longest argument read as a path.
MAX_PATH_TEXT = 1024
#: Stands for unknown text where it must not match anything.
_OPAQUE = "�"
_DRIVE_RE = re.compile(r"[A-Za-z]:[\\/]")
_GLOB_CHARS = frozenset("*?[]{}")


def path_text(word: Word) -> str:
    """The word's text, with a leading home-directory variable written as `~`."""
    text = word.text
    if (
        text.startswith(DYN)
        and word.variables
        and word.variables[0].casefold() in p.HOME_VARIABLES
        and not word.subs
    ):
        return "~" + text[1:]
    return text


def _matches(patterns: tuple[str, ...], path: NormalisedPath) -> bool:
    return any(may_match(pattern, path) for pattern in patterns)


class PathChecks(AnalyzerState):
    def path(self, text: str, *, writes: bool, strict: bool = False) -> None:
        if not text or len(text) > MAX_PATH_TEXT:
            return
        candidates = {text}
        if "=" in text:
            candidates.add(text.partition("=")[2])
        if ":" in text and not _DRIVE_RE.match(text):
            candidates.add(text.partition(":")[2])
        base = self.cwd
        if base is UNKNOWN_LOCATION and not strict:
            base = NormalisedPath(())
        for value in candidates:
            # The readings already turned every real expansion into DYN (home variables
            # into `~`); a `$` or `%` left in the text is a literal character.
            literal = value.replace("$", _OPAQUE).replace("%", _OPAQUE)
            if not strict:
                literal = literal.replace(DYN, _OPAQUE)
            normal = normalise_path(literal, windows=True)
            if normal.empty:
                continue
            self.path_classes(join_paths(base, normal), writes=writes)

    def path_classes(self, path: NormalisedPath, *, writes: bool) -> None:
        if _matches(self.cfg.all_credential_paths, path):
            self.classes.add(C.CREDENTIAL_ACCESS)
        if not writes:
            return
        for patterns, cls in (
            (self.cfg.all_agent_config_paths, C.AGENT_CONFIG_CHANGE),
            (GIT_HOOK_PATHS, C.GIT_HOOKS_CHANGE),
            (GIT_CONFIG_PATHS, C.GIT_CONFIG_CHANGE),
            (PRIVILEGE_PATHS, C.PRIVILEGE_ESCALATION),
            (TAMPER_PATHS, C.SECURITY_TOOL_TAMPER),
        ):
            if _matches(patterns, path):
                self.classes.add(cls)

    def path_word(self, word: Word, *, writes: bool, strict: bool) -> None:
        self.path(path_text(word), writes=writes, strict=strict)

    def change_directory(self, name: str, args: list[Word]) -> None:
        """`cd`, `pushd`, `Set-Location` and friends: later relative paths are read from
        the new directory; one that cannot be named makes them unknown (review H1)."""
        self.moved = True
        if name in ("popd", "pop-location"):
            self.cwd = UNKNOWN_LOCATION
            return
        targets = [w for w in args if not w.text.startswith(("-", "/d", "/D")) or w.text == "-"]
        if not targets:
            if name in ("cd", "chdir") and not args:
                self.cwd = NormalisedPath(("~",))
            return
        word = targets[0]
        text = path_text(word)
        if DYN in text or text == "-" or any(ch in _GLOB_CHARS for ch in text):
            self.cwd = UNKNOWN_LOCATION
            return
        moved = join_paths(self.cwd, normalise_path(text, windows=True))
        self.cwd = UNKNOWN_LOCATION if moved.unknown or "*" in moved.text else moved

    def environment_reads(self, words: list[Word]) -> None:
        """A variable named like a secret, or a PowerShell `$env:` value that is not a
        plain location, handed to any program is a credential read (review H2)."""
        for word in words:
            for name in word.variables:
                low = name.casefold()
                secret = bool(p.SECRET_VARIABLE_RE.fullmatch(name))
                env = low.startswith("env:") and low not in p.BENIGN_ENV_VARIABLES
                if secret or env:
                    self.classes.add(C.CREDENTIAL_ACCESS)
