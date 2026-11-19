"""Classify a shell command string into `CommandClass` values.

The text is read twice, once as a POSIX shell and once as PowerShell/cmd, because the
hook does not say reliably which shell will run it. The danger classes found by either
reading are kept (ambiguity resolves to the more dangerous answer).

`unparseable` is added when EITHER reading fails or finds something it cannot read, and
the danger classes of the other reading are kept with it (review M3); also when the text
holds a character PowerShell reads as a quote, dash or space but a POSIX shell reads as a
letter (review C3, M2), or when the readings disagree on text with other non-ASCII
characters. `read_only_command` only when both readings parsed and found nothing but
plain readers, and the text is ASCII.
"""

from __future__ import annotations

from typing import Annotated

from pydantic import Field, field_validator

from ciso.common.schemas import Model
from ciso.governance.analysis import analyze
from ciso.governance.classes import CommandClass
from ciso.governance.danger_paths import AGENT_CONFIG_PATHS, CREDENTIAL_PATHS
from ciso.governance.globs import check_pattern
from ciso.governance.lexer_types import POWERSHELL_SPECIAL
from ciso.governance.shell_lexer import Dialect, HiddenCommand, ParseError, parse_script

#: Most patterns of one kind a ruleset may add.
MAX_PATTERNS = 128

_Patterns = Annotated[tuple[str, ...], Field(max_length=MAX_PATTERNS)]


class ClassifierConfig(Model):
    """What the classifier needs from the ruleset. Path lists ADD to the built-in ones."""

    protected_branches: Annotated[tuple[str, ...], Field(min_length=1, max_length=MAX_PATTERNS)]
    credential_paths: _Patterns = ()
    agent_config_paths: _Patterns = ()

    @field_validator("protected_branches", "credential_paths", "agent_config_paths")
    @classmethod
    def _patterns(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        for pattern in value:
            check_pattern(pattern, "/")
        return value

    @property
    def all_credential_paths(self) -> tuple[str, ...]:
        return CREDENTIAL_PATHS + self.credential_paths

    @property
    def all_agent_config_paths(self) -> tuple[str, ...]:
        return AGENT_CONFIG_PATHS + self.agent_config_paths


class CommandAnalysis(Model):
    """Classes found, the branches a push in the command names (empty if none), and
    whether a push names no destination branch (`unknown_branch`: the branch is unknown,
    which restrictive rules treat as protected)."""

    classes: frozenset[CommandClass]
    branches: frozenset[str] = frozenset()
    unknown_branch: bool = False


_UNPARSEABLE = CommandAnalysis(classes=frozenset({CommandClass.UNPARSEABLE}))
_MARKERS = frozenset({CommandClass.UNPARSEABLE, CommandClass.READ_ONLY_COMMAND})


def classify_command(
    command: str | None,
    config: ClassifierConfig,
    *,
    target_branch: str | None = None,
    truncated: bool = False,
) -> CommandAnalysis:
    """Classify `command`. Never raises: anything unexpected is `unparseable`.

    `target_branch` is accepted for callers but no longer decides anything: a push that
    names no destination is a push to an unknown branch (review H5). `truncated` means the
    source cut the text, so it is not fully visible.
    """
    del target_branch
    if not command or not command.strip():
        return _UNPARSEABLE
    try:
        result = _classify(command, config)
    except Exception:
        return _UNPARSEABLE
    if truncated:
        classes = (result.classes - {CommandClass.READ_ONLY_COMMAND}) | {CommandClass.UNPARSEABLE}
        return result.model_copy(update={"classes": frozenset(classes)})
    return result


def _classify(command: str, config: ClassifierConfig) -> CommandAnalysis:
    readings: list[frozenset[CommandClass]] = []
    branches: set[str] = set()
    unknown_branch = False
    failed = False
    for dialect in Dialect:
        try:
            script = parse_script(command, dialect)
            found, named, unknown = analyze(script, config)
        except (HiddenCommand, ParseError):
            failed = True
            continue
        readings.append(frozenset(found))
        branches |= named
        unknown_branch = unknown_branch or unknown
    danger = {c for found in readings for c in found} - _MARKERS
    unparseable = (
        failed
        or any(CommandClass.UNPARSEABLE in found for found in readings)
        or any(ch in POWERSHELL_SPECIAL for ch in command)
        or (not command.isascii() and len(set(readings)) > 1)
    )
    classes = set(danger)
    if unparseable:
        classes.add(CommandClass.UNPARSEABLE)
    elif (
        command.isascii()
        and len(readings) == len(Dialect)
        and all(found == {CommandClass.READ_ONLY_COMMAND} for found in readings)
    ):
        classes.add(CommandClass.READ_ONLY_COMMAND)
    return CommandAnalysis(
        classes=frozenset(classes), branches=frozenset(branches), unknown_branch=unknown_branch
    )
