"""Classify a shell command string into `CommandClass` values.

The text is read twice, once as a POSIX shell and once as PowerShell/cmd, because the
hook does not say reliably which shell will run it. The danger classes found by either
reading are kept (ambiguity resolves to the more dangerous answer). `unparseable` is kept
when neither reading could read the text with confidence; `read_only_command` only when
every successful reading found nothing but known readers.
"""

from __future__ import annotations

from typing import Annotated

from pydantic import Field, field_validator

from ciso.common.schemas import Model
from ciso.governance.analysis import analyze
from ciso.governance.classes import CommandClass
from ciso.governance.danger_paths import AGENT_CONFIG_PATHS, CREDENTIAL_PATHS
from ciso.governance.globs import check_pattern
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
    """Classes found, and the branches a push in the command names (empty if none)."""

    classes: frozenset[CommandClass]
    branches: frozenset[str] = frozenset()


_UNPARSEABLE = CommandAnalysis(classes=frozenset({CommandClass.UNPARSEABLE}))


def classify_command(
    command: str | None,
    config: ClassifierConfig,
    *,
    target_branch: str | None = None,
    truncated: bool = False,
) -> CommandAnalysis:
    """Classify `command`. Never raises: anything unexpected is `unparseable`.

    `target_branch` is the branch the source reported for the action, used when a push
    names none. `truncated` means the source cut the text, so it is not fully visible.
    """
    if not command or not command.strip():
        return _UNPARSEABLE
    try:
        result = _classify(command, config, target_branch)
    except Exception:
        return _UNPARSEABLE
    if truncated:
        classes = (result.classes - {CommandClass.READ_ONLY_COMMAND}) | {CommandClass.UNPARSEABLE}
        return result.model_copy(update={"classes": frozenset(classes)})
    return result


def _classify(command: str, config: ClassifierConfig, target_branch: str | None) -> CommandAnalysis:
    danger: set[CommandClass] = set()
    branches: set[str] = set()
    readings = 0
    unreadable = 0
    read_only_everywhere = True
    hidden = False
    for dialect in Dialect:
        try:
            script = parse_script(command, dialect)
            found, named = analyze(script, config, target_branch)
        except HiddenCommand:
            hidden = True
            unreadable += 1
            continue
        except ParseError:
            unreadable += 1
            continue
        readings += 1
        branches |= named
        if CommandClass.UNPARSEABLE in found:
            unreadable += 1
        if CommandClass.READ_ONLY_COMMAND not in found:
            read_only_everywhere = False
        danger |= found - {CommandClass.UNPARSEABLE, CommandClass.READ_ONLY_COMMAND}
    classes = set(danger)
    if unreadable == len(Dialect) or hidden:
        classes.add(CommandClass.UNPARSEABLE)
    elif readings == len(Dialect) and unreadable == 0 and read_only_everywhere and not danger:
        # Read-only only when EVERY reading parsed and found nothing but readers: a
        # reading that failed may be the shell that actually runs the text.
        classes.add(CommandClass.READ_ONLY_COMMAND)
    return CommandAnalysis(classes=frozenset(classes), branches=frozenset(branches))
