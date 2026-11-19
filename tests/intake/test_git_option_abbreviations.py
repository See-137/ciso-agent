"""Queue Q22, intake side: an abbreviated long push option never earns a refinement it
would not earn spelled in full.

git resolves `--recei=x` to `--receive-pack=x`, `--force-w` to `--force-with-lease`,
`--mir` to `--mirror`. The intake resolves every long option to the full push option it uniquely
prefixes; unknown or ambiguous gives no refinement (`shell_command`, governance decides),
a refused option gives no refinement, a force option is recorded as force. A short
cluster holding `o` (push option) or `d` (delete) gives no refinement.
"""

from __future__ import annotations

import pytest

from ciso.common.activity import ActionKind
from ciso.intake.gitcommand import classify_git

pytestmark = pytest.mark.adversarial

PUSH = ActionKind.GIT_PUSH
SHELL = ActionKind.SHELL_COMMAND
TARGET = {"remote": "origin", "branch": "feature"}
FORCED = {**TARGET, "force": "true"}

INTAKE_CASES: list[tuple[str, ActionKind, dict[str, str]]] = [
    # refused options, abbreviated
    ("git push --rec=./x.sh origin feature", SHELL, {}),  # git: ambiguous
    ("git push --recei=./x.sh origin feature", SHELL, {}),
    ("git push --receive=./x.sh origin feature", SHELL, {}),
    ("git push --exe=./x.sh origin feature", SHELL, {}),
    ("git push --ex ./x.sh origin feature", SHELL, {}),
    ("git push --mir origin", SHELL, {}),
    ("git push --al origin", SHELL, {}),
    ("git push --bra origin", SHELL, {}),
    ("git push --ta origin", SHELL, {}),
    ("git push --re=elsewhere origin feature", SHELL, {}),
    ("git push --push-o=x origin feature", SHELL, {}),
    ("git push --del origin feature", SHELL, {}),
    ("git push --pru origin feature", SHELL, {}),
    # force, abbreviated: recorded as force
    ("git push --forc origin feature", SHELL, {}),  # git: ambiguous
    ("git push --forc=x origin feature", SHELL, {}),
    ("git push --force-with origin feature", PUSH, FORCED),
    ("git push --force-w=feature origin feature", PUSH, FORCED),
    ("git push --force-i origin feature", PUSH, FORCED),
    ("git push -fu origin feature", PUSH, FORCED),
    ("git push -uf origin feature", PUSH, FORCED),
    # ambiguous or unknown: no refinement
    ("git push --f origin feature", SHELL, {}),
    ("git push --no-f origin feature", SHELL, {}),
    ("git push --bogus origin feature", SHELL, {}),
    ("git push --=x origin feature", SHELL, {}),
    # short clusters
    ("git push -uo x origin feature", SHELL, {}),
    ("git push -ox origin feature", SHELL, {}),
    ("git push -d origin feature", SHELL, {}),
    ("git push -ud origin feature", SHELL, {}),
    ("git push -z origin feature", SHELL, {}),
    # plain forms still refine
    ("git push origin feature", PUSH, TARGET),
    ("git push -u origin feature", PUSH, TARGET),
    ("git push --set-up origin feature", PUSH, TARGET),
    ("git push --verbose origin feature", PUSH, TARGET),
    ("git push --force origin feature", PUSH, FORCED),
]


@pytest.mark.parametrize(("command", "kind", "target"), INTAKE_CASES)
def test_push_option_spellings(command: str, kind: ActionKind, target: dict[str, str]) -> None:
    assert classify_git(command) == (kind, target)
