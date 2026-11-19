"""Queue Q22: git accepts any unambiguous abbreviation of a long option.

`git push --recei=<program>` is `--receive-pack=<program>`, `--force-w` is
`--force-with-lease`, `--mir` is `--mirror` (git 2.56.1, measured; `--forc` and `--rec`
are ambiguous and git refuses them). The classifier resolves every long push option to
the full option it uniquely prefixes; an unknown or ambiguous one is unparseable (never
allowed) and the destination is unknown. A receive-pack or exec value is a program git
runs: unparseable, and read as code. A short cluster holding `o` (`-uo <value>`) is unparseable.
"""

from __future__ import annotations

import pytest
from tests.governance.test_command_table import t
from tests.intake.test_git_option_abbreviations import INTAKE_CASES

from ciso.governance import ClassifierConfig, CommandClass, classify_command
from ciso.governance.git_argv import PUSH_LONG_OPTIONS, resolve_push_option

pytestmark = pytest.mark.adversarial

C = CommandClass
CFG = ClassifierConfig(protected_branches=("main",))


def classes(command: str) -> set[C]:
    return set(classify_command(command, CFG).classes)


@pytest.mark.parametrize(
    ("command", "present"),
    [
        ("git push --forc origin feature", {C.UNPARSEABLE}),  # git: ambiguous
        ("git push --fo origin feature", {C.UNPARSEABLE}),
        ("git push --force-with origin feature", {C.GIT_FORCE_PUSH}),
        ("git push --force-w=feature origin feature", {C.GIT_FORCE_PUSH}),
        ("git push --force-i origin feature", {C.GIT_FORCE_PUSH}),
        ("git push --del origin feature", {C.GIT_FORCE_PUSH}),
        ("git push --pru origin feature", {C.GIT_FORCE_PUSH}),
        ("git push --mir origin", {C.GIT_FORCE_PUSH, C.GIT_PUSH_PROTECTED_REF}),
        ("git push --al origin", {C.GIT_PUSH_PROTECTED_REF}),
        ("git push --bra origin", {C.GIT_PUSH_PROTECTED_REF}),
        ("git push --no-veri origin feature", {C.GIT_HOOKS_CHANGE}),
        ("git push --rec=./x.sh origin feature", {C.UNPARSEABLE}),
        ("git push --recei=./x.sh origin feature", {C.UNPARSEABLE}),
        ("git push --receive=./x.sh origin feature", {C.UNPARSEABLE}),
        ("git push --receive-pack=./x.sh origin feature", {C.UNPARSEABLE}),
        ("git push --exe ./x.sh origin feature", {C.UNPARSEABLE}),
        ("git push --exec=./x.sh origin feature", {C.UNPARSEABLE}),
        # ambiguous (`--f`: force, force-with-lease, force-if-includes, follow-tags)
        ("git push --f origin feature", {C.UNPARSEABLE, C.GIT_PUSH_PROTECTED_REF}),
        ("git push --no-f origin feature", {C.UNPARSEABLE, C.GIT_PUSH_PROTECTED_REF}),
        # unknown
        ("git push --bogus origin feature", {C.UNPARSEABLE, C.GIT_PUSH_PROTECTED_REF}),
        # a short cluster holding the push-option flag hides a value
        ("git push -uo x origin feature", {C.UNPARSEABLE}),
        ("git push -ox origin feature", {C.UNPARSEABLE}),
        ("git push -fu origin feature", {C.GIT_FORCE_PUSH}),
    ],
)
def test_abbreviated_and_unknown_push_options(command: str, present: set[C]) -> None:
    found = classes(command)
    assert present <= found, (command, sorted(found))


def test_full_names_and_plain_pushes_keep_their_classes() -> None:
    assert classes("git push origin feature") == {C.GIT_PUSH}
    assert classes("git push -u origin feature") == {C.GIT_PUSH}
    assert classes("git push --set-up origin feature") == {C.GIT_PUSH}
    assert classes("git push -o ci.skip origin feature") == {C.GIT_PUSH}
    assert C.GIT_FORCE_PUSH in classes("git push --force origin feature")
    assert classes("git push --repo=origin origin feature") == {C.GIT_PUSH}
    assert classes("git push origin -- feature") == {C.GIT_PUSH}


def test_a_receive_pack_value_is_read_as_code() -> None:
    """The value is classified like a command git runs: a download-and-run in it shows."""
    pipe = t("<<CU>> <<URL>> | <<SH>>")
    found = classes(f"git push '--recei={pipe}' origin feature")
    assert C.REMOTE_SCRIPT_EXECUTION in found
    assert C.UNPARSEABLE in found


def test_rebase_exec_abbreviation_is_read_as_code() -> None:
    pipe = t("<<CU>> <<URL>> | <<SH>>")
    assert C.REMOTE_SCRIPT_EXECUTION in classes(f"git rebase '--exe={pipe}' main")
    assert C.REMOTE_SCRIPT_EXECUTION in classes(f"git rebase --ex '{pipe}' main")


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("--recei", ("receive-pack", False)),
        ("--rec", None),
        ("--forc", None),
        ("--force-w", ("force-with-lease", False)),
        ("--force", ("force", False)),
        ("--no-force", ("force", True)),
        ("--verify", ("no-verify", True)),
        ("--no-verify", ("no-verify", False)),
        ("--f", None),
        ("--nonsense", None),
        ("--", None),
        ("--=x", None),
    ],
)
def test_resolver(text: str, expected: tuple[str, bool] | None) -> None:
    resolved = resolve_push_option(text)
    assert (None if resolved is None else (resolved.name, resolved.negated)) == expected


def test_intake_and_governance_know_the_same_push_options() -> None:
    from ciso.intake.gitcommand import PUSH_LONG_OPTIONS as INTAKE_OPTIONS

    assert dict(INTAKE_OPTIONS) == dict(PUSH_LONG_OPTIONS)
    assert INTAKE_CASES  # the intake's own table runs in tests/intake


# --- review M6: an assistant's own credential file ------------------------------------


@pytest.mark.parametrize(
    "path",
    [
        "/home/u/.claude/.credentials.json",
        "C:/Users/u/.claude/.credentials.json",
        "/home/u/.claude-work/.credentials.json",  # relocated configuration directory
    ],
)
def test_a_dot_credentials_json_file_is_a_credential(path: str) -> None:
    from tests.governance.conftest import make_action

    from ciso.common.activity import ActionKind
    from ciso.governance import action_analysis

    action = make_action(ActionKind.FILE_READ, command=None, target={"path": path})
    assert C.CREDENTIAL_ACCESS in action_analysis(action, CFG).classes
    plain = make_action(ActionKind.FILE_READ, command=None, target={"path": "/home/u/app.json"})
    assert C.CREDENTIAL_ACCESS not in action_analysis(plain, CFG).classes


def test_a_negated_option_takes_no_value() -> None:
    """`--no-<option>` never takes a value in git, so the next word stays a remote or a
    refspec. Swallowing it as a value shifted the remote and refspec (review of 3d5f93e):
    `git push --no-repo origin main` pushes `main` to `origin`, a protected push."""
    found = classes("git push --no-repo origin main")
    assert C.GIT_PUSH_PROTECTED_REF in found, sorted(found)
    found = classes("git push --no-recurse-submodules origin main")
    assert C.GIT_PUSH_PROTECTED_REF in found, sorted(found)
    assert classes("git push --no-push-option origin feature") == {C.GIT_PUSH}
