"""Fix round QF1: the pre-push rules in the default ruleset, and `bulk_write` (queue Q15).

The pre-push rules: a scanned, complete push of a known person's agent to a branch that is
not protected is allowed; a scanned push or commit with a finding of high severity or
worse (a secret, failed tests) is denied; a protected branch, a force push and a push of
an unknown person stay at ask or worse.

`bulk_write`: recursive copies and moves, sync tools and archive extraction whose
destination is the current directory, a parent, the home directory, a root or unknown.
Such a write can plant files (agent configuration among them) that no path rule sees, so
the default ruleset asks.
"""

from __future__ import annotations

import json
from collections.abc import Callable

import pytest
from tests.governance.conftest import make_action, make_attribution, make_inspection
from tests.governance.test_command_table import t

from ciso.common.activity import ActionKind, AgentClass, GovernanceDecision, Severity, Verdict
from ciso.common.enums import InformationState
from ciso.governance import (
    DEFAULT_RULESET_PATH,
    ClassifierConfig,
    CommandClass,
    GovernanceEngine,
    classify_command,
)

pytestmark = pytest.mark.policy

Build = Callable[..., GovernanceEngine]
C = CommandClass
CFG = ClassifierConfig(protected_branches=("main", "master", "release/*", "prod*"))
ALLOW_PUSH = "allow-scanned-push-known-people"
DENY_HIGH = "deny-high-findings-in-scanned-push-or-commit"
ASK_FORCE = "ask-force-push-any-branch"
ASK_BULK = "ask-bulk-write"


def push(
    build: Build,
    *findings: tuple[str, Severity],
    branch: str | None = "feature/a",
    complete: bool = True,
    force: bool = False,
    **attr: object,
) -> GovernanceDecision:
    """A plain push the intake refined to `git_push`, decided with its scan result."""
    target = {"remote": "origin"}
    if branch is not None:
        target["branch"] = branch
    if force:
        target["force"] = "true"
    action = make_action(ActionKind.GIT_PUSH, target=target)
    inspection = make_inspection(*findings, complete=complete)
    return build().decide(action, make_attribution(**attr), inspection)  # type: ignore[arg-type]


# --- 1. pre-push rules in the default ruleset ------------------------------------------


def test_the_default_ruleset_version_is_bumped_and_names_the_new_rules() -> None:
    raw = json.loads(DEFAULT_RULESET_PATH.read_text(encoding="utf-8"))
    assert raw["version"] == "governance-default-2026.11.19-3"
    ids = {rule["id"] for rule in raw["rules"]}
    assert {ALLOW_PUSH, DENY_HIGH, ASK_FORCE, ASK_BULK} <= ids


@pytest.mark.parametrize("kind_of_agent", [AgentClass.EMPLOYEE_OPERATED, AgentClass.ORGANIZATIONAL])
def test_a_clean_scanned_push_to_a_feature_branch_is_allowed(
    build: Build, kind_of_agent: AgentClass
) -> None:
    decision = push(build, agent_class=kind_of_agent)
    assert decision.verdict is Verdict.ALLOW
    assert decision.reasons[0].code == "rule_allow"
    assert ALLOW_PUSH in decision.matched_rule_ids


def test_a_low_finding_does_not_stop_the_allow(build: Build) -> None:
    assert push(build, ("code_risk", Severity.LOW)).verdict is Verdict.ALLOW


@pytest.mark.parametrize("branch", ["main", "release/2", "prod-eu", None])
def test_a_protected_or_unknown_branch_is_still_asked(build: Build, branch: str | None) -> None:
    decision = push(build, branch=branch)
    assert decision.verdict is Verdict.ASK
    assert "ask-push-to-protected-branch" in decision.matched_rule_ids


def test_a_force_push_to_a_feature_branch_is_asked_not_allowed(build: Build) -> None:
    decision = push(build, force=True)
    assert decision.verdict is Verdict.ASK
    assert ASK_FORCE in decision.matched_rule_ids


@pytest.mark.parametrize(
    "attr",
    [
        {"person": None, "state": InformationState.UNKNOWN},
        {"agent_class": AgentClass.UNKNOWN},
        {"state": InformationState.INFERRED},
        {"person": "actor:nobody_here"},
    ],
)
def test_a_push_of_an_unknown_person_or_agent_is_not_allowed(
    build: Build, attr: dict[str, object]
) -> None:
    assert push(build, **attr).verdict is not Verdict.ALLOW  # type: ignore[arg-type]


def test_an_incomplete_scan_is_denied(build: Build) -> None:
    decision = push(build, complete=False)
    assert decision.verdict is Verdict.DENY
    assert decision.reasons[0].code == "inspection_incomplete"


@pytest.mark.parametrize(
    "category", ["test_failure", "secret", "sandbox", "sensitive_path", "scan_suppression"]
)
def test_a_high_finding_in_a_scanned_push_is_denied(build: Build, category: str) -> None:
    decision = push(build, (category, Severity.HIGH))
    assert decision.verdict is Verdict.DENY
    assert DENY_HIGH in decision.matched_rule_ids


def test_a_high_finding_in_a_scanned_commit_is_denied(build: Build) -> None:
    engine = build()
    failing = make_inspection(("test_failure", Severity.HIGH))
    for action in (
        make_action(ActionKind.GIT_COMMIT),
        make_action(command="git commit -m x"),
    ):
        decision = engine.decide(action, make_attribution(), failing)
        assert decision.verdict is Verdict.DENY
        assert DENY_HIGH in decision.matched_rule_ids
        clean = engine.decide(action, make_attribution(), make_inspection())
        assert clean.verdict is Verdict.ASK  # a scanned commit is not allowed by a rule


@pytest.mark.parametrize(
    "command",
    [
        "git push origin feature/a",
        "git push origin feature/a && python tool.py",
        "git push origin feature/a; touch notes.txt",
    ],
)
def test_the_allow_is_only_for_the_plain_push_kind(build: Build, command: str) -> None:
    """A shell command is never allowed by the push rule: the intake refines only one
    plain push to the `git_push` kind, so a chain after a push cannot ride on the allow."""
    action = make_action(command=command, target={"branch": "feature/a"})
    decision = build().decide(action, make_attribution(), make_inspection())
    assert decision.verdict is not Verdict.ALLOW
    assert ALLOW_PUSH not in decision.matched_rule_ids


# --- 3. bulk_write (Q15) ---------------------------------------------------------------


def classes(command: str) -> frozenset[C]:
    return classify_command(command, CFG).classes


BULK = [
    "cp -r vendor/pkg .",
    "cp -R x ./",
    "cp -a /tmp/x ..",
    "cp -r x ~",
    "cp -r x $HOME",
    'cp -r x "$DEST"',
    "cp --recursive x .",
    "cp -r -t . a b",
    "cp -r x /",
    'cp -r x "$(git rev-parse --show-toplevel)"',
    "cd sub && cp -r x ..",
    "cd $X && tar -xf a.tar",
    "mv /tmp/pkg/* .",
    "rsync -a src/ ./",
    "rsync -a host:src/ .",
    "robocopy C:\\src . /E",
    "robocopy \\\\srv\\share %USERPROFILE% /MIR",
    "xcopy D:\\pkg . /s /e",
    "xcopy D:\\pkg /s",
    "Copy-Item -Recurse C:\\x -Destination .",
    "Copy-Item C:\\x .. -Recurse",
    "cpi -r x ~",
    "tar -xzf a.tgz",
    "tar xf a.tar",
    "tar -xf a.tar -C ..",
    "tar --extract -f a.tar --directory=$HOME",
    "unzip a.zip",
    "unzip -o a.zip -d ..",
    "7z x a.7z",
    "7z e a.zip -o.",
    "Expand-Archive a.zip .",
    "Expand-Archive -Path a.zip -DestinationPath $env:USERPROFILE",
    "Expand-Archive a.zip",
    "sudo tar -xf a.tar -C /",
    # Review of bulk_write.py: option spellings that must not evade the gate.
    "cp --recur x .",
    "cp --arch x ..",
    "cp -r --target-directory=. a b",
    "cp -r --target=.. a b",
    "tar --ext -f a.tar",
    "tar -xf a.tar --directory=..",
    "tar -xf a.tar --dir=$HOME",
    "tar -xf a.tar -C..",
    "tar xfC a.tar ..",
    "Copy-Item -Recurse:$true x -Destination:.",
    "Copy-Item -Rec x -Destination:~",
    "Copy-Item x -Destination:.. -Recurse",
    "Expand-Archive a.zip -DestinationPath:.",
    "Expand-Archive a.zip -Dest ..",
    # Fail closed: an option the reader does not know makes the destination unknown.
    "cp -r --weird x out",
    "cp --zork x out",
    "tar -xf a.tar --transform=s,^,../, -C out",
    "tar -xf a.tar --zork -C out",
    "unzip -Q a.zip -d out",
    "rsync -a --zork src/ backup/",
    "Copy-Item -Recurse -Zork x -Destination out",
    "xcopy src dst /s /zork",
    "robocopy src /E dst",
    "mv --zork a b",
    # Members that may escape the destination make it unknown.
    "tar -xPf a.tar -C out",
    "tar -xf a.tar --absolute-names -C out",
    "tar -xf a.tar --abs -C out",
    "7z x a.7z -spf -oout",
    "7z x a.7z -spf2 -oout",
    "7z x a.7z -zork -oout",
    "unzip -: a.zip -d out",
    "unzip -o -: a.zip -d out",
    "Expand-Archive a.zip -Zork out",
]


@pytest.mark.parametrize("command", BULK)
def test_bulk_writes_into_broad_places_are_bulk_write(command: str) -> None:
    assert C.BULK_WRITE in classes(command)


NOT_BULK = [
    "cp a.txt .",
    "cp -r src build/out",
    "cp -r src ../backup",
    "tar -xf a.tar -C build/tmp",
    "tar -tf a.tar",
    "tar -cf a.tar src",
    "unzip a.zip -d out",
    "unzip -l a.zip",
    "7z x a.7z -oout",
    "7z l a.7z",
    "Expand-Archive a.zip -DestinationPath out",
    "robocopy src dst /E",
    "xcopy src dst /s",
    "xcopy a.txt .",
    "rsync -a src/ backup/",
    "Copy-Item a.txt .",
    "Copy-Item -Force a.txt .",
    "mv a.txt b.txt",
    "cp -r --target-directory=build a b",
    "tar -xf a.tar --directory=build/tmp",
    "tar --list -f a.tar",
    "unzip -qq a.zip -d out",
    "rsync -a --exclude .git src/ backup/",
    "7z x a.7z -y -oout",
    "7z x a.7z -aoa -oout",
    "7z x a.7z -pxyz -oout",
    # An unambiguous long-option prefix is read as the full option, not as unknown.
    "cp -r --target=build a b",
    "tar -xf a.tar --dir=build",
    "ls -la",
]


@pytest.mark.parametrize("command", NOT_BULK)
def test_ordinary_copies_and_extractions_are_not_bulk_write(command: str) -> None:
    assert C.BULK_WRITE not in classes(command)


@pytest.mark.parametrize("command", ["tar -xf a.tar", "cp -r vendor/pkg .", "unzip a.zip"])
def test_the_default_ruleset_asks_for_a_bulk_write(build: Build, command: str) -> None:
    action = make_action(command=command)
    attribution = make_attribution(agent_class=AgentClass.ORGANIZATIONAL)
    decision = build().decide(action, attribution, None)
    assert decision.verdict is Verdict.ASK
    assert ASK_BULK in decision.matched_rule_ids
    assert decision.reasons[0].code == "rule_ask"


def test_a_bulk_write_that_also_pushes_is_not_allowed(build: Build) -> None:
    action = make_action(command=t("tar -xf a.tar && git push origin feature/a"))
    decision = build().decide(action, make_attribution(), make_inspection())
    assert decision.verdict is not Verdict.ALLOW


# --- review H4 (b): every allow needs a VERIFIED person ------------------------------------


def test_every_allow_rule_of_the_default_requires_a_verified_person() -> None:
    raw = json.loads(DEFAULT_RULESET_PATH.read_text(encoding="utf-8"))
    allows = [rule for rule in raw["rules"] if rule["effect"] == "allow"]
    assert len(allows) == 3
    for rule in allows:
        assert rule["match"]["attribution_states"] == ["verified"], rule["id"]


def test_a_declared_person_is_asked_where_a_verified_one_is_allowed(build: Build) -> None:
    declared = {"state": InformationState.DECLARED}
    assert push(build).verdict is Verdict.ALLOW
    held = push(build, **declared)  # type: ignore[arg-type]
    assert (held.verdict, held.reasons[0].code) == (Verdict.ASK, "default_ask")
    engine = build()
    read = make_action(ActionKind.FILE_READ, target={"path": "README.md"})
    shell = make_action(command="git status")
    for action in (read, shell):
        assert engine.decide(action, make_attribution(), None).verdict is Verdict.ALLOW
        assert engine.decide(action, make_attribution(**declared), None).verdict is Verdict.ASK  # type: ignore[arg-type]


# --- review H4 (c): the hook client's own configuration is a credential ------------------

#: The managed pack's source: where the hook client keeps its device token and code.
PACK_SOURCE = (
    DEFAULT_RULESET_PATH.parents[4]
    / "integrations"
    / "claude_code"
    / "managed"
    / "pack_source.json"
)


def _pack_paths() -> list[str]:
    pack = json.loads(PACK_SOURCE.read_text(encoding="utf-8"))
    paths = [env["AIGOV_DEVICE_TOKEN_FILE"] for env in pack["platform_env"].values()]
    paths += [hook["client"] for hook in pack["platform_hook"].values()]
    for rules in pack["platform_deny"].values():
        for rule in rules:
            inner = rule.partition("(")[2].rstrip(")").removeprefix("//")
            paths.append("/" + inner.replace("/**", "/x"))
    return paths


def test_every_managed_pack_location_is_a_credential_path() -> None:
    paths = _pack_paths()
    assert len(paths) >= 12
    for path in paths:
        assert C.CREDENTIAL_ACCESS in classes(f'cat "{path}"'), path


@pytest.mark.parametrize(
    "command",
    [
        "cat /c/ProgramData/AIGovernance/device-token",
        r"type C:\ProgramData\AIGovernance\device-token",
        r"Get-Content 'C:\ProgramData\AIGovernance\device-token'",
        "cat /etc/ai-governance/device-token",
        "python -c \"print(open('/etc/ai-governance/device-token').read())\"",
        "ls /etc/ai-governance",
    ],
)
def test_reading_the_device_token_is_credential_access(build: Build, command: str) -> None:
    assert C.CREDENTIAL_ACCESS in classes(command)
    decision = build().decide(make_action(command=command), make_attribution(), None)
    assert decision.verdict is Verdict.DENY
    assert "deny-credential-access-employee-unknown-agents" in decision.matched_rule_ids


def test_a_file_read_of_the_device_token_is_denied(build: Build) -> None:
    action = make_action(
        ActionKind.FILE_READ, target={"path": r"C:\ProgramData\AIGovernance\device-token"}
    )
    assert build().decide(action, make_attribution(), None).verdict is Verdict.DENY


@pytest.mark.parametrize("command", ["cat governance/notes.md", "ls ai/governance-docs"])
def test_ordinary_governance_named_paths_are_not_credentials(command: str) -> None:
    assert C.CREDENTIAL_ACCESS not in classes(command)
