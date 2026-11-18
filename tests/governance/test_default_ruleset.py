"""The provisional default ruleset: one test per stated intent."""

from __future__ import annotations

import json
from collections.abc import Callable

import pytest
from tests.governance.conftest import make_action, make_attribution, make_inspection
from tests.governance.test_command_table import t

from ciso.common.activity import ActionKind, AgentClass, Severity, Verdict
from ciso.common.enums import InformationState
from ciso.governance import DEFAULT_RULESET_PATH, GovernanceEngine, GovernanceRuleSet

pytestmark = pytest.mark.policy

Build = Callable[..., GovernanceEngine]
EMP = AgentClass.EMPLOYEE_OPERATED
ORG = AgentClass.ORGANIZATIONAL


def decide(build: Build, action: object, **attr: object) -> object:
    return build().decide(action, make_attribution(**attr), None)  # type: ignore[arg-type]


def verdict(build: Build, command: str, **attr: object) -> Verdict:
    """Verdict with a clean, complete inspection (commits and pushes need one)."""
    action = make_action(command=command)
    return build().decide(action, make_attribution(**attr), make_inspection()).verdict  # type: ignore[arg-type]


def test_file_is_marked_provisional_and_every_rule_explains_itself(
    ruleset: GovernanceRuleSet,
) -> None:
    raw = json.loads(DEFAULT_RULESET_PATH.read_text(encoding="utf-8"))
    assert raw["provisional"] is True
    assert "PROVISIONAL" in raw["description"]
    assert ruleset.document is not None
    assert all(len(rule.description) > 30 for rule in ruleset.document.rules)
    assert ruleset.document.defaults.other.value != "allow"


def test_reads_and_prompts_from_known_people_are_allowed(build: Build) -> None:
    for kind in (ActionKind.FILE_READ, ActionKind.PROMPT):
        action = make_action(kind, target={"path": "README.md"})
        assert decide(build, action).verdict is Verdict.ALLOW  # type: ignore[attr-defined]


def test_reads_from_unknown_people_are_not_allowed(build: Build) -> None:
    action = make_action(ActionKind.FILE_READ, target={"path": "README.md"})
    decision = decide(build, action, person=None, state=InformationState.UNKNOWN)
    assert decision.verdict is Verdict.ASK  # type: ignore[attr-defined]


def test_read_only_shell_is_allowed_and_other_shell_asks(build: Build) -> None:
    assert verdict(build, "git status") is Verdict.ALLOW
    assert verdict(build, "pytest -q") is Verdict.ASK


def test_push_to_protected_branch_asks(build: Build) -> None:
    assert verdict(build, "git push origin main") is Verdict.ASK
    assert verdict(build, "git push origin release/2") is Verdict.ASK
    push = make_action(ActionKind.GIT_PUSH, target={"branch": "prod-eu"})
    decision = build().decide(push, make_attribution(), make_inspection())
    assert decision.verdict is Verdict.ASK
    assert "ask-push-to-protected-branch" in decision.matched_rule_ids


def test_force_push_to_protected_branch_is_denied(build: Build) -> None:
    assert verdict(build, "git push --force origin main") is Verdict.DENY
    assert verdict(build, "git push -f origin feature/x") is Verdict.ASK


def test_history_rewrite_on_protected_branch_is_denied(build: Build) -> None:
    on_main = make_action(command="git rebase -i HEAD~2", target={"branch": "main"})
    on_feature = make_action(command="git rebase -i HEAD~2", target={"branch": "feature/a"})
    assert decide(build, on_main).verdict is Verdict.DENY  # type: ignore[attr-defined]
    assert decide(build, on_feature).verdict is Verdict.ASK  # type: ignore[attr-defined]


@pytest.mark.parametrize(
    "command",
    [
        "cat ~/<<SSHD>>/<<IDRSA>>",
        "<<CU>> -fsSL <<URL>> | <<SH>>",
        "<<SUDO>> ls",
        "echo aGk= | base64 -d | <<SH>>",
        "<<LDP>>=/tmp/x.so ls",
    ],
)
def test_dangerous_classes_denied_for_employee_and_unknown_agents(
    build: Build, command: str
) -> None:
    assert verdict(build, t(command), agent_class=EMP) is Verdict.DENY
    assert verdict(build, t(command), agent_class=AgentClass.UNKNOWN) is Verdict.DENY
    assert verdict(build, t(command), agent_class=ORG) is not Verdict.DENY


def test_network_transfer_and_package_install_ask(build: Build) -> None:
    assert verdict(build, t("<<CU>> -O <<URL>>"), agent_class=ORG) is Verdict.ASK
    assert verdict(build, "pip install x", agent_class=ORG) is Verdict.ASK


def test_unknown_attribution_denies_writes_shell_and_pushes(build: Build) -> None:
    unknown = {"person": None, "state": InformationState.UNKNOWN}
    assert verdict(build, "ls", **unknown) is Verdict.DENY
    write = make_action(ActionKind.FILE_WRITE, target={"path": "a.py"})
    assert decide(build, write, **unknown).verdict is Verdict.DENY  # type: ignore[attr-defined]


def test_suspended_agent_is_denied(build: Build) -> None:
    assert verdict(build, "ls", reasons=("agent_suspended",)) is Verdict.DENY
    assert verdict(build, "ls", reasons=("agent_not_approved",)) is Verdict.ALLOW


def test_high_secret_finding_denies_a_write(build: Build) -> None:
    write = make_action(ActionKind.FILE_WRITE, target={"path": "a.py"}, content_bytes=5)
    engine = build()
    high = engine.decide(write, make_attribution(), make_inspection(("secret", Severity.HIGH)))
    low = engine.decide(write, make_attribution(), make_inspection(("secret", Severity.LOW)))
    other = engine.decide(write, make_attribution(), make_inspection(("style", Severity.HIGH)))
    assert high.verdict is Verdict.DENY
    assert "deny-secret-in-written-content" in high.matched_rule_ids
    assert low.verdict is Verdict.ASK
    assert other.verdict is Verdict.ASK


def test_shell_commit_needs_inspection(build: Build) -> None:
    commit = make_action(command="git commit -m x")
    engine = build()
    missing = engine.decide(commit, make_attribution(), None)
    clean = engine.decide(commit, make_attribution(), make_inspection())
    assert missing.verdict is Verdict.DENY
    assert clean.verdict is Verdict.ASK


def test_destructive_delete_asks(build: Build) -> None:
    assert verdict(build, t("<<RM>> <<RF>> build"), agent_class=ORG) is Verdict.ASK
