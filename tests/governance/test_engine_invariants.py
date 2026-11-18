"""Built-in invariants of the governance engine, each with a test that reaches the guard
and one that proves the allowed path still works."""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

import pytest
from tests.fakes.core import FakeAudit, FakeKillSwitch, FakePrincipals
from tests.governance.conftest import make_action, make_attribution, make_inspection
from tests.governance.test_command_table import t

from ciso.common.activity import (
    ActionKind,
    AgentClass,
    ObservedAction,
    Phase,
    Severity,
    Verdict,
)
from ciso.common.enums import InformationState, KillCapability
from ciso.governance import (
    MESSAGES,
    GovernanceEngine,
    GovernanceRuleSet,
    ReasonCode,
    deny_all,
    parse_ruleset,
)

pytestmark = pytest.mark.policy

Build = Callable[..., GovernanceEngine]


def codes(decision: object) -> list[str]:
    return [r.code for r in decision.reasons]  # type: ignore[attr-defined]


def permissive_rules(**extra: object) -> GovernanceRuleSet:
    """Allows every kind for verified people, so only an invariant can deny."""
    kinds = '["shell_command", "file_write", "file_edit", "file_read", "prompt", "git_push"]'
    text = (
        '{"schema_version": 1, "version": "t1", "description": "test", "provisional": true,'
        ' "read_only_kinds": ["file_read", "prompt"], "defaults": {"read_only": "deny",'
        ' "other": "deny"}, "protected_branches": ["main"],'
        f' "missing_inspection": "{extra.get("missing", "deny")}",'
        ' "rules": [{"id": "allow-all", "description": "test", "effect": "allow",'
        f' "match": {{"kinds": {kinds}, "attribution_states": ["verified"]}}}}]}}'
    )
    loaded = parse_ruleset(text, Path("t.json"))
    assert not loaded.deny_all, loaded.deny_reason
    return loaded


# --- 1. ruleset unavailable -------------------------------------------------------------


def test_deny_all_ruleset_denies_even_reads(build: Build) -> None:
    decision = build(deny_all("broken")).decide(
        make_action(ActionKind.FILE_READ, target={"path": "README.md"}), make_attribution(), None
    )
    assert decision.verdict is Verdict.DENY
    assert codes(decision) == ["ruleset_unavailable"]


def test_loaded_ruleset_allows_a_known_reader(build: Build) -> None:
    decision = build().decide(make_action(command="ls -la"), make_attribution(), None)
    assert decision.verdict is Verdict.ALLOW
    assert decision.matched_rule_ids == ("allow-read-only-shell-known-people",)


# --- 2. attribution of another session -----------------------------------------------


def test_attribution_from_another_session_is_denied(build: Build) -> None:
    other = make_attribution().model_copy(update={"session_id": "sess-other"})
    decision = build().decide(make_action(command="ls"), other, None)
    assert codes(decision) == ["attribution_mismatch"]


# --- 3. kill switch --------------------------------------------------------------------


def test_kill_switch_denies_writes_but_not_reads(build: Build, killswitch: FakeKillSwitch) -> None:
    killswitch.blocked.add(KillCapability.WRITES)
    engine = build(permissive_rules())
    shell = engine.decide(make_action(command="ls"), make_attribution(), None)
    read = engine.decide(
        make_action(ActionKind.FILE_READ, target={"path": "a.txt"}), make_attribution(), None
    )
    assert codes(shell) == ["kill_switch_engaged"]
    assert read.verdict is Verdict.ALLOW
    assert KillCapability.WRITES in killswitch.reads


def test_unreadable_kill_switch_denies_writes(build: Build, killswitch: FakeKillSwitch) -> None:
    killswitch.broken = True
    decision = build(permissive_rules()).decide(make_action(command="ls"), make_attribution(), None)
    assert codes(decision) == ["kill_switch_engaged"]


def test_kill_switch_that_raises_denies_writes(
    build: Build, killswitch: FakeKillSwitch, monkeypatch: pytest.MonkeyPatch
) -> None:
    def boom(capability: KillCapability) -> bool:
        raise OSError("state file gone")

    monkeypatch.setattr(killswitch, "is_blocked", boom)
    decision = build(permissive_rules()).decide(make_action(command="ls"), make_attribution(), None)
    assert codes(decision) == ["kill_switch_engaged"]


# --- 4. disputed attribution -----------------------------------------------------------


def test_disputed_attribution_denies_non_reads(build: Build) -> None:
    engine = build(permissive_rules())
    disputed = make_attribution(state=InformationState.DISPUTED)
    shell = engine.decide(make_action(command="ls"), disputed, None)
    read = engine.decide(make_action(ActionKind.FILE_READ, target={"path": "a"}), disputed, None)
    assert codes(shell) == ["attribution_disputed"]
    assert "attribution_disputed" not in codes(read)


# --- 5. critical finding ----------------------------------------------------------------


def test_critical_finding_denies(build: Build) -> None:
    engine = build(permissive_rules())
    action = make_action(ActionKind.FILE_WRITE, target={"path": "src/a.py"})
    critical = engine.decide(
        action, make_attribution(), make_inspection(("code", Severity.CRITICAL))
    )
    high = engine.decide(action, make_attribution(), make_inspection(("code", Severity.HIGH)))
    assert codes(critical) == ["critical_finding"]
    assert high.verdict is Verdict.ALLOW


def test_critical_finding_of_another_action_is_ignored(build: Build) -> None:
    engine = build(permissive_rules())
    action = make_action(ActionKind.FILE_WRITE, target={"path": "src/a.py"})
    other = make_inspection(("code", Severity.CRITICAL), action_id="act-other")
    assert engine.decide(action, make_attribution(), other).verdict is Verdict.ALLOW


# --- 6. classes denied whatever the rules say ------------------------------------------


def test_agent_config_change_is_denied_even_when_rules_allow(build: Build) -> None:
    engine = build(permissive_rules())
    write = engine.decide(
        make_action(ActionKind.FILE_WRITE, target={"path": t("<<MCP>>")}),
        make_attribution(),
        None,
    )
    plain = engine.decide(
        make_action(ActionKind.FILE_WRITE, target={"path": "src/app.py"}),
        make_attribution(),
        None,
    )
    assert codes(write) == ["agent_config_change"]
    assert plain.verdict is Verdict.ALLOW


def test_security_tool_tamper_is_denied_even_when_rules_allow(build: Build) -> None:
    engine = build(permissive_rules())
    decision = engine.decide(make_action(command=t("<<UFW>> disable")), make_attribution(), None)
    assert codes(decision) == ["security_tool_tamper"]


# --- 7. unparseable is never allowed ---------------------------------------------------


def test_unparseable_command_is_capped_at_ask(build: Build) -> None:
    engine = build(permissive_rules())
    capped = engine.decide(make_action(command="$CMD --x"), make_attribution(), None)
    normal = engine.decide(make_action(command="pytest -q"), make_attribution(), None)
    assert capped.verdict is Verdict.ASK
    assert codes(capped)[0] == "unparseable_command"
    assert normal.verdict is Verdict.ALLOW


def test_truncated_command_is_capped_at_ask(build: Build) -> None:
    decision = build(permissive_rules()).decide(
        make_action(command="ls", command_truncated=True), make_attribution(), None
    )
    assert decision.verdict is Verdict.ASK


# --- 8. identity resolved now ----------------------------------------------------------


def test_identity_store_down_denies(build: Build, principals: FakePrincipals) -> None:
    principals.broken = True
    decision = build().decide(make_action(command="ls"), make_attribution(), None)
    assert codes(decision) == ["identity_unavailable"]


def test_person_is_resolved_now_not_trusted_from_the_record(
    build: Build, principals: FakePrincipals
) -> None:
    engine = build()
    allowed = engine.decide(make_action(command="ls"), make_attribution(), None)
    principals.remove("human_emp")
    removed = engine.decide(make_action(command="ls"), make_attribution(), None)
    assert allowed.verdict is Verdict.ALLOW
    assert removed.verdict is Verdict.ASK
    assert principals.lookups == ["human_emp", "human_emp"]


def test_malformed_or_non_actor_person_ref_is_unknown(build: Build) -> None:
    engine = build()
    for ref in ("human_emp", "agent:human_emp"):
        decision = engine.decide(make_action(command="ls"), make_attribution(ref), None)
        assert decision.verdict is Verdict.ASK


def test_agent_actor_is_not_a_person(build: Build) -> None:
    decision = build().decide(make_action(command="ls"), make_attribution("actor:agent_ciso"), None)
    assert decision.verdict is Verdict.ASK


# --- 9. internal error -----------------------------------------------------------------


def test_exception_while_deciding_is_internal_error(
    build: Build, monkeypatch: pytest.MonkeyPatch
) -> None:
    import ciso.governance.engine as engine_module

    def boom(*args: object, **kwargs: object) -> object:
        raise RuntimeError("bug")

    monkeypatch.setattr(engine_module, "action_analysis", boom)
    decision = build().decide(make_action(command="ls"), make_attribution(), None)
    assert decision.verdict is Verdict.DENY
    assert codes(decision) == ["internal_error"]


def test_clock_failure_is_internal_error(
    build: Build, monkeypatch: pytest.MonkeyPatch, clock: object
) -> None:
    def boom() -> object:
        raise RuntimeError("clock")

    monkeypatch.setattr(clock, "now", boom)
    decision = build().decide(make_action(command="ls"), make_attribution(), None)
    # The fake audit sink shares the broken clock, so the audit failure is recorded too.
    assert decision.verdict is Verdict.DENY
    assert "internal_error" in codes(decision)


# --- 10. audit ------------------------------------------------------------------------


def test_every_decision_is_audited_without_command_text(build: Build, audit: FakeAudit) -> None:
    secret_looking = "echo hunter2-should-not-appear"
    decision = build().decide(make_action(command=secret_looking), make_attribution(), None)
    event = audit.find("governance.decide")[0]
    assert event.actor_id == "svc_governance"
    assert event.details["verdict"] == decision.verdict.value
    assert event.details["ruleset_hash"] == decision.ruleset_hash
    assert event.details["action_id"] == "act-1"
    assert event.details["session_id"] == "sess-1"
    assert event.details["kind"] == "shell_command"
    assert event.details["reason_codes"] == codes(decision)
    assert "hunter2" not in repr(event.model_dump())


def test_audit_failure_denies_before_phase(build: Build, audit: FakeAudit) -> None:
    audit.fail = True
    decision = build().decide(make_action(command="ls"), make_attribution(), None)
    assert decision.verdict is Verdict.DENY
    assert codes(decision)[0] == "audit_unavailable"


def test_audit_failure_keeps_after_phase_verdict(build: Build, audit: FakeAudit) -> None:
    audit.fail = True
    decision = build().decide(
        make_action(command="ls", phase=Phase.AFTER), make_attribution(), None
    )
    assert decision.verdict is Verdict.ALLOW


# --- 11. explanations -----------------------------------------------------------------


def test_explanation_is_the_fixed_message_and_never_echoes_content(build: Build) -> None:
    command = t("<<RM>> <<RF>> very-private-folder-name")
    decision = build().decide(make_action(command=command), make_attribution(), None)
    assert decision.explanation == MESSAGES[ReasonCode(codes(decision)[0])]
    assert "very-private" not in decision.explanation


def test_every_reason_code_has_a_clean_message() -> None:
    for code in ReasonCode:
        message = MESSAGES[code]
        assert message
        assert "\n" not in message
        assert len(message) <= 512


# --- 12. inspection required by a rule ------------------------------------------------


def _write(path: str = "src/a.py") -> ObservedAction:
    return make_action(ActionKind.FILE_WRITE, target={"path": path}, content_bytes=10)


def test_missing_inspection_denies_when_a_rule_requires_it(build: Build) -> None:
    decision = build().decide(_write(), make_attribution(), None)
    assert decision.verdict is Verdict.DENY
    assert "inspection_missing" in codes(decision)


def test_incomplete_inspection_denies(build: Build) -> None:
    decision = build().decide(_write(), make_attribution(), make_inspection(complete=False))
    assert "inspection_incomplete" in codes(decision)
    assert decision.verdict is Verdict.DENY


def test_inspection_of_another_action_counts_as_missing(build: Build) -> None:
    decision = build().decide(_write(), make_attribution(), make_inspection(action_id="act-9"))
    assert "inspection_missing" in codes(decision)


def test_complete_clean_inspection_lets_the_other_rules_decide(build: Build) -> None:
    decision = build().decide(_write(), make_attribution(), make_inspection())
    assert decision.verdict is Verdict.ASK
    assert codes(decision) == ["default_ask"]


def test_ruleset_may_say_ask_for_a_missing_inspection(build: Build) -> None:
    text = (
        (Path(__file__).parents[2] / "src/ciso/governance/rulesets/default.json")
        .read_text(encoding="utf-8")
        .replace('"missing_inspection": "deny"', '"missing_inspection": "ask"')
    )
    rules = parse_ruleset(text, Path("x.json"))
    decision = build(rules).decide(_write(), make_attribution(), None)
    assert decision.verdict is Verdict.ASK
    assert "inspection_missing" in codes(decision)


def test_organizational_agent_with_unknown_state_is_still_denied(build: Build) -> None:
    decision = build().decide(
        make_action(command="pytest"),
        make_attribution(
            None, state=InformationState.UNKNOWN, agent_class=AgentClass.ORGANIZATIONAL
        ),
        None,
    )
    assert decision.verdict is Verdict.DENY
