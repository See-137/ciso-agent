"""Ruleset loading (deny-all on any problem), rule semantics, globs, requires_inspection."""

from __future__ import annotations

import json
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest
from tests.governance.conftest import make_action, make_attribution, make_inspection

from ciso.common.activity import ActionKind, Severity, Verdict
from ciso.common.enums import ActorType, Role
from ciso.common.principal import RoleGrant
from ciso.governance import (
    DEFAULT_RULESET_PATH,
    DENY_ALL_HASH,
    GovernanceEngine,
    load_ruleset,
    parse_ruleset,
    requires_inspection,
)
from ciso.governance.globs import check_pattern, glob_match, normalize_path

pytestmark = pytest.mark.policy

Build = Callable[..., GovernanceEngine]


def base(**changes: Any) -> dict[str, Any]:
    doc: dict[str, Any] = {
        "schema_version": 1,
        "version": "t1",
        "description": "test",
        "provisional": True,
        "read_only_kinds": ["file_read"],
        "defaults": {"read_only": "ask", "other": "deny"},
        "protected_branches": ["main"],
        "rules": [],
    }
    doc.update(changes)
    return doc


def load(doc: dict[str, Any] | str) -> Any:
    text = doc if isinstance(doc, str) else json.dumps(doc)
    return parse_ruleset(text, Path("t.json"))


def rule(effect: str = "deny", **match: Any) -> dict[str, Any]:
    return {
        "id": f"r-{effect}-{len(match)}",
        "description": "test",
        "effect": effect,
        "match": match,
    }


# --- loader: deny-all on every kind of problem ---------------------------------------


@pytest.mark.parametrize(
    ("doc", "reason"),
    [
        ("{not json", "malformed JSON"),
        ('{"schema_version": 1, "schema_version": 1}', "duplicate key"),
        (base(extra_key=1), "schema violation"),
        (base(schema_version=True), "schema violation"),
        (base(schema_version=2), "schema violation"),
        (base(defaults={"read_only": "allow", "other": "allow"}), "cannot be allow"),
        (base(read_only_kinds=["shell_command"]), "cannot be declared read-only"),
        (base(rules=[rule("allow", attribution_states=["verified"])]), "must name kinds"),
        (base(rules=[rule("allow", kinds=["shell_command"])]), "attribution_states"),
        (
            base(
                rules=[
                    rule(
                        "allow", kinds=["shell_command"], attribution_states=["verified", "unknown"]
                    )
                ]
            ),
            "attribution_states",
        ),
        (base(rules=[rule(kinds=[])]), "empty list"),
        (base(rules=[rule(command_classes=["no_such_class"])]), "schema violation"),
        (base(rules=[rule(targets={"branch": ["ma[in]"]})]), "glob"),
        (base(rules=[rule(targets={"branch": ["a/**b"]})]), "glob"),
        (base(rules=[rule(targets={})]), "at least one"),
        (base(rules=[rule(attribution_reasons=["Bad Code"])]), "reason code"),
        (base(rules=[rule(person_known="yes")]), "schema violation"),
        (
            base(rules=[rule(kinds=["shell_command"]), rule(kinds=["shell_command"])]),
            "duplicate rule id",
        ),
        (base(protected_branches=[]), "schema violation"),
        (base(missing_inspection="allow"), "schema violation"),
        (
            base(rules=[{"id": "x", "description": "", "effect": "deny", "match": {}}]),
            "schema violation",
        ),
    ],
)
def test_bad_rulesets_load_as_deny_all(doc: dict[str, Any] | str, reason: str) -> None:
    loaded = load(doc)
    assert loaded.deny_all
    assert reason in loaded.deny_reason
    assert loaded.content_hash == DENY_ALL_HASH
    assert loaded.document is None


def test_a_good_ruleset_loads_and_its_hash_ignores_a_bom() -> None:
    text = json.dumps(base())
    plain = load(text)
    bom = load("\ufeff" + text)
    assert not plain.deny_all
    assert plain.content_hash == bom.content_hash
    assert plain.content_hash != DENY_ALL_HASH


def test_file_problems_load_as_deny_all(tmp_path: Path) -> None:
    missing = load_ruleset(tmp_path / "nope.json")
    binary = tmp_path / "bin.json"
    binary.write_bytes(b"\xff\xfe\x00")
    big = tmp_path / "big.json"
    big.write_bytes(b" " * 1_000_001)
    assert "cannot read" in missing.deny_reason
    assert "UTF-8" in load_ruleset(binary).deny_reason
    assert "too large" in load_ruleset(big).deny_reason


def test_shipped_default_ruleset_loads() -> None:
    assert not load_ruleset(DEFAULT_RULESET_PATH).deny_all


# --- rule semantics ---------------------------------------------------------------


def engine_with(build: Build, *rules: dict[str, Any], **changes: Any) -> GovernanceEngine:
    loaded = load(base(rules=list(rules), **changes))
    assert not loaded.deny_all, loaded.deny_reason
    return build(loaded)


ALLOW_SHELL = {"kinds": ["shell_command"], "attribution_states": ["verified"]}


def test_strictest_effect_wins(build: Build) -> None:
    engine = engine_with(
        build,
        {**rule("allow", **ALLOW_SHELL), "id": "a"},
        {**rule("ask", kinds=["shell_command"]), "id": "b"},
    )
    decision = engine.decide(make_action(command="pytest"), make_attribution(), None)
    assert decision.verdict is Verdict.ASK
    assert decision.matched_rule_ids == ("a", "b")


def test_no_match_uses_the_declared_default(build: Build) -> None:
    engine = engine_with(build)
    shell = engine.decide(make_action(command="ls"), make_attribution(), None)
    read = engine.decide(
        make_action(ActionKind.FILE_READ, target={"path": "a"}), make_attribution(), None
    )
    assert (shell.verdict, read.verdict) == (Verdict.DENY, Verdict.ASK)
    assert [r.code for r in shell.reasons] == ["default_deny"]


def test_unknown_target_matches_a_restriction_but_not_an_allow(build: Build) -> None:
    allow = {**rule("allow", **ALLOW_SHELL, targets={"repository": ["corp/*"]}), "id": "a"}
    deny = {**rule("deny", kinds=["shell_command"], targets={"server": ["prod.*"]}), "id": "d"}
    engine = engine_with(build, allow, deny)
    known = engine.decide(
        make_action(command="ls", target={"repository": "corp/app", "server": "dev.x"}),
        make_attribution(),
        None,
    )
    unknown_server = engine.decide(
        make_action(command="ls", target={"repository": "corp/app"}), make_attribution(), None
    )
    unknown_repo = engine.decide(
        make_action(command="ls", target={"server": "dev.x"}), make_attribution(), None
    )
    assert known.verdict is Verdict.ALLOW
    assert unknown_server.verdict is Verdict.DENY
    assert unknown_repo.verdict is Verdict.DENY  # allow missed, default deny


def test_restrictions_ignore_case_allows_do_not(build: Build) -> None:
    allow = {**rule("allow", **ALLOW_SHELL, targets={"repository": ["corp/app"]}), "id": "a"}
    deny = {**rule("deny", kinds=["shell_command"], targets={"branch": ["main"]}), "id": "d"}
    engine = engine_with(build, allow, deny)
    upper = engine.decide(
        make_action(command="ls", target={"repository": "CORP/APP", "branch": "x"}),
        make_attribution(),
        None,
    )
    main = engine.decide(
        make_action(command="ls", target={"repository": "corp/app", "branch": "MAIN"}),
        make_attribution(),
        None,
    )
    assert upper.verdict is Verdict.DENY
    assert main.verdict is Verdict.DENY


def test_person_roles_are_resolved_now_and_scoped_to_the_target(
    build: Build, principals: Any
) -> None:
    allow = {**rule("allow", **ALLOW_SHELL, person_roles=["system_owner"]), "id": "a"}
    engine = engine_with(build, allow)
    from tests.fakes.core import make_principal

    principals.register(
        make_principal(
            "owner_x",
            ActorType.HUMAN,
            Role.SYSTEM_OWNER,
            grants=(
                RoleGrant(role=Role.SYSTEM_OWNER, scope={"repository": frozenset({"corp/a"})}),
            ),
        )
    )
    attr = make_attribution("actor:owner_x")
    inside = engine.decide(
        make_action(command="pytest", target={"repository": "corp/a"}), attr, None
    )
    outside = engine.decide(
        make_action(command="pytest", target={"repository": "corp/b"}), attr, None
    )
    employee = engine.decide(
        make_action(command="pytest", target={"repository": "corp/a"}), make_attribution(), None
    )
    assert inside.verdict is Verdict.ALLOW
    assert outside.verdict is Verdict.DENY
    assert employee.verdict is Verdict.DENY


def test_inspection_condition_matches_findings(build: Build) -> None:
    deny = {
        **rule(
            "deny",
            kinds=["file_write"],
            inspection={"categories": ["secret"], "min_severity": "medium"},
        ),
        "id": "d",
    }
    engine = engine_with(build, deny, defaults={"read_only": "ask", "other": "ask"})
    write = make_action(ActionKind.FILE_WRITE, target={"path": "a.py"})
    med = engine.decide(write, make_attribution(), make_inspection(("secret", Severity.MEDIUM)))
    low = engine.decide(write, make_attribution(), make_inspection(("secret", Severity.LOW)))
    none = engine.decide(write, make_attribution(), None)
    partial = engine.decide(write, make_attribution(), make_inspection(complete=False))
    assert med.verdict is Verdict.DENY
    assert low.verdict is Verdict.ASK
    assert none.verdict is Verdict.DENY  # unknown matches a restriction
    assert partial.verdict is Verdict.DENY  # an incomplete scan may have missed it


def test_attribution_reason_and_phase_and_source_conditions(build: Build) -> None:
    deny = {
        **rule(
            "deny", attribution_reasons=["operator_mismatch"], phases=["before"], sources=["hook"]
        ),
        "id": "d",
    }
    allow = {**rule("allow", **ALLOW_SHELL), "id": "a"}
    engine = engine_with(build, deny, allow)
    hit = engine.decide(
        make_action(command="ls"), make_attribution(reasons=("operator_mismatch",)), None
    )
    miss = engine.decide(make_action(command="ls"), make_attribution(), None)
    assert hit.verdict is Verdict.DENY
    assert miss.verdict is Verdict.ALLOW


# --- globs -----------------------------------------------------------------------


@pytest.mark.parametrize(
    ("pattern", "value", "separator", "expected"),
    [
        ("release/*", "release/1.2", "/", True),
        ("release/*", "release/1/2", "/", False),
        ("release/**", "release/1/2", "/", True),
        ("**/x", "x", "/", True),
        ("prod*", "production", "/", True),
        ("prod*", "preprod", "/", False),
        ("*.corp.example", "a.corp.example", ".", True),
        ("*.corp.example", "a.b.corp.example", ".", False),
        ("main", "main2", "/", False),
        ("ma?n", "main", "/", True),
    ],
)
def test_glob_is_anchored_and_segment_aware(
    pattern: str, value: str, separator: str, expected: bool
) -> None:
    assert glob_match(pattern, value, separator, casefold=False) is expected


def test_glob_patterns_refuse_regex_syntax() -> None:
    for bad in ("ma[in]", "(a|b)", "a/**b", "a//b", "^main$"):
        with pytest.raises(ValueError, match="glob"):
            check_pattern(bad, "/")


def test_path_normalization() -> None:
    assert normalize_path("C:\\x\\..\\y\\.\\z") == "C:/y/z"
    assert normalize_path("/a//b/../c") == "/a/c"


# --- requires_inspection ------------------------------------------------------------


def test_requires_inspection() -> None:
    write = make_action(ActionKind.FILE_WRITE, target={"path": "a"}, content_bytes=3)
    empty = make_action(ActionKind.FILE_WRITE, target={"path": "a"})
    assert requires_inspection(write)
    assert not requires_inspection(empty)
    assert requires_inspection(make_action(ActionKind.GIT_COMMIT))
    assert requires_inspection(make_action(ActionKind.GIT_PUSH))
    assert requires_inspection(make_action(command="git push origin x"))
    assert requires_inspection(make_action(command="git commit -m x"))
    assert not requires_inspection(make_action(command="ls"))
    assert not requires_inspection(make_action(ActionKind.FILE_READ, target={"path": "a"}))
