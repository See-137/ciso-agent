"""T1.12: rules are versioned declarative data; any load failure means deny-all."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from ciso.common.enums import ActorType, AuthorityLevel, Environment, Role
from ciso.policy import (
    DEFAULT_RULESET_PATH,
    MatchFacts,
    RuleMatch,
    RuleSet,
    load_default_ruleset,
    load_ruleset,
)

pytestmark = pytest.mark.policy


def _doc(**over: Any) -> dict[str, Any]:
    doc: dict[str, Any] = {
        "schema_version": 1,
        "version": "test-1",
        "risk_classes": ["low", "high"],
        "rules": [
            {
                "id": "r-read",
                "description": "reads",
                "effect": "allow",
                "match": {"authority_levels": [0, 1], "writes": False},
            }
        ],
    }
    doc.update(over)
    return doc


def _write(tmp_path: Path, content: str | bytes) -> Path:
    path = tmp_path / "rules.json"
    if isinstance(content, bytes):
        path.write_bytes(content)
    else:
        path.write_text(content, encoding="utf-8")
    return path


def _assert_deny_all(ruleset: RuleSet, fragment: str) -> None:
    assert ruleset.deny_all is True
    assert ruleset.rules == ()
    assert fragment in ruleset.deny_reason, ruleset.deny_reason


def test_valid_file_loads(tmp_path: Path) -> None:
    ruleset = load_ruleset(_write(tmp_path, json.dumps(_doc())))
    assert ruleset.deny_all is False
    assert ruleset.deny_reason == ""
    assert ruleset.version == "test-1"
    assert [r.id for r in ruleset.rules] == ["r-read"]
    assert len(ruleset.content_hash) == 64
    assert ruleset.risk_classes == ("low", "high")


def test_content_hash_ignores_formatting_but_tracks_content(tmp_path: Path) -> None:
    a = load_ruleset(_write(tmp_path, json.dumps(_doc())))
    b = load_ruleset(_write(tmp_path, json.dumps(_doc(), indent=4, sort_keys=True)))
    c = load_ruleset(_write(tmp_path, json.dumps(_doc(version="test-2"))))
    assert a.content_hash == b.content_hash
    assert a.content_hash != c.content_hash


def test_missing_file_is_deny_all(tmp_path: Path) -> None:
    _assert_deny_all(load_ruleset(tmp_path / "absent.json"), "cannot read")


def test_malformed_json_is_deny_all(tmp_path: Path) -> None:
    _assert_deny_all(load_ruleset(_write(tmp_path, '{"rules": [')), "malformed")


def test_invalid_utf8_is_deny_all(tmp_path: Path) -> None:
    raw = json.dumps(_doc()).encode("utf-8").replace(b"reads", b"r\xff\xfeads")
    _assert_deny_all(load_ruleset(_write(tmp_path, raw)), "not valid UTF-8")


def test_deep_nesting_is_deny_all(tmp_path: Path) -> None:
    _assert_deny_all(load_ruleset(_write(tmp_path, "[" * 100_000 + "]" * 100_000)), "nest")


def test_utf8_bom_is_stripped_and_hash_unchanged(tmp_path: Path) -> None:
    plain = load_ruleset(_write(tmp_path, json.dumps(_doc())))
    with_bom = load_ruleset(_write(tmp_path, b"\xef\xbb\xbf" + json.dumps(_doc()).encode()))
    assert with_bom.deny_all is False, with_bom.deny_reason
    assert with_bom.content_hash == plain.content_hash


def test_duplicate_json_key_is_deny_all(tmp_path: Path) -> None:
    text = json.dumps(_doc()).replace('"effect": "allow"', '"effect": "deny", "effect": "allow"')
    assert text.count('"effect"') == 2
    _assert_deny_all(load_ruleset(_write(tmp_path, text)), "duplicate key")


@pytest.mark.parametrize(
    "mutate",
    [
        lambda d: d.update(extra_top="x"),
        lambda d: d["rules"][0].update(priority=1),
        lambda d: d["rules"][0]["match"].update(command="anything"),
        lambda d: d["rules"][0].update(effect="permit"),
        lambda d: d["rules"][0]["match"].update(authority_levels=["1"]),
        lambda d: d["rules"][0]["match"].update(authority_levels=[7]),
        lambda d: d["rules"][0]["match"].update(authority_levels=[True]),
        lambda d: d["rules"][0]["match"].update(authority_levels=[1.0]),
        lambda d: d["rules"][0]["match"].update(writes="false"),
        lambda d: d.update(schema_version=2),
        lambda d: d.update(schema_version=1.0),
        lambda d: d.update(schema_version=True),
        lambda d: d.pop("version"),
        lambda d: d.update(risk_classes=[]),
        lambda d: d["rules"][0]["match"].update(risk_classes=["unlisted"]),
        lambda d: d["rules"][0].update(effect="require_approval"),
        lambda d: d["rules"][0].update(approver_roles=["employee"], effect="require_approval"),
        lambda d: d["rules"][0].update(approver_roles=["auditor"], effect="require_approval"),
        lambda d: d["rules"][0].update(
            approver_roles=["security_admin"], effect="require_approval"
        ),
        lambda d: d["rules"][0].update(approver_roles=["system_owner"]),
        lambda d: d["rules"][0]["match"].update(operations=["bad pattern!"]),
        lambda d: d["rules"][0]["match"].update(operations=["ticket..x"]),
    ],
)
def test_schema_violation_is_deny_all(tmp_path: Path, mutate: Any) -> None:
    doc = _doc()
    mutate(doc)
    _assert_deny_all(load_ruleset(_write(tmp_path, json.dumps(doc))), "schema")


def test_duplicate_rule_id_is_deny_all(tmp_path: Path) -> None:
    doc = _doc()
    doc["rules"].append(dict(doc["rules"][0]))
    _assert_deny_all(load_ruleset(_write(tmp_path, json.dumps(doc))), "duplicate rule id")


def test_top_level_not_an_object_is_deny_all(tmp_path: Path) -> None:
    _assert_deny_all(load_ruleset(_write(tmp_path, "[]")), "schema")


@pytest.mark.parametrize("roles", [["system_owner"], ["executive_risk_owner", "system_owner"]])
def test_require_approval_with_approver_roles_loads(tmp_path: Path, roles: list[str]) -> None:
    doc = _doc()
    doc["rules"][0].update(effect="require_approval", approver_roles=roles)
    ruleset = load_ruleset(_write(tmp_path, json.dumps(doc)))
    assert ruleset.deny_all is False, ruleset.deny_reason
    assert {r.value for r in ruleset.rules[0].approver_roles} == set(roles)


def test_default_ruleset_loads_and_is_versioned() -> None:
    ruleset = load_default_ruleset()
    assert DEFAULT_RULESET_PATH.name == "default.json"
    assert ruleset.deny_all is False, ruleset.deny_reason
    assert ruleset.version == "default-2026.11.17-3"
    assert len(ruleset.content_hash) == 64
    approvers = {r for rule in ruleset.rules for r in rule.approver_roles}
    assert approvers == {Role.SYSTEM_OWNER, Role.EXECUTIVE_RISK_OWNER}


def test_deny_all_factory() -> None:
    _assert_deny_all(RuleSet.deny_everything("operator said so"), "operator said so")


# --- structural requester gate ----------------------------------------------------


@pytest.mark.parametrize(
    "rule",
    [
        {"id": "x", "effect": "allow", "match": {}},
        {"id": "x", "effect": "allow", "match": {"authority_levels": [3]}},
        {"id": "x", "effect": "allow", "match": {"operations": ["ticket.*"]}},
        {"id": "x", "effect": "allow", "match": {"required_roles": ["security_admin"]}},
        {"id": "x", "effect": "allow", "match": {"authority_levels": [0, 1]}},
        {"id": "x", "effect": "allow", "match": {"authority_levels": [1], "writes": True}},
        {
            "id": "x",
            "effect": "allow",
            "match": {"authority_levels": [2], "actor_types": ["human"]},
        },
        {
            "id": "x",
            "effect": "allow",
            "match": {"authority_levels": [0], "actor_types": ["human"]},
        },
        {
            "id": "x",
            "effect": "allow",
            "match": {"authority_levels": [1, 2], "actor_types": ["agent", "human"]},
        },
        {
            "id": "x",
            "effect": "require_approval",
            "approver_roles": ["system_owner"],
            "match": {"authority_levels": [4]},
        },
    ],
)
def test_ungated_requester_rule_is_deny_all(tmp_path: Path, rule: dict[str, Any]) -> None:
    ruleset = load_ruleset(_write(tmp_path, json.dumps(_doc(rules=[rule]))))
    _assert_deny_all(ruleset, "must name actor_types")


@pytest.mark.parametrize(
    "rule",
    [
        {"id": "x", "effect": "allow", "match": {"authority_levels": [0, 1], "writes": False}},
        {"id": "x", "effect": "deny", "match": {}},
        {"id": "x", "effect": "hold", "match": {"authority_levels": [3]}},
        {
            "id": "x",
            "effect": "allow",
            "match": {"authority_levels": [3], "actor_types": ["agent", "service"]},
        },
        {
            "id": "x",
            "effect": "allow",
            "match": {"actor_types": ["human"], "required_roles": ["system_owner"]},
        },
        {
            "id": "x",
            "effect": "require_approval",
            "approver_roles": ["system_owner"],
            "match": {"authority_levels": [4], "actor_types": ["agent"]},
        },
    ],
)
def test_gated_requester_rule_loads(tmp_path: Path, rule: dict[str, Any]) -> None:
    ruleset = load_ruleset(_write(tmp_path, json.dumps(_doc(rules=[rule]))))
    assert ruleset.deny_all is False, ruleset.deny_reason


# --- segment-aware operation patterns ----------------------------------------------


def _facts(operation: str) -> MatchFacts:
    return MatchFacts(
        operation=operation,
        authority_level=AuthorityLevel.L0_OBSERVE,
        writes=False,
        protected=False,
        actor_type=ActorType.AGENT,
        covered_roles=frozenset(),
        environment=Environment.STAGING,
        risk_class="low",
        channel=None,
    )


@pytest.mark.parametrize(
    ("pattern", "operation", "expected"),
    [
        ("ticket.*", "ticket.create", True),
        ("ticket.*", "ticket.admin.purge", False),
        ("ticket*", "tickets_admin.purge", False),
        ("ticket.*", "tickets_admin.purge", False),
        ("ticket.create_*", "ticket.create_draft", True),
        ("ticket.create_*", "ticket.create.draft", False),
        ("*.read", "asset.read", True),
        ("*.read", "asset.inner.read", False),
        ("*.*.read", "asset.inner.read", True),
        ("asset.read", "asset.read", True),
        ("asset.read", "asset.reader", False),
    ],
)
def test_operation_pattern_star_stays_in_its_segment(
    pattern: str, operation: str, expected: bool
) -> None:
    assert RuleMatch(operations=(pattern,)).matches(_facts(operation)) is expected
