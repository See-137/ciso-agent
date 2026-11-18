"""An identifier with a trailing newline is not that identifier.

`$` in a regular expression also matches just before a final line feed, so a validator
written as `^...$` and used with `.match()` accepts `"draft.create\\n"`. Every policy
identifier validator must refuse it. Each test names the site it guards.
"""

from __future__ import annotations

from typing import Any

import pytest
from pydantic import ValidationError
from tests.policy.conftest import EnvelopeBuilder, NoArgs

from ciso.common.enums import AuthorityLevel, Environment
from ciso.common.ids import new_id
from ciso.policy import EnvelopeScope, OperationSpec, Rule, RuleEffect, RuleMatch
from ciso.policy.rules import RuleSetDocument

pytestmark = pytest.mark.policy


def _spec(name: str) -> OperationSpec:
    return OperationSpec(name=name, authority_level=AuthorityLevel.L0_OBSERVE, args_model=NoArgs)


def _scope(**over: Any) -> EnvelopeScope:
    fields: dict[str, Any] = {
        "resource": "app:billing",
        "tenant": "tenant_main",
        "environment": Environment.STAGING,
        "boundary": "internal",
        "classification": "internal",
    }
    fields.update(over)
    return EnvelopeScope(**fields)


def _document(**over: Any) -> RuleSetDocument:
    fields: dict[str, Any] = {
        "schema_version": 1,
        "version": "1.0",
        "risk_classes": ("low",),
        "rules": (),
    }
    fields.update(over)
    return RuleSetDocument(**fields)


# --- catalog.py: operation name -------------------------------------------------------


def test_operation_name_with_trailing_newline_is_refused() -> None:
    assert _spec("draft.create").name == "draft.create"
    with pytest.raises(ValidationError, match="bad operation name"):
        _spec("draft.create\n")


def test_operation_name_with_embedded_newline_is_refused() -> None:
    with pytest.raises(ValidationError, match="bad operation name"):
        _spec("draft\n.create")


# --- envelope.py: scope ---------------------------------------------------------------


def test_scope_classification_with_trailing_newline_is_refused() -> None:
    assert _scope().classification == "internal"
    with pytest.raises(ValidationError, match="bad classification label"):
        _scope(classification="internal\n")


@pytest.mark.parametrize("field", ["tenant", "boundary"])
def test_scope_tenant_and_boundary_with_trailing_newline_are_refused(field: str) -> None:
    assert getattr(_scope(**{field: "zone-1"}), field) == "zone-1"
    with pytest.raises(ValidationError, match="bad scope value"):
        _scope(**{field: "zone-1\n"})


def test_scope_resource_with_trailing_newline_is_refused() -> None:
    with pytest.raises(ValidationError, match="bad entity ref"):
        _scope(resource="app:billing\n")


# --- envelope.py: envelope ------------------------------------------------------------


@pytest.mark.parametrize("field", ["idempotency_key", "actor_id"])
def test_envelope_key_fields_with_trailing_newline_are_refused(
    build: EnvelopeBuilder, field: str
) -> None:
    assert getattr(build(**{field: "key-0002"}), field) == "key-0002"
    with pytest.raises(ValidationError, match="bad identifier"):
        build(**{field: "key-0002\n"})


def test_envelope_requesting_component_with_trailing_newline_is_refused(
    build: EnvelopeBuilder,
) -> None:
    assert build(requesting_component="planner").requesting_component == "planner"
    with pytest.raises(ValidationError, match="bad requesting_component"):
        build(requesting_component="planner\n")


def test_envelope_risk_class_with_trailing_newline_is_refused(build: EnvelopeBuilder) -> None:
    assert build(risk_class="medium").risk_class == "medium"
    with pytest.raises(ValidationError, match="bad risk_class"):
        build(risk_class="medium\n")


def test_envelope_request_id_with_trailing_newline_is_refused(build: EnvelopeBuilder) -> None:
    ident = new_id("req")
    assert build(request_id=ident).request_id == ident
    with pytest.raises(ValidationError, match="request_id must be an id"):
        build(request_id=ident + "\n")


def test_envelope_refs_with_trailing_newline_are_refused(build: EnvelopeBuilder) -> None:
    with pytest.raises(ValidationError, match="bad entity ref"):
        build(target_resource="app:billing\n")
    with pytest.raises(ValidationError, match="bad entity ref"):
        build(supporting_evidence=("finding:f1\n",))


def test_newline_changes_the_envelope_hash_so_it_must_not_validate(
    build: EnvelopeBuilder,
) -> None:
    """Positive evidence of the harm: were the value accepted, the same request would
    hash differently from its clean twin. The clean one builds; the other is refused."""
    ident = new_id("req")
    clean = build(request_id=ident, idempotency_key="idem-0009")
    assert len(clean.envelope_hash()) == 64
    with pytest.raises(ValidationError) as info:
        build(request_id=ident, idempotency_key="idem-0009\n")
    assert [error["loc"] for error in info.value.errors()] == [("idempotency_key",)]


# --- rules.py -------------------------------------------------------------------------


def test_rule_operation_pattern_with_trailing_newline_is_refused() -> None:
    assert RuleMatch(operations=("asset.*",)).operations == ("asset.*",)
    with pytest.raises(ValidationError, match="bad operation pattern"):
        RuleMatch(operations=("asset.*\n",))


def test_rule_id_with_trailing_newline_is_refused() -> None:
    match = RuleMatch(operations=("asset.read",))
    assert Rule(id="deny-1", effect=RuleEffect.DENY, match=match).id == "deny-1"
    with pytest.raises(ValidationError, match="bad rule id"):
        Rule(id="deny-1\n", effect=RuleEffect.DENY, match=match)


def test_ruleset_version_with_trailing_newline_is_refused() -> None:
    assert _document().version == "1.0"
    with pytest.raises(ValidationError, match="bad ruleset version"):
        _document(version="1.0\n")


def test_ruleset_risk_class_with_trailing_newline_is_refused() -> None:
    assert _document(risk_classes=("low", "high")).risk_classes == ("low", "high")
    with pytest.raises(ValidationError, match="bad risk class"):
        _document(risk_classes=("low", "high\n"))
