"""Declarative policy rules: versioned JSON data, closed schema (ADR-0009).

A rule matches when every condition it states holds; a condition left out matches
anything. When several rules match, the strictest effect wins:
deny > hold > require_approval > allow; for require_approval the approver roles are the
intersection over the matching rules. No rule can override the engine's built-in
invariants (see `ciso.policy.engine`).

`required_roles` is satisfied only by a role the resolved principal holds through a
grant that reaches the target (`Principal.covering_roles`), never by holding it alone.
Operation patterns are matched segment by segment: `*` never crosses a dot.
"""

from __future__ import annotations

import re
from enum import StrEnum
from fnmatch import fnmatchcase
from typing import Annotated, Any, Literal

from pydantic import BeforeValidator, field_validator, model_validator

from ciso.common.enums import APPROVER_ROLES, ActorType, AuthorityLevel, Environment, Role
from ciso.common.schemas import Model

_RULE_ID_RE = re.compile(r"^[a-z0-9][a-z0-9_.-]{0,63}$")
_PATTERN_RE = re.compile(r"^[a-z0-9_*]+(\.[a-z0-9_*]+)*$")
_LABEL_RE = re.compile(r"^[a-z][a-z0-9_]{0,31}$")


def _integer_only(value: Any) -> Any:
    """Refuse `true` and `4.0` where an integer is meant: one meaning, one spelling."""
    if isinstance(value, bool | float):
        raise ValueError("expected an integer, not a boolean or a float")
    return value


Level = Annotated[AuthorityLevel, BeforeValidator(_integer_only)]


def pattern_matches(pattern: str, operation: str) -> bool:
    """Segment-aware match: same number of dot segments, `*` stays inside its segment."""
    wanted = pattern.split(".")
    actual = operation.split(".")
    return len(wanted) == len(actual) and all(
        fnmatchcase(seg, pat) for pat, seg in zip(wanted, actual, strict=True)
    )


class RuleEffect(StrEnum):
    ALLOW = "allow"
    DENY = "deny"
    HOLD = "hold"
    REQUIRE_APPROVAL = "require_approval"


#: Higher wins when several rules match.
EFFECT_STRENGTH: dict[RuleEffect, int] = {
    RuleEffect.ALLOW: 0,
    RuleEffect.REQUIRE_APPROVAL: 1,
    RuleEffect.HOLD: 2,
    RuleEffect.DENY: 3,
}


class MatchFacts(Model):
    """What a rule can be matched against, taken from a validated envelope."""

    operation: str
    authority_level: AuthorityLevel
    writes: bool
    protected: bool
    actor_type: ActorType
    covered_roles: frozenset[Role]
    environment: Environment
    risk_class: str
    channel: str | None


class RuleMatch(Model):
    """Conditions. `required_roles` matches when at least one listed role is held through
    a grant that reaches the target. `channels` matches only operations that send to one
    of the listed channels."""

    operations: tuple[str, ...] | None = None
    authority_levels: tuple[Level, ...] | None = None
    writes: bool | None = None
    protected: bool | None = None
    actor_types: tuple[ActorType, ...] | None = None
    required_roles: tuple[Role, ...] | None = None
    environments: tuple[Environment, ...] | None = None
    risk_classes: tuple[str, ...] | None = None
    channels: tuple[str, ...] | None = None

    @field_validator("operations")
    @classmethod
    def _patterns(cls, value: tuple[str, ...] | None) -> tuple[str, ...] | None:
        for pattern in value or ():
            if len(pattern) > 128 or not _PATTERN_RE.fullmatch(pattern):
                raise ValueError(f"bad operation pattern: {pattern!r}")
        return value

    @model_validator(mode="after")
    def _non_empty(self) -> RuleMatch:
        for name in type(self).model_fields:
            value = getattr(self, name)
            if isinstance(value, tuple) and not value:
                raise ValueError(f"condition {name!r} is an empty list; omit it instead")
        return self

    def matches(self, facts: MatchFacts) -> bool:
        checks = (
            self.operations is None
            or any(pattern_matches(p, facts.operation) for p in self.operations),
            self.authority_levels is None or facts.authority_level in self.authority_levels,
            self.writes is None or facts.writes is self.writes,
            self.protected is None or facts.protected is self.protected,
            self.actor_types is None or facts.actor_type in self.actor_types,
            self.required_roles is None or bool(facts.covered_roles & set(self.required_roles)),
            self.environments is None or facts.environment in self.environments,
            self.risk_classes is None or facts.risk_class in self.risk_classes,
            self.channels is None or facts.channel in self.channels,
        )
        return all(checks)


class Rule(Model):
    id: str
    description: str = ""
    effect: RuleEffect
    match: RuleMatch
    approver_roles: tuple[Role, ...] = ()

    @field_validator("id")
    @classmethod
    def _id(cls, value: str) -> str:
        if not _RULE_ID_RE.fullmatch(value):
            raise ValueError(f"bad rule id: {value!r}")
        return value

    @model_validator(mode="after")
    def _approvers(self) -> Rule:
        if self.effect is RuleEffect.REQUIRE_APPROVAL:
            if not self.approver_roles:
                raise ValueError(f"rule {self.id!r}: require_approval must name approver_roles")
            outside = set(self.approver_roles) - APPROVER_ROLES
            if outside:
                names = ", ".join(sorted(r.value for r in outside))
                raise ValueError(f"rule {self.id!r}: roles cannot approve: {names}")
        elif self.approver_roles:
            raise ValueError(f"rule {self.id!r}: approver_roles only fit require_approval")
        return self

    @model_validator(mode="after")
    def _requester_gated(self) -> Rule:
        """An allow or require_approval rule that can match a write, or anything at L2 or
        above, must say who may request: it names `actor_types`, and when humans are
        included, `required_roles`. Only a read-only rule (`writes: false`) limited to
        L0-L1 is exempt. Otherwise any actor, an employee included, would pass."""
        if self.effect not in (RuleEffect.ALLOW, RuleEffect.REQUIRE_APPROVAL):
            return self
        levels = self.match.authority_levels
        low_only = levels is not None and max(levels) < AuthorityLevel.L2_COORDINATE
        if low_only and self.match.writes is False:
            return self
        types = self.match.actor_types
        if types is None or (ActorType.HUMAN in types and self.match.required_roles is None):
            raise ValueError(
                f"rule {self.id!r}: {self.effect.value} at L2 or above must name actor_types, "
                "and required_roles when humans are included"
            )
        return self


class RuleSetDocument(Model):
    """The on-disk format. `schema_version` is the format; `version` is the content."""

    schema_version: Annotated[Literal[1], BeforeValidator(_integer_only)]
    version: str
    risk_classes: tuple[str, ...]
    rules: tuple[Rule, ...]

    @field_validator("version")
    @classmethod
    def _version(cls, value: str) -> str:
        if not re.fullmatch(r"^[A-Za-z0-9._-]{1,64}$", value):
            raise ValueError("bad ruleset version")
        return value

    @field_validator("risk_classes")
    @classmethod
    def _risk_classes(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if not value or len(set(value)) != len(value):
            raise ValueError("risk_classes must be a non-empty list of unique labels")
        for label in value:
            if not _LABEL_RE.fullmatch(label):
                raise ValueError(f"bad risk class: {label!r}")
        return value

    @model_validator(mode="after")
    def _cross_checks(self) -> RuleSetDocument:
        seen: set[str] = set()
        for rule in self.rules:
            if rule.id in seen:
                raise ValueError(f"duplicate rule id: {rule.id!r}")
            seen.add(rule.id)
            unknown = set(rule.match.risk_classes or ()) - set(self.risk_classes)
            if unknown:
                raise ValueError(f"rule {rule.id!r} names undefined risk classes")
        return self


class RuleSet(Model):
    """A loaded ruleset. When `deny_all` is true, `deny_reason` says why and the engine
    denies every request."""

    version: str
    content_hash: str
    risk_classes: tuple[str, ...]
    rules: tuple[Rule, ...]
    deny_all: bool = False
    deny_reason: str = ""

    @classmethod
    def from_document(cls, document: RuleSetDocument, content_hash: str) -> RuleSet:
        return cls(
            version=document.version,
            content_hash=content_hash,
            risk_classes=document.risk_classes,
            rules=document.rules,
        )

    @classmethod
    def deny_everything(cls, reason: str) -> RuleSet:
        return cls(
            version="deny-all",
            content_hash="",
            risk_classes=(),
            rules=(),
            deny_all=True,
            deny_reason=reason or "ruleset unavailable",
        )
