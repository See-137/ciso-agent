"""Declarative governance rules: versioned JSON data with a closed schema.

A rule matches when none of its conditions is false. A condition whose fact is unknown
(a target attribute nobody reported, an inspection that did not run) counts as a match
for a restrictive rule (`deny`, `ask`) and as a miss for a permissive one (`allow`): an
unknown fact can make the answer stricter, never looser. Restrictive rules also compare
patterns without case; allow rules compare them exactly.

When several rules match, the strictest effect wins: deny > ask > allow. With no match,
the ruleset's declared default applies; it may be `allow` only for the kinds the file
declares read-only, and only kinds from `PURE_READ_KINDS` may be declared read-only.
An `allow` rule must name `kinds`; if any of them is not read-only it must also name
`attribution_states`, without `unknown` or `disputed`.
"""

from __future__ import annotations

import re
from enum import StrEnum
from typing import Annotated, Literal

from pydantic import BeforeValidator, Field, field_validator, model_validator

from ciso.common.activity import ActionKind, ActivitySource, AgentClass, Phase, Severity
from ciso.common.enums import InformationState, Role
from ciso.common.schemas import Model
from ciso.governance.classes import CommandClass
from ciso.governance.commands import ClassifierConfig
from ciso.governance.globs import SEPARATORS, check_pattern

#: Kinds that never change anything. A ruleset may declare only these read-only.
PURE_READ_KINDS: frozenset[ActionKind] = frozenset(
    {
        ActionKind.PROMPT,
        ActionKind.FILE_READ,
        ActionKind.SESSION_START,
        ActionKind.SESSION_END,
        # The agent finished a turn: reported after the fact, changes nothing (queue Q6).
        ActionKind.TURN_END,
    }
)
#: Most rules in one ruleset; most patterns per target attribute.
MAX_RULES = 256
MAX_TARGET_PATTERNS = 64

_RULE_ID_RE = re.compile(r"[a-z0-9][a-z0-9_.-]{0,63}")
_CODE_RE = re.compile(r"[a-z][a-z0-9_]{0,63}")
_LABEL_RE = re.compile(r"[a-z][a-z0-9_]{0,31}")
_TRUSTED_STATES = frozenset({InformationState.VERIFIED, InformationState.DECLARED})


def _strict_bool(value: object) -> object:
    if not isinstance(value, bool):
        raise ValueError("expected true or false")
    return value


StrictBool = Annotated[bool, BeforeValidator(_strict_bool)]


def _integer_only(value: object) -> object:
    """Refuse `true` and `1.0` where the integer 1 is meant."""
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError("expected an integer")
    return value


class Effect(StrEnum):
    ALLOW = "allow"
    ASK = "ask"
    DENY = "deny"


#: Higher wins when several rules match.
STRENGTH: dict[Effect, int] = {Effect.ALLOW: 0, Effect.ASK: 1, Effect.DENY: 2}


def _non_empty(model: Model) -> None:
    for name in type(model).model_fields:
        value = getattr(model, name)
        if isinstance(value, tuple) and not value:
            raise ValueError(f"condition {name!r} is an empty list; omit it instead")


class TargetMatch(Model):
    """Glob patterns per target attribute. Within one attribute any pattern may match;
    all attributes named must match."""

    repository: tuple[str, ...] | None = None
    branch: tuple[str, ...] | None = None
    path: tuple[str, ...] | None = None
    host: tuple[str, ...] | None = None
    server: tuple[str, ...] | None = None
    remote: tuple[str, ...] | None = None

    @model_validator(mode="after")
    def _patterns(self) -> TargetMatch:
        _non_empty(self)
        named = 0
        for key, separator in SEPARATORS.items():
            patterns = getattr(self, key)
            if patterns is None:
                continue
            named += 1
            if len(patterns) > MAX_TARGET_PATTERNS:
                raise ValueError(f"too many patterns for {key!r}")
            for pattern in patterns:
                check_pattern(pattern, separator)
        if not named:
            raise ValueError("targets must name at least one attribute")
        return self

    def items(self) -> list[tuple[str, tuple[str, ...]]]:
        return [(k, getattr(self, k)) for k in SEPARATORS if getattr(self, k) is not None]


class InspectionMatch(Model):
    """Matches when a finding has one of `categories` (if given) at `min_severity` or
    worse (if given), and the inspection's completeness equals `complete` (if given)."""

    min_severity: Severity | None = None
    categories: tuple[str, ...] | None = None
    complete: StrictBool | None = None

    @model_validator(mode="after")
    def _check(self) -> InspectionMatch:
        _non_empty(self)
        for label in self.categories or ():
            if not _LABEL_RE.fullmatch(label):
                raise ValueError(f"bad finding category: {label!r}")
        if self.min_severity is None and self.categories is None and self.complete is None:
            raise ValueError("an inspection condition must say something")
        return self


class RuleMatch(Model):
    kinds: tuple[ActionKind, ...] | None = None
    phases: tuple[Phase, ...] | None = None
    sources: tuple[ActivitySource, ...] | None = None
    agent_classes: tuple[AgentClass, ...] | None = None
    attribution_states: tuple[InformationState, ...] | None = None
    attribution_reasons: tuple[str, ...] | None = None
    person_known: StrictBool | None = None
    person_roles: tuple[Role, ...] | None = None
    command_classes: tuple[CommandClass, ...] | None = None
    targets: TargetMatch | None = None
    inspection: InspectionMatch | None = None

    @model_validator(mode="after")
    def _check(self) -> RuleMatch:
        _non_empty(self)
        for code in self.attribution_reasons or ():
            if not _CODE_RE.fullmatch(code):
                raise ValueError(f"bad attribution reason code: {code!r}")
        return self


class Rule(Model):
    id: str
    description: Annotated[str, Field(min_length=1, max_length=1000)]
    effect: Effect
    match: RuleMatch
    #: The rule needs a complete inspection of the action's content to be judged.
    requires_inspection: StrictBool = False

    @field_validator("id")
    @classmethod
    def _id(cls, value: str) -> str:
        if not _RULE_ID_RE.fullmatch(value):
            raise ValueError(f"bad rule id: {value!r}")
        return value


class Defaults(Model):
    read_only: Effect
    other: Effect

    @field_validator("other")
    @classmethod
    def _not_allow(cls, value: Effect) -> Effect:
        if value is Effect.ALLOW:
            raise ValueError("the default for actions that are not read-only cannot be allow")
        return value


class RuleSetDocument(Model):
    """The on-disk format. `schema_version` is the format; `version` is the content."""

    schema_version: Annotated[Literal[1], BeforeValidator(_integer_only)]
    version: Annotated[str, Field(pattern=r"^[A-Za-z0-9._-]{1,64}$")]
    description: Annotated[str, Field(min_length=1, max_length=2000)]
    provisional: StrictBool
    read_only_kinds: tuple[ActionKind, ...]
    defaults: Defaults
    #: What happens when a matched rule needs an inspection that is missing or incomplete.
    missing_inspection: Literal["deny", "ask"] = "deny"
    protected_branches: Annotated[tuple[str, ...], Field(min_length=1, max_length=128)]
    credential_paths: Annotated[tuple[str, ...], Field(max_length=128)] = ()
    agent_config_paths: Annotated[tuple[str, ...], Field(max_length=128)] = ()
    rules: Annotated[tuple[Rule, ...], Field(max_length=MAX_RULES)]

    @model_validator(mode="after")
    def _cross_checks(self) -> RuleSetDocument:
        outside = set(self.read_only_kinds) - PURE_READ_KINDS
        if outside:
            raise ValueError(f"kinds cannot be declared read-only: {sorted(outside)}")
        seen: set[str] = set()
        for rule in self.rules:
            if rule.id in seen:
                raise ValueError(f"duplicate rule id: {rule.id!r}")
            seen.add(rule.id)
            if rule.effect is Effect.ALLOW:
                self._gated(rule)
        self.classifier_config()  # validates the pattern lists
        return self

    def _gated(self, rule: Rule) -> None:
        kinds = rule.match.kinds
        if kinds is None:
            raise ValueError(f"rule {rule.id!r}: an allow rule must name kinds")
        if set(kinds) <= set(self.read_only_kinds):
            return
        states = rule.match.attribution_states
        if states is None or not set(states) <= _TRUSTED_STATES:
            raise ValueError(
                f"rule {rule.id!r}: an allow rule for actions that are not read-only must "
                "name attribution_states, and only verified or declared"
            )

    def classifier_config(self) -> ClassifierConfig:
        return ClassifierConfig(
            protected_branches=self.protected_branches,
            credential_paths=self.credential_paths,
            agent_config_paths=self.agent_config_paths,
        )


class GovernanceRuleSet(Model):
    """A loaded ruleset. When `deny_all` is true the engine denies every action and
    `deny_reason` says why (for operators, never shown to engineers)."""

    version: str
    content_hash: Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
    document: RuleSetDocument | None
    deny_all: bool = False
    deny_reason: str = ""

    @model_validator(mode="after")
    def _consistent(self) -> GovernanceRuleSet:
        if (self.document is None) is not self.deny_all:
            raise ValueError("a ruleset has a document exactly when it is not deny-all")
        return self
