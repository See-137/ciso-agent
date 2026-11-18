"""The action envelope (blueprint 9.4) and its validation against the operation catalog.

The envelope carries only request fields. The result fields of 9.4 (policy_decision,
approver, execution_result, residual_risk) live on the decision and execution records, so
a requester cannot pre-fill its own approval: passing one is a schema error.

The envelope names its actor by id and claimed type only. It carries no roles or scopes:
the policy engine resolves the actor through the identity store at every evaluation and
decides on that answer, never on anything the requester wrote.
"""

from __future__ import annotations

import json
import re
from collections.abc import Mapping
from datetime import datetime, timedelta
from enum import Enum
from typing import Any

from pydantic import BaseModel, JsonValue, ValidationError, field_validator, model_validator

from ciso.common.clock import Clock, ensure_utc
from ciso.common.enums import ActorType, AuthorityLevel, Environment
from ciso.common.errors import ValidationFailed
from ciso.common.ids import EntityRef, is_id
from ciso.common.schemas import FrozenMap, Model, UtcDatetime, canonical_json, content_hash, thaw
from ciso.policy.catalog import OperationCatalog, OperationSpec
from ciso.policy.decision import ReasonCode

_KEY_RE = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")
_COMPONENT_RE = re.compile(r"^[a-z][a-z0-9_.-]{0,63}$")
_LABEL_RE = re.compile(r"^[a-z][a-z0-9_]{0,31}$")
_MAX_TEXT = 2000


def _ref(value: str) -> str:
    try:
        EntityRef.parse(value)
    except ValidationFailed as exc:
        raise ValueError(str(exc)) from exc
    return value


def _text(value: str, name: str) -> str:
    if not value.strip() or len(value) > _MAX_TEXT:
        raise ValueError(f"{name} must be non-blank and at most {_MAX_TEXT} characters")
    return value


class EnvelopeScope(Model):
    """Where the action lands. `resource` is the system the authority covers (an entity
    ref); the envelope's `target_resource` is the exact thing acted on. `classification`
    is the data label of the target, or None when unknown: a role grant narrowed by
    classification then does not apply."""

    resource: str
    tenant: str
    environment: Environment
    boundary: str
    classification: str | None = None

    @field_validator("classification")
    @classmethod
    def _classification(cls, value: str | None) -> str | None:
        if value is not None and not _LABEL_RE.fullmatch(value):
            raise ValueError(f"bad classification label: {value!r}")
        return value

    def attributes(self, target_resource: str) -> dict[str, str | None]:
        """The attribute values a role grant is matched against (`RoleGrant.covers`)."""
        return {
            "system": self.resource,
            "resource": target_resource,
            "tenant": self.tenant,
            "environment": self.environment.value,
            "boundary": self.boundary,
            "classification": self.classification,
        }

    @field_validator("resource")
    @classmethod
    def _resource(cls, value: str) -> str:
        return _ref(value)

    @field_validator("tenant", "boundary")
    @classmethod
    def _labels(cls, value: str) -> str:
        if not _KEY_RE.fullmatch(value):
            raise ValueError(f"bad scope value: {value!r}")
        return value


class Precondition(Model):
    """A condition that must still be true at execution (checked by ciso.execution)."""

    name: str
    ref: str
    expectation: str

    @field_validator("ref")
    @classmethod
    def _ref_ok(cls, value: str) -> str:
        return _ref(value)


class RollbackPlan(Model):
    description: str
    steps: tuple[str, ...] = ()


class VerificationPlan(Model):
    method: str
    description: str


class ActionEnvelope(Model):
    """A proposed action, exactly as the requester states it. Blueprint 9.4."""

    request_id: str
    idempotency_key: str
    requesting_component: str
    actor_id: str
    actor_type: ActorType
    target_resource: str
    scope: EnvelopeScope
    operation: str
    arguments: FrozenMap[str, JsonValue]
    purpose: str
    supporting_evidence: tuple[str, ...]
    risk_class: str
    authority_level: AuthorityLevel
    preconditions: tuple[Precondition, ...]
    expiry: UtcDatetime
    rollback_plan: RollbackPlan | None = None
    verification_plan: VerificationPlan | None = None

    @field_validator("request_id")
    @classmethod
    def _request_id(cls, value: str) -> str:
        if not is_id(value, "req"):
            raise ValueError("request_id must be an id with prefix 'req'")
        return value

    @field_validator("idempotency_key", "actor_id")
    @classmethod
    def _key(cls, value: str) -> str:
        if not _KEY_RE.fullmatch(value):
            raise ValueError("bad identifier")
        return value

    @field_validator("actor_type")
    @classmethod
    def _actor_type(cls, value: ActorType) -> ActorType:
        if value is ActorType.ANONYMOUS:
            raise ValueError("an anonymous actor cannot request an action")
        return value

    @model_validator(mode="after")
    def _encodable(self) -> ActionEnvelope:
        """Every string must encode as UTF-8, or the canonical hash cannot be computed."""
        try:
            self._canonical().encode("utf-8")
        except UnicodeEncodeError as exc:
            raise ValueError("envelope contains text that is not valid UTF-8") from exc
        return self

    @field_validator("requesting_component")
    @classmethod
    def _component(cls, value: str) -> str:
        if not _COMPONENT_RE.fullmatch(value):
            raise ValueError("bad requesting_component")
        return value

    @field_validator("target_resource")
    @classmethod
    def _target(cls, value: str) -> str:
        return _ref(value)

    @field_validator("supporting_evidence")
    @classmethod
    def _evidence(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        return tuple(_ref(item) for item in value)

    @field_validator("purpose")
    @classmethod
    def _purpose(cls, value: str) -> str:
        return _text(value, "purpose")

    @field_validator("risk_class")
    @classmethod
    def _risk(cls, value: str) -> str:
        if not _LABEL_RE.fullmatch(value):
            raise ValueError("bad risk_class")
        return value

    def _canonical(self) -> str:
        return canonical_json(_normalise(self.model_dump(mode="python")))

    def envelope_hash(self) -> str:
        """Canonical SHA-256 of every request field. Approvals bind to this value.

        Stable under key order. Covers `actor_id` and `actor_type`; roles are not in the
        envelope, so they are not in the hash.
        """
        return content_hash(_normalise(self.model_dump(mode="python")))


def _normalise(value: Any) -> Any:
    """Turn a dumped model into plain JSON data with a deterministic order for sets."""
    if isinstance(value, BaseModel):
        return _normalise(value.model_dump(mode="python"))
    if isinstance(value, Mapping):
        return {str(key): _normalise(item) for key, item in value.items()}
    if isinstance(value, set | frozenset):
        return sorted((_normalise(item) for item in value), key=canonical_json)
    if isinstance(value, list | tuple):
        return [_normalise(item) for item in value]
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, datetime):
        return ensure_utc(value).isoformat()
    return value


class EnvelopeRejected(ValidationFailed):
    """The envelope is invalid for its operation. `code` says which check failed."""

    def __init__(self, code: ReasonCode, detail: str) -> None:
        super().__init__(detail)
        self.code = code
        self.detail = detail


class CheckedEnvelope(Model):
    """An envelope that passed validation, with what the catalog says about it."""

    envelope: ActionEnvelope
    spec: OperationSpec
    arguments: Model
    authority_level: AuthorityLevel
    channel: str | None


class EnvelopeValidator:
    """Checks an envelope against the catalog, the clock and the expiry cap.

    `max_envelope_ttl` caps how far in the future an expiry may be. `None` means the
    knob is unset, so every envelope for a writing operation is refused (G14, ADR-0019).
    `risk_classes` are the labels the loaded ruleset declares.
    """

    def __init__(
        self,
        catalog: OperationCatalog,
        clock: Clock,
        max_envelope_ttl: timedelta | None = None,
        *,
        risk_classes: tuple[str, ...],
    ) -> None:
        if max_envelope_ttl is not None and max_envelope_ttl <= timedelta(0):
            raise ValueError("max_envelope_ttl must be positive")
        self._catalog = catalog
        self._clock = clock
        self._ttl = max_envelope_ttl
        self._risk_classes = frozenset(risk_classes)

    def lookup(self, envelope: ActionEnvelope) -> OperationSpec:
        spec = self._catalog.get(envelope.operation)
        if spec is None:
            raise EnvelopeRejected(
                ReasonCode.UNKNOWN_OPERATION, f"operation {envelope.operation!r} is not registered"
            )
        return spec

    def validate(self, envelope: ActionEnvelope) -> CheckedEnvelope:
        """Return the checked envelope or raise EnvelopeRejected with a reason code."""
        spec = self.lookup(envelope)
        if envelope.risk_class not in self._risk_classes:
            raise EnvelopeRejected(
                ReasonCode.UNKNOWN_RISK_CLASS, f"risk class {envelope.risk_class!r} is not defined"
            )
        if envelope.authority_level < spec.authority_level:
            raise EnvelopeRejected(
                ReasonCode.AUTHORITY_UNDERSTATED,
                f"{spec.name} needs level {spec.authority_level.value}, "
                f"envelope claims {envelope.authority_level.value}",
            )
        arguments = self._arguments(spec, envelope)
        self._check_expiry(spec, envelope)
        self._check_support(spec, envelope)
        channel = None
        if spec.channel_argument is not None:
            channel = str(getattr(arguments, spec.channel_argument))
        return CheckedEnvelope(
            envelope=envelope,
            spec=spec,
            arguments=arguments,
            authority_level=max(envelope.authority_level, spec.authority_level),
            channel=channel,
        )

    @staticmethod
    def _arguments(spec: OperationSpec, envelope: ActionEnvelope) -> Model:
        try:
            return spec.args_model.model_validate_json(
                json.dumps(thaw(envelope.arguments)), strict=True
            )
        except ValidationError as exc:
            fields = sorted({".".join(map(str, err["loc"])) for err in exc.errors()})
            raise EnvelopeRejected(
                ReasonCode.INVALID_ARGUMENTS, f"arguments fail the schema at: {fields}"
            ) from exc

    def _check_expiry(self, spec: OperationSpec, envelope: ActionEnvelope) -> None:
        now = self._clock.now()
        if envelope.expiry <= now:
            raise EnvelopeRejected(ReasonCode.ENVELOPE_EXPIRED, "envelope has expired")
        if self._ttl is None:
            if spec.writes:
                raise EnvelopeRejected(
                    ReasonCode.ENVELOPE_TTL_UNSET,
                    "max_envelope_ttl is not configured; writes are refused",
                )
            return
        if envelope.expiry - now > self._ttl:
            raise EnvelopeRejected(
                ReasonCode.ENVELOPE_TTL_EXCEEDED, "envelope expiry is beyond the allowed window"
            )

    @staticmethod
    def _check_support(spec: OperationSpec, envelope: ActionEnvelope) -> None:
        if spec.writes and not envelope.supporting_evidence:
            raise EnvelopeRejected(
                ReasonCode.EVIDENCE_REQUIRED, "a writing operation needs supporting evidence"
            )
        if spec.authority_level >= AuthorityLevel.L3_EXECUTE and (
            envelope.rollback_plan is None or envelope.verification_plan is None
        ):
            raise EnvelopeRejected(
                ReasonCode.PLAN_REQUIRED, "L3 and above need rollback and verification plans"
            )
