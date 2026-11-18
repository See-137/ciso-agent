"""Step 1 of the external model path: the proposal (blueprint 8.4, FR-018).

A proposal names why an external model may be useful, the candidate provider and model,
and the context offered for sending. Nothing here sends anything, and nothing here is
reachable from normal inference routing (gap G1).

Item text is the sensitive part. It is kept out of `repr()`, and no error raised by this
package quotes it.
"""

from __future__ import annotations

import re
from enum import StrEnum
from typing import Any

from pydantic import Field, field_validator

from ciso.common.classification import UNKNOWN_LABEL, ClassificationScheme
from ciso.common.enums import ActorType
from ciso.common.errors import ExternalInferenceBlocked, ValidationFailed
from ciso.common.ids import EntityRef, is_id
from ciso.common.schemas import Model, UtcDatetime, canonical_json, sha256_hex

#: Prefix of an external request id (`new_id(REQUEST_ID_PREFIX)`).
REQUEST_ID_PREFIX = "xrq"
#: `EntityRef` kind used as the audit target of an external request.
REQUEST_REF_KIND = "external_request"

# Provider, model and source are opaque identifiers supplied by configuration or the
# caller. The shape is narrow so that none of them can carry free text.
_OPAQUE_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:/@+-]{0,127}")
#: Actor ids and correlation ids: identifiers only, so neither can carry control
#: characters, padding or a look-alike of another id into a record (review finding M5).
_ACTOR_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:@-]{0,127}")
_LABEL_RE = re.compile(r"[a-z][a-z0-9_]{0,31}")
_MAX_PURPOSE_CHARS = 1000
# Structural caps (review finding M6). The byte limits on the whole payload and on the
# answer are safety settings of the gateway and have no default.
#: Most context items one proposal may offer.
MAX_ITEMS = 200
#: Most characters in one context item.
MAX_ITEM_TEXT_CHARS = 100_000
#: Most refs listed in one audit event; beyond it the count and a digest stand in.
MAX_AUDIT_REFS = 20


class ExternalReason(StrEnum):
    """Stable reason codes. Values are a wire format: do not rename."""

    #: The feature flag is off (the default). Nothing is built.
    FEATURE_DISABLED = "feature_disabled"
    #: The actor id does not resolve to a known, enabled actor right now.
    REQUESTER_UNKNOWN = "requester_unknown"
    #: The actor is an agent or a service. The path is never automatic (blueprint 8.4).
    REQUESTER_NOT_HUMAN = "requester_not_human"
    #: No classification scheme is configured (ADR-0017), so nothing can be judged.
    NO_SCHEME = "no_classification_scheme"
    #: The allowed classifications are unset (gap G26), so nothing may be sent.
    NO_ALLOWED_CLASSIFICATIONS = "no_allowed_classifications"
    #: The item has no label or a label nobody configured (blueprint 11.1).
    CLASSIFICATION_UNKNOWN = "classification_unknown"
    #: The item's label is not in the allowed set.
    CLASSIFICATION_NOT_ALLOWED = "classification_not_allowed"
    #: Every offered item was dropped.
    NOTHING_SENDABLE = "nothing_sendable"
    #: What was presented is not a well-formed proposal.
    PROPOSAL_INVALID = "proposal_invalid"
    #: No proposal with this request id was ever recorded by `propose`.
    PROPOSAL_UNKNOWN = "proposal_unknown"
    #: The proposal differs from the one recorded under its request id.
    PROPOSAL_MISMATCH = "proposal_mismatch"


class ExternalRequestRefused(ExternalInferenceBlocked):
    """A refusal on the external path, with the reason code tests and callers match on."""

    def __init__(self, reason: ExternalReason) -> None:
        super().__init__(f"external inference refused: {reason.value}")
        self.reason = reason


def classify(scheme: ClassificationScheme | None, label: str | None) -> str:
    """The label to act on. Missing, unrecognised, or no scheme at all: `unknown`.

    Blueprint 11.1: "If classification is unknown, treat as sensitive until classified."
    An unrecognised label is never echoed back, because it is caller-supplied text.
    """
    if scheme is None or label is None or label not in scheme.labels:
        return UNKNOWN_LABEL
    return label


def _encodable(value: str) -> str:
    """Text that cannot be written as UTF-8 cannot be hashed or sent."""
    try:
        value.encode("utf-8")
    except UnicodeEncodeError:
        raise ValueError("text is not valid UTF-8") from None
    return value


def _opaque(value: str) -> str:
    if not _OPAQUE_RE.fullmatch(value):
        raise ValueError("expected a short identifier without spaces")
    return value


def entity_ref_text(value: str) -> str:
    """A string that parses as an `EntityRef`. The error never quotes the value."""
    try:
        EntityRef.parse(value)
    except ValueError:
        raise ValueError("bad entity ref") from None
    return value


def label_text(value: str) -> str:
    """A string shaped like a classification label (or `unknown`)."""
    if not _LABEL_RE.fullmatch(value):
        raise ValueError("bad classification label")
    return value


def clean_actor(value: object) -> str:
    """The actor id a caller named, refused unless it is exactly an identifier."""
    if not isinstance(value, str) or not _ACTOR_RE.fullmatch(value):
        raise ValidationFailed("actor id must be a short identifier")
    return value


def clean_correlation(value: object) -> str:
    """Empty, or an identifier. Never cut to fit."""
    if isinstance(value, str) and value == "":
        return ""
    if not isinstance(value, str) or not _ACTOR_RE.fullmatch(value):
        raise ValidationFailed("correlation id must be a short identifier")
    return value


def capped_refs(name: str, rows: list[dict[str, Any]]) -> dict[str, Any]:
    """Audit form of a list of refs: at most `MAX_AUDIT_REFS` entries under `name`, with
    the full length and a digest of the full list beside them, so one event stays small
    whatever was offered (review finding M6)."""
    return {
        name: rows[:MAX_AUDIT_REFS],
        f"{name}_count": len(rows),
        f"{name}_sha256": sha256_hex(canonical_json(rows)),
    }


def request_target(candidate: object) -> str:
    """The audit target for whatever was presented as a proposal: its request ref when
    the id has the shape of one, otherwise empty. Never free text."""
    ident = getattr(candidate, "request_id", None)
    if isinstance(ident, str) and is_id(ident, REQUEST_ID_PREFIX):
        return f"{REQUEST_REF_KIND}:{ident}"
    return ""


class ContextItem(Model):
    """One piece of context offered for sending.

    `classification` is the label as the source gave it; `None` means unlabelled. The
    proposal service stores the normalised label (see `classify`).
    """

    ref: str
    text: str = Field(repr=False)
    classification: str | None = None
    source: str

    @field_validator("ref")
    @classmethod
    def _ref(cls, value: str) -> str:
        return entity_ref_text(value)

    @field_validator("classification")
    @classmethod
    def _label(cls, value: str | None) -> str | None:
        # Length only: a label nobody configured is accepted here and becomes `unknown`
        # in `classify`. The cap keeps a "label" from being a paragraph.
        if value is not None and len(value) > 64:
            raise ValueError("classification label too long")
        return value

    @field_validator("source")
    @classmethod
    def _source(cls, value: str) -> str:
        return _opaque(value)

    @field_validator("text")
    @classmethod
    def _text(cls, value: str) -> str:
        if len(value) > MAX_ITEM_TEXT_CHARS:
            raise ValueError("context item text is too long")
        return _encodable(value)


class ExternalRequestProposal(Model):
    """Blueprint 8.4 step 1. Built by `ExternalProposalService.propose`, never by the agent."""

    request_id: str
    requester_actor_id: str
    requester_actor_type: ActorType
    purpose: str = Field(max_length=_MAX_PURPOSE_CHARS)
    provider_name: str
    model_name: str
    items: tuple[ContextItem, ...] = Field(min_length=1, max_length=MAX_ITEMS)
    created_at: UtcDatetime

    @field_validator("request_id")
    @classmethod
    def _request_id(cls, value: str) -> str:
        if not is_id(value, REQUEST_ID_PREFIX):
            raise ValueError("bad external request id")
        return value

    @field_validator("requester_actor_id")
    @classmethod
    def _requester(cls, value: str) -> str:
        if not _ACTOR_RE.fullmatch(value):
            raise ValueError("requester must be an actor id")
        return value

    @field_validator("purpose")
    @classmethod
    def _purpose(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("purpose must not be blank")
        return _encodable(value)

    @field_validator("provider_name", "model_name")
    @classmethod
    def _names(cls, value: str) -> str:
        return _opaque(value)

    @field_validator("items")
    @classmethod
    def _unique_refs(cls, items: tuple[ContextItem, ...]) -> tuple[ContextItem, ...]:
        refs = [item.ref for item in items]
        if len(set(refs)) != len(refs):
            raise ValueError("each context item needs its own ref")
        return items
