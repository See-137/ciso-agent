"""Steps 2 and 3 of the external model path: minimize and preview (blueprint 8.4, 11.1).

`minimize` drops every item whose classification may not leave, redacts secrets from the
rest, and records what it dropped and why. `build_preview` turns the result into the exact
bytes that would later be transmitted, and their hash. `approval_binding` gives the five
values an approval must cover (gap G2).

Nothing in this module sends anything.
"""

from __future__ import annotations

import hmac
import json
from typing import Any

from pydantic import Field, field_validator, model_validator

from ciso.common.classification import UNKNOWN_LABEL, ClassificationScheme
from ciso.common.errors import ValidationFailed
from ciso.common.ids import is_id
from ciso.common.protocols import Redactor
from ciso.common.schemas import Model, canonical_json, sha256_hex
from ciso.inference.external.proposal import (
    REQUEST_ID_PREFIX,
    ExternalReason,
    ExternalRequestProposal,
    ExternalRequestRefused,
    classify,
    entity_ref_text,
    label_text,
)

#: Version of the transmitted layout. Part of the bytes, so a layout change changes the hash.
PAYLOAD_SCHEMA_VERSION = 1


_PAYLOAD_KEYS = frozenset({"schema", "request_id", "provider", "model", "purpose", "items"})
_ITEM_KEYS = frozenset({"ref", "classification", "text"})


class ItemLabel(Model):
    """An item that was kept: its ref and label, no text. Both are shape-checked, so
    neither can carry free text into a database row or an audit event."""

    ref: str
    classification: str

    @field_validator("ref")
    @classmethod
    def _ref(cls, value: str) -> str:
        return entity_ref_text(value)

    @field_validator("classification")
    @classmethod
    def _label(cls, value: str) -> str:
        return label_text(value)


class DroppedItem(ItemLabel):
    """An item that was not kept, and why. No text."""

    reason: ExternalReason


class KeptItem(ItemLabel):
    """An item that survived minimization. `text` is already redacted."""

    source: str
    text: str = Field(repr=False)


class MinimizedPayload(Model):
    """Result of step 3. Everything offered is in exactly one of `kept` and `dropped`."""

    request_id: str
    provider_name: str
    model_name: str
    #: The purpose after secret redaction. This is the purpose an approval binds to.
    purpose: str
    kept: tuple[KeptItem, ...]
    dropped: tuple[DroppedItem, ...]
    #: Most sensitive label among the kept items; `unknown` when nothing was kept.
    classification: str
    #: Why nothing can be sent, or None when at least one item remains.
    blocked_reason: ExternalReason | None

    @model_validator(mode="after")
    def _consistent(self) -> MinimizedPayload:
        if (self.blocked_reason is None) != bool(self.kept):
            raise ValueError("a payload is blocked exactly when nothing was kept")
        return self

    @property
    def sendable(self) -> bool:
        return self.blocked_reason is None and bool(self.kept)


def _check_allowed(scheme: ClassificationScheme, allowed: tuple[str, ...]) -> frozenset[str]:
    """`unknown` and labels outside the scheme can never be allowed (ADR-0017)."""
    for label in allowed:
        if label == UNKNOWN_LABEL or label not in scheme.labels:
            raise ValidationFailed(
                "allowed classifications must be labels of the configured scheme"
            )
    return frozenset(allowed)


def _drop_reason(label: str, allowed: frozenset[str]) -> ExternalReason | None:
    if label == UNKNOWN_LABEL:
        return ExternalReason.CLASSIFICATION_UNKNOWN
    if label not in allowed:
        return ExternalReason.CLASSIFICATION_NOT_ALLOWED
    return None


def minimize(
    proposal: ExternalRequestProposal,
    *,
    scheme: ClassificationScheme | None,
    allowed_classifications: tuple[str, ...] = (),
    redactor: Redactor,
) -> MinimizedPayload:
    """Drop what may not leave, redact the rest, and say what was dropped (8.4 step 3).

    No scheme, or an empty allowed set (the default, gap G26), drops everything and the
    result is blocked. An item with a missing or unrecognised label is `unknown` and is
    always dropped. Raises `ValidationFailed` if the allowed set names `unknown` or a label
    outside the scheme.
    """
    whole: ExternalReason | None = None
    allowed: frozenset[str] = frozenset()
    if scheme is None:
        whole = ExternalReason.NO_SCHEME
    elif not allowed_classifications:
        whole = ExternalReason.NO_ALLOWED_CLASSIFICATIONS
    else:
        allowed = _check_allowed(scheme, tuple(allowed_classifications))

    kept: list[KeptItem] = []
    dropped: list[DroppedItem] = []
    for item in proposal.items:
        label = classify(scheme, item.classification)
        reason = whole if whole is not None else _drop_reason(label, allowed)
        if reason is not None:
            dropped.append(DroppedItem(ref=item.ref, classification=label, reason=reason))
            continue
        kept.append(
            KeptItem(
                ref=item.ref,
                classification=label,
                source=item.source,
                text=redactor.redact(item.text),
            )
        )

    blocked = whole
    if blocked is None and not kept:
        blocked = ExternalReason.NOTHING_SENDABLE
    governing = UNKNOWN_LABEL
    if kept and scheme is not None:
        governing = scheme.most_sensitive([item.classification for item in kept])
    return MinimizedPayload(
        request_id=proposal.request_id,
        provider_name=proposal.provider_name,
        model_name=proposal.model_name,
        purpose=redactor.redact(proposal.purpose),
        kept=tuple(kept),
        dropped=tuple(dropped),
        classification=governing,
        blocked_reason=blocked,
    )


def preview_bytes(payload: MinimizedPayload) -> bytes:
    """The exact bytes that would be transmitted and hashed (8.4 step 2).

    Canonical JSON (sorted keys, no whitespace), UTF-8. Holds the request id, provider,
    model, purpose and the kept, redacted items in the order they were offered. An item's
    `source` is not sent: the provider does not need it (11.1 minimum data).
    Raises `ExternalRequestRefused` for a blocked payload: there is nothing to send.
    """
    if payload.blocked_reason is not None or not payload.kept:
        raise ExternalRequestRefused(payload.blocked_reason or ExternalReason.NOTHING_SENDABLE)
    document: dict[str, Any] = {
        "schema": PAYLOAD_SCHEMA_VERSION,
        "request_id": payload.request_id,
        "provider": payload.provider_name,
        "model": payload.model_name,
        "purpose": payload.purpose,
        "items": [
            {"ref": item.ref, "classification": item.classification, "text": item.text}
            for item in payload.kept
        ],
    }
    try:
        return canonical_json(document).encode("utf-8")
    except UnicodeEncodeError:
        raise ValidationFailed("payload text cannot be encoded as UTF-8") from None


def _no_repeats(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    found: dict[str, Any] = {}
    for key, value in pairs:
        if key in found:
            raise ValueError("payload names a key twice")
        found[key] = value
    return found


def parse_payload(raw: bytes) -> dict[str, Any]:
    """Read payload bytes back, strictly (review finding C1, defence in depth).

    Refused: a key named twice (two readers could disagree about which one counts), any
    key besides the six of the layout and the three of an item, a value of the wrong
    type, another layout version, a request id that is not one, and bytes that are not
    exactly the canonical serialisation of what they say. The error never quotes the
    bytes.
    """
    try:
        said = json.loads(raw.decode("utf-8"), object_pairs_hook=_no_repeats)
    except (json.JSONDecodeError, UnicodeDecodeError, RecursionError):
        raise ValueError("payload bytes are not acceptable JSON") from None
    if not isinstance(said, dict) or set(said) != _PAYLOAD_KEYS:
        raise ValueError("payload does not have exactly the expected keys")
    items = said["items"]
    texts = (said["request_id"], said["provider"], said["model"], said["purpose"])
    if (
        said["schema"] != PAYLOAD_SCHEMA_VERSION
        or isinstance(said["schema"], bool)
        or not all(isinstance(value, str) for value in texts)
        or not is_id(said["request_id"], REQUEST_ID_PREFIX)
        or not isinstance(items, list)
    ):
        raise ValueError("payload fields have the wrong shape")
    for item in items:
        if (
            not isinstance(item, dict)
            or set(item) != _ITEM_KEYS
            or not all(isinstance(value, str) for value in item.values())
        ):
            raise ValueError("payload item does not have exactly the expected keys")
    if canonical_json(said).encode("utf-8") != raw:
        raise ValueError("payload bytes are not in canonical form")
    return said


class PayloadPreview(Model):
    """What a human is shown before deciding (8.4 step 2). For display only: the gateway
    never authorizes or sends a preview it was handed, it builds its own from the
    recorded proposal.

    For a sendable payload `preview_bytes` is the exact byte string that would be sent and
    `payload_hash` is its SHA-256. For a blocked payload both are None. The model refuses
    to exist if the hash is not the hash of the bytes, if the bytes fail `parse_payload`,
    or if the named request, provider, model, purpose or kept refs differ from what the
    bytes say.
    """

    request_id: str
    provider_name: str
    model_name: str
    purpose: str
    classification: str
    kept: tuple[ItemLabel, ...]
    dropped: tuple[DroppedItem, ...]
    blocked_reason: ExternalReason | None
    preview_bytes: bytes | None = Field(repr=False)
    payload_hash: str | None

    @model_validator(mode="after")
    def _bytes_match(self) -> PayloadPreview:
        raw, digest = self.preview_bytes, self.payload_hash
        if self.blocked_reason is not None:
            if raw is not None or digest is not None or self.kept:
                raise ValueError("a blocked preview carries no payload")
            return self
        if raw is None or digest is None or not self.kept:
            raise ValueError("a sendable preview needs its bytes and their hash")
        if not hmac.compare_digest(sha256_hex(raw), digest):
            raise ValueError("payload_hash is not the hash of preview_bytes")
        said = parse_payload(raw)
        named = (self.request_id, self.provider_name, self.model_name, self.purpose)
        in_bytes = (said["request_id"], said["provider"], said["model"], said["purpose"])
        refs = [(item.ref, item.classification) for item in self.kept]
        refs_in_bytes = [(item["ref"], item["classification"]) for item in said["items"]]
        if named != in_bytes or refs != refs_in_bytes:
            raise ValueError("preview fields do not match preview_bytes")
        return self

    @property
    def sendable(self) -> bool:
        return self.blocked_reason is None and self.preview_bytes is not None


def build_preview(payload: MinimizedPayload) -> PayloadPreview:
    """Serialise a minimized payload once; the hash is taken over those same bytes."""
    raw: bytes | None = None
    digest: str | None = None
    if payload.sendable:
        raw = preview_bytes(payload)
        digest = sha256_hex(raw)
    return PayloadPreview(
        request_id=payload.request_id,
        provider_name=payload.provider_name,
        model_name=payload.model_name,
        purpose=payload.purpose,
        classification=payload.classification,
        kept=tuple(ItemLabel(ref=i.ref, classification=i.classification) for i in payload.kept),
        dropped=payload.dropped,
        blocked_reason=payload.blocked_reason,
        preview_bytes=raw,
        payload_hash=digest,
    )


class ApprovalBinding(Model):
    """What an approval of an external request must cover (8.4 step 4, gap G2)."""

    request_id: str
    provider_name: str
    model_name: str
    purpose: str
    payload_hash: str

    def subject_hash(self) -> str:
        """One hash over all five values, for an approval record that binds one subject."""
        return sha256_hex(canonical_json(self))


def approval_binding(preview: PayloadPreview) -> ApprovalBinding:
    """The binding for a preview. Raises `ExternalRequestRefused` if nothing is sendable."""
    if preview.blocked_reason is not None or preview.payload_hash is None:
        raise ExternalRequestRefused(preview.blocked_reason or ExternalReason.NOTHING_SENDABLE)
    return ApprovalBinding(
        request_id=preview.request_id,
        provider_name=preview.provider_name,
        model_name=preview.model_name,
        purpose=preview.purpose,
        payload_hash=preview.payload_hash,
    )
