"""Configuration, with safety parameters that have no silent defaults.

The blueprint leaves many numbers open (expiry windows, freshness thresholds, rate limits;
sections 15.1 and 20). So every such value here defaults to `None`, and a component that
receives `None` refuses to act. A deployment must name a settings file to get anything
other than a platform that observes and refuses. `config/provisional-settings.json` holds
values that are good enough to exercise the platform and are explicitly provisional
(ADR-0019).
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Annotated, Any, Final

from pydantic import Field, model_validator

from ciso.common.classification import ClassificationScheme
from ciso.common.enums import APPROVER_ROLES, Role
from ciso.common.errors import ValidationFailed
from ciso.common.schemas import Model

Seconds = Annotated[float, Field(gt=0, allow_inf_nan=False)]
Count = Annotated[int, Field(gt=0, strict=True)]

LOOPBACK_HOSTS = frozenset({"127.0.0.1", "::1", "localhost"})

#: Roles that may be named as the approver of an external model request (blueprint 8.4
#: step 4). Which one is an open decision (OD-14); none is the default.
EXTERNAL_APPROVER_ROLES = APPROVER_ROLES

#: Every `Settings` field that names a cryptographic key. Each must be a `secret://`
#: reference, and `ciso.app.readiness` checks at start-up that each one that is set
#: resolves to a key of at least the minimum length.
KEY_REF_FIELDS: Final = (
    "audit_hmac_key_ref",
    "audit_witness_key_ref",
    "killswitch_key_ref",
    "evidence_key_ref",
    "backup_key_ref",
    "external_digest_key_ref",
)


class SafetySettings(Model):
    """Every field is optional and unset by default. Unset means the feature refuses."""

    # identity
    max_token_ttl_seconds: Seconds | None = None
    # policy and approvals
    max_envelope_ttl_seconds: Seconds | None = None
    approval_ttl_seconds: Seconds | None = None
    allow_self_approval: bool = False
    # workflows
    queue_lease_seconds: Seconds | None = None
    queue_max_attempts: Count | None = None
    queue_backoff_base_seconds: Seconds | None = None
    queue_backoff_max_seconds: Seconds | None = None
    # inference
    inference_timeout_seconds: Seconds | None = None
    inference_max_abandoned_calls: Count | None = None
    # audit: publish a witness entry every N appends (1 = every append)
    audit_witness_every: Count | None = None
    # kill switch
    killswitch_claim_timeout_seconds: Seconds | None = None
    # observability
    health_check_timeout_seconds: Seconds | None = None
    metrics_max_series_per_metric: Count | None = None
    # registry
    fact_freshness_seconds: Seconds | None = None
    fact_expiry_seconds: Seconds | None = None
    retirement_grace_seconds: Seconds | None = None
    # connectors and events
    event_clock_skew_seconds: Seconds | None = None
    # discovery
    scan_max_rate_per_second: Seconds | None = None
    scan_max_concurrency: Count | None = None
    # execution
    tool_rate_limit_per_minute: Count | None = None
    # api
    api_rate_limit_per_minute: Count | None = None
    # external inference (blueprint 8.4): the largest payload that may be authorized and
    # sent, and the largest answer that is read. Unset: authorize and transmit refuse.
    external_max_payload_bytes: Count | None = None
    external_max_response_bytes: Count | None = None

    @model_validator(mode="after")
    def _consistent(self) -> SafetySettings:
        base, cap = self.queue_backoff_base_seconds, self.queue_backoff_max_seconds
        if base is not None and cap is not None and base > cap:
            raise ValueError("queue_backoff_base_seconds exceeds queue_backoff_max_seconds")
        fresh, expiry = self.fact_freshness_seconds, self.fact_expiry_seconds
        if fresh is not None and expiry is not None and fresh > expiry:
            raise ValueError("fact_freshness_seconds exceeds fact_expiry_seconds")
        return self


class ExternalInferenceSettings(Model):
    """Blueprint 8.4. Off, with no approver and no allowed data, until someone decides."""

    enabled: bool = False
    approver_role: Role | None = None
    allowed_classifications: tuple[str, ...] = ()

    @model_validator(mode="after")
    def _approver_is_human_role(self) -> ExternalInferenceSettings:
        if self.approver_role is not None and self.approver_role not in EXTERNAL_APPROVER_ROLES:
            raise ValueError(
                "the external-inference approver must be a human-only role that carries "
                "approval authority; the auditor is read-only and the admin does not approve"
            )
        return self

    @property
    def usable(self) -> bool:
        """True only when every prerequisite has been decided explicitly."""
        return (
            self.enabled and self.approver_role is not None and bool(self.allowed_classifications)
        )


class Settings(Model):
    data_dir: Path = Path("data")
    bind_host: str = "127.0.0.1"
    bind_port: Annotated[int, Field(ge=1, le=65535)] = 8765
    allow_non_loopback_bind: bool = False
    classification_labels: tuple[str, ...] | None = None
    audit_hmac_key_ref: str | None = None
    #: Where the audit head anchor is kept. Unset puts it under the data directory, which
    #: anyone who can write that directory can also roll back; readiness reports this.
    audit_anchor_path: Path | None = None
    #: An append-only file of signed audit heads kept on storage the data-directory
    #: writer cannot change. Unset means the audit log is not witnessed (ADR-0013).
    audit_witness_path: Path | None = None
    #: Key for signing witness entries. Use a different secret from the anchor key.
    audit_witness_key_ref: str | None = None
    killswitch_key_ref: str | None = None
    evidence_key_ref: str | None = None
    backup_key_ref: str | None = None
    #: Key for the digests the external model path stores (per-item text, the answer).
    #: Unset: item digests are unkeyed and no answer digest is kept (blueprint 8.4 step 6).
    external_digest_key_ref: str | None = None
    safety: SafetySettings = SafetySettings()
    external_inference: ExternalInferenceSettings = ExternalInferenceSettings()

    @model_validator(mode="after")
    def _check(self) -> Settings:
        if self.bind_host not in LOOPBACK_HOSTS and not self.allow_non_loopback_bind:
            raise ValueError(
                "bind_host is not loopback; set allow_non_loopback_bind after the host and "
                "network decision is made (OD-01, ADR-0015)"
            )
        for name in KEY_REF_FIELDS:
            ref = getattr(self, name)
            if ref is not None and not ref.startswith("secret://"):
                raise ValueError(f"{name} must be a secret:// reference, not a value")
        if self.classification_labels is not None:
            scheme = ClassificationScheme(labels=self.classification_labels)
            for label in self.external_inference.allowed_classifications:
                scheme.normalise(label)
        elif self.external_inference.allowed_classifications:
            raise ValueError("external inference names classifications but no scheme is set")
        return self

    @property
    def classification(self) -> ClassificationScheme | None:
        if self.classification_labels is None:
            return None
        return ClassificationScheme(labels=self.classification_labels)

    @property
    def operational_db(self) -> Path:
        return self.data_dir / "db" / "ciso.db"

    @property
    def audit_db(self) -> Path:
        return self.data_dir / "db" / "audit.db"

    @property
    def audit_anchor(self) -> Path:
        """Kept outside the databases' directory: the audit log refuses an anchor
        beside its database. The default is still under `data_dir`, so whoever can
        write that directory can roll both back; `integrity_warnings` says so
        (ADR-0013)."""
        if self.audit_anchor_path is not None:
            return self.audit_anchor_path
        return self.data_dir / "anchor" / "audit-head.json"

    @property
    def audit_anchor_is_isolated(self) -> bool:
        """False when the anchor shares the data directory with the log it protects."""
        return self.audit_anchor_path is not None

    def integrity_warnings(self) -> list[str]:
        """Conditions that weaken tamper evidence without stopping the platform."""
        warnings: list[str] = []
        if not self.audit_anchor_is_isolated:
            warnings.append("audit anchor is stored under the data directory")
        if self.audit_witness_path is None:
            warnings.append("audit log has no witness outside the data directory")
        elif self.audit_witness_key_ref is None or self.safety.audit_witness_every is None:
            warnings.append("audit witness path is set but its key or cadence is not")
        return warnings

    @property
    def evidence_dir(self) -> Path:
        return self.data_dir / "evidence"

    def missing_for_writes(self) -> list[str]:
        """Names of unset values without which no write path can run. Empty means ready."""
        missing: list[str] = []
        for name in ("audit_hmac_key_ref", "killswitch_key_ref"):
            if getattr(self, name) is None:
                missing.append(name)
        for name in ("max_envelope_ttl_seconds", "approval_ttl_seconds", "max_token_ttl_seconds"):
            if getattr(self.safety, name) is None:
                missing.append(f"safety.{name}")
        return missing


def load_settings(path: Path | str | None) -> Settings:
    """Read a JSON settings file. `None` gives the all-refusing defaults.

    Unknown keys are an error: a misspelt safety parameter must not silently stay unset.
    """
    if path is None:
        return Settings()
    file = Path(path)
    try:
        raw: Any = json.loads(file.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise ValidationFailed(f"settings file not found: {file}") from exc
    except json.JSONDecodeError as exc:
        raise ValidationFailed(f"settings file is not valid JSON: {file}: {exc}") from exc
    except (OSError, UnicodeDecodeError) as exc:
        raise ValidationFailed(f"settings file cannot be read: {file}: {exc}") from exc
    if not isinstance(raw, dict):
        raise ValidationFailed("settings file must hold a JSON object")
    raw.pop("_comment", None)
    try:
        return Settings.model_validate(raw)
    except ValueError as exc:
        raise ValidationFailed(f"invalid settings in {file}: {exc}") from exc
