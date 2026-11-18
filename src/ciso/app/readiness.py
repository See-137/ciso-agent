"""What the composition root reports at start-up: missing values and integrity warnings.

`Readiness.missing` lists what blocks write paths; `Readiness.warnings` lists what weakens
tamper evidence or monitoring without stopping anything. Both are computed here from
`Settings` and the secret store, before any service is built, so the container itself only
wires services (plan T1.14, G14, G18; ADR-0013).
"""

from __future__ import annotations

import logging
from collections.abc import Iterable
from typing import Final

from ciso.app.settings import KEY_REF_FIELDS, Settings
from ciso.common.errors import CisoError, FailClosed
from ciso.common.schemas import Model
from ciso.vault import MIN_KEY_BYTES, EnvSecretStore, resolve_key_bytes

logger = logging.getLogger(__name__)

#: Secret references checked at start-up. Each is used as a cryptographic key, so each must
#: resolve to at least `MIN_KEY_BYTES` bytes. Resolving also registers the value with the
#: redactor, so it is scrubbed from every later log line and audit detail.
SECRET_REF_FIELDS: Final = KEY_REF_FIELDS
HEALTH_UNTIMED: Final = "health_check_timeout_seconds (not set; every health check reads unknown)"
WITNESS_UNDER_DATA_DIR: Final = "audit witness is stored under the data directory"
ANCHOR_UNDER_DATA_DIR: Final = "audit anchor is stored under the data directory"
EXTERNAL_NO_TRANSPORT: Final = (
    "external inference is enabled but this build ships no transport; authorize and transmit refuse"
)
EXTERNAL_NO_DIGEST_KEY: Final = (
    "external inference is enabled without external_digest_key_ref; "
    "item digests are unkeyed and no answer digest is kept"
)


class Readiness(Model):
    """`missing`: what blocks write paths (empty means ready). `warnings`: what weakens
    tamper evidence or monitoring without stopping anything
    (`Settings.integrity_warnings()`, a witness or anchor under the data directory,
    untimed health checks). `governance`: what the governance services lack."""

    ready: bool
    missing: tuple[str, ...]
    warnings: tuple[str, ...] = ()
    #: What the AI-activity governance services run without (unset values, a ruleset that
    #: did not load). Each makes its own part refuse; none blocks the platform's writes or
    #: weakens tamper evidence, so it is listed apart (`ciso.app.governance_wiring`).
    governance: tuple[str, ...] = ()


def unusable_refs(settings: Settings, store: EnvSecretStore) -> dict[str, str]:
    """Resolve every configured key reference now. Returns field name -> readiness entry
    for each one that does not resolve or is shorter than `MIN_KEY_BYTES`."""
    failed: dict[str, str] = {}
    for name in SECRET_REF_FIELDS:
        ref = getattr(settings, name)
        if ref is None:
            continue
        try:
            resolve_key_bytes(store, ref)
        except FailClosed:
            logger.warning("start-up: %s is too short or empty; dependent writes refuse", name)
            failed[name] = f"{name} (shorter than {MIN_KEY_BYTES} bytes)"
        except CisoError:
            logger.warning("start-up: %s does not resolve; dependent writes refuse", name)
            failed[name] = f"{name} (unresolvable)"
    return failed


def external_missing(settings: Settings) -> tuple[str, ...]:
    """What an ENABLED external model path still lacks (blueprint 8.4, G14, G26). Empty
    while the path is off: an unset value then blocks nothing anybody asked for. The
    gateway refuses on each of these by itself; this only makes the refusal visible at
    start-up. An unusable digest key is reported by `unusable_refs`."""
    external = settings.external_inference
    if not external.enabled:
        return ()
    missing: list[str] = []
    if external.approver_role is None:
        missing.append("external_inference.approver_role")
    if not external.allowed_classifications:
        missing.append("external_inference.allowed_classifications")
    for name in ("external_max_payload_bytes", "external_max_response_bytes"):
        if getattr(settings.safety, name) is None:
            missing.append(f"safety.{name}")
    return tuple(missing)


def all_missing(settings: Settings, *found: Iterable[str]) -> tuple[str, ...]:
    """Everything that makes the platform not ready, each entry once, in a fixed order:
    unset values no write path can run without, what an enabled external path lacks, then
    whatever start-up found (`found`: unusable key references, audit and gate problems)."""
    names = (*settings.missing_for_writes(), *external_missing(settings))
    return tuple(dict.fromkeys((*names, *(item for group in found for item in group))))


def startup_warnings(settings: Settings) -> tuple[str, ...]:
    """`Settings.integrity_warnings()` plus placement checks the settings cannot make
    alone, plus untimed health checks, plus what an enabled external model path runs
    without. Empty only when anchor and witness are both configured outside the data
    directory, health checks are timed and the external path is off."""
    warnings = list(settings.integrity_warnings())
    data_dir = settings.data_dir.resolve()
    anchor = settings.audit_anchor_path
    if (
        anchor is not None
        and anchor.resolve().is_relative_to(data_dir)
        and ANCHOR_UNDER_DATA_DIR not in warnings
    ):
        warnings.append(ANCHOR_UNDER_DATA_DIR)
    witness = settings.audit_witness_path
    if witness is not None and witness.resolve().is_relative_to(data_dir):
        warnings.append(WITNESS_UNDER_DATA_DIR)
    if settings.safety.health_check_timeout_seconds is None:
        warnings.append(HEALTH_UNTIMED)
    if settings.external_inference.enabled:
        warnings.append(EXTERNAL_NO_TRANSPORT)
        if settings.external_digest_key_ref is None:
            warnings.append(EXTERNAL_NO_DIGEST_KEY)
    return tuple(warnings)
