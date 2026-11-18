"""What the composition root reports at start-up: missing values and integrity warnings.

`Readiness.missing` lists what blocks write paths; `Readiness.warnings` lists what weakens
tamper evidence or monitoring without stopping anything. Both are computed here from
`Settings` and the secret store, before any service is built, so the container itself only
wires services (plan T1.14, G14, G18; ADR-0013).
"""

from __future__ import annotations

import logging
from typing import Final

from ciso.app.settings import Settings
from ciso.common.errors import CisoError, FailClosed
from ciso.common.schemas import Model
from ciso.vault import MIN_KEY_BYTES, EnvSecretStore, resolve_key_bytes

logger = logging.getLogger(__name__)

#: Secret references checked at start-up. Each is used as a cryptographic key, so each must
#: resolve to at least `MIN_KEY_BYTES` bytes. Resolving also registers the value with the
#: redactor, so it is scrubbed from every later log line and audit detail.
SECRET_REF_FIELDS: Final = (
    "audit_hmac_key_ref",
    "audit_witness_key_ref",
    "killswitch_key_ref",
    "evidence_key_ref",
    "backup_key_ref",
)
HEALTH_UNTIMED: Final = "health_check_timeout_seconds (not set; every health check reads unknown)"
WITNESS_UNDER_DATA_DIR: Final = "audit witness is stored under the data directory"
ANCHOR_UNDER_DATA_DIR: Final = "audit anchor is stored under the data directory"


class Readiness(Model):
    """`missing`: what blocks write paths (empty means ready). `warnings`: what weakens
    tamper evidence or monitoring without stopping anything
    (`Settings.integrity_warnings()`, a witness or anchor under the data directory,
    untimed health checks)."""

    ready: bool
    missing: tuple[str, ...]
    warnings: tuple[str, ...] = ()


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


def startup_warnings(settings: Settings) -> tuple[str, ...]:
    """`Settings.integrity_warnings()` plus placement checks the settings cannot make
    alone, plus untimed health checks. Empty only when anchor and witness are both
    configured outside the data directory and health checks are timed."""
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
    return tuple(warnings)
