"""Shared helpers for the composition-root tests: provisional settings and a fast build."""

from __future__ import annotations

import io
from pathlib import Path
from typing import Any

from ciso.app import Container, build_container
from ciso.app.settings import Settings, load_settings
from ciso.common.clock import FixedClock
from ciso.common.enums import ActorType, AuditOutcome
from ciso.common.protocols import AuditEvent
from ciso.identity import ScryptParams

REPO_ROOT = Path(__file__).resolve().parents[2]
PROVISIONAL = REPO_ROOT / "config" / "provisional-settings.json"
FAST_SCRYPT = ScryptParams(n=16, r=1, p=1)
AUDIT_KEY = "audit-hmac-key-for-container-tests-41c9"
SECRET_ENV = {
    "CISO_SECRET_AUDIT_HMAC_KEY": AUDIT_KEY,
    "CISO_SECRET_KILLSWITCH_KEY": "killswitch-key-for-container-tests-6e30",
    "CISO_SECRET_EVIDENCE_KEY": "evidence-key-for-container-tests-88d2",
    "CISO_SECRET_BACKUP_KEY": "backup-key-for-container-tests-1f07",
    "CISO_SECRET_EXTERNAL_DIGEST_KEY": "external-digest-key-for-container-tests-7b2c",
}


def provisional(data_dir: Path, *, isolated_anchor: bool = True, **safety: Any) -> Settings:
    """Provisional values. `isolated_anchor` keeps the anchor outside the data directory;
    False uses the default anchor at `data_dir/anchor/`."""
    base = load_settings(PROVISIONAL)
    update: dict[str, Any] = {"data_dir": data_dir}
    if isolated_anchor:
        update["audit_anchor_path"] = data_dir.parent / "anchors" / data_dir.name / "head.json"
    if safety:
        update["safety"] = base.safety.model_copy(update=safety)
    return base.model_copy(update=update)


def build(
    settings: Settings,
    environ: dict[str, str] | None = None,
    clock: FixedClock | None = None,
    stream: io.StringIO | None = None,
) -> Container:
    return build_container(
        settings,
        environ=environ if environ is not None else {},
        clock=clock or FixedClock(),
        scrypt=FAST_SCRYPT,
        log_stream=stream,
    )


def event(n: int = 0) -> AuditEvent:
    return AuditEvent(
        actor_id="human_test",
        actor_type=ActorType.HUMAN,
        action="test.event",
        target=f"asset:{n}",
        outcome=AuditOutcome.SUCCESS,
    )
