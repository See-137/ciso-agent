"""Plain helpers for the API tests (not fixtures)."""

from __future__ import annotations

import io
import warnings
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from fastapi import FastAPI

from ciso.app import Container
from ciso.app.settings import Settings, load_settings
from ciso.common.clock import FixedClock
from ciso.common.enums import ActorType, Role
from ciso.common.principal import Principal
from ciso.identity import ScryptParams

# The installed starlette deprecates its httpx-based TestClient in favour of a package that
# is not installed; the run treats warnings as errors. Silence exactly that one warning at
# import time and report the missing dependency instead of adding it here.
with warnings.catch_warnings():
    warnings.filterwarnings("ignore", message="Using `httpx` with `starlette.testclient`")
    from fastapi.testclient import TestClient

REPO_ROOT = Path(__file__).resolve().parents[2]
PROVISIONAL = REPO_ROOT / "config" / "provisional-settings.json"
FAST_SCRYPT = ScryptParams(n=16, r=1, p=1)
SECRET_ENV = {
    "CISO_SECRET_AUDIT_HMAC_KEY": "audit-hmac-key-for-api-tests-5b21",
    "CISO_SECRET_KILLSWITCH_KEY": "killswitch-key-for-api-tests-d813",
    "CISO_SECRET_EVIDENCE_KEY": "evidence-key-for-api-tests-0c4e9b72",
    "CISO_SECRET_BACKUP_KEY": "backup-key-for-api-tests-9a7d3e15f0",
}
#: High enough that ordinary tests never hit it.
GENEROUS_LIMIT = 10_000


def settings_for(data_dir: Path, **safety: Any) -> Settings:
    base = load_settings(PROVISIONAL)
    return base.model_copy(
        update={
            "data_dir": data_dir,
            "audit_anchor_path": data_dir.parent / "anchors" / data_dir.name / "head.json",
            "safety": base.safety.model_copy(update=safety),
        }
    )


@dataclass
class Api:
    container: Container
    app: FastAPI
    client: TestClient
    clock: FixedClock
    logs: io.StringIO
    admin: Principal
    admin_token: str
    tokens: dict[str, str] = field(default_factory=dict)

    def headers(self, token: str) -> dict[str, str]:
        return {"Authorization": f"Bearer {token}"}

    def actor(self, name: str, actor_type: ActorType, *roles: Role) -> tuple[str, str]:
        """Create an actor with `roles`; return (actor_id, token)."""
        identity = self.container.identity
        authn = self.container.authenticator
        assert identity is not None
        assert authn is not None
        actor = identity.create_actor(self.admin, actor_type, name)
        for role in roles:
            identity.assign_role(self.admin, actor.id, role)
        issued = authn.issue_token(actor.id, self.admin)
        return actor.id, issued.token


ApiFactory = Callable[..., Api]
