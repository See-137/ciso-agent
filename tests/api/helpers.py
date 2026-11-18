"""Plain helpers for the API tests (not fixtures)."""

from __future__ import annotations

import dataclasses
import io
import warnings
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from fastapi import FastAPI

from ciso.app import Container
from ciso.app.container import build_external_gateway
from ciso.app.settings import ExternalInferenceSettings, Settings, load_settings
from ciso.common.clock import FixedClock
from ciso.common.enums import ActorType, Role
from ciso.common.principal import Principal
from ciso.identity import RoleScope, ScryptParams
from ciso.inference.external import TransportResponse

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
    "CISO_SECRET_EXTERNAL_DIGEST_KEY": "external-digest-key-for-api-tests-4d1f",
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


#: Labels of the provisional scheme that the external-path tests allow to leave.
EXTERNAL_ALLOWED = ("public", "internal")


def external_on(settings: Settings, **changes: Any) -> Settings:
    """`settings` with the external model path switched on and fully decided (approver:
    system_owner). `changes` override fields of the external block."""
    block = ExternalInferenceSettings(
        enabled=True, approver_role=Role.SYSTEM_OWNER, allowed_classifications=EXTERNAL_ALLOWED
    )
    return settings.model_copy(update={"external_inference": block.model_copy(update=changes)})


class SpyTransport:
    """Test-only `ExternalTransport`. Records every call; never touches the network."""

    def __init__(self, body: bytes = b"OKAPI-BASALT-42 answer body") -> None:
        self.calls: list[tuple[str, str, bytes]] = []
        self.body = body
        self.raises: Exception | None = None

    def send(self, *, provider_name: str, model_name: str, payload: bytes) -> TransportResponse:
        self.calls.append((provider_name, model_name, payload))
        if self.raises is not None:
            raise self.raises
        return TransportResponse(body=self.body, metadata={"provider_request_id": "r-123"})


def with_transport(transport: SpyTransport) -> Callable[[Container], Container]:
    """A `rewire` for `make_api`: the same container with its external gateway rebuilt by
    the composition root's own builder, plus a test transport (the build ships none)."""

    def rewire(container: Container) -> Container:
        gateway = build_external_gateway(
            container.settings,
            engine=container.operational_engine,
            clock=container.clock,
            audit=container.audit,
            redactor=container.redactor,
            principals=container.identity,
            killswitch=container.killswitch_reader,
            approvals=container.approvals,
            secrets=container.secret_store,
            transport=transport,
        )
        return dataclasses.replace(container, external_inference=gateway)

    return rewire


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

    def human(
        self,
        name: str,
        *roles: Role,
        issuer: Principal | None = None,
        scope: RoleScope | None = None,
    ) -> tuple[Principal, str]:
        """A human holding `roles` (each narrowed to `scope` when given) whose token
        `issuer` minted (default: the first admin). Returns (principal as stored, token)."""
        identity, authn = self.container.identity, self.container.authenticator
        actor = identity.create_actor(self.admin, ActorType.HUMAN, name)
        for role in roles:
            if scope is None:
                identity.assign_role(self.admin, actor.id, role)
            else:
                identity.assign_role(self.admin, actor.id, role, scope=scope)
        found = identity.resolve(actor.id)
        assert found is not None
        return found, authn.issue_token(actor.id, issuer or self.admin).token

    def audit_records(self, action_prefix: str) -> list[Any]:
        return list(self.container.audit.query(limit=500, action_prefix=action_prefix))


ApiFactory = Callable[..., Api]
