"""Device routes: register a managed machine and issue its token, or revoke it.

Both need `identity.manage` (held by `security_admin` only), and the identity service
checks again that the caller is a current human administrator. The token is in the
response of `POST /v1/devices` exactly once; only its hash is stored, and it expires
within `safety.max_token_ttl_seconds` (`ciso.app.devices`).
"""

from __future__ import annotations

from typing import Annotated, Any, Final

from fastapi import Depends, FastAPI
from pydantic import Field

from ciso.api.deps import require
from ciso.app.container import Container
from ciso.common.principal import Principal
from ciso.common.schemas import Model

MANAGE: Final = require("identity.manage")


class DeviceRequest(Model):
    name: str = Field(min_length=1, max_length=64)


def register_device_routes(router: FastAPI, container: Container) -> None:
    """Add the routes to `router` directly, so the route enumeration sees each one."""
    devices = container.governance.devices

    @router.post("/v1/devices", status_code=201)
    def register(
        body: DeviceRequest, principal: Annotated[Principal, Depends(MANAGE)]
    ) -> dict[str, Any]:
        made = devices.register(principal, body.name)
        return {
            "device_id": made.device.device_id,
            "name": made.device.name,
            "token_id": made.token.token_id,
            "expires_at": made.token.expires_at.isoformat(),
            "token": made.token.token,
        }

    @router.delete("/v1/devices/{device_id}")
    def revoke(device_id: str, principal: Annotated[Principal, Depends(MANAGE)]) -> dict[str, Any]:
        result: dict[str, Any] = devices.revoke(principal, device_id).model_dump(mode="json")
        return result
