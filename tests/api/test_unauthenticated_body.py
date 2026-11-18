"""One 401 body for every cause (FR-003, review F8): each of the two layers on its own.

`test_auth_system` checks the bodies a client sees. Two layers produce that: every
refusal in `ciso.api.deps` is built by `unauthenticated()`, and the `ApiError` handler in
`ciso.api.app` rewrites any 401 to the fixed body. These tests take one layer away at a
time, so a regression in either is caught even while the other still hides it.
"""

from __future__ import annotations

from datetime import timedelta
from typing import Annotated

import pytest
from fastapi import Depends, Request
from fastapi.responses import JSONResponse
from tests.api.helpers import Api

from ciso.api import AUTHENTICATED, require
from ciso.api.deps import UNAUTHENTICATED_BODY, ApiError
from ciso.common.enums import ActorType, Role
from ciso.common.principal import Principal

pytestmark = pytest.mark.policy

WHOAMI = "/v1/system/whoami"


def _refusal_headers(api: Api) -> dict[str, dict[str, str]]:
    _, revoked = api.actor("Revoked", ActorType.HUMAN, Role.AUDITOR)
    api.container.authenticator.revoke_token(revoked.split(".")[0], api.admin)
    disabled_id, disabled = api.actor("Disabled", ActorType.HUMAN, Role.AUDITOR)
    api.container.identity.disable_actor(api.admin, disabled_id)
    return {
        "no header": {},
        "wrong scheme": {"Authorization": f"Basic {api.admin_token}"},
        "no token": {"Authorization": "Bearer "},
        "garbage": {"Authorization": "Bearer not-a-token"},
        "two parts": {"Authorization": f"Bearer {api.admin_token} extra"},
        "revoked": api.headers(revoked),
        "disabled actor": api.headers(disabled),
    }


def test_every_refusal_is_built_identically_before_normalisation(api: Api) -> None:
    async def raw(request: Request, exc: Exception) -> JSONResponse:
        assert isinstance(exc, ApiError)
        body = {"error": exc.code, "message": exc.message}
        return JSONResponse(body, status_code=exc.status, headers=exc.headers)

    api.app.add_exception_handler(ApiError, raw)  # pass refusals through untouched
    _, expiring = api.actor("Expiring", ActorType.HUMAN, Role.AUDITOR)
    responses = {
        name: api.client.get(WHOAMI, headers=headers)
        for name, headers in _refusal_headers(api).items()
    }
    api.clock.advance(timedelta(days=2))
    responses["expired"] = api.client.get(WHOAMI, headers=api.headers(expiring))
    assert len(responses) == 8
    for name, r in responses.items():
        assert r.status_code == 401, name
        assert r.json() == dict(UNAUTHENTICATED_BODY), name
        assert r.headers["www-authenticate"] == "Bearer", name


def test_handler_rewrites_any_401_to_the_fixed_body(api: Api) -> None:
    @api.app.get("/v1/test/odd-refusal")
    def odd(_: Annotated[Principal, Depends(require(AUTHENTICATED))]) -> None:
        raise ApiError(401, "token_expired", "your token expired at noon")

    r = api.client.get("/v1/test/odd-refusal", headers=api.headers(api.admin_token))
    assert r.status_code == 401
    assert r.json() == dict(UNAUTHENTICATED_BODY)
    assert r.headers["www-authenticate"] == "Bearer"
