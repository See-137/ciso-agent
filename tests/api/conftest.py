"""API test fixtures: a real container on tmp_path, a TestClient, and actors with tokens."""

from __future__ import annotations

import io
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

import pytest
from tests.api.helpers import (
    FAST_SCRYPT,
    GENEROUS_LIMIT,
    SECRET_ENV,
    Api,
    ApiFactory,
    TestClient,
    settings_for,
)

from ciso.api import create_app
from ciso.app import Container, build_container
from ciso.app.settings import Settings
from ciso.common.clock import FixedClock
from ciso.common.enums import ActorType
from ciso.common.principal import Principal


@pytest.fixture
def make_api(tmp_path: Path) -> Iterator[ApiFactory]:
    built: list[tuple[Container, TestClient]] = []

    def factory(
        settings: Settings | None = None,
        *,
        change: Callable[[Settings], Settings] | None = None,
        rewire: Callable[[Container], Container] | None = None,
        environ: dict[str, str] | None = None,
        **safety: Any,
    ) -> Api:
        """`change` edits the provisional settings before the build; `rewire` swaps a
        service on the built container before the app is made (test doubles only);
        `environ` replaces the secret environment."""
        safety.setdefault("api_rate_limit_per_minute", GENEROUS_LIMIT)
        chosen = settings or settings_for(tmp_path / f"data{len(built)}", **safety)
        if change is not None:
            chosen = change(chosen)
        clock = FixedClock()
        logs = io.StringIO()
        container = build_container(
            chosen,
            environ=dict(SECRET_ENV if environ is None else environ),
            clock=clock,
            scrypt=FAST_SCRYPT,
            log_stream=logs,
        )
        if rewire is not None:
            # A copy that shares the lifecycle: closing either releases everything once.
            container = rewire(container)
        app = create_app(container)
        client = TestClient(app, raise_server_exceptions=False)
        built.append((container, client))
        admin, token = Principal(actor_id="", actor_type=ActorType.HUMAN), ""
        if container.readiness().ready:
            boot = container.host_local.bootstrap_first_admin("First Admin")
            found = container.identity.resolve(boot.actor.id)
            assert found is not None
            admin, token = found, boot.token.token
        return Api(container, app, client, clock, logs, admin, token)

    yield factory
    for container, client in built:
        client.close()
        container.close()


@pytest.fixture
def api(make_api: ApiFactory) -> Api:
    return make_api()
