"""The start-up integrity gate is wired into the composition root (blueprint 10.3, 11.2,
NFR-018; M1 fix pass item 9).

The container runs the `ciso.ops` start-up sequence, which walks the audit chain. A log
that fails or cannot be verified blocks writes through `GatedKillSwitch`, the only
kill-switch reader the container hands out; state-changing API requests are refused while
read routes keep answering.
"""

from __future__ import annotations

import warnings
from collections.abc import Iterator
from pathlib import Path
from typing import Annotated

import pytest
from fastapi import Depends
from tests.app.helpers import SECRET_ENV, build, event, provisional

from ciso.api import create_app, require
from ciso.app import Container
from ciso.app.settings import Settings
from ciso.common.enums import KillCapability
from ciso.common.principal import Principal
from ciso.ops import GatedKillSwitch, IntegrityStatus

with warnings.catch_warnings():
    warnings.filterwarnings("ignore", message="Using `httpx` with `starlette.testclient`")
    from fastapi.testclient import TestClient

pytestmark = pytest.mark.resilience

W = KillCapability.WRITES
WRITE_ROUTE = "/v1/test/write"
MANAGE = require("identity.manage")


def first_start(settings: Settings) -> str:
    """Build once, bootstrap an admin, write a few records; return the admin's token."""
    with build(settings, SECRET_ENV) as c:
        assert c.readiness().ready is True, c.readiness().missing
        token = c.host_local.bootstrap_first_admin("First Admin").token.token
        for n in range(3):
            c.audit.append(event(n))
    return token


def raw_audit_sql(settings: Settings, *statements: str) -> None:
    from sqlalchemy import create_engine

    engine = create_engine(f"sqlite:///{settings.audit_db}")
    try:
        with engine.begin() as conn:
            for statement in statements:
                conn.exec_driver_sql(statement)
    finally:
        engine.dispose()


def tamper_a_middle_record(settings: Settings) -> None:
    raw_audit_sql(
        settings,
        "DROP TRIGGER audit_record_no_update",
        "UPDATE audit_record SET target = 'asset:forged' WHERE seq = 2",
    )


@pytest.fixture
def settings(tmp_path: Path) -> Settings:
    return provisional(tmp_path / "d")


@pytest.fixture
def client_for() -> Iterator[object]:
    opened: list[tuple[Container, TestClient]] = []

    def make(settings: Settings) -> tuple[Container, TestClient]:
        container = build(settings, SECRET_ENV)
        app = create_app(container)

        def handler(_: Annotated[Principal, Depends(MANAGE)]) -> dict[str, str]:
            return {"done": "yes"}

        app.add_api_route(WRITE_ROUTE, handler, methods=["POST"])
        client = TestClient(app, raise_server_exceptions=False)
        opened.append((container, client))
        return container, client

    yield make
    for container, client in opened:
        client.close()
        container.close()


def assert_reads_answer(client: TestClient, token: str) -> None:
    h = {"Authorization": f"Bearer {token}"}
    assert client.get("/healthz").status_code == 200
    assert client.get("/v1/system/health", headers=h).status_code == 200
    assert client.get("/v1/system/whoami", headers=h).status_code == 200
    assert client.get("/v1/audit", params={"limit": 5}, headers=h).status_code == 200


class TestGateWiring:
    def test_the_container_hands_out_the_gated_reader(self, settings: Settings) -> None:
        first_start(settings)
        with build(settings, SECRET_ENV) as c:
            assert isinstance(c.killswitch_reader, GatedKillSwitch)
            assert c.killswitch_reader is not c.killswitch

    def test_an_untampered_restart_is_clear(self, settings: Settings, client_for: object) -> None:
        token = first_start(settings)
        container, client = client_for(settings)  # type: ignore[operator]
        assert container.readiness().ready is True, container.readiness().missing
        assert container.startup_report.audit_status is IntegrityStatus.OK
        assert container.killswitch_reader.is_blocked(W) is False
        r = client.post(WRITE_ROUTE, headers={"Authorization": f"Bearer {token}"})
        assert r.status_code == 200, r.text
        assert_reads_answer(client, token)

    def test_a_tampered_audit_log_blocks_writes(
        self, settings: Settings, client_for: object
    ) -> None:
        token = first_start(settings)
        tamper_a_middle_record(settings)
        container, client = client_for(settings)  # type: ignore[operator]
        report = container.startup_report
        assert report.audit_status is IntegrityStatus.FAILED
        assert report.writes_blocked is True
        assert container.killswitch_reader.is_blocked(W) is True
        assert container.killswitch_reader.is_blocked(KillCapability.L3_RUNS) is True
        assert container.killswitch.is_blocked(W) is False  # the operator switch is clear
        assert any(m.startswith("audit_integrity (failed") for m in container.readiness().missing)
        r = client.post(WRITE_ROUTE, headers={"Authorization": f"Bearer {token}"})
        assert r.status_code == 503
        assert r.json()["error"] == "writes_blocked"
        assert_reads_answer(client, token)
        components = {c.name: c for c in container.health.aggregate().components}
        assert components["audit_integrity"].state.value == "unhealthy"

    def test_a_deleted_anchor_is_unverifiable_and_blocks_writes(
        self, settings: Settings, client_for: object
    ) -> None:
        token = first_start(settings)
        settings.audit_anchor.unlink()
        container, client = client_for(settings)  # type: ignore[operator]
        assert container.startup_report.audit_status is IntegrityStatus.UNVERIFIABLE
        assert container.killswitch_reader.is_blocked(W) is True
        assert container.killswitch_reader.is_blocked(KillCapability.EXTERNAL_INFERENCE) is True
        assert any(
            m.startswith("audit_integrity (unverifiable") for m in container.readiness().missing
        )
        r = client.post(WRITE_ROUTE, headers={"Authorization": f"Bearer {token}"})
        assert r.status_code == 503
        assert r.json()["error"] == "writes_blocked"
        assert_reads_answer(client, token)

    def test_kill_switch_routes_still_work_while_writes_are_gated(
        self, settings: Settings, client_for: object
    ) -> None:
        token = first_start(settings)
        tamper_a_middle_record(settings)
        container, client = client_for(settings)  # type: ignore[operator]
        h = {"Authorization": f"Bearer {token}"}
        body = {"capabilities": ["writes"], "reason": "incident"}
        assert client.post("/v1/killswitch/engage", json=body, headers=h).status_code == 200
        assert container.killswitch.is_blocked(W) is True
        assert client.get("/v1/killswitch", headers=h).status_code == 200
