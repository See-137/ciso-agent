"""Fixtures shared by every test. Module-specific fixtures live next to their tests.

Owned by the coordinator: builders add fixtures in their own test directories.
"""

from __future__ import annotations

import ipaddress
import socket
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from sqlalchemy import Engine
from tests.fakes.core import FakeAudit, FakeKillSwitch, FakeRedactor, FakeSecrets, make_principal

from ciso.common.classification import ClassificationScheme
from ciso.common.clock import FixedClock
from ciso.common.db import create_db_engine, init_operational_schema
from ciso.common.enums import ActorType, Role
from ciso.common.principal import Principal

REPO_ROOT = Path(__file__).resolve().parents[1]


class EgressAttempt(AssertionError):
    """A test tried to open a connection to something other than this machine."""


def _is_loopback(address: Any) -> bool:
    host = address[0] if isinstance(address, tuple) and address else address
    if not isinstance(host, str):
        return False
    if host in {"localhost", ""}:
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


@pytest.fixture(autouse=True)
def egress_guard(monkeypatch: pytest.MonkeyPatch) -> list[Any]:
    """Blueprint 8.4, NFR-003: nothing in this build may reach the network.

    Loopback is allowed because the event loop and the test client use it. Any other
    destination raises, and is also recorded so a test can assert the list is empty even
    if the code under test swallowed the exception.
    """
    attempts: list[Any] = []
    real_connect = socket.socket.connect
    real_connect_ex = socket.socket.connect_ex

    def guarded_connect(self: socket.socket, address: Any) -> None:
        if not _is_loopback(address):
            attempts.append(address)
            raise EgressAttempt(f"network egress attempted: {address!r}")
        real_connect(self, address)

    def guarded_connect_ex(self: socket.socket, address: Any) -> int:
        if not _is_loopback(address):
            attempts.append(address)
            raise EgressAttempt(f"network egress attempted: {address!r}")
        return real_connect_ex(self, address)

    monkeypatch.setattr(socket.socket, "connect", guarded_connect)
    monkeypatch.setattr(socket.socket, "connect_ex", guarded_connect_ex)
    return attempts


@pytest.fixture(autouse=True)
def _no_stray_runtime_data() -> Iterator[None]:
    """Tests write under tmp_path only. A `data/` directory in the repo means a leak."""
    existed = (REPO_ROOT / "data").exists()
    yield
    if not existed:
        assert not (REPO_ROOT / "data").exists(), "a test created data/ in the repository"


@pytest.fixture
def clock() -> FixedClock:
    return FixedClock()


@pytest.fixture
def engine() -> Iterator[Engine]:
    """Private in-memory operational database with every imported table created."""
    eng = create_db_engine(None)
    init_operational_schema(eng)
    yield eng
    eng.dispose()


@pytest.fixture
def data_dir(tmp_path: Path) -> Path:
    path = tmp_path / "data"
    path.mkdir()
    return path


@pytest.fixture
def classification() -> ClassificationScheme:
    """Test-only labels. The real scheme is an open decision (OD-09)."""
    return ClassificationScheme(labels=("public", "internal", "confidential", "restricted"))


@pytest.fixture
def audit(clock: FixedClock) -> FakeAudit:
    return FakeAudit(clock)


@pytest.fixture
def killswitch() -> FakeKillSwitch:
    return FakeKillSwitch()


@pytest.fixture
def secrets() -> FakeSecrets:
    return FakeSecrets()


@pytest.fixture
def redactor() -> FakeRedactor:
    return FakeRedactor()


@pytest.fixture
def admin() -> Principal:
    return make_principal("human_admin", ActorType.HUMAN, Role.SECURITY_ADMIN)


@pytest.fixture
def system_owner() -> Principal:
    return make_principal("human_owner", ActorType.HUMAN, Role.SYSTEM_OWNER)


@pytest.fixture
def risk_owner() -> Principal:
    return make_principal("human_risk", ActorType.HUMAN, Role.EXECUTIVE_RISK_OWNER)


@pytest.fixture
def employee() -> Principal:
    return make_principal("human_emp", ActorType.HUMAN, Role.EMPLOYEE)


@pytest.fixture
def auditor() -> Principal:
    return make_principal("human_aud", ActorType.HUMAN, Role.AUDITOR)


@pytest.fixture
def agent() -> Principal:
    """The CISO orchestrator's own identity. Holds no human role, ever."""
    return make_principal("agent_ciso", ActorType.AGENT)


@pytest.fixture
def service() -> Principal:
    return make_principal("svc_connector", ActorType.SERVICE)
