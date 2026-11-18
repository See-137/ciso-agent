"""Identity fixtures. Importing the tables module first registers them before `engine`.

The shared `admin` fixture is a made-up Principal with no database row; identity now
refuses such objects (review H2), so these tests use a real admin created by bootstrap.
"""

from __future__ import annotations

from collections.abc import Callable
from datetime import timedelta

import pytest
from sqlalchemy import Engine
from tests.fakes.core import FakeAudit

import ciso.identity.tables  # noqa: F401 - registers the identity tables
from ciso.common.classification import ClassificationScheme
from ciso.common.clock import Clock, FixedClock
from ciso.common.enums import AuditOutcome
from ciso.common.errors import FailClosed
from ciso.common.principal import Principal
from ciso.common.protocols import AuditEvent, AuditReceipt
from ciso.identity.authn import Authenticator, ScryptParams
from ciso.identity.hostlocal import BootstrapResult, HostLocalAdmin
from ciso.identity.service import IdentityService

#: Deliberately weak so each test stays fast. Production uses PRODUCTION_SCRYPT.
FAST_SCRYPT = ScryptParams(n=16, r=1, p=1)
MAX_TTL = timedelta(hours=8)


class SelectiveAudit(FakeAudit):
    """FakeAudit that can refuse only some outcomes, e.g. only the RESULT record.

    `on_append` runs before each event is recorded; tests use it to change the database
    between a pre-check and the write transaction, as a concurrent caller would.
    """

    def __init__(self, clock: Clock | None = None) -> None:
        super().__init__(clock)
        self.fail_outcomes: set[AuditOutcome] = set()
        self.on_append: Callable[[AuditEvent], None] | None = None

    def append(self, event: AuditEvent) -> AuditReceipt:
        if event.outcome in self.fail_outcomes:
            raise FailClosed("audit path unavailable")
        if self.on_append is not None:
            self.on_append(event)
        return super().append(event)


@pytest.fixture
def audit(clock: FixedClock) -> SelectiveAudit:
    return SelectiveAudit(clock)


@pytest.fixture
def identity(
    engine: Engine, clock: FixedClock, audit: FakeAudit, classification: ClassificationScheme
) -> IdentityService:
    return IdentityService(engine, clock, audit, classification)


@pytest.fixture
def authn(
    engine: Engine, clock: FixedClock, audit: FakeAudit, identity: IdentityService
) -> Authenticator:
    return Authenticator(engine, clock, audit, identity, max_token_ttl=MAX_TTL, scrypt=FAST_SCRYPT)


@pytest.fixture
def hostlocal(
    engine: Engine, clock: FixedClock, audit: FakeAudit, authn: Authenticator
) -> HostLocalAdmin:
    return HostLocalAdmin(engine, clock, audit, authn.minter)


@pytest.fixture
def root(hostlocal: HostLocalAdmin) -> BootstrapResult:
    return hostlocal.bootstrap_first_admin("First Admin")


@pytest.fixture
def root_admin(root: BootstrapResult, identity: IdentityService) -> Principal:
    """A real, current, human security_admin as identity resolves it."""
    principal = identity.resolve(root.actor.id)
    assert principal is not None
    return principal
