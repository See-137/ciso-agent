"""Kill-switch fixtures. Importing the tables here registers them before `engine` runs."""

from __future__ import annotations

from collections.abc import Callable, Iterator
from pathlib import Path

import pytest
from sqlalchemy import Engine
from tests.fakes.core import FakeAudit, FakePrincipals, FakeSecrets

from ciso.common.clock import Clock, FixedClock
from ciso.common.db import create_db_engine, init_operational_schema
from ciso.common.enums import AuditOutcome, KillCapability
from ciso.common.errors import FailClosed
from ciso.common.protocols import AuditEvent, AuditReceipt
from ciso.killswitch import KillSwitch, KillSwitchRecord
from ciso.killswitch.models import ENGAGE_ACTION, INITIALISE_ACTION, RELEASE_ACTION

KEY_REF = "secret://killswitch_key"
KEY_VALUE = "k" * 16 + "-test-only-mac-key"


class ScriptedAudit(FakeAudit):
    """FakeAudit whose failures can target one kind of record.

    `fail_if(event) -> True` makes that append raise; `during(event)` runs inside the
    append before it is recorded (to probe locks, race a second instance, etc.).
    """

    def __init__(self, clock: Clock | None = None) -> None:
        super().__init__(clock)
        self.fail_if: Callable[[AuditEvent], bool] | None = None
        self.during: Callable[[AuditEvent], None] | None = None

    def append(self, event: AuditEvent) -> AuditReceipt:
        if self.during is not None:
            self.during(event)
        if self.fail_if is not None and self.fail_if(event):
            raise FailClosed("audit path unavailable (scripted)")
        return super().append(event)

    def outcomes(self, action: str) -> list[AuditOutcome]:
        return [e.outcome for e in self.find(action)]


class AuditHistory:
    """`KillSwitchHistory` read from the sink's recorded events, as the real one will be."""

    def __init__(self, audit: FakeAudit) -> None:
        self._audit = audit
        self.extra: list[KillSwitchRecord] = []
        self.broken = False

    def last_killswitch_record(
        self, capability: KillCapability | None = None
    ) -> KillSwitchRecord | None:
        if self.broken:
            raise FailClosed("audit log unreadable")
        records = [
            KillSwitchRecord(
                action=e.action,
                capabilities=tuple(KillCapability(c) for c in e.details["capabilities"]),
            )
            for e in self._audit.events
            if e.outcome is AuditOutcome.SUCCESS
            and e.action in (ENGAGE_ACTION, RELEASE_ACTION, INITIALISE_ACTION)
        ] + self.extra
        for record in reversed(records):
            if capability is None or capability in record.capabilities:
                return record
        return None


class SleepRecorder:
    def __init__(self) -> None:
        self.calls: list[float] = []
        self.hook: Callable[[int], None] | None = None

    def __call__(self, seconds: float) -> None:
        self.calls.append(seconds)
        if self.hook is not None:
            self.hook(len(self.calls))


@pytest.fixture
def audit(clock: FixedClock) -> ScriptedAudit:
    return ScriptedAudit(clock)


@pytest.fixture
def key_secrets() -> FakeSecrets:
    return FakeSecrets({KEY_REF: KEY_VALUE})


@pytest.fixture
def history(audit: ScriptedAudit) -> AuditHistory:
    return AuditHistory(audit)


@pytest.fixture
def sleeper() -> SleepRecorder:
    return SleepRecorder()


@pytest.fixture
def make_switch(
    audit: ScriptedAudit,
    clock: FixedClock,
    principals: FakePrincipals,
    key_secrets: FakeSecrets,
    history: AuditHistory,
    sleeper: SleepRecorder,
) -> Callable[..., KillSwitch]:
    def make(engine: Engine, **overrides: object) -> KillSwitch:
        args: dict[str, object] = {
            "engine": engine,
            "audit": audit,
            "clock": clock,
            "principals": principals,
            "secrets": key_secrets,
            "key_ref": KEY_REF,
            "history": history,
            "sleep": sleeper,
        }
        args.update(overrides)
        return KillSwitch(**args)  # type: ignore[arg-type]

    return make


@pytest.fixture
def switch(engine: Engine, make_switch: Callable[..., KillSwitch]) -> KillSwitch:
    ks = make_switch(engine)
    ks.initialise()
    return ks


@pytest.fixture
def file_db(tmp_path: Path) -> Iterator[tuple[Path, Engine]]:
    path = tmp_path / "ops.db"
    eng = create_db_engine(path)
    init_operational_schema(eng)
    yield path, eng
    eng.dispose()
