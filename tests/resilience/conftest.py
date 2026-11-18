"""Fixtures for the ops (backup, restore, restart) tests.

Every fixture here is prefixed `ops_` and none is autouse, so `test_queue_recovery.py`
(another lane) is unaffected: it neither requests nor shadows any of them.
"""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

import pytest
from sqlalchemy import Engine
from tests.fakes.core import FakeRedactor, FakeSecrets, make_principal

from ciso.audit import AuditLog, HeadAnchor, init_audit_schema
from ciso.common.clock import FixedClock
from ciso.common.db import create_db_engine, init_operational_schema
from ciso.common.enums import ActorType, Role
from ciso.common.principal import Principal
from ciso.common.protocols import AuditEvent, AuditReceipt, AuditSink
from ciso.killswitch import KillSwitch
from ciso.workflows import JobQueue

ANCHOR_KEY_REF = "secret://audit_anchor_key"
ANCHOR_KEY = "anchor-key-for-ops-tests-91c2e7d40b5a"
BACKUP_KEY_REF = "secret://backup_key"
BACKUP_KEY = "backup-key-for-ops-tests-4be8a0d1f37c"
KILLSWITCH_KEY_REF = "secret://killswitch_key"
KILLSWITCH_KEY = "killswitch-key-for-ops-tests-77d0aa"
ADMIN = make_principal("human_admin", ActorType.HUMAN, Role.SECURITY_ADMIN)


class SwitchableSink:
    """Wraps a real sink; `fail = True` makes every append raise."""

    def __init__(self, inner: AuditSink) -> None:
        self.inner = inner
        self.fail = False

    def append(self, event: AuditEvent) -> AuditReceipt:
        if self.fail:
            raise RuntimeError("audit sink unavailable (test)")
        return self.inner.append(event)


class _Directory:
    """Principal resolver that knows the one admin."""

    def resolve(self, actor_id: str) -> Principal | None:
        return ADMIN if actor_id == ADMIN.actor_id else None


class Platform:
    """One "process" worth of engines and services over the files of an `OpsWorld`."""

    def __init__(self, world: OpsWorld) -> None:
        self.world = world
        self.op_engine = create_db_engine(world.op_db)
        self.audit_engine = create_db_engine(world.audit_db)
        world.engines.extend([self.op_engine, self.audit_engine])
        init_operational_schema(self.op_engine)
        init_audit_schema(self.audit_engine)
        anchor = HeadAnchor(world.anchor, world.secrets, ANCHOR_KEY_REF)
        self.audit_log = AuditLog(
            self.audit_engine,
            world.clock,
            FakeRedactor(),
            anchor,
            expected_log_id=world.log_id,
        )
        if world.log_id is None:
            world.log_id = self.audit_log.initialise()
        self.sink = SwitchableSink(self.audit_log)
        self.killswitch = KillSwitch(
            engine=self.op_engine,
            audit=self.sink,
            clock=world.clock,
            principals=_Directory(),
            secrets=world.secrets,
            key_ref=KILLSWITCH_KEY_REF,
        )
        self.queue = JobQueue(
            self.op_engine,
            world.clock,
            self.sink,
            _Directory(),
            lease_seconds=30,
            max_attempts=3,
            backoff_base_seconds=10,
            backoff_max_seconds=60,
        )

    @property
    def engines(self) -> dict[str, Engine]:
        return {"operational": self.op_engine, "audit": self.audit_engine}

    def crash(self) -> None:
        """Drop every handle without any orderly shutdown."""
        self.op_engine.dispose()
        self.audit_engine.dispose()


class OpsWorld:
    """Files of one installation under `root/data`, laid out like the backup members."""

    def __init__(self, root: Path) -> None:
        self.root = root
        self.data = root / "data"
        self.op_db = self.data / "db" / "ciso.db"
        self.audit_db = self.data / "db" / "audit.db"
        self.anchor = self.data / "anchor" / "audit-head.json"
        self.evidence = self.data / "evidence"
        self.clock = FixedClock()
        self.secrets = self.secrets_with_backup_key(BACKUP_KEY)
        self.engines: list[Engine] = []
        self.log_id: str | None = None
        self.admin = ADMIN
        self.anchor_key_ref = ANCHOR_KEY_REF
        self.backup_key_ref = BACKUP_KEY_REF

    def secrets_with_backup_key(self, value: str) -> FakeSecrets:
        return FakeSecrets(
            {ANCHOR_KEY_REF: ANCHOR_KEY, BACKUP_KEY_REF: value, KILLSWITCH_KEY_REF: KILLSWITCH_KEY}
        )

    def start(self) -> Platform:
        return Platform(self)

    def close(self) -> None:
        for engine in self.engines:
            engine.dispose()


@pytest.fixture
def ops_world(tmp_path: Path) -> Iterator[OpsWorld]:
    world = OpsWorld(tmp_path)
    yield world
    world.close()
