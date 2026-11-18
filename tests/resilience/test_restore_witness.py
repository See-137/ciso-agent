"""A restore behind the audit witness is reported and starts with writes blocked (M1 fix
pass item 11, report-and-block part; blueprint 10.3, review C1)."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
from tests.fakes.core import FakeAudit, FakeRedactor, FakeSecrets
from tests.resilience.test_backup_restore import ADMIN, make_backup, populate

from ciso.audit import AuditLog, FileHeadWitness, HeadAnchor
from ciso.common.db import create_db_engine
from ciso.common.enums import KillCapability
from ciso.observability import HealthRegistry
from ciso.ops import (
    AwaitingReports,
    GatedKillSwitch,
    IntegrityState,
    IntegrityStatus,
    RestoreService,
)
from ciso.ops.backup import ANCHOR_MEMBER, AUDIT_MEMBER
from ciso.ops.lifecycle import startup
from ciso.ops.restore import RESTORED_BEHIND_WITNESS

pytestmark = pytest.mark.resilience

WITNESS_REF = "secret://audit_witness_key"
WITNESS_SECRETS = FakeSecrets({WITNESS_REF: "witness-key-for-restore-tests-5c1e9a"})
LATER = datetime(2026, 11, 18, tzinfo=UTC)


def witness_at(path: Path) -> FileHeadWitness:
    return FileHeadWitness(path, WITNESS_SECRETS, WITNESS_REF)


def restore_with(world: Any, witness: FileHeadWitness | None, name: str = "restored") -> Any:
    archive = make_backup(world, FakeAudit())
    service = RestoreService(
        world.secrets,
        world.clock,
        FakeAudit(),
        FakeRedactor(),
        key_ref=world.backup_key_ref,
        audit_key_ref=world.anchor_key_ref,
        witness=witness,
    )
    return service.restore(archive, world.root / name, ADMIN)


def test_a_restore_behind_the_witness_is_reported_with_both_seqs(ops_world: Any) -> None:
    populate(ops_world)  # three records: head seq 3
    witness = witness_at(ops_world.root / "witness" / "heads.jsonl")
    assert ops_world.log_id is not None
    witness.publish(ops_world.log_id, 5, "b" * 64, LATER)  # the live log went on to seq 5
    report = restore_with(ops_world, witness)
    assert report.audit_verified is True  # against its own anchor
    assert report.witness_gap == (3, 5)
    named = [w for w in report.warnings if w.startswith(RESTORED_BEHIND_WITNESS)]
    assert named == [f"{RESTORED_BEHIND_WITNESS} (restored seq 3, witnessed seq 5)"]


def test_a_restore_level_with_the_witness_has_no_gap(ops_world: Any) -> None:
    populate(ops_world)
    witness = witness_at(ops_world.root / "witness" / "heads.jsonl")
    report = restore_with(ops_world, witness)
    assert report.witness_gap is None
    assert not [w for w in report.warnings if w.startswith(RESTORED_BEHIND_WITNESS)]


def test_without_a_witness_nothing_is_compared(ops_world: Any) -> None:
    populate(ops_world)
    report = restore_with(ops_world, None)
    assert report.witness_gap is None


def test_the_restored_instance_starts_with_writes_blocked(ops_world: Any) -> None:
    populate(ops_world)
    witness = witness_at(ops_world.root / "witness" / "heads.jsonl")
    assert ops_world.log_id is not None
    witness.publish(ops_world.log_id, 5, "b" * 64, LATER)
    report = restore_with(ops_world, witness)
    target = report.target_dir
    platform = ops_world.start()  # for its kill switch and clock only
    engine = create_db_engine(target / AUDIT_MEMBER)
    try:
        anchor = HeadAnchor(target / ANCHOR_MEMBER, ops_world.secrets, ops_world.anchor_key_ref)
        restored = AuditLog(
            engine,
            ops_world.clock,
            FakeRedactor(),
            anchor,
            expected_log_id=ops_world.log_id,
            witness=witness,
            witness_every=1,
        )
        integrity = IntegrityState()
        result = startup(
            operational_engine=platform.op_engine,
            audit_log=restored,
            killswitch=platform.killswitch,
            integrity=integrity,
            health=HealthRegistry(
                ops_world.clock, check_timeout_seconds=2, redactor=FakeRedactor()
            ),
            awaiting=AwaitingReports(()),
            clock=ops_world.clock,
        )
    finally:
        engine.dispose()
    assert result.audit_status is IntegrityStatus.FAILED
    assert result.audit_reason == "rolled_back"
    assert GatedKillSwitch(platform.killswitch, integrity).is_blocked(KillCapability.WRITES)
