"""Plain helpers for the audit tests (not fixtures)."""

from __future__ import annotations

import shutil
from pathlib import Path

from sqlalchemy import Engine, text

from ciso.common.enums import ActorType, AuditOutcome
from ciso.common.protocols import AuditEvent

ANCHOR_KEY_REF = "secret://audit_anchor_key"
ANCHOR_KEY_VALUE = "anchor-key-for-audit-tests-7f3a9c0b5e"
WITNESS_KEY_REF = "secret://audit_witness_key"
WITNESS_KEY_VALUE = "witness-key-for-audit-tests-11d0e2f4a8"
REDACTED_SECRET = "s3cr3t-token-value-XYZ987"


def make_event(n: int = 0, **overrides: object) -> AuditEvent:
    fields: dict[str, object] = {
        "actor_id": "human_admin",
        "actor_type": ActorType.HUMAN,
        "action": "test.event",
        "target": f"asset:{n}",
        "outcome": AuditOutcome.SUCCESS,
        "correlation_id": f"corr_{n}",
        "details": {"n": n},
    }
    fields.update(overrides)
    return AuditEvent.model_validate(fields)


def raw_sql(engine: Engine, *statements: str) -> None:
    """Run SQL as an attacker with file access would: no audit code involved."""
    with engine.begin() as conn:
        for statement in statements:
            conn.exec_driver_sql(statement)


def raw_exec(engine: Engine, statement: str, **params: object) -> None:
    """One attacker statement with bound parameters."""
    with engine.begin() as conn:
        conn.execute(text(statement), params)


def raw_scalar(engine: Engine, statement: str, **params: object) -> object:
    with engine.begin() as conn:
        return conn.execute(text(statement), params).scalar()


def drop_triggers(engine: Engine) -> None:
    raw_sql(
        engine,
        "DROP TRIGGER audit_record_no_update",
        "DROP TRIGGER audit_record_no_delete",
        "DROP TRIGGER audit_record_chain_order",
    )


def db_files(db_path: Path) -> list[Path]:
    """The database file and its WAL companions, whichever exist."""
    return [p for p in db_path.parent.iterdir() if p.name.startswith(db_path.name)]


def copy_db(db_path: Path, dest: Path) -> None:
    """Snapshot a closed database (all engines disposed) into `dest`."""
    dest.mkdir(parents=True, exist_ok=True)
    for path in db_files(db_path):
        shutil.copy2(path, dest / path.name)


def restore_db(snapshot: Path, db_path: Path) -> None:
    """Put a snapshot back over a closed database, as an attacker restoring a copy would."""
    for path in db_files(db_path):
        path.unlink()
    for path in snapshot.iterdir():
        shutil.copy2(path, db_path.parent / path.name)
