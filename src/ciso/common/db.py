"""Database plumbing shared by modules that own tables.

Two databases exist: the operational one (`operational_metadata`) and the audit one, which
ciso.audit owns by itself so that ordinary writers never hold a handle to it.
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from sqlalchemy import (
    Column,
    DateTime,
    Engine,
    Integer,
    MetaData,
    String,
    Table,
    create_engine,
    event,
    select,
)
from sqlalchemy.engine import Dialect
from sqlalchemy.pool import StaticPool
from sqlalchemy.types import TypeDecorator

from ciso.common.clock import ensure_utc

NAMING_CONVENTION = {
    "ix": "ix_%(table_name)s_%(column_0_N_name)s",
    "uq": "uq_%(table_name)s_%(column_0_N_name)s",
    "ck": "ck_%(table_name)s_%(constraint_name)s",
    "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
    "pk": "pk_%(table_name)s",
}

#: Every operational table registers here. Modules import this, never each other's tables.
operational_metadata = MetaData(naming_convention=NAMING_CONVENTION)


class UtcDateTime(TypeDecorator[datetime]):
    """Stores UTC, refuses naive values, returns aware values.

    SQLite drops timezone information, so it is reattached on the way out.
    """

    impl = DateTime
    cache_ok = True

    def process_bind_param(self, value: datetime | None, dialect: Dialect) -> datetime | None:
        if value is None:
            return None
        return ensure_utc(value).replace(tzinfo=None)

    def process_result_value(self, value: datetime | None, dialect: Dialect) -> datetime | None:
        if value is None:
            return None
        return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)


def create_db_engine(path: Path | str | None) -> Engine:
    """Open a SQLite database. `None` gives a private in-memory database for tests."""
    if path is None:
        engine = create_engine(
            "sqlite://", poolclass=StaticPool, connect_args={"check_same_thread": False}
        )
    else:
        file = Path(path)
        file.parent.mkdir(parents=True, exist_ok=True)
        engine = create_engine(f"sqlite:///{file.as_posix()}")

    @event.listens_for(engine, "connect")
    def _pragmas(dbapi_connection: Any, _record: Any) -> None:
        cursor = dbapi_connection.cursor()
        try:
            cursor.execute("PRAGMA foreign_keys=ON")
            cursor.execute("PRAGMA busy_timeout=5000")
            if path is not None:
                cursor.execute("PRAGMA journal_mode=WAL")
                cursor.execute("PRAGMA synchronous=FULL")
        finally:
            cursor.close()

    return engine


schema_version = Table(
    "schema_version",
    operational_metadata,
    Column("module", String(64), primary_key=True),
    Column("version", Integer, nullable=False),
)

#: module name -> schema version. Each module's tables.py calls register_schema().
_REGISTERED: dict[str, int] = {}


def register_schema(module: str, version: int) -> None:
    """Declare that `module` owns tables at `version`. Called at import time by tables.py."""
    if version < 1:
        raise ValueError("schema version starts at 1")
    _REGISTERED[module] = version


def init_operational_schema(engine: Engine) -> None:
    """Create every registered operational table and record module versions.

    Safe to call again. A stored version newer than the code refuses to start, because
    this build has no downgrade path. Upgrades need a migration tool (ADR-0002, open).
    """
    operational_metadata.create_all(engine)
    with engine.begin() as conn:
        stored = {row.module: row.version for row in conn.execute(select(schema_version))}
        for module, version in sorted(_REGISTERED.items()):
            have = stored.get(module)
            if have is None:
                conn.execute(schema_version.insert().values(module=module, version=version))
            elif have != version:
                raise RuntimeError(
                    f"schema for {module!r} is at version {have}, code expects {version}; "
                    "no migration path exists in this build"
                )


def registered_schemas() -> dict[str, int]:
    return dict(_REGISTERED)
