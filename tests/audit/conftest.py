"""Fixtures for the audit tests: a file-backed audit database, an anchor and a witness in
directories of their own (never beside the database)."""

from __future__ import annotations

from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

import pytest
from sqlalchemy import Engine
from tests.audit.helpers import (
    ANCHOR_KEY_REF,
    ANCHOR_KEY_VALUE,
    REDACTED_SECRET,
    WITNESS_KEY_REF,
    WITNESS_KEY_VALUE,
)
from tests.fakes.core import FakeRedactor, FakeSecrets

from ciso.audit import AuditLog, HeadAnchor, init_audit_schema
from ciso.common.clock import FixedClock
from ciso.common.db import create_db_engine


@pytest.fixture
def audit_db_path(tmp_path: Path) -> Path:
    return tmp_path / "db" / "audit.db"


@pytest.fixture
def anchor_path(tmp_path: Path) -> Path:
    return tmp_path / "anchor" / "audit.anchor.json"


@pytest.fixture
def witness_path(tmp_path: Path) -> Path:
    return tmp_path / "witness" / "heads.jsonl"


@pytest.fixture
def audit_engine(audit_db_path: Path) -> Iterator[Engine]:
    eng = create_db_engine(audit_db_path)
    init_audit_schema(eng)
    yield eng
    eng.dispose()


@pytest.fixture
def anchor_secrets() -> FakeSecrets:
    return FakeSecrets({ANCHOR_KEY_REF: ANCHOR_KEY_VALUE, WITNESS_KEY_REF: WITNESS_KEY_VALUE})


@pytest.fixture
def audit_redactor() -> FakeRedactor:
    return FakeRedactor(REDACTED_SECRET)


@pytest.fixture
def head_anchor(anchor_path: Path, anchor_secrets: FakeSecrets) -> HeadAnchor:
    return HeadAnchor(anchor_path, anchor_secrets, ANCHOR_KEY_REF)


@pytest.fixture
def make_log(
    audit_engine: Engine, clock: FixedClock, audit_redactor: FakeRedactor, head_anchor: HeadAnchor
) -> Callable[..., AuditLog]:
    """Build an AuditLog; any constructor argument can be overridden by keyword."""

    def build(**overrides: Any) -> AuditLog:
        engine = overrides.pop("engine", audit_engine)
        redactor = overrides.pop("redactor", audit_redactor)
        anchor = overrides.pop("anchor", head_anchor)
        return AuditLog(engine, clock, redactor, anchor, **overrides)

    return build


@pytest.fixture
def audit_log(make_log: Callable[..., AuditLog]) -> AuditLog:
    """An initialised, empty log."""
    log = make_log()
    log.initialise()
    return log
