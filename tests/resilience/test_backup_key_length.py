"""The backup archive key must be at least `MIN_KEY_BYTES` long (item 3, M1 fix pass)."""

from __future__ import annotations

from typing import Any

import pytest
from tests.fakes.core import FakeAudit
from tests.resilience.test_backup_restore import ADMIN, backup_service, populate, sources

from ciso.common.errors import FailClosed
from ciso.ops.backup import resolve_secret
from ciso.vault import MIN_KEY_BYTES

pytestmark = pytest.mark.resilience

SHORT = "b" * (MIN_KEY_BYTES - 1)
LONG = "b" * MIN_KEY_BYTES


def test_resolve_secret_refuses_31_bytes_and_accepts_32(ops_world: Any) -> None:
    ref = ops_world.backup_key_ref
    with pytest.raises(FailClosed) as info:
        resolve_secret(ops_world.secrets_with_backup_key(SHORT), ref, "backup")
    assert ref in str(info.value)
    assert SHORT not in str(info.value)
    assert resolve_secret(ops_world.secrets_with_backup_key(LONG), ref, "backup") == LONG.encode()


def test_backup_with_a_short_key_writes_nothing(ops_world: Any) -> None:
    populate(ops_world)
    service = backup_service(
        ops_world, FakeAudit(), secrets=ops_world.secrets_with_backup_key(SHORT)
    )
    with pytest.raises(FailClosed):
        service.create(sources(ops_world), ops_world.root / "b", ADMIN)
    assert not (ops_world.root / "b").exists()


def test_backup_with_a_32_byte_key_is_created(ops_world: Any) -> None:
    populate(ops_world)
    service = backup_service(
        ops_world, FakeAudit(), secrets=ops_world.secrets_with_backup_key(LONG)
    )
    manifest = service.create(sources(ops_world), ops_world.root / "b", ADMIN)
    assert (ops_world.root / "b" / manifest.file_name).is_file()
