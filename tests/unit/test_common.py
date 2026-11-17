from __future__ import annotations

from collections.abc import Iterator
from datetime import UTC, datetime, timedelta, timezone
from pathlib import Path

import pytest
from pydantic import ValidationError
from sqlalchemy import Column, Engine, MetaData, String, Table, insert, select

from ciso.common.clock import FixedClock, SystemClock, ensure_utc
from ciso.common.db import UtcDateTime, create_db_engine
from ciso.common.enums import ActorType, AuthorityLevel, Role
from ciso.common.errors import ValidationFailed
from ciso.common.ids import EntityRef, entity_ref, is_id, new_id
from ciso.common.principal import Principal
from ciso.common.schemas import Model, UtcDatetime, canonical_json, content_hash

pytestmark = pytest.mark.unit


class TestIds:
    def test_ids_are_prefixed_and_valid(self) -> None:
        ident = new_id("fnd")
        assert ident.startswith("fnd_")
        assert is_id(ident)
        assert is_id(ident, "fnd")
        assert not is_id(ident, "rsk")

    def test_ids_sort_by_creation_time(self) -> None:
        early = new_id("evt", at_ms=1_000)
        late = new_id("evt", at_ms=2_000)
        assert early < late

    def test_ids_are_unique(self) -> None:
        assert len({new_id("x1", at_ms=5) for _ in range(500)}) == 500

    @pytest.mark.parametrize("prefix", ["", "A", "1ab", "has space", "waytoolongprefix"])
    def test_bad_prefix_is_rejected(self, prefix: str) -> None:
        with pytest.raises(ValidationFailed):
            new_id(prefix)

    def test_entity_ref_round_trip(self) -> None:
        ref = EntityRef.parse("asset:ast_123")
        assert ref == EntityRef("asset", "ast_123")
        assert str(ref) == "asset:ast_123"
        assert entity_ref("ai_asset", "x:y") == "ai_asset:x:y"

    @pytest.mark.parametrize("value", ["", "asset", ":id", "Asset:1", "asset:", "asset:a b"])
    def test_bad_entity_ref_is_rejected(self, value: str) -> None:
        with pytest.raises(ValidationFailed):
            EntityRef.parse(value)


class TestClock:
    def test_system_clock_is_utc_aware(self) -> None:
        assert SystemClock().now().tzinfo is UTC

    def test_fixed_clock_only_moves_when_told(self) -> None:
        clock = FixedClock()
        first = clock.now()
        assert clock.now() == first
        clock.advance(minutes=5)
        assert clock.now() - first == timedelta(minutes=5)

    def test_naive_datetime_is_rejected(self) -> None:
        with pytest.raises(ValueError, match="naive"):
            ensure_utc(datetime(2026, 1, 1))  # noqa: DTZ001
        with pytest.raises(ValueError, match="timezone-aware"):
            FixedClock(datetime(2026, 1, 1))  # noqa: DTZ001

    def test_aware_datetime_is_normalised_to_utc(self) -> None:
        plus_two = datetime(2026, 1, 1, 14, 0, tzinfo=timezone(timedelta(hours=2)))
        assert ensure_utc(plus_two) == datetime(2026, 1, 1, 12, 0, tzinfo=UTC)
        assert ensure_utc(plus_two).tzinfo is UTC


class TestEnums:
    def test_authority_levels_are_ordered(self) -> None:
        assert (
            AuthorityLevel.L2_COORDINATE < AuthorityLevel.L3_EXECUTE < AuthorityLevel.L4_HIGH_IMPACT
        )


class _Sample(Model):
    name: str
    when: UtcDatetime


class TestSchemas:
    def test_unknown_fields_are_an_error(self) -> None:
        with pytest.raises(ValidationError):
            _Sample.model_validate({"name": "a", "when": "2026-01-01T00:00:00Z", "extra": 1})

    def test_models_are_frozen(self) -> None:
        sample = _Sample(name="a", when=datetime(2026, 1, 1, tzinfo=UTC))
        with pytest.raises(ValidationError):
            sample.name = "b"  # type: ignore[misc]

    def test_naive_datetime_field_is_rejected(self) -> None:
        with pytest.raises(ValidationError):
            _Sample(name="a", when=datetime(2026, 1, 1))  # noqa: DTZ001

    def test_canonical_json_ignores_key_order(self) -> None:
        assert canonical_json({"b": 1, "a": [2, 3]}) == canonical_json({"a": [2, 3], "b": 1})
        assert canonical_json({"a": 1}) == '{"a":1}'

    def test_content_hash_changes_with_content(self) -> None:
        one = content_hash({"target": "a", "op": "x"})
        assert one == content_hash({"op": "x", "target": "a"})
        assert one != content_hash({"target": "b", "op": "x"})
        assert len(one) == 64


class TestPrincipal:
    def test_human_can_hold_admin(self) -> None:
        principal = Principal(
            actor_id="h1", actor_type=ActorType.HUMAN, roles=frozenset({Role.SECURITY_ADMIN})
        )
        assert principal.is_human
        assert principal.has_role(Role.SECURITY_ADMIN)

    @pytest.mark.parametrize("actor_type", [ActorType.AGENT, ActorType.SERVICE])
    @pytest.mark.parametrize(
        "role",
        [Role.SECURITY_ADMIN, Role.SYSTEM_OWNER, Role.EXECUTIVE_RISK_OWNER, Role.AUDITOR],
    )
    def test_agents_and_services_cannot_hold_human_roles(
        self, actor_type: ActorType, role: Role
    ) -> None:
        with pytest.raises(ValidationError, match="cannot hold"):
            Principal(actor_id="a1", actor_type=actor_type, roles=frozenset({role}))


class TestDb:
    @pytest.fixture
    def mem(self) -> Iterator[tuple[Engine, Table]]:
        engine = create_db_engine(None)
        metadata = MetaData()
        table = Table(
            "t", metadata, Column("id", String, primary_key=True), Column("at", UtcDateTime)
        )
        metadata.create_all(engine)
        yield engine, table
        engine.dispose()

    def test_datetimes_round_trip_as_aware_utc(self, mem: tuple[Engine, Table]) -> None:
        engine, table = mem
        moment = datetime(2026, 11, 17, 9, 30, tzinfo=timezone(timedelta(hours=2)))
        with engine.begin() as conn:
            conn.execute(insert(table).values(id="a", at=moment))
            stored = conn.execute(select(table.c.at)).scalar_one()
        assert stored == moment
        assert stored.tzinfo is UTC

    def test_naive_datetime_cannot_be_stored(self, mem: tuple[Engine, Table]) -> None:
        engine, table = mem
        with pytest.raises(Exception, match="naive"), engine.begin() as conn:
            conn.execute(insert(table).values(id="a", at=datetime(2026, 1, 1)))  # noqa: DTZ001

    def test_file_database_uses_wal_and_foreign_keys(self, data_dir: Path) -> None:
        engine = create_db_engine(data_dir / "x.db")
        try:
            with engine.connect() as conn:
                assert conn.exec_driver_sql("PRAGMA journal_mode").scalar_one() == "wal"
                assert conn.exec_driver_sql("PRAGMA foreign_keys").scalar_one() == 1
        finally:
            engine.dispose()
