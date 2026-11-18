"""Two threads see the same unknown agent at the same moment, on a file database.

Exactly one observed record may result, and both callers must get it. The matching step is
slowed down so both threads are inside `attribute` at once.
"""

from __future__ import annotations

import threading
import time
from collections.abc import Iterator
from pathlib import Path

import pytest
from sqlalchemy import Engine, func, select
from tests.agents.conftest import ActionFactory
from tests.fakes.core import FakeAudit

from ciso.agents import AgentRegistry
from ciso.agents import store as agents_store
from ciso.agents import tables as t
from ciso.common.activity import Attribution
from ciso.common.clock import FixedClock
from ciso.common.db import create_db_engine, init_operational_schema

pytestmark = pytest.mark.unit


@pytest.fixture
def file_engine(tmp_path: Path) -> Iterator[Engine]:
    eng = create_db_engine(tmp_path / "ops.db")
    init_operational_schema(eng)
    yield eng
    eng.dispose()


def test_unknown_agent_first_seen_race(
    file_engine: Engine,
    clock: FixedClock,
    make_action: ActionFactory,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    real = agents_store.candidate_agents
    inside = threading.Barrier(2, timeout=1.5)
    overlapped: list[bool] = []

    def slow(*args: object) -> object:
        try:
            inside.wait()
            overlapped.append(True)
        except threading.BrokenBarrierError:
            overlapped.append(False)
        time.sleep(0.2)
        return real(*args)  # type: ignore[arg-type]

    monkeypatch.setattr(agents_store, "candidate_agents", slow)
    audit = FakeAudit(clock)
    results: list[Attribution] = []
    errors: list[BaseException] = []
    start = threading.Barrier(2, timeout=10)

    def run() -> None:
        registry = AgentRegistry(file_engine, clock, audit)
        try:
            start.wait()
            results.append(registry.attribute(make_action(session="race")))
        except BaseException as exc:
            errors.append(exc)

    threads = [threading.Thread(target=run) for _ in range(2)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=30)

    assert errors == []
    assert len(results) == 2
    assert results[0].agent_ref is not None
    assert results[0].agent_ref == results[1].agent_ref
    with file_engine.connect() as conn:
        assert conn.execute(select(func.count()).select_from(t.agents)).scalar_one() == 1
    assert len(audit.find("agents.agent.observed")) == 1
    # The write lock serialises the two calls: the second finds the session already tied
    # to the observed agent and never reaches matching, so matching ran once, alone.
    assert overlapped == [False]
