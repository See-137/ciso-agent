"""Approved heads: where a later push may start its scan (review H1, queue Q18).

The client cannot be trusted to say where the pushed range starts: its remote-tracking
refs are files the agent can move. So the service remembers every head it let a scanned
push go out with, per repository key (`normalize_repository`) and destination branch.
Everything reachable from such a head was scanned (from an earlier approved head, or from
the root), so a later push may start there; an upload naming any other base is refused,
and with no approved head the client scans the whole history (bounded by the commit cap).
The sandbox checks that the base is an ancestor inside the bundle.
"""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import Engine, select
from sqlalchemy.exc import IntegrityError

from ciso.app.change_models import MAX_BASES
from ciso.app.tables import approved_heads
from ciso.common.db import read_connection
from ciso.common.ids import new_id


def list_bases(engine: Engine, repository: str, branch: str) -> tuple[str, ...]:
    """Approved heads for (repository key, branch), newest first, at most `MAX_BASES`."""
    t = approved_heads
    with read_connection(engine) as conn:
        rows = conn.execute(
            select(t.c.head)
            .where(t.c.repository == repository, t.c.branch == branch)
            .order_by(t.c.recorded_at.desc(), t.c.id.desc())
            .limit(MAX_BASES)
        ).all()
    return tuple(str(row.head) for row in rows)


def is_approved(engine: Engine, repository: str, branch: str, head: str) -> bool:
    t = approved_heads
    with read_connection(engine) as conn:
        row = conn.execute(
            select(t.c.id).where(
                t.c.repository == repository, t.c.branch == branch, t.c.head == head
            )
        ).first()
    return row is not None


def add_head(
    engine: Engine,
    *,
    repository: str,
    branch: str,
    head: str,
    change_id: str,
    decision_id: str,
    now: datetime,
) -> bool:
    """Record one approved head. False when it was already recorded."""
    if is_approved(engine, repository, branch, head):
        return False
    try:
        with engine.begin() as conn:
            conn.execute(
                approved_heads.insert().values(
                    id=new_id("aph"), repository=repository, branch=branch, head=head,
                    change_id=change_id, decision_id=decision_id, recorded_at=now,
                )
            )  # fmt: skip
    except IntegrityError:
        return False  # recorded concurrently
    return True
