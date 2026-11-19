"""Builders for the pre-push change tests: a change service on an in-memory database, a
queue, and uploads in the wire shape."""

from __future__ import annotations

import base64
import hashlib
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from sqlalchemy import Engine
from tests.fakes.core import FakeAudit, FakePrincipals, FakeSecrets

from ciso.app.changes import ChangeService
from ciso.common.clock import FixedClock
from ciso.common.db import create_db_engine, init_operational_schema
from ciso.workflows import JobQueue

KEY_REF = "secret://change_store_key"
KEY = "change-store-key-for-tests-0123456789abcdef"
DEVICE = "svc_device_1"
SESSION = "sess-1"
#: Planted in diffs; must never appear in stored bytes.
MARKER = "PLANTED-MARKER-7f3a9c"
BUNDLE = b"# v2 git bundle\n" + b"0" * 40 + b" HEAD\n\nPACK-bytes-" + MARKER.encode()
CLEAN_DIFF = (
    "diff --git a/app.py b/app.py\n"
    "--- a/app.py\n"
    "+++ b/app.py\n"
    "@@ -1,1 +1,2 @@\n"
    " x = 1\n"
    f"+y = 2  # {MARKER}\n"
)
SECRET_DIFF = (
    "diff --git a/cfg.py b/cfg.py\n"
    "--- a/cfg.py\n"
    "+++ b/cfg.py\n"
    "@@ -1,1 +1,2 @@\n"
    " x = 1\n"
    '+AWS_SECRET = "AKIAQWERTYUIOPASDFGH"\n'
)


def sha(text: str) -> str:
    return hashlib.sha1(text.encode(), usedforsecurity=False).hexdigest()


HEAD = sha("head")
BASE = sha("base")


def push_upload(**changes: Any) -> dict[str, Any]:
    body: dict[str, Any] = {
        "session_id": SESSION,
        "kind": "push",
        "remote": "origin",
        "branch": "feature",
        "source": "feature",
        "head": HEAD,
        "base": BASE,
        "commits": [HEAD],
        "diff_b64": base64.b64encode(CLEAN_DIFF.encode()).decode(),
        "bundle_b64": base64.b64encode(BUNDLE).decode(),
    }
    body.update(changes)
    return body


def commit_upload(**changes: Any) -> dict[str, Any]:
    body: dict[str, Any] = {
        "session_id": SESSION,
        "kind": "commit",
        "head": sha("tree"),
        "base": BASE,
        "diff_b64": base64.b64encode(CLEAN_DIFF.encode()).decode(),
    }
    body.update(changes)
    return body


@dataclass
class ChangeWorld:
    engine: Engine
    clock: FixedClock
    audit: FakeAudit
    queue: JobQueue
    service: ChangeService
    store_dir: Path


def build_queue(engine: Engine, clock: FixedClock, audit: FakeAudit) -> JobQueue:
    return JobQueue(
        engine,
        clock,
        audit,
        FakePrincipals(),
        lease_seconds=60,
        max_attempts=2,
        backoff_base_seconds=1,
        backoff_max_seconds=4,
    )


def build_changes(
    tmp_path: Path,
    *,
    key_ref: str | None = KEY_REF,
    retention: int | None = 600,
    secrets: dict[str, str] | None = None,
) -> ChangeWorld:
    engine = create_db_engine(None)
    init_operational_schema(engine)
    clock = FixedClock()
    audit = FakeAudit(clock)
    queue = build_queue(engine, clock, audit)
    store_dir = tmp_path / "changes"
    service = ChangeService(
        engine,
        clock=clock,
        audit=audit,
        queue=queue,
        secrets=FakeSecrets({KEY_REF: KEY} if secrets is None else secrets),
        key_ref=key_ref,
        retention_seconds=retention,
        store_dir=store_dir,
        actor_id="ciso_governance",
    )
    return ChangeWorld(engine, clock, audit, queue, service, store_dir)
