"""The change store behind `POST /v1/changes` (docs/skill/decision-api.md, pre-push).

`submit` takes a change a device uploaded for a push or commit its agent is about to run:

1. validates it (`ChangeUpload`, bounded by `ciso.app.change_models`);
2. refuses unless the store is configured: `change_key_ref` must resolve to a usable key
   and `change_retention_seconds` must be set (unset means refuse);
3. inspects the diff in-process at once (`ciso.inspection.inspect_diff`);
4. writes diff and bundle as ONE file under `store_dir`, AES-GCM encrypted
   (`ciso.app.change_crypto`), then the row, then (pushes only) one sandbox job on the
   durable queue. An identical upload from the same device and session (same commits,
   same bytes) that has not expired returns the stored change instead.

`resolve` is what `decide` asks: unknown, expired, foreign (another device or session)
and mismatched (another kind, remote, branch, source branch or head commit) ids raise
`ChangeRefused`.
`record_report` / `record_failure` are the worker's. `purge` deletes a change's file,
one file at a time, once its report is in (or it never needed one) and its retention has
ended; the row stays as the record.

Audit order (builder rules): the attempt is audited before the write transaction, the
result after it; the sink is never called while the write lock is held.
"""

from __future__ import annotations

import hashlib
import json
import logging
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

from pydantic import ValidationError
from sqlalchemy import Engine, select, update

from ciso.app.change_crypto import ChangeCipher, frame, unframe
from ciso.app.change_models import (
    CHANGE_ID_PREFIX,
    SANDBOX_JOB_KIND,
    ChangeReceipt,
    ChangeRefusal,
    ChangeRefused,
    ChangeState,
    ChangeUpload,
    ResolvedChange,
    SandboxInput,
)
from ciso.app.change_shape import ChangeKind, ChangeShape
from ciso.app.tables import changes
from ciso.common.activity import InspectionResult
from ciso.common.clock import Clock
from ciso.common.db import read_connection
from ciso.common.enums import ActorType, AuditOutcome
from ciso.common.errors import CisoError, FailClosed, NotFound, ValidationFailed
from ciso.common.ids import is_id, new_id
from ciso.common.protocols import AuditEvent, AuditSink, SecretResolver
from ciso.common.schemas import canonical_json, sha256_hex
from ciso.inspection import inspect_diff
from ciso.workflows import JobQueue

logger = logging.getLogger(__name__)

SUBMIT_ACTION = "governance.change.submit"
REPORT_ACTION = "governance.change.report"
PURGE_ACTION = "governance.change.purge"
QUEUE_SOURCE = "governance.changes"
_FILE_SUFFIX = ".bin"


class ChangeService:
    """See the module docstring. `retention_seconds` and `key_ref` unset: submit refuses."""

    def __init__(
        self,
        engine: Engine,
        *,
        clock: Clock,
        audit: AuditSink,
        queue: JobQueue,
        secrets: SecretResolver,
        key_ref: str | None,
        retention_seconds: int | None,
        store_dir: Path,
        actor_id: str,
    ) -> None:
        self._engine = engine
        self._clock = clock
        self._audit = audit
        self._queue = queue
        self._secrets = secrets
        self._key_ref = key_ref
        self._retention = retention_seconds
        self._dir = store_dir
        self._actor = actor_id

    # --- upload ----------------------------------------------------------------------

    def submit(self, raw: Any, *, device_actor_id: str) -> ChangeReceipt:
        """Store one uploaded change. Raises `ValidationFailed` for a malformed upload and
        `FailClosed` when the store is not configured or a step fails."""
        upload, diff, bundle = _parse(raw)
        cipher, retention = self._ready()
        now = self._clock.now()
        fingerprint = _fingerprint(device_actor_id, upload, diff, bundle)
        found = self._existing(fingerprint, device_actor_id, now)
        if found is not None:
            return ChangeReceipt(change_id=found, created=False)
        change_id = new_id(CHANGE_ID_PREFIX)
        target = {
            "change_id": change_id,
            "kind": upload.kind.value,
            "session_id": upload.session_id,
        }
        self._emit(
            SUBMIT_ACTION, change_id, AuditOutcome.ATTEMPT, {**target, "device": device_actor_id}
        )
        text = diff.decode("utf-8", errors="replace")
        result = inspect_diff(text, action_id=change_id)
        self._write_file(change_id, cipher.seal(change_id, frame(diff, bundle)))
        state = ChangeState.PENDING if upload.kind is ChangeKind.PUSH else ChangeState.NOT_NEEDED
        self._insert(change_id, upload, device_actor_id, fingerprint, state, result, now, retention)
        if state is ChangeState.PENDING:
            self._queue.enqueue(
                SANDBOX_JOB_KIND, {"change_id": change_id}, source=QUEUE_SOURCE, event_id=change_id
            )
        details = {**target, "complete": result.complete, "findings": len(result.findings)}
        self._emit(SUBMIT_ACTION, change_id, AuditOutcome.SUCCESS, details)
        return ChangeReceipt(change_id=change_id, created=True)

    def _ready(self) -> tuple[ChangeCipher, int]:
        if self._key_ref is None or self._retention is None:
            raise FailClosed("the change store is not configured (key or retention unset)")
        try:
            return ChangeCipher.from_secret(self._secrets, self._key_ref), self._retention
        except CisoError as exc:
            raise FailClosed("the change store key cannot be used") from exc

    def _existing(self, fingerprint: str, device: str, now: datetime) -> str | None:
        with read_connection(self._engine) as conn:
            rows = conn.execute(
                select(changes.c.change_id)
                .where(
                    changes.c.fingerprint == fingerprint,
                    changes.c.device_actor_id == device,
                    changes.c.expires_at > now,
                    changes.c.deleted_at.is_(None),
                )
                .order_by(changes.c.created_at.desc())
                .limit(1)
            ).all()
        return str(rows[0].change_id) if rows else None

    def _write_file(self, change_id: str, blob: bytes) -> None:
        self._dir.mkdir(parents=True, exist_ok=True)
        final = self._path(change_id)
        temp = final.with_suffix(".tmp")
        temp.write_bytes(blob)
        temp.replace(final)

    def _insert(
        self,
        change_id: str,
        upload: ChangeUpload,
        device: str,
        fingerprint: str,
        state: ChangeState,
        result: InspectionResult,
        now: datetime,
        retention: int,
    ) -> None:
        with self._engine.begin() as conn:
            conn.execute(
                changes.insert().values(
                    change_id=change_id,
                    device_actor_id=device,
                    session_id=upload.session_id,
                    kind=upload.kind.value,
                    remote=upload.remote,
                    branch=upload.branch,
                    source=upload.source,
                    head=upload.head,
                    base=upload.base,
                    commits=json.dumps(list(upload.commits)),
                    fingerprint=fingerprint,
                    state=state.value,
                    diff_result=result.model_dump_json(),
                    created_at=now,
                    expires_at=now + timedelta(seconds=retention),
                )
            )

    # --- decide ----------------------------------------------------------------------

    def resolve(
        self,
        change_id: str,
        *,
        device_actor_id: str,
        session_id: str,
        shape: ChangeShape,
        head: str,
    ) -> ResolvedChange:
        """The change for this decision, or `ChangeRefused` (see the module docstring)."""
        row = self._row(change_id)
        if row is None:
            raise ChangeRefused(ChangeRefusal.UNKNOWN)
        if row.device_actor_id != device_actor_id or row.session_id != session_id:
            raise ChangeRefused(ChangeRefusal.FOREIGN)
        if row.deleted_at is not None or self._clock.now() >= row.expires_at:
            raise ChangeRefused(ChangeRefusal.EXPIRED)
        stored = (row.kind, row.remote, row.branch, row.source, row.head)
        if stored != (shape.kind.value, shape.remote, shape.branch, shape.source, head):
            raise ChangeRefused(ChangeRefusal.MISMATCH)
        sandbox = row.sandbox_result
        return ResolvedChange(
            change_id=row.change_id,
            state=ChangeState(row.state),
            diff=InspectionResult.model_validate_json(row.diff_result),
            sandbox=None if sandbox is None else InspectionResult.model_validate_json(sandbox),
        )

    def _row(self, change_id: str) -> Any:
        if not isinstance(change_id, str) or not is_id(change_id, CHANGE_ID_PREFIX):
            return None
        with read_connection(self._engine) as conn:
            return conn.execute(select(changes).where(changes.c.change_id == change_id)).first()

    # --- worker ----------------------------------------------------------------------

    def load_for_sandbox(self, change_id: str) -> SandboxInput:
        """The bundle and base of a pending push. `NotFound`, `FailClosed` (no key) or
        `IntegrityFailure` (the file was changed) otherwise."""
        row = self._row(change_id)
        if row is None or row.kind != ChangeKind.PUSH.value or row.deleted_at is not None:
            raise NotFound(f"no stored push change {change_id}")
        cipher, _ = self._ready()
        blob = self._path(change_id).read_bytes()
        _diff, bundle = unframe(cipher.open(change_id, blob))
        return SandboxInput(change_id=change_id, bundle=bundle, base=row.base)

    def has_finished(self, change_id: str) -> bool:
        """True when the change exists and is no longer waiting for its report."""
        row = self._row(change_id)
        return row is not None and row.state != ChangeState.PENDING.value

    def record_report(self, change_id: str, result: InspectionResult) -> None:
        self._finish(change_id, ChangeState.DONE, result.model_dump_json(), result.complete)

    def record_failure(self, change_id: str) -> None:
        self._finish(change_id, ChangeState.FAILED, None, False)

    def _finish(
        self, change_id: str, state: ChangeState, result: str | None, complete: bool
    ) -> None:
        now = self._clock.now()
        with self._engine.begin() as conn:
            done = conn.execute(
                update(changes)
                .where(
                    changes.c.change_id == change_id, changes.c.state == ChangeState.PENDING.value
                )
                .values(state=state.value, sandbox_result=result, report_at=now)
            ).rowcount
        if done != 1:
            raise NotFound(f"no pending change {change_id}")
        details = {"change_id": change_id, "state": state.value, "complete": complete}
        self._emit(REPORT_ACTION, change_id, AuditOutcome.SUCCESS, details)

    # --- retention -------------------------------------------------------------------

    def purge(self) -> int:
        """Delete the file of every change whose report is in (or needed none) and whose
        retention has ended. Returns how many files were deleted."""
        now = self._clock.now()
        finished = (ChangeState.DONE.value, ChangeState.FAILED.value, ChangeState.NOT_NEEDED.value)
        with read_connection(self._engine) as conn:
            due = conn.execute(
                select(changes.c.change_id).where(
                    changes.c.deleted_at.is_(None),
                    changes.c.expires_at <= now,
                    changes.c.state.in_(finished),
                )
            ).all()
        deleted = 0
        for row in due:
            self._path(row.change_id).unlink(missing_ok=True)
            with self._engine.begin() as conn:
                conn.execute(
                    update(changes)
                    .where(changes.c.change_id == row.change_id, changes.c.deleted_at.is_(None))
                    .values(deleted_at=now)
                )
            deleted += 1
        if deleted:
            self._emit(PURGE_ACTION, "", AuditOutcome.SUCCESS, {"deleted": deleted})
        return deleted

    # --- helpers ---------------------------------------------------------------------

    def _path(self, change_id: str) -> Path:
        return self._dir / f"{change_id}{_FILE_SUFFIX}"

    def _emit(
        self, action: str, target: str, outcome: AuditOutcome, details: dict[str, Any]
    ) -> None:
        event = AuditEvent(
            actor_id=self._actor,
            actor_type=ActorType.SERVICE,
            action=action,
            target=target,
            outcome=outcome,
            details=details,
        )
        try:
            self._audit.append(event)
        except Exception as exc:
            logger.error("change store: %s not audited (%s)", action, type(exc).__name__)
            raise FailClosed(f"{action} could not be audited") from exc


def _parse(raw: Any) -> tuple[ChangeUpload, bytes, bytes]:
    if not isinstance(raw, dict):
        raise ValidationFailed("a change upload is a JSON object")
    try:
        upload = ChangeUpload.model_validate(raw)
        return upload, upload.diff(), upload.bundle()
    except (ValidationError, ValueError):
        raise ValidationFailed("the change upload is not valid") from None


def _fingerprint(device: str, upload: ChangeUpload, diff: bytes, bundle: bytes) -> str:
    shape = upload.model_dump(mode="json", exclude={"diff_b64", "bundle_b64"})
    return sha256_hex(
        canonical_json(
            {
                "device": device,
                "upload": shape,
                "diff": hashlib.sha256(diff).hexdigest(),
                "bundle": hashlib.sha256(bundle).hexdigest(),
            }
        )
    )
