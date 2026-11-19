"""The change store behind `POST /v1/changes` (docs/skill/decision-api.md, pre-push).

`submit` takes a change a device uploaded for a push or commit its agent is about to run:

1. refuses while the kill switch blocks WRITES or cannot be read (review M1);
2. validates it (`ChangeUpload`, bounded by `ciso.app.change_models`; the bundle must name
   exactly the stated head, review M2);
3. refuses unless the store is configured: `change_key_ref` must resolve to a usable key
   and `change_retention_seconds` must be set (unset means refuse);
4. an identical upload from the same device and session (same commits, same bytes) that
   has not expired and did not fail returns the stored change (audited as deduplicated);
5. a push must start at a head the service approved for its repository and branch, or at
   the root (`base: null`; review H1, `ciso.app.change_heads`), and a device may have one
   push waiting for its sandbox run at a time (review L3);
6. inspects the diff in-process at once (`ciso.inspection.inspect_diff`);
7. writes diff and bundle as ONE file under `store_dir`, AES-GCM encrypted, then the row
   (the file is removed again when the row cannot be written, review L6), then (pushes
   only) one sandbox job on the durable queue.

`resolve` is what `decide` asks: unknown, expired, foreign (another device or session),
mismatched (another kind, remote, branch, source branch or head commit) and refused
(the sandbox scanned something else) ids raise `ChangeRefused`.
`record_report` / `record_failure` / `record_refused` are the worker's; `reconcile_dead`
fails a pending change whose job the queue dead-lettered (an expired last lease).
`purge` deletes a change's file, one file at a time, once its report is in (or it never
needed one) and its retention has ended; the row stays as the record.

Audit order (builder rules): the attempt is audited before the write transaction, the
result after it; the sink is never called while the write lock is held.
"""

from __future__ import annotations

import hashlib
import json
import logging
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Final

from pydantic import ValidationError
from sqlalchemy import Engine, select, update

from ciso.app import change_heads
from ciso.app.change_crypto import ChangeCipher, frame, unframe
from ciso.app.change_models import (
    CHANGE_ID_PREFIX,
    SANDBOX_JOB_KIND,
    ChangeReceipt,
    ChangeRefusal,
    ChangeRefused,
    ChangeState,
    ChangeUpload,
    DeviceBusy,
    ResolvedChange,
    SandboxInput,
    UploadRefusal,
    UploadRefused,
    normalize_repository,
)
from ciso.app.change_shape import ChangeKind, ChangeShape
from ciso.app.tables import changes
from ciso.common.activity import InspectionResult
from ciso.common.clock import Clock
from ciso.common.db import read_connection
from ciso.common.enums import ActorType, AuditOutcome, KillCapability
from ciso.common.errors import CisoError, FailClosed, NotFound, ValidationFailed
from ciso.common.ids import is_id, new_id
from ciso.common.protocols import AuditEvent, AuditSink, KillSwitchReader, SecretResolver
from ciso.common.schemas import canonical_json, sha256_hex
from ciso.inspection import inspect_diff
from ciso.workflows import JobQueue, JobState

logger = logging.getLogger(__name__)

SUBMIT_ACTION: Final = "governance.change.submit"
REPORT_ACTION: Final = "governance.change.report"
PURGE_ACTION: Final = "governance.change.purge"
HEAD_ACTION: Final = "governance.change.approve_head"
QUEUE_SOURCE: Final = "governance.changes"
_FILE_SUFFIX: Final = ".bin"
#: Most pending changes one `reconcile_dead` call looks at.
MAX_RECONCILE: Final = 100
#: States that end a change's wait for the sandbox.
_FINISHED: Final = (
    ChangeState.DONE.value,
    ChangeState.FAILED.value,
    ChangeState.NOT_NEEDED.value,
    ChangeState.REFUSED.value,
)
#: An identical upload of a change in these states is stored and scanned again (L2).
_RETRYABLE: Final = (ChangeState.FAILED.value, ChangeState.REFUSED.value)


class ChangeService:
    """See the module docstring. `retention_seconds` and `key_ref` unset: submit refuses.
    `killswitch` must be the container's gated reader."""

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
        killswitch: KillSwitchReader,
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
        self._killswitch = killswitch

    def writes_blocked(self) -> bool:
        """True while the gated reader blocks WRITES, or cannot be read (fail closed)."""
        try:
            return bool(self._killswitch.is_blocked(KillCapability.WRITES))
        except Exception as exc:
            logger.error("change store: kill switch unreadable (%s)", type(exc).__name__)
            return True

    # --- upload ----------------------------------------------------------------------

    def submit(self, raw: Any, *, device_actor_id: str) -> ChangeReceipt:
        """Store one uploaded change. Raises `ValidationFailed` for a malformed upload,
        `UploadRefused` for a base the service did not approve, `DeviceBusy` while this
        device has another push pending, and `FailClosed` while writes are blocked, when
        the store is not configured or a step fails."""
        if self.writes_blocked():
            raise FailClosed("writes are blocked: change uploads are refused")
        upload, diff, bundle = _parse(raw)
        cipher, retention = self._ready()
        now = self._clock.now()
        fingerprint = _fingerprint(device_actor_id, upload, diff, bundle)
        found = self._existing(fingerprint, device_actor_id, now)
        if found is not None:
            details = {"change_id": found, "kind": upload.kind.value,
                       "session_id": upload.session_id, "deduplicated": True}  # fmt: skip
            self._emit(SUBMIT_ACTION, found, AuditOutcome.SUCCESS, details)
            return ChangeReceipt(change_id=found, created=False)
        repository = self._check_push(upload, device_actor_id, now)
        change_id = new_id(CHANGE_ID_PREFIX)
        target = {"change_id": change_id, "kind": upload.kind.value,
                  "session_id": upload.session_id}  # fmt: skip
        self._emit(
            SUBMIT_ACTION, change_id, AuditOutcome.ATTEMPT, {**target, "device": device_actor_id}
        )
        result = inspect_diff(diff.decode("utf-8", errors="replace"), action_id=change_id)
        self._write_file(change_id, cipher.seal(change_id, frame(diff, bundle)))
        state = ChangeState.PENDING if upload.kind is ChangeKind.PUSH else ChangeState.NOT_NEEDED
        row = _Row(change_id, upload, repository, device_actor_id, fingerprint, state, result)
        try:
            self._insert(row, now, retention)
        except BaseException:
            self._path(change_id).unlink(missing_ok=True)
            raise
        if state is ChangeState.PENDING:
            self._queue.enqueue(
                SANDBOX_JOB_KIND, {"change_id": change_id}, source=QUEUE_SOURCE, event_id=change_id
            )
        details = {**target, "complete": result.complete, "findings": len(result.findings)}
        self._emit(SUBMIT_ACTION, change_id, AuditOutcome.SUCCESS, details)
        return ChangeReceipt(change_id=change_id, created=True)

    def _check_push(self, upload: ChangeUpload, device: str, now: datetime) -> str | None:
        """The repository key of a push whose base is approved and whose device is free."""
        if upload.kind is not ChangeKind.PUSH:
            return None
        assert upload.repository is not None and upload.branch is not None
        repository = normalize_repository(upload.repository)
        if upload.base is not None and not change_heads.is_approved(
            self._engine, repository, upload.branch, upload.base
        ):
            raise UploadRefused(UploadRefusal.BASE_NOT_APPROVED)
        with read_connection(self._engine) as conn:
            busy = conn.execute(
                select(changes.c.change_id).where(
                    changes.c.device_actor_id == device,
                    changes.c.state == ChangeState.PENDING.value,
                    changes.c.expires_at > now,
                )
            ).first()
        if busy is not None:
            raise DeviceBusy()
        return repository

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
                    changes.c.state.not_in(_RETRYABLE),
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

    def _insert(self, row: _Row, now: datetime, retention: int) -> None:
        upload = row.upload
        with self._engine.begin() as conn:
            conn.execute(
                changes.insert().values(
                    change_id=row.change_id,
                    device_actor_id=row.device,
                    session_id=upload.session_id,
                    kind=upload.kind.value,
                    repository=row.repository,
                    remote=upload.remote,
                    branch=upload.branch,
                    source=upload.source,
                    head=upload.head,
                    base=upload.base,
                    commits=json.dumps(list(upload.commits)),
                    fingerprint=row.fingerprint,
                    state=row.state.value,
                    diff_result=row.result.model_dump_json(),
                    created_at=now,
                    expires_at=now + timedelta(seconds=retention),
                )
            )

    # --- approved heads ----------------------------------------------------------------

    def approved_bases(self, repository: str, branch: str) -> tuple[str, ...]:
        """Approved heads for a repository (any spelling) and branch, newest first."""
        return change_heads.list_bases(self._engine, normalize_repository(repository), branch)

    def record_approved(self, change: ResolvedChange, *, decision_id: str) -> None:
        """Remember a pushed head the rules allowed after its full scan (review H1)."""
        if change.kind is not ChangeKind.PUSH or change.repository is None or not change.branch:
            return
        added = change_heads.add_head(
            self._engine, repository=change.repository, branch=change.branch,
            head=change.head, change_id=change.change_id, decision_id=decision_id,
            now=self._clock.now(),
        )  # fmt: skip
        if added:
            details = {"change_id": change.change_id, "decision_id": decision_id,
                       "branch": change.branch}  # fmt: skip
            self._emit(HEAD_ACTION, change.change_id, AuditOutcome.SUCCESS, details)

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
        if row.state == ChangeState.REFUSED.value:
            raise ChangeRefused(ChangeRefusal.SANDBOX_MISMATCH)
        sandbox = row.sandbox_result
        return ResolvedChange(
            change_id=row.change_id,
            state=ChangeState(row.state),
            diff=InspectionResult.model_validate_json(row.diff_result),
            sandbox=None if sandbox is None else InspectionResult.model_validate_json(sandbox),
            kind=ChangeKind(row.kind),
            repository=row.repository,
            branch=row.branch,
            head=row.head,
        )

    def _row(self, change_id: str) -> Any:
        if not isinstance(change_id, str) or not is_id(change_id, CHANGE_ID_PREFIX):
            return None
        with read_connection(self._engine) as conn:
            return conn.execute(select(changes).where(changes.c.change_id == change_id)).first()

    # --- worker ----------------------------------------------------------------------

    def load_for_sandbox(self, change_id: str) -> SandboxInput:
        """The bundle, head, commits and base of a pending push. `NotFound`, `FailClosed`
        (no key) or `IntegrityFailure` (the file was changed) otherwise."""
        row = self._row(change_id)
        if row is None or row.kind != ChangeKind.PUSH.value or row.deleted_at is not None:
            raise NotFound(f"no stored push change {change_id}")
        cipher, _ = self._ready()
        blob = self._path(change_id).read_bytes()
        _diff, bundle = unframe(cipher.open(change_id, blob))
        return SandboxInput(
            change_id=change_id, bundle=bundle, base=row.base, head=row.head,
            commits=tuple(json.loads(row.commits)),
        )  # fmt: skip

    def has_finished(self, change_id: str) -> bool:
        """True when the change exists and is no longer waiting for its report."""
        row = self._row(change_id)
        return row is not None and row.state != ChangeState.PENDING.value

    def record_report(self, change_id: str, result: InspectionResult) -> None:
        self._finish(change_id, ChangeState.DONE, result.model_dump_json(), result.complete)

    def record_failure(self, change_id: str) -> None:
        self._finish(change_id, ChangeState.FAILED, None, False)

    def record_refused(self, change_id: str) -> None:
        """The sandbox report named another job or another head (reviews L1, M2)."""
        self._finish(change_id, ChangeState.REFUSED, None, False)

    def reconcile_dead(self) -> int:
        """Fail every pending change whose sandbox job the queue dead-lettered (a job
        whose last lease expired is dead-lettered by `lease`, which cannot say which change
        it was). Looks up each job through the queue's idempotent `enqueue`. Returns how
        many changes were failed."""
        with read_connection(self._engine) as conn:
            pending = conn.execute(
                select(changes.c.change_id)
                .where(changes.c.state == ChangeState.PENDING.value)
                .order_by(changes.c.created_at)
                .limit(MAX_RECONCILE)
            ).all()
        failed = 0
        for row in pending:
            job = self._queue.enqueue(
                SANDBOX_JOB_KIND, {"change_id": row.change_id}, source=QUEUE_SOURCE,
                event_id=row.change_id,
            ).job  # fmt: skip
            if job.state is JobState.DEAD:
                try:
                    self.record_failure(row.change_id)
                    failed += 1
                except NotFound:
                    continue
        return failed

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
        with read_connection(self._engine) as conn:
            due = conn.execute(
                select(changes.c.change_id).where(
                    changes.c.deleted_at.is_(None),
                    changes.c.expires_at <= now,
                    changes.c.state.in_(_FINISHED),
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


class _Row:
    """What one new change row holds besides the times."""

    __slots__ = ("change_id", "device", "fingerprint", "repository", "result", "state", "upload")

    def __init__(
        self,
        change_id: str,
        upload: ChangeUpload,
        repository: str | None,
        device: str,
        fingerprint: str,
        state: ChangeState,
        result: InspectionResult,
    ) -> None:
        self.change_id = change_id
        self.upload = upload
        self.repository = repository
        self.device = device
        self.fingerprint = fingerprint
        self.state = state
        self.result = result


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
