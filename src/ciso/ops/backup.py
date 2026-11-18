"""Encrypted online backup (T1.16, ADR-0014, blueprint 10.3, 11.1, NFR-007, NFR-018).

`BackupService.create` copies the named sources into one encrypted archive (format in
`ciso.ops.archive`) while the platform keeps running:

- SQLite databases are copied with the SQLite online backup API from a separate
  connection to the live file. Nothing copies or renames an open database file.
- The audit database and its head anchor are captured together: the service holds the
  audit database's write lock (the lock `AuditLog.append` needs) while it reads the anchor
  and copies the database, so the pair is consistent. A source set with one and not the
  other is refused, because a restored audit log cannot be verified without its anchor.
- Evidence blobs are a directory member: every regular file under it is archived.
  A symbolic link under it is refused.

Plaintext copies of the databases exist only in a private temp directory (created under
`temp_root` when given, which must not be the destination) and are deleted in a `finally`.
The archive is written to a temp name in the destination directory and renamed when
complete. The backup is audited as `backup.create`; if that audit write fails, the archive
is deleted and the call raises `FailClosed`.

Who may back up: a human holding `security_admin`, or a service (a scheduler). Agents and
other humans are refused and the refusal is audited.

`key_ref` is the `secret://` reference of the backup secret. `None` refuses: no key is ever
generated here. Member names mirror `Settings` data-directory layout, so a restore target
holds databases under `db/`, the anchor under `anchor/` (the audit log refuses an anchor
inside the database directory) and evidence under `evidence/`.
"""

from __future__ import annotations

import contextlib
import logging
import shutil
import sqlite3
import tempfile
from collections.abc import Iterator
from pathlib import Path

from ciso.common.clock import Clock
from ciso.common.enums import ActorType, AuditOutcome, Role
from ciso.common.errors import AuthorizationError, FailClosed, ValidationFailed
from ciso.common.ids import new_id
from ciso.common.principal import Principal
from ciso.common.protocols import AuditEvent, AuditSink, SecretResolver
from ciso.common.schemas import Model
from ciso.ops.archive import (
    FORMAT_VERSION,
    ArchiveWriter,
    BackupManifest,
    MemberEntry,
    MemberKind,
    archive_file_name,
    check_member_name,
)
from ciso.vault import resolve_key_bytes

logger = logging.getLogger(__name__)

OPERATIONAL_MEMBER = "db/ciso.db"
AUDIT_MEMBER = "db/audit.db"
ANCHOR_MEMBER = "anchor/audit-head.json"
EVIDENCE_PREFIX = "evidence/"
BACKUP_ACTION = "backup.create"


class BackupSources(Model):
    """The named members of a backup. Paths of live files on this host."""

    operational_db: Path | None = None
    audit_db: Path | None = None
    audit_anchor: Path | None = None
    evidence_dir: Path | None = None


def resolve_secret(secrets: SecretResolver, key_ref: str | None, what: str) -> bytes:
    """Resolve a `secret://` reference to key bytes or raise `FailClosed`: unset,
    unresolvable, empty, or shorter than `ciso.vault.MIN_KEY_BYTES`. Never logs the value."""
    if key_ref is None:
        raise FailClosed(f"no {what} key is configured; refusing")
    try:
        return resolve_key_bytes(secrets, key_ref)
    except FailClosed as exc:
        raise FailClosed(f"{what} {exc}") from exc
    except Exception as exc:
        raise FailClosed(f"{what} key could not be resolved: {key_ref}") from exc


def sqlite_uri(path: Path, mode: str) -> str:
    """`file:` URI that never creates a missing database (`mode=rw` or `mode=ro`)."""
    return f"{path.resolve().as_uri()}?mode={mode}"


def table_row_counts(path: Path) -> dict[str, int]:
    """Rows per user table, opened read-only."""
    with contextlib.closing(sqlite3.connect(sqlite_uri(path, "ro"), uri=True)) as conn:
        names = [
            row[0]
            for row in conn.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table' "
                "AND name NOT LIKE 'sqlite_%' ORDER BY name"
            )
        ]
        counts: dict[str, int] = {}
        for name in names:
            quoted = '"' + name.replace('"', '""') + '"'
            counts[name] = int(conn.execute(f"SELECT COUNT(*) FROM {quoted}").fetchone()[0])  # noqa: S608
    return counts


def _online_copy(source: Path, dest: Path) -> None:
    """SQLite online backup of a live database into `dest`, then a single-file journal."""
    with (
        contextlib.closing(sqlite3.connect(sqlite_uri(source, "rw"), uri=True)) as src,
        contextlib.closing(sqlite3.connect(dest)) as out,
    ):
        src.backup(out)
        out.execute("PRAGMA journal_mode=DELETE")


@contextlib.contextmanager
def _audit_write_lock(audit_db: Path) -> Iterator[None]:
    """Hold the audit database's write lock so no append runs between the two copies."""
    with contextlib.closing(
        sqlite3.connect(sqlite_uri(audit_db, "rw"), uri=True, isolation_level=None)
    ) as lock:
        try:
            lock.execute("BEGIN IMMEDIATE")
        except sqlite3.OperationalError as exc:
            raise FailClosed("audit database is busy; backup not taken") from exc
        try:
            yield
        finally:
            lock.execute("ROLLBACK")


def _audit_log_id(copy: Path) -> str | None:
    """The audit log's id from the copied database's identity row, if it has one."""
    with contextlib.closing(sqlite3.connect(sqlite_uri(copy, "ro"), uri=True)) as conn:
        try:
            row = conn.execute("SELECT log_id FROM audit_meta WHERE id = 1").fetchone()
        except sqlite3.OperationalError:
            return None
    return str(row[0]) if row is not None and row[0] is not None else None


class BackupService:
    def __init__(
        self,
        secrets: SecretResolver,
        clock: Clock,
        audit: AuditSink,
        *,
        key_ref: str | None,
        temp_root: Path | None = None,
    ) -> None:
        self._secrets = secrets
        self._clock = clock
        self._audit = audit
        self._key_ref = key_ref
        self._temp_root = temp_root

    def create(
        self, sources: BackupSources, destination_dir: Path, principal: Principal
    ) -> BackupManifest:
        """Write one encrypted archive into `destination_dir` and return its manifest.

        The archive is `destination_dir / manifest.file_name`.
        """
        self._authorise(principal)
        secret = resolve_secret(self._secrets, self._key_ref, "backup")
        _check_sources(sources)
        destination = Path(destination_dir)
        destination.mkdir(parents=True, exist_ok=True)
        archive_id = new_id("bak")
        final = destination / archive_file_name(archive_id)
        partial = destination / f".{archive_id}.partial"
        work = Path(tempfile.mkdtemp(prefix="ciso-backup-", dir=self._temp_root))
        try:
            if work.resolve().is_relative_to(destination.resolve()):
                raise ValidationFailed("the backup temp directory must not be the destination")
            with partial.open("xb") as out:
                writer = ArchiveWriter(out, secret, archive_id)
                manifest = self._write_members(writer, sources, work, archive_id, principal)
                out.flush()
            partial.replace(final)
        finally:
            partial.unlink(missing_ok=True)
            shutil.rmtree(work, ignore_errors=False)
        self._audit_created(principal, manifest, final)
        return manifest

    # -- internals ----------------------------------------------------------------------

    def _write_members(
        self,
        writer: ArchiveWriter,
        sources: BackupSources,
        work: Path,
        archive_id: str,
        principal: Principal,
    ) -> BackupManifest:
        members: list[MemberEntry] = []
        log_id: str | None = None
        if sources.operational_db is not None:
            members.append(_sqlite_member(writer, OPERATIONAL_MEMBER, sources.operational_db, work))
        if sources.audit_db is not None and sources.audit_anchor is not None:
            copy = work / "audit.copy"
            with _audit_write_lock(sources.audit_db):
                anchor_bytes = sources.audit_anchor.read_bytes()
                _online_copy(sources.audit_db, copy)
            members.append(_sqlite_entry(writer, AUDIT_MEMBER, copy))
            members.append(writer.add_bytes(ANCHOR_MEMBER, MemberKind.FILE, anchor_bytes))
            log_id = _audit_log_id(copy)
        if sources.evidence_dir is not None:
            members.extend(_evidence_members(writer, sources.evidence_dir))
        manifest = BackupManifest(
            format_version=FORMAT_VERSION,
            archive_id=archive_id,
            created_at=self._clock.now(),
            created_by=principal.actor_id,
            key_id=writer.key_id,
            audit_log_id=log_id,
            members=tuple(members),
        )
        writer.finish(manifest)
        return manifest

    def _authorise(self, principal: Principal) -> None:
        if principal.actor_type is ActorType.SERVICE or (
            principal.is_human and principal.has_role(Role.SECURITY_ADMIN)
        ):
            return
        why = "backup needs a human security_admin or a service identity"
        try:
            self._audit.append(_event(principal, AuditOutcome.DENIED, {"reason": why}))
        except Exception as exc:
            raise AuthorizationError(f"{why} (refusal could not be audited)") from exc
        raise AuthorizationError(why)

    def _audit_created(self, principal: Principal, manifest: BackupManifest, path: Path) -> None:
        details: dict[str, object] = {
            "archive_id": manifest.archive_id,
            "key_id": manifest.key_id,
            "audit_log_id": manifest.audit_log_id,
            "members": [
                {"name": m.name, "size": m.size, "sha256": m.sha256} for m in manifest.members
            ],
        }
        try:
            self._audit.append(_event(principal, AuditOutcome.SUCCESS, details))
        except Exception as exc:
            path.unlink(missing_ok=True)
            raise FailClosed("backup could not be audited; the archive was removed") from exc


def _event(principal: Principal, outcome: AuditOutcome, details: dict[str, object]) -> AuditEvent:
    return AuditEvent(
        actor_id=principal.actor_id,
        actor_type=principal.actor_type,
        action=BACKUP_ACTION,
        target=f"backup:{details.get('archive_id', 'refused')}",
        outcome=outcome,
        details=details,
    )


def _check_sources(sources: BackupSources) -> None:
    """The anchor travels with the audit database, and every named source exists."""
    if (sources.audit_db is None) != (sources.audit_anchor is None):
        raise ValidationFailed("the audit database and its anchor file must be backed up together")
    if sources.operational_db is None and sources.audit_db is None:
        raise ValidationFailed("a backup needs at least one database")
    for path in (sources.operational_db, sources.audit_db, sources.audit_anchor):
        if path is not None and not Path(path).is_file():
            raise ValidationFailed(f"backup source is not a file: {path}")
    if sources.evidence_dir is not None and not Path(sources.evidence_dir).is_dir():
        raise ValidationFailed(f"evidence source is not a directory: {sources.evidence_dir}")


def _sqlite_member(writer: ArchiveWriter, name: str, source: Path, work: Path) -> MemberEntry:
    copy = work / (name.replace("/", "_") + ".copy")
    _online_copy(source, copy)
    return _sqlite_entry(writer, name, copy)


def _sqlite_entry(writer: ArchiveWriter, name: str, copy: Path) -> MemberEntry:
    counts = table_row_counts(copy)
    entry = writer.add_member(name, MemberKind.SQLITE, copy)
    return MemberEntry.model_validate({**entry.model_dump(), "row_counts": counts})


def _evidence_members(writer: ArchiveWriter, root: Path) -> list[MemberEntry]:
    members: list[MemberEntry] = []
    for path in sorted(root.rglob("*")):
        if path.is_symlink():
            raise ValidationFailed(f"evidence directory holds a symbolic link: {path}")
        if not path.is_file():
            continue
        name = check_member_name(EVIDENCE_PREFIX + path.relative_to(root).as_posix())
        members.append(writer.add_member(name, MemberKind.FILE, path))
    return members
