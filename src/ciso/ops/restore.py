"""Restore and archive verification (T1.16, ADR-0014, blueprint 10.3, NFR-018).

`RestoreService.restore` writes an archive's members into an EMPTY directory, never over
live files. Order:

1. Only a human holding `security_admin` may restore; a refusal is audited.
2. The target must be empty (or absent; it is then created).
3. The whole archive is authenticated (every GCM tag, the manifest, member order, sizes
   and SHA-256) before anything is written. Any failure raises `IntegrityFailure` and
   leaves the target empty.
4. The attempt is audited; if that fails nothing is written.
5. Members are decrypted into the target. If anything fails, everything written is
   removed again.
6. The restored databases are opened read-only and their row counts compared with the
   manifest. The restored audit log is verified against the restored anchor.
7. The result is audited; if that fails the restored files are removed and `FailClosed`
   is raised.

The report says plainly whether the restored audit log verified. It always warns that a
restore brings back the kill-switch flags as they were at backup time (ADR-0018): an
engage made after the backup is lost, so engage the switch before a restored instance is
brought into use.

Witness. When a `HeadWitness` is given and the restored log is behind the head it last
witnessed for that log id, the report carries the named warning
`restored_behind_witness (restored seq N, witnessed seq M)` and `witness_gap = (N, M)`.
The check itself is not weakened: an instance started on the restored files with that
witness fails its start-up verification (`rolled_back`) and the integrity gate keeps
writes blocked, which is the intended result until a person decides. (An operation to
accept a restore as the witness's new baseline is designed but not built; see the M1
fix-pass report.)

The audit verification opens the restored audit database with the platform's normal
engine, because `AuditLog.verify` takes the write lock while it reads; it does not change
any row.
"""

from __future__ import annotations

import logging
import shutil
from pathlib import Path
from typing import BinaryIO

from ciso.audit import AuditLog, HeadAnchor, HeadWitness, VerifyStatus
from ciso.common.clock import Clock
from ciso.common.db import create_db_engine
from ciso.common.enums import ActorType, AuditOutcome, Role
from ciso.common.errors import AuthorizationError, FailClosed, IntegrityFailure, ValidationFailed
from ciso.common.principal import Principal
from ciso.common.protocols import AuditEvent, AuditSink, Redactor, SecretResolver
from ciso.common.schemas import Model
from ciso.ops.archive import BackupManifest, MemberKind, check_member_name, read_archive
from ciso.ops.backup import ANCHOR_MEMBER, AUDIT_MEMBER, resolve_secret, table_row_counts

logger = logging.getLogger(__name__)

RESTORE_ACTION = "restore.run"
KILLSWITCH_WARNING = (
    "A restore brings back the kill-switch flags as they were at backup time; an engage "
    "made after the backup is lost. Engage the kill switch before bringing a restored "
    "instance into use."
)


ROLLBACK_WARNING = (
    "The restored audit log is checked against its own restored anchor only. A restore is "
    "a rollback: records written after the backup are not in it, and this check cannot "
    "tell a legitimate restore from a rollback."
)


#: Named warning: the restored audit log is behind the head the witness last saw.
RESTORED_BEHIND_WITNESS = "restored_behind_witness"
#: Named warning: a witness was given but could not be read for the comparison.
WITNESS_NOT_COMPARED = "witness_not_compared"


class RestoreReport(Model):
    archive_id: str
    target_dir: Path
    members: tuple[str, ...]
    row_counts_match: bool
    row_count_mismatches: tuple[str, ...]
    #: ok, failed, unverifiable, or not_in_archive.
    audit_status: str
    audit_reason: str | None
    audit_verified: bool
    audit_log_id: str | None
    #: (restored head seq, witnessed seq) when the restore is behind the witness.
    witness_gap: tuple[int, int] | None = None
    warnings: tuple[str, ...]
    summary: str


class RestoreService:
    def __init__(
        self,
        secrets: SecretResolver,
        clock: Clock,
        audit: AuditSink,
        redactor: Redactor,
        *,
        key_ref: str | None,
        audit_key_ref: str | None,
        witness: HeadWitness | None = None,
    ) -> None:
        self._secrets = secrets
        self._clock = clock
        self._audit = audit
        self._redactor = redactor
        self._key_ref = key_ref
        self._audit_key_ref = audit_key_ref
        self._witness = witness

    def verify_archive(self, archive: Path) -> BackupManifest:
        """Authenticate the whole archive without writing anything. Raises
        `IntegrityFailure` for a tampered, truncated, reordered or wrong-key archive."""
        secret = resolve_secret(self._secrets, self._key_ref, "backup")
        return read_archive(Path(archive), secret)

    def restore(self, archive: Path, target_dir: Path, principal: Principal) -> RestoreReport:
        self._authorise(principal)
        target = Path(target_dir)
        _require_empty(target)
        manifest = self.verify_archive(archive)
        self._append(principal, AuditOutcome.ATTEMPT, manifest.archive_id, {})
        try:
            self._write_members(Path(archive), target)
            report = self._check(manifest, target)
        except BaseException:
            _empty(target)
            raise
        try:
            self._append(principal, AuditOutcome.SUCCESS, manifest.archive_id, _summary(report))
        except Exception as exc:
            _empty(target)
            raise FailClosed("restore could not be audited; restored files were removed") from exc
        return report

    # -- internals ----------------------------------------------------------------------

    def _authorise(self, principal: Principal) -> None:
        if principal.actor_type is ActorType.HUMAN and principal.has_role(Role.SECURITY_ADMIN):
            return
        why = "restore needs a human security_admin"
        try:
            self._append(principal, AuditOutcome.DENIED, "refused", {"reason": why})
        except Exception as exc:
            raise AuthorizationError(f"{why} (refusal could not be audited)") from exc
        raise AuthorizationError(why)

    def _append(
        self,
        principal: Principal,
        outcome: AuditOutcome,
        archive_id: str,
        details: dict[str, object],
    ) -> None:
        self._audit.append(
            AuditEvent(
                actor_id=principal.actor_id,
                actor_type=principal.actor_type,
                action=RESTORE_ACTION,
                target=f"backup:{archive_id}",
                outcome=outcome,
                details=details,
            )
        )

    def _write_members(self, archive: Path, target: Path) -> None:
        secret = resolve_secret(self._secrets, self._key_ref, "backup")
        root = target.resolve()

        def open_sink(_index: int, name: str) -> BinaryIO:
            dest = (root / check_member_name(name)).resolve()
            if not dest.is_relative_to(root):
                raise IntegrityFailure("archive member would land outside the target")
            dest.parent.mkdir(parents=True, exist_ok=True)
            return dest.open("xb")

        read_archive(archive, secret, open_sink)

    def _check(self, manifest: BackupManifest, target: Path) -> RestoreReport:
        mismatches: list[str] = []
        for member in manifest.members:
            if member.kind is not MemberKind.SQLITE:
                continue
            found = table_row_counts(target / member.name)
            if found != dict(member.row_counts):
                mismatches.append(member.name)
        status, reason, head_seq = self._verify_audit(manifest, target)
        verified = status == VerifyStatus.OK.value
        warnings = [KILLSWITCH_WARNING, ROLLBACK_WARNING]
        if not verified:
            warnings.append(f"The restored audit log did NOT verify: {status} ({reason}).")
        gap = self._witness_gap(manifest.audit_log_id, head_seq, warnings)
        summary = (
            f"Restored {len(manifest.members)} members of {manifest.archive_id}. "
            f"Row counts {'match' if not mismatches else 'DO NOT match'} the manifest. "
            f"Restored audit log verified: {'yes' if verified else 'NO'} ({status})."
        )
        return RestoreReport(
            archive_id=manifest.archive_id,
            target_dir=target,
            members=tuple(m.name for m in manifest.members),
            row_counts_match=not mismatches,
            row_count_mismatches=tuple(mismatches),
            audit_status=status,
            audit_reason=reason,
            audit_verified=verified,
            audit_log_id=manifest.audit_log_id,
            witness_gap=gap,
            warnings=tuple(warnings),
            summary=summary,
        )

    def _witness_gap(
        self, log_id: str | None, head_seq: int | None, warnings: list[str]
    ) -> tuple[int, int] | None:
        """Compare the restored head with the witness; add the named warning if behind."""
        if self._witness is None or log_id is None or head_seq is None:
            return None
        try:
            latest = self._witness.latest(log_id)
        except Exception as exc:
            logger.warning("restore: witness unreadable (%s)", type(exc).__name__)
            warnings.append(f"{WITNESS_NOT_COMPARED} ({type(exc).__name__})")
            return None
        if latest is None or latest.seq <= head_seq:
            return None
        warnings.append(
            f"{RESTORED_BEHIND_WITNESS} (restored seq {head_seq}, witnessed seq {latest.seq})"
        )
        return head_seq, latest.seq

    def _verify_audit(
        self, manifest: BackupManifest, target: Path
    ) -> tuple[str, str | None, int | None]:
        """(status, reason, restored head seq or None when nothing could be read)."""
        if manifest.member(AUDIT_MEMBER) is None or manifest.member(ANCHOR_MEMBER) is None:
            return "not_in_archive", "archive holds no audit log", None
        if self._audit_key_ref is None:
            return VerifyStatus.UNVERIFIABLE.value, "audit_key_ref_unset", None
        anchor = HeadAnchor(target / ANCHOR_MEMBER, self._secrets, self._audit_key_ref)
        engine = create_db_engine(target / AUDIT_MEMBER)
        try:
            log = AuditLog(
                engine, self._clock, self._redactor, anchor, expected_log_id=manifest.audit_log_id
            )
            result = log.verify()
        except FailClosed:
            logger.exception("restored audit database could not be read")
            return VerifyStatus.UNVERIFIABLE.value, "audit_database_unreadable", None
        finally:
            engine.dispose()
        return VerifyStatus(result.status).value, result.reason, result.head_seq


def _require_empty(target: Path) -> None:
    if target.exists():
        if not target.is_dir():
            raise ValidationFailed(f"restore target is not a directory: {target}")
        if any(target.iterdir()):
            raise ValidationFailed(f"restore target is not empty: {target}")
    else:
        target.mkdir(parents=True)


def _empty(target: Path) -> None:
    """Remove what the restore wrote. The target was empty when the restore began."""
    for child in target.iterdir():
        if child.is_dir() and not child.is_symlink():
            shutil.rmtree(child)
        else:
            child.unlink()


def _summary(report: RestoreReport) -> dict[str, object]:
    return {
        "row_counts_match": report.row_counts_match,
        "audit_status": report.audit_status,
        "audit_reason": report.audit_reason,
        "members": list(report.members),
    }
