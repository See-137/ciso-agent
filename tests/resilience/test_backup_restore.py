"""Encrypted backup and restore (T1.16, ADR-0014, blueprint 10.3, 11.1, NFR-007, NFR-018)."""

from __future__ import annotations

import sqlite3
from contextlib import closing
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
from sqlalchemy import text
from tests.fakes.core import FakeAudit, FakeRedactor, make_principal

from ciso.common.enums import ActorType, AuditOutcome, Role
from ciso.common.errors import AuthorizationError, FailClosed, IntegrityFailure, ValidationFailed
from ciso.common.principal import Principal
from ciso.common.protocols import AuditEvent
from ciso.ops import BackupService, BackupSources, MemberKind, RestoreService, describe_layout

pytestmark = pytest.mark.resilience

OP_MARKERS = ("MARKER-OPS-ALPHA-7731", "MARKER-OPS-DELTA-2208")
AUDIT_MARKER = "MARKER-AUDIT-BRAVO-5519"
EVIDENCE_MARKER = "MARKER-EVIDENCE-CHARLIE-0042"
ALL_MARKERS = (*OP_MARKERS, AUDIT_MARKER, EVIDENCE_MARKER)

ADMIN = make_principal("human_admin", ActorType.HUMAN, Role.SECURITY_ADMIN)
ADMIN_TIME = datetime(2026, 11, 17, 12, 0, tzinfo=UTC)


def populate(world: Any) -> Any:
    platform = world.start()
    for i, marker in enumerate(OP_MARKERS):
        platform.queue.enqueue("ingest", {"note": marker}, source="fixture", event_id=f"e{i}")
    for n in range(3):
        platform.audit_log.append(
            AuditEvent(
                actor_id="human_admin",
                actor_type=ActorType.HUMAN,
                action="test.event",
                target=f"asset:{n}",
                outcome=AuditOutcome.SUCCESS,
                details={"note": AUDIT_MARKER, "n": n},
            )
        )
    (world.evidence / "case1").mkdir(parents=True)
    (world.evidence / "case1" / "blob.bin").write_bytes(EVIDENCE_MARKER.encode() * 50)
    (world.evidence / "top.txt").write_bytes(b"evidence two")
    return platform


def sources(world: Any, **overrides: Any) -> BackupSources:
    fields: dict[str, Any] = {
        "operational_db": world.op_db,
        "audit_db": world.audit_db,
        "audit_anchor": world.anchor,
        "evidence_dir": world.evidence,
    }
    fields.update(overrides)
    return BackupSources(**fields)


def backup_service(world: Any, audit: FakeAudit, **kw: Any) -> BackupService:
    (world.root / "tmpwork").mkdir(exist_ok=True)
    return BackupService(
        kw.pop("secrets", world.secrets),
        world.clock,
        audit,
        key_ref=kw.pop("key_ref", world.backup_key_ref),
        temp_root=world.root / "tmpwork",
    )


def restore_service(world: Any, audit: FakeAudit, secrets: Any = None) -> RestoreService:
    return RestoreService(
        secrets or world.secrets,
        world.clock,
        audit,
        FakeRedactor(),
        key_ref=world.backup_key_ref,
        audit_key_ref=world.anchor_key_ref,
    )


def make_backup(world: Any, audit: FakeAudit, dest_name: str = "backups") -> Path:
    manifest = backup_service(world, audit).create(sources(world), world.root / dest_name, ADMIN)
    return world.root / dest_name / manifest.file_name


def counts(path: Path) -> dict[str, int]:
    uri = f"{path.resolve().as_uri()}?mode=ro"
    with closing(sqlite3.connect(uri, uri=True)) as conn:
        names = [
            r[0]
            for r in conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'"
            )
        ]
        return {n: conn.execute(f'SELECT COUNT(*) FROM "{n}"').fetchone()[0] for n in names}  # noqa: S608


def files_under(root: Path) -> list[Path]:
    return sorted(p for p in root.rglob("*") if p.is_file())


def assert_no_plaintext_leak(
    world: Any, allowed_roots: tuple[Path, ...] = (), min_checked: int = 0
) -> None:
    """No temp file is left and no marker sits in any file outside the live data and the
    given restore targets."""
    assert (world.root / "tmpwork").is_dir()  # the check below looked somewhere real
    assert files_under(world.root / "tmpwork") == []
    checked = 0
    for path in files_under(world.root):
        if path.is_relative_to(world.data) or any(path.is_relative_to(r) for r in allowed_roots):
            continue
        checked += 1
        body = path.read_bytes()
        for marker in ALL_MARKERS:
            assert marker.encode() not in body, f"{marker} found in {path}"
    assert checked >= min_checked


# -- round trip ------------------------------------------------------------------------


def test_round_trip_restores_counts_and_a_verifiable_audit_log(ops_world: Any) -> None:
    platform = populate(ops_world)
    audit = FakeAudit(ops_world.clock)
    archive = make_backup(ops_world, audit)
    manifest_counts = {
        "db/ciso.db": counts(ops_world.op_db),
        "db/audit.db": counts(ops_world.audit_db),
    }
    target = ops_world.root / "restored"
    report = restore_service(ops_world, audit).restore(archive, target, ADMIN)

    assert report.row_counts_match is True
    assert report.audit_status == "ok"
    assert report.audit_verified is True
    assert "verified: yes" in report.summary
    assert any("kill-switch" in w for w in report.warnings)
    assert counts(target / "db" / "ciso.db") == manifest_counts["db/ciso.db"]
    assert counts(target / "db" / "audit.db") == manifest_counts["db/audit.db"]
    assert counts(target / "db" / "ciso.db")["workflow_jobs"] == 2
    assert counts(target / "db" / "audit.db")["audit_record"] == 3
    assert (target / "evidence" / "case1" / "blob.bin").read_bytes() == (
        ops_world.evidence / "case1" / "blob.bin"
    ).read_bytes()
    assert (target / "anchor" / "audit-head.json").read_bytes() == ops_world.anchor.read_bytes()
    assert audit.actions() == ["backup.create", "restore.run", "restore.run"]
    assert [e.outcome for e in audit.find("restore.run")] == [
        AuditOutcome.ATTEMPT,
        AuditOutcome.SUCCESS,
    ]
    platform.crash()
    assert_no_plaintext_leak(ops_world, allowed_roots=(target,), min_checked=1)


def test_manifest_records_counts_hashes_and_key_id_not_key(ops_world: Any) -> None:
    populate(ops_world)
    audit = FakeAudit(ops_world.clock)
    manifest = backup_service(ops_world, audit).create(
        sources(ops_world), ops_world.root / "b", ADMIN
    )
    names = [m.name for m in manifest.members]
    assert names[:3] == ["db/ciso.db", "db/audit.db", "anchor/audit-head.json"]
    assert set(names[3:]) == {"evidence/case1/blob.bin", "evidence/top.txt"}
    op = manifest.member("db/ciso.db")
    assert op is not None
    assert op.row_counts["workflow_jobs"] == 2
    assert len(manifest.key_id) == 64
    assert "backup-key" not in manifest.model_dump_json()
    with pytest.raises(TypeError):
        op.row_counts["workflow_jobs"] = 0  # type: ignore[index]


def test_backup_while_engines_are_open_and_a_write_is_in_flight(ops_world: Any) -> None:
    platform = populate(ops_world)
    audit = FakeAudit(ops_world.clock)
    with platform.op_engine.connect() as conn:
        conn.execute(text("CREATE TABLE scratch_uncommitted (x TEXT)"))
        conn.execute(text("INSERT INTO scratch_uncommitted VALUES ('MARKER-OPS-ALPHA-7731')"))
        # This connection holds the operational write lock with uncommitted work.
        archive = make_backup(ops_world, audit)
        conn.rollback()
    platform.audit_log.append(
        AuditEvent(
            actor_id="x",
            actor_type=ActorType.SERVICE,
            action="after.backup",
            outcome=AuditOutcome.SUCCESS,
        )
    )
    report = restore_service(ops_world, audit).restore(archive, ops_world.root / "r", ADMIN)
    assert report.row_counts_match
    restored = counts(ops_world.root / "r" / "db" / "ciso.db")
    assert restored["workflow_jobs"] == 2
    assert "scratch_uncommitted" not in restored  # committed state only
    assert report.audit_verified


def test_archive_holds_no_plaintext_marker(ops_world: Any) -> None:
    populate(ops_world)
    archive = make_backup(ops_world, FakeAudit(ops_world.clock))
    body = archive.read_bytes()
    found = [m for m in ALL_MARKERS if m.encode() in body or m.encode("utf-16-le") in body]
    assert found == []
    # Positive control: the markers really are in the live files.
    assert OP_MARKERS[0].encode() in ops_world.op_db.read_bytes() + _wal(ops_world.op_db)
    assert_no_plaintext_leak(ops_world, min_checked=1)


def test_plaintext_copies_live_only_in_the_private_temp_dir(
    ops_world: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    import ciso.ops.backup as backup_module

    populate(ops_world)
    seen: list[Path] = []
    real = backup_module._online_copy

    def spy(source: Path, dest: Path) -> None:
        seen.append(dest)
        real(source, dest)
        assert dest.is_file()

    monkeypatch.setattr(backup_module, "_online_copy", spy)
    make_backup(ops_world, FakeAudit(ops_world.clock))
    assert len(seen) == 2  # both databases went through a temp copy
    assert all(p.is_relative_to(ops_world.root / "tmpwork") for p in seen)
    assert not any(p.exists() for p in seen)
    assert list((ops_world.root / "tmpwork").iterdir()) == []


def _wal(db: Path) -> bytes:
    wal = db.with_name(db.name + "-wal")
    return wal.read_bytes() if wal.exists() else b""


# -- tampering -------------------------------------------------------------------------


def _flip(path: Path, offset: int) -> None:
    data = bytearray(path.read_bytes())
    data[offset] ^= 0x01
    path.write_bytes(bytes(data))


def _offsets(archive: Path) -> dict[str, int]:
    spans = describe_layout(archive)
    header = spans[0]
    first = spans[1]
    manifest = spans[-1]
    assert manifest.kind == "manifest"
    return {
        "header_magic": 0,
        "header_archive_id": 12,
        "header_salt": header.end - 40,
        "header_key_id": header.end - 5,
        "member_name": first.start + 4,
        "member_size": first.start + 3 + len(first.name) + 2,
        "member_nonce": first.body_start - 3,
        "member_body": (first.body_start + first.tag_start) // 2,
        "member_tag": first.tag_start + 3,
        "manifest_body": (manifest.body_start + manifest.tag_start) // 2,
        "manifest_tag": manifest.end - 1,
    }


@pytest.mark.parametrize(
    "where",
    [
        "header_magic",
        "header_archive_id",
        "header_salt",
        "header_key_id",
        "member_name",
        "member_size",
        "member_nonce",
        "member_body",
        "member_tag",
        "manifest_body",
        "manifest_tag",
    ],
)
def test_one_flipped_byte_fails_and_leaves_target_empty(ops_world: Any, where: str) -> None:
    populate(ops_world)
    audit = FakeAudit(ops_world.clock)
    archive = make_backup(ops_world, audit)
    service = restore_service(ops_world, audit)
    assert service.verify_archive(archive).archive_id  # positive control before tampering
    _flip(archive, _offsets(archive)[where])
    with pytest.raises(IntegrityFailure):
        service.verify_archive(archive)
    target = ops_world.root / "target"
    with pytest.raises(IntegrityFailure):
        service.restore(archive, target, ADMIN)
    assert list(target.iterdir()) == []
    assert "restore.run" not in audit.actions()  # nothing was attempted
    assert_no_plaintext_leak(ops_world)


@pytest.mark.parametrize("cut", [1, 17, 200, "half", "after_first_member"])
def test_truncated_archive_fails(ops_world: Any, cut: Any) -> None:
    populate(ops_world)
    audit = FakeAudit(ops_world.clock)
    archive = make_backup(ops_world, audit)
    data = archive.read_bytes()
    if cut == "half":
        keep = len(data) // 2
    elif cut == "after_first_member":
        keep = describe_layout(archive)[1].end
    else:
        keep = len(data) - int(cut)
    archive.write_bytes(data[:keep])
    target = ops_world.root / "target"
    with pytest.raises(IntegrityFailure):
        restore_service(ops_world, audit).restore(archive, target, ADMIN)
    assert list(target.iterdir()) == []


def test_extra_bytes_after_manifest_fail(ops_world: Any) -> None:
    populate(ops_world)
    archive = make_backup(ops_world, FakeAudit(ops_world.clock))
    archive.write_bytes(archive.read_bytes() + b"\x00")
    with pytest.raises(IntegrityFailure, match="after its manifest"):
        restore_service(ops_world, FakeAudit()).verify_archive(archive)


def test_wrong_key_fails(ops_world: Any) -> None:
    populate(ops_world)
    archive = make_backup(ops_world, FakeAudit(ops_world.clock))
    other = ops_world.secrets_with_backup_key("a-completely-different-backup-key-9911")
    target = ops_world.root / "target"
    with pytest.raises(IntegrityFailure, match="different key"):
        restore_service(ops_world, FakeAudit(), secrets=other).restore(archive, target, ADMIN)
    assert list(target.iterdir()) == []


def _splice(data: bytes, start: int, end: int, replacement: bytes) -> bytes:
    return data[:start] + replacement + data[end:]


def test_member_swapped_in_from_another_archive_fails(ops_world: Any) -> None:
    populate(ops_world)
    audit = FakeAudit(ops_world.clock)
    a = make_backup(ops_world, audit, "a")
    b = make_backup(ops_world, audit, "b")
    span_a, span_b = describe_layout(a)[2], describe_layout(b)[2]
    assert span_a.name == span_b.name == "db/audit.db"
    spliced = _splice(
        a.read_bytes(), span_a.start, span_a.end, b.read_bytes()[span_b.start : span_b.end]
    )
    a.write_bytes(spliced)
    with pytest.raises(IntegrityFailure):
        restore_service(ops_world, audit).verify_archive(a)


def test_reordered_members_fail(ops_world: Any) -> None:
    populate(ops_world)
    archive = make_backup(ops_world, FakeAudit(ops_world.clock))
    data = archive.read_bytes()
    spans = describe_layout(archive)
    first, second = spans[1], spans[2]
    swapped = (
        data[: first.start]
        + data[second.start : second.end]
        + data[first.start : first.end]
        + data[second.end :]
    )
    archive.write_bytes(swapped)
    with pytest.raises(IntegrityFailure):
        restore_service(ops_world, FakeAudit()).verify_archive(archive)


# -- refusals --------------------------------------------------------------------------


def test_no_key_ref_refuses_and_writes_nothing(ops_world: Any) -> None:
    populate(ops_world)
    service = backup_service(ops_world, FakeAudit(), key_ref=None)
    with pytest.raises(FailClosed, match="no backup key"):
        service.create(sources(ops_world), ops_world.root / "b", ADMIN)
    assert not (ops_world.root / "b").exists()


def test_unresolvable_key_refuses(ops_world: Any) -> None:
    populate(ops_world)
    service = backup_service(ops_world, FakeAudit(), key_ref="secret://missing_key")
    with pytest.raises(FailClosed):
        service.create(sources(ops_world), ops_world.root / "b", ADMIN)


@pytest.mark.parametrize(
    "overrides",
    [{"audit_anchor": None}, {"audit_db": None}],
    ids=["audit_db_without_anchor", "anchor_without_audit_db"],
)
def test_audit_db_and_anchor_travel_together(ops_world: Any, overrides: dict[str, Any]) -> None:
    populate(ops_world)
    service = backup_service(ops_world, FakeAudit())
    with pytest.raises(ValidationFailed, match="together"):
        service.create(sources(ops_world, **overrides), ops_world.root / "b", ADMIN)
    assert not (ops_world.root / "b").exists()


def test_operational_only_backup_is_allowed_and_reports_no_audit(ops_world: Any) -> None:
    populate(ops_world)
    audit = FakeAudit(ops_world.clock)
    manifest = backup_service(ops_world, audit).create(
        sources(ops_world, audit_db=None, audit_anchor=None, evidence_dir=None),
        ops_world.root / "b",
        ADMIN,
    )
    report = restore_service(ops_world, audit).restore(
        ops_world.root / "b" / manifest.file_name, ops_world.root / "t", ADMIN
    )
    assert report.audit_status == "not_in_archive"
    assert report.audit_verified is False
    assert "verified: NO" in report.summary


def test_restore_into_non_empty_directory_refuses(ops_world: Any) -> None:
    populate(ops_world)
    audit = FakeAudit(ops_world.clock)
    archive = make_backup(ops_world, audit)
    target = ops_world.root / "live"
    target.mkdir()
    (target / "ciso.db").write_bytes(b"live data")  # any file makes it non-empty
    with pytest.raises(ValidationFailed, match="not empty"):
        restore_service(ops_world, audit).restore(archive, target, ADMIN)
    assert (target / "ciso.db").read_bytes() == b"live data"
    assert [p.name for p in target.iterdir()] == ["ciso.db"]


@pytest.mark.parametrize(
    "who",
    [
        make_principal("agent_ciso", ActorType.AGENT),
        make_principal("svc_backup", ActorType.SERVICE),
        make_principal("human_owner", ActorType.HUMAN, Role.SYSTEM_OWNER),
    ],
    ids=["agent", "service", "human_without_role"],
)
def test_restore_needs_a_human_security_admin(ops_world: Any, who: Principal) -> None:
    populate(ops_world)
    audit = FakeAudit(ops_world.clock)
    archive = make_backup(ops_world, audit)
    target = ops_world.root / "target"
    with pytest.raises(AuthorizationError):
        restore_service(ops_world, audit).restore(archive, target, who)
    assert not target.exists() or list(target.iterdir()) == []
    denied = audit.find("restore.run")
    assert [e.outcome for e in denied] == [AuditOutcome.DENIED]
    assert denied[0].actor_id == who.actor_id


@pytest.mark.parametrize(
    "who",
    [
        make_principal("agent_ciso", ActorType.AGENT),
        make_principal("human_emp", ActorType.HUMAN, Role.EMPLOYEE),
    ],
    ids=["agent", "human_without_role"],
)
def test_backup_refuses_agents_and_plain_humans(ops_world: Any, who: Principal) -> None:
    populate(ops_world)
    audit = FakeAudit(ops_world.clock)
    with pytest.raises(AuthorizationError):
        backup_service(ops_world, audit).create(sources(ops_world), ops_world.root / "b", who)
    assert [e.outcome for e in audit.find("backup.create")] == [AuditOutcome.DENIED]
    assert not (ops_world.root / "b").exists()


def test_backup_by_a_service_is_allowed(ops_world: Any) -> None:
    populate(ops_world)
    audit = FakeAudit(ops_world.clock)
    svc = make_principal("svc_scheduler", ActorType.SERVICE)
    manifest = backup_service(ops_world, audit).create(
        sources(ops_world), ops_world.root / "b", svc
    )
    assert (ops_world.root / "b" / manifest.file_name).is_file()
    assert audit.find("backup.create")[0].outcome is AuditOutcome.SUCCESS


def test_failing_audit_sink_removes_the_archive(ops_world: Any) -> None:
    populate(ops_world)
    audit = FakeAudit(ops_world.clock)
    audit.fail = True
    dest = ops_world.root / "b"
    with pytest.raises(FailClosed, match="removed"):
        backup_service(ops_world, audit).create(sources(ops_world), dest, ADMIN)
    assert list(dest.iterdir()) == []
    assert_no_plaintext_leak(ops_world)


def test_failing_audit_on_restore_attempt_writes_nothing(ops_world: Any) -> None:
    populate(ops_world)
    audit = FakeAudit(ops_world.clock)
    archive = make_backup(ops_world, audit)
    audit.fail = True
    target = ops_world.root / "t"
    with pytest.raises(FailClosed):
        restore_service(ops_world, audit).restore(archive, target, ADMIN)
    assert list(target.iterdir()) == []


def test_restored_audit_log_that_fails_is_reported_plainly(ops_world: Any) -> None:
    """Back up a tampered audit log: the archive is fine, the restored log is not."""
    platform = populate(ops_world)
    with platform.audit_engine.begin() as conn:
        conn.exec_driver_sql("DROP TRIGGER audit_record_no_update")
        conn.exec_driver_sql("UPDATE audit_record SET target = 'asset:forged' WHERE seq = 2")
    audit = FakeAudit(ops_world.clock)
    archive = make_backup(ops_world, audit)
    report = restore_service(ops_world, audit).restore(archive, ops_world.root / "t", ADMIN)
    assert report.audit_status == "failed"
    assert report.audit_verified is False
    assert report.audit_reason == "hash_mismatch"
    assert any("did NOT verify" in w for w in report.warnings)


def test_no_plaintext_left_after_a_failed_backup(ops_world: Any) -> None:
    populate(ops_world)
    # A missing evidence directory fails after nothing; a vanished source fails mid-way.
    service = backup_service(ops_world, FakeAudit(ops_world.clock))
    bad = sources(ops_world, operational_db=ops_world.root / "nope.db")
    with pytest.raises(ValidationFailed):
        service.create(bad, ops_world.root / "b", ADMIN)
    assert_no_plaintext_leak(ops_world)


def test_member_index_is_bound_into_the_tag(tmp_path: Path) -> None:
    """A record written for position 5 does not authenticate at position 0, even when the
    manifest agrees with it: the associated data, not only the manifest, binds the order."""
    from ciso.ops.archive import FORMAT_VERSION, ArchiveWriter, BackupManifest, read_archive

    secret = b"direct-archive-test-secret-0193"
    source = tmp_path / "plain.bin"
    source.write_bytes(b"payload")
    archive = tmp_path / "x.cisobak"
    with archive.open("xb") as out:
        writer = ArchiveWriter(out, secret, "bak_test")
        writer._count = 5  # write the member as if it were the sixth record
        entry = writer.add_member("member.bin", MemberKind.FILE, source)
        writer._count = 0  # the manifest claims a one-member archive
        writer.finish(
            BackupManifest(
                format_version=FORMAT_VERSION,
                archive_id="bak_test",
                created_at=ADMIN_TIME,
                created_by="t",
                key_id=writer.key_id,
                members=(entry,),
            )
        )
    with pytest.raises(IntegrityFailure, match="authentication"):
        read_archive(archive, secret)
