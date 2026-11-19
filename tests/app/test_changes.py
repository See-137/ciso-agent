"""The change store behind `POST /v1/changes` (docs/skill/decision-api.md, pre-push).

Encryption at rest, in-process diff inspection, one queued sandbox job per change,
refusals of unknown, expired, foreign and mismatched change ids, pending vs complete,
and the single-file delete once the report is in and the retention has ended."""

from __future__ import annotations

import base64
from collections.abc import Iterator
from datetime import timedelta
from pathlib import Path

import pytest
from sqlalchemy import select
from tests.app.change_helpers import (
    BASE,
    BUNDLE,
    DEVICE,
    HEAD,
    MARKER,
    SECRET_DIFF,
    SESSION,
    ChangeWorld,
    build_changes,
    commit_upload,
    push_upload,
    sha,
)

from ciso.app.change_crypto import ChangeCipher
from ciso.app.change_models import (
    SANDBOX_JOB_KIND,
    ChangeRefusal,
    ChangeRefused,
    ChangeState,
    ResolvedChange,
)
from ciso.app.change_shape import ChangeKind, ChangeShape
from ciso.app.tables import changes as changes_table
from ciso.common.activity import InspectionResult
from ciso.common.errors import FailClosed, IntegrityFailure, ValidationFailed

pytestmark = pytest.mark.unit

PUSH = ChangeShape(kind=ChangeKind.PUSH, remote="origin", branch="feature", source="feature")


@pytest.fixture
def world(tmp_path: Path) -> Iterator[ChangeWorld]:
    built = build_changes(tmp_path)
    yield built
    built.engine.dispose()


def _resolve(world: ChangeWorld, change_id: str, **changes: object) -> ResolvedChange:
    args: dict[str, object] = {
        "device_actor_id": DEVICE,
        "session_id": SESSION,
        "shape": PUSH,
        "head": HEAD,
    }
    args.update(changes)
    return world.service.resolve(change_id, **args)  # type: ignore[arg-type]


def _clean_report(change_id: str) -> InspectionResult:
    return InspectionResult(action_id=change_id, checks_run=("sandbox.report",), complete=True)


# --- storage -------------------------------------------------------------------------


def test_the_stored_change_is_encrypted_at_rest(world: ChangeWorld) -> None:
    receipt = world.service.submit(push_upload(), device_actor_id=DEVICE)
    files = list(world.store_dir.iterdir())
    assert [f.name for f in files] == [f"{receipt.change_id}.bin"]
    stored = files[0].read_bytes()
    assert len(stored) > len(BUNDLE)  # positive evidence that the content is in there
    for planted in (MARKER.encode(), base64.b64encode(MARKER.encode()), b"diff --git"):
        assert planted not in stored
    with world.engine.connect() as conn:
        row = conn.execute(select(changes_table)).one()
    assert MARKER not in repr(tuple(row))


def test_the_worker_gets_back_the_bundle_it_was_sent(world: ChangeWorld) -> None:
    receipt = world.service.submit(push_upload(), device_actor_id=DEVICE)
    got = world.service.load_for_sandbox(receipt.change_id)
    assert (got.bundle, got.base) == (BUNDLE, BASE)
    assert MARKER not in repr(got)


def test_a_tampered_file_does_not_decrypt(world: ChangeWorld) -> None:
    receipt = world.service.submit(push_upload(), device_actor_id=DEVICE)
    path = world.store_dir / f"{receipt.change_id}.bin"
    data = bytearray(path.read_bytes())
    data[-1] ^= 1
    path.write_bytes(bytes(data))
    with pytest.raises(IntegrityFailure):
        world.service.load_for_sandbox(receipt.change_id)


@pytest.mark.parametrize(
    ("key_ref", "retention", "secrets"),
    [
        (None, 600, None),  # no key reference
        ("secret://change_store_key", None, None),  # no retention
        ("secret://change_store_key", 600, {}),  # key does not resolve
        ("secret://change_store_key", 600, {"secret://change_store_key": "short"}),
    ],
)
def test_no_usable_key_or_retention_refuses(
    tmp_path: Path, key_ref: str | None, retention: int | None, secrets: dict[str, str] | None
) -> None:
    world = build_changes(tmp_path, key_ref=key_ref, retention=retention, secrets=secrets)
    try:
        with pytest.raises(FailClosed):
            world.service.submit(push_upload(), device_actor_id=DEVICE)
        assert not world.store_dir.exists() or not list(world.store_dir.iterdir())
    finally:
        world.engine.dispose()


@pytest.mark.parametrize(
    "bad",
    [
        {"kind": "rebase"},
        {"head": "HEAD"},
        {"commits": []},
        {"commits": [sha("other")]},  # newest is not head
        {"bundle_b64": None},
        {"bundle_b64": base64.b64encode(b"not a bundle").decode()},
        {"diff_b64": "%%% not base64"},
        {"session_id": "bad session"},
        {"extra": 1},
    ],
)
def test_a_malformed_upload_is_refused(world: ChangeWorld, bad: dict[str, object]) -> None:
    with pytest.raises(ValidationFailed):
        world.service.submit(push_upload(**bad), device_actor_id=DEVICE)
    assert world.queue.lease([SANDBOX_JOB_KIND], "w1") is None
    assert not world.store_dir.exists() or not list(world.store_dir.iterdir())


def test_the_diff_is_inspected_at_once_and_a_sandbox_job_is_queued(world: ChangeWorld) -> None:
    receipt = world.service.submit(push_upload(), device_actor_id=DEVICE)
    assert receipt.created
    resolved = _resolve(world, receipt.change_id)
    assert resolved.state is ChangeState.PENDING
    assert resolved.diff.complete
    assert "inspection.secrets" in resolved.diff.checks_run
    job = world.queue.lease([SANDBOX_JOB_KIND], "w1")
    assert job is not None
    assert job.payload["change_id"] == receipt.change_id
    assert [e.action for e in world.audit.find("governance.change.submit")] == [
        "governance.change.submit",
        "governance.change.submit",
    ]


def test_a_secret_in_the_diff_is_a_finding(world: ChangeWorld) -> None:
    diff = base64.b64encode(SECRET_DIFF.encode()).decode()
    receipt = world.service.submit(push_upload(diff_b64=diff), device_actor_id=DEVICE)
    resolved = _resolve(world, receipt.change_id)
    assert any(f.category == "secret" for f in resolved.diff.findings)


def test_the_same_change_twice_is_stored_once(world: ChangeWorld) -> None:
    first = world.service.submit(push_upload(), device_actor_id=DEVICE)
    again = world.service.submit(push_upload(), device_actor_id=DEVICE)
    assert (again.change_id, again.created) == (first.change_id, False)
    assert len(list(world.store_dir.iterdir())) == 1
    other = world.service.submit(push_upload(session_id="sess-2"), device_actor_id=DEVICE)
    assert other.change_id != first.change_id


def test_a_commit_is_inspected_without_a_sandbox_job(world: ChangeWorld) -> None:
    receipt = world.service.submit(commit_upload(), device_actor_id=DEVICE)
    resolved = world.service.resolve(
        receipt.change_id,
        device_actor_id=DEVICE,
        session_id=SESSION,
        shape=ChangeShape(kind=ChangeKind.COMMIT),
        head=sha("tree"),
    )
    assert resolved.state is ChangeState.NOT_NEEDED
    assert world.queue.lease([SANDBOX_JOB_KIND], "w1") is None


# --- resolving for a decision ----------------------------------------------------------


def test_pending_then_done(world: ChangeWorld) -> None:
    receipt = world.service.submit(push_upload(), device_actor_id=DEVICE)
    assert _resolve(world, receipt.change_id).state is ChangeState.PENDING
    world.service.record_report(receipt.change_id, _clean_report(receipt.change_id))
    done = _resolve(world, receipt.change_id)
    assert done.state is ChangeState.DONE
    assert done.sandbox is not None
    assert done.sandbox.complete


def test_a_failed_sandbox_run_is_recorded(world: ChangeWorld) -> None:
    receipt = world.service.submit(push_upload(), device_actor_id=DEVICE)
    world.service.record_failure(receipt.change_id)
    assert _resolve(world, receipt.change_id).state is ChangeState.FAILED


@pytest.mark.parametrize(
    ("changes", "code"),
    [
        ({"device_actor_id": "svc_device_2"}, ChangeRefusal.FOREIGN),
        ({"session_id": "sess-other"}, ChangeRefusal.FOREIGN),
        ({"head": sha("different")}, ChangeRefusal.MISMATCH),
        ({"shape": PUSH.model_copy(update={"branch": "main"})}, ChangeRefusal.MISMATCH),
        ({"shape": ChangeShape(kind=ChangeKind.COMMIT)}, ChangeRefusal.MISMATCH),
        ({"shape": PUSH.model_copy(update={"source": None})}, ChangeRefusal.MISMATCH),
        ({"shape": PUSH.model_copy(update={"source": "other"})}, ChangeRefusal.MISMATCH),
    ],
)  # fmt: skip
def test_foreign_and_mismatched_ids_are_refused(
    world: ChangeWorld, changes: dict[str, object], code: ChangeRefusal
) -> None:
    receipt = world.service.submit(push_upload(), device_actor_id=DEVICE)
    with pytest.raises(ChangeRefused) as caught:
        _resolve(world, receipt.change_id, **changes)
    assert caught.value.code is code
    assert _resolve(world, receipt.change_id).change_id == receipt.change_id


@pytest.mark.parametrize("change_id", ["chg_01JD3Z6B8Q4W5X7Y9Z0A1B2C3D", "not-an-id", ""])
def test_unknown_ids_are_refused(world: ChangeWorld, change_id: str) -> None:
    with pytest.raises(ChangeRefused) as caught:
        _resolve(world, change_id)
    assert caught.value.code is ChangeRefusal.UNKNOWN


def test_an_expired_change_is_refused(world: ChangeWorld) -> None:
    receipt = world.service.submit(push_upload(), device_actor_id=DEVICE)
    world.clock.advance(seconds=599)
    assert _resolve(world, receipt.change_id).change_id == receipt.change_id
    world.clock.advance(seconds=1)
    with pytest.raises(ChangeRefused) as caught:
        _resolve(world, receipt.change_id)
    assert caught.value.code is ChangeRefusal.EXPIRED


def test_an_expired_change_is_not_reused_for_a_new_upload(world: ChangeWorld) -> None:
    first = world.service.submit(push_upload(), device_actor_id=DEVICE)
    world.clock.advance(timedelta(seconds=601))
    again = world.service.submit(push_upload(), device_actor_id=DEVICE)
    assert again.created
    assert again.change_id != first.change_id


# --- retention -------------------------------------------------------------------------


def test_the_file_is_deleted_once_the_report_is_in_and_retention_ended(
    world: ChangeWorld,
) -> None:
    receipt = world.service.submit(push_upload(), device_actor_id=DEVICE)
    path = world.store_dir / f"{receipt.change_id}.bin"
    world.clock.advance(seconds=601)
    assert world.service.purge() == 0  # report not in yet: kept
    assert path.is_file()
    world.service.record_report(receipt.change_id, _clean_report(receipt.change_id))
    assert world.service.purge() == 1
    assert not path.exists()
    assert world.service.purge() == 0
    with world.engine.connect() as conn:
        row = conn.execute(select(changes_table)).one()
    assert row.deleted_at is not None


def test_a_reported_change_is_kept_until_its_retention_ends(world: ChangeWorld) -> None:
    receipt = world.service.submit(push_upload(), device_actor_id=DEVICE)
    world.service.record_report(receipt.change_id, _clean_report(receipt.change_id))
    assert world.service.purge() == 0
    assert (world.store_dir / f"{receipt.change_id}.bin").is_file()


def test_the_cipher_refuses_a_changed_blob() -> None:
    """Directly at the cipher: the framing check must not be what catches tampering."""
    cipher = ChangeCipher(b"k" * 32)
    blob = bytearray(cipher.seal("chg_x", b"plaintext body"))
    assert cipher.open("chg_x", bytes(blob)) == b"plaintext body"
    blob[-1] ^= 1
    with pytest.raises(IntegrityFailure):
        cipher.open("chg_x", bytes(blob))
    with pytest.raises(IntegrityFailure):
        cipher.open("chg_y", cipher.seal("chg_x", b"plaintext body"))  # moved to another id
