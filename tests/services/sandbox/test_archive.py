"""Archive intake: hostile tar archives and bundles are refused as a whole, never partly used."""

from __future__ import annotations

import gzip
import io
import tarfile
import zlib

import pytest
from services.sandbox.archive import ArchiveRejected, pack_tree, read_tree, validate_bundle
from tests.services.sandbox.support import tar_of, tar_with

from services.sandbox import archive

pytestmark = pytest.mark.resilience


def member(name: str, kind: bytes = tarfile.REGTYPE, data: bytes = b"x", **kw: object):  # type: ignore[no-untyped-def]
    info = tarfile.TarInfo(name)
    info.type = kind
    if kind in (tarfile.REGTYPE, tarfile.AREGTYPE):
        info.size = len(data)
        payload: bytes | None = data
    else:
        payload = None
    for key, value in kw.items():
        setattr(info, key, value)
    return info, payload


def test_reads_regular_files_and_directories() -> None:
    data = tar_with(
        [
            member("pkg", tarfile.DIRTYPE),
            member("pkg/a.py", data=b"print(1)\n"),
            member("run.sh", data=b"#!/bin/sh\n", mode=0o755),
        ]
    )
    tree = read_tree(data)
    assert tree.paths() == ("pkg/a.py", "run.sh")
    by_path = {f.path: f for f in tree.files}
    assert by_path["run.sh"].executable
    assert not by_path["pkg/a.py"].executable
    assert by_path["pkg/a.py"].data == b"print(1)\n"


def test_gzip_tar_is_accepted() -> None:
    tree = read_tree(tar_of({"a.txt": b"hello"}, gz=True))
    assert tree.paths() == ("a.txt",)


def test_leading_dot_slash_is_normalised() -> None:
    tree = read_tree(tar_with([member("./src/x.py")]))
    assert tree.paths() == ("src/x.py",)


@pytest.mark.parametrize(
    ("name", "reason"),
    [
        ("../escape.txt", "traversal"),
        ("a/../../escape.txt", "traversal"),
        ("/etc/passwd", "absolute"),
        ("C:/Windows/x", "absolute"),
        ("a\\..\\b", "backslash"),
        ("bad\x01name", "control"),
        ("bad\nname", "control"),
        ("", "empty"),
    ],
)
def test_hostile_names_are_refused(name: str, reason: str) -> None:
    with pytest.raises(ArchiveRejected, match=reason):
        read_tree(tar_with([member("ok.txt"), member(name)]))


@pytest.mark.parametrize(
    ("kind", "reason"),
    [
        (tarfile.SYMTYPE, "link"),
        (tarfile.LNKTYPE, "link"),
        (tarfile.CHRTYPE, "special"),
        (tarfile.BLKTYPE, "special"),
        (tarfile.FIFOTYPE, "special"),
    ],
)
def test_links_and_device_files_are_refused(kind: bytes, reason: str) -> None:
    hostile = member("thing", kind)
    if kind in (tarfile.SYMTYPE, tarfile.LNKTYPE):
        hostile[0].linkname = "/etc/passwd"
    with pytest.raises(ArchiveRejected, match=reason):
        read_tree(tar_with([member("ok.txt"), hostile]))


def test_duplicate_path_is_refused() -> None:
    with pytest.raises(ArchiveRejected, match="duplicate"):
        read_tree(tar_with([member("a.txt"), member("a.txt")]))


def test_file_and_directory_with_the_same_path_is_refused() -> None:
    with pytest.raises(ArchiveRejected, match="conflict"):
        read_tree(tar_with([member("a"), member("a/b.txt")]))


def test_too_many_members_is_refused(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(archive, "MAX_MEMBERS", 3)
    read_tree(tar_with([member(f"f{i}") for i in range(3)]))
    with pytest.raises(ArchiveRejected, match="members"):
        read_tree(tar_with([member(f"f{i}") for i in range(4)]))


def test_expanded_size_cap(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(archive, "MAX_EXPANDED_BYTES", 10)
    read_tree(tar_with([member("a", data=b"12345"), member("b", data=b"12345")]))
    with pytest.raises(ArchiveRejected, match="expanded"):
        read_tree(tar_with([member("a", data=b"123456"), member("b", data=b"12345")]))


def test_single_file_cap(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(archive, "MAX_FILE_BYTES", 4)
    with pytest.raises(ArchiveRejected, match="file too large"):
        read_tree(tar_with([member("a", data=b"12345")]))


def test_gzip_bomb_is_stopped_while_decompressing(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(archive, "MAX_EXPANDED_BYTES", 64 * 1024)
    monkeypatch.setattr(archive, "MAX_MEMBERS", 10)
    bomb = gzip.compress(b"\0" * (4 * 1024 * 1024))
    assert len(bomb) < 64 * 1024
    produced: list[int] = []
    real = zlib.decompressobj

    class Counting:
        def __init__(self, wbits: int) -> None:
            self._inner = real(wbits=wbits)

        def decompress(self, data: bytes, max_length: int = 0) -> bytes:
            out: bytes = self._inner.decompress(data, max_length)
            produced.append(len(out))
            return out

        def __getattr__(self, name: str) -> object:
            return getattr(self._inner, name)

    monkeypatch.setattr(zlib, "decompressobj", Counting)
    with pytest.raises(ArchiveRejected, match="expanded"):
        read_tree(bomb)
    # Inflation stopped near the cap; it never produced the whole 4 MiB.
    assert 0 < sum(produced) < 1024 * 1024


def test_archive_size_cap(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(archive, "MAX_ARCHIVE_BYTES", 100)
    with pytest.raises(ArchiveRejected, match="archive too large"):
        read_tree(b"\0" * 101)


@pytest.mark.parametrize(
    "data",
    [
        b"PK\x03\x04rest-of-a-zip",
        b"BZh91AY&SY",
        b"\xfd7zXZ\x00",
        b"not an archive at all, just text that is long enough to be read" * 20,
    ],
)
def test_other_formats_and_garbage_are_refused(data: bytes) -> None:
    with pytest.raises(ArchiveRejected):
        read_tree(data)


def test_deep_paths_are_refused(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(archive, "MAX_DEPTH", 3)
    read_tree(tar_with([member("a/b/c")]))
    with pytest.raises(ArchiveRejected, match="deep"):
        read_tree(tar_with([member("a/b/c/d")]))


def test_pack_tree_rebuilds_only_regular_files_with_fixed_metadata() -> None:
    original = tar_with(
        [
            member("src/a.py", data=b"A", mode=0o4666, uid=0, gid=0, uname="root"),
            member("run.sh", data=b"B", mode=0o755),
        ]
    )
    packed = pack_tree(read_tree(original))
    with tarfile.open(fileobj=io.BytesIO(packed), mode="r:") as tf:
        infos = {m.name: m for m in tf.getmembers()}
    assert set(infos) == {"src", "src/a.py", "run.sh"}
    assert infos["src/a.py"].mode == 0o644
    assert infos["run.sh"].mode == 0o755
    assert infos["src"].isdir()
    assert all(m.uid == 65534 and m.mtime == 0 for m in infos.values())
    assert read_tree(packed).paths() == ("run.sh", "src/a.py")


def test_tree_repr_hides_content() -> None:
    tree = read_tree(tar_of({"a.txt": b"TOPSECRETVALUE"}))
    assert "TOPSECRETVALUE" not in repr(tree)
    assert "TOPSECRETVALUE" not in repr(tree.files[0])


def test_bundle_header_and_size(monkeypatch: pytest.MonkeyPatch) -> None:
    validate_bundle(b"# v2 git bundle\n0123 refs/heads/main\n\nPACK")
    validate_bundle(b"# v3 git bundle\n@object-format=sha1\n\nPACK")
    with pytest.raises(ArchiveRejected, match="bundle"):
        validate_bundle(b"# v9 git bundle\n")
    with pytest.raises(ArchiveRejected, match="bundle"):
        validate_bundle(tar_of({"a": b"b"}))
    monkeypatch.setattr(archive, "MAX_ARCHIVE_BYTES", 20)
    with pytest.raises(ArchiveRejected, match="archive too large"):
        validate_bundle(b"# v2 git bundle\n" + b"x" * 10)
