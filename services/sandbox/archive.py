"""Reading untrusted archives without trusting them.

The governance service sends the change as a tar archive (optionally gzip-compressed) or a
git bundle. A tar is read entirely in memory and checked member by member; any hostile
entry rejects the whole archive (never a partial use). The sandbox then streams a tar it
rebuilt itself (`pack_tree`): regular files and directories only, fixed modes and owner,
no timestamps. Nothing is written to the host's disk.

Defenses: path traversal (`..`), absolute paths (`/x`, `C:/x`), backslashes, control
characters, symlinks and hard links, device files and FIFOs, sparse files, duplicates and
file/directory conflicts, member count, per-file size, expanded size, path depth and
length, and decompression bombs (gzip is inflated incrementally against the cap). Zip,
bzip2, xz and anything else are refused.
"""

from __future__ import annotations

import io
import tarfile
import unicodedata
import zlib
from dataclasses import dataclass, field
from pathlib import PurePosixPath
from typing import Final

from services.sandbox.job import MAX_ARCHIVE_BYTES

from ciso.common.errors import ValidationFailed

#: Most members (files and directories) in one tree.
MAX_MEMBERS: Final = 20_000
#: Largest single file, in bytes.
MAX_FILE_BYTES: Final = 16 * 1024 * 1024
#: Largest total of file sizes after decompression, in bytes.
MAX_EXPANDED_BYTES: Final = 128 * 1024 * 1024
#: Deepest path (number of components).
MAX_DEPTH: Final = 32
#: Longest path, in characters.
MAX_PATH_CHARS: Final = 400

_GZIP_MAGIC = b"\x1f\x8b"
#: Worst-case tar bytes per member besides content: header, long-name header, padding.
_TAR_OVERHEAD_PER_MEMBER: Final = 4 * 512
_TAR_TRAILER: Final = 20 * 512
_BUNDLE_HEADERS = (b"# v2 git bundle\n", b"# v3 git bundle\n")
#: Uid/gid written into rebuilt archives (the sandbox user, `nobody`).
OWNER_ID: Final = 65534


class ArchiveRejected(ValidationFailed):
    """The archive is malformed, too large or contains a hostile entry."""


@dataclass(frozen=True)
class SourceFile:
    path: str
    data: bytes = field(repr=False)
    executable: bool = False


@dataclass(frozen=True)
class SourceTree:
    """Validated files (sorted by path) and the directories that hold them."""

    files: tuple[SourceFile, ...]
    dirs: tuple[str, ...]

    def paths(self) -> tuple[str, ...]:
        return tuple(f.path for f in self.files)


def _raw_tar_cap() -> int:
    """Largest uncompressed tar stream: file content plus header and padding per member."""
    return MAX_EXPANDED_BYTES + MAX_MEMBERS * _TAR_OVERHEAD_PER_MEMBER + _TAR_TRAILER


def _inflate(data: bytes) -> bytes:
    """Gunzip with the expanded-size cap enforced while inflating (gzip bomb defense)."""
    cap = _raw_tar_cap()
    inflater = zlib.decompressobj(wbits=16 + zlib.MAX_WBITS)
    out = bytearray()
    pending = data
    try:
        while pending:
            room = cap + 1 - len(out)
            out += inflater.decompress(pending, max(room, 1))
            if len(out) > cap:
                raise ArchiveRejected("archive rejected: expanded size over the limit")
            pending = inflater.unconsumed_tail
            if inflater.eof:
                break
    except zlib.error as exc:
        raise ArchiveRejected("archive rejected: corrupt gzip stream") from exc
    if not inflater.eof:
        raise ArchiveRejected("archive rejected: truncated gzip stream")
    return bytes(out)


def _clean_path(name: str) -> str:
    """The normalised relative path, or `ArchiveRejected` naming why not."""
    if not name:
        raise ArchiveRejected("archive rejected: empty member name")
    if any(unicodedata.category(ch) in {"Cc", "Cf", "Zl", "Zp"} for ch in name):
        raise ArchiveRejected("archive rejected: control character in member name")
    if "\\" in name:
        raise ArchiveRejected("archive rejected: backslash in member name")
    if name.startswith("/") or (len(name) > 1 and name[1] == ":"):
        raise ArchiveRejected("archive rejected: absolute member name")
    if len(name) > MAX_PATH_CHARS:
        raise ArchiveRejected("archive rejected: member name too long")
    parts = [part for part in PurePosixPath(name).parts if part != "."]
    if ".." in parts:
        raise ArchiveRejected("archive rejected: path traversal in member name")
    if not parts:
        raise ArchiveRejected("archive rejected: empty member name")
    if len(parts) > MAX_DEPTH:
        raise ArchiveRejected("archive rejected: member path too deep")
    return "/".join(parts)


def _member_kind(member: tarfile.TarInfo) -> str:
    if member.issym() or member.islnk():
        raise ArchiveRejected("archive rejected: link member")
    if member.ischr() or member.isblk() or member.isfifo() or member.isdev():
        raise ArchiveRejected("archive rejected: special (device or fifo) member")
    if member.issparse():
        raise ArchiveRejected("archive rejected: sparse member")
    if member.isdir():
        return "dir"
    if member.isreg():
        return "file"
    raise ArchiveRejected("archive rejected: unsupported member type")


def _read_members(tf: tarfile.TarFile) -> SourceTree:
    files: dict[str, SourceFile] = {}
    dirs: set[str] = set()
    expanded = 0
    count = 0
    while (member := tf.next()) is not None:
        count += 1
        if count > MAX_MEMBERS:
            raise ArchiveRejected("archive rejected: too many members")
        path = _clean_path(member.name)
        kind = _member_kind(member)
        if path in files or (kind == "file" and path in dirs):
            raise ArchiveRejected("archive rejected: duplicate member path")
        if kind == "dir":
            dirs.add(path)
            continue
        if member.size > MAX_FILE_BYTES:
            raise ArchiveRejected("archive rejected: file too large")
        expanded += member.size
        if expanded > MAX_EXPANDED_BYTES:
            raise ArchiveRejected("archive rejected: expanded size over the limit")
        handle = tf.extractfile(member)
        if handle is None:
            raise ArchiveRejected("archive rejected: unreadable member")
        with handle:
            data = handle.read(member.size + 1)
        if len(data) != member.size:
            raise ArchiveRejected("archive rejected: member size mismatch")
        files[path] = SourceFile(path=path, data=data, executable=bool(member.mode & 0o111))
    return _finish(files, dirs)


def _finish(files: dict[str, SourceFile], dirs: set[str]) -> SourceTree:
    parents = {str(p) for path in files for p in PurePosixPath(path).parents if str(p) != "."}
    all_dirs = dirs | parents
    if all_dirs & set(files):
        raise ArchiveRejected("archive rejected: file and directory path conflict")
    return SourceTree(
        files=tuple(files[path] for path in sorted(files)), dirs=tuple(sorted(all_dirs))
    )


def read_tree(data: bytes) -> SourceTree:
    """Validate an uncompressed or gzip-compressed tar archive and return its files."""
    if len(data) > MAX_ARCHIVE_BYTES:
        raise ArchiveRejected("archive rejected: archive too large")
    raw = _inflate(data) if data.startswith(_GZIP_MAGIC) else data
    if len(raw) > _raw_tar_cap():
        raise ArchiveRejected("archive rejected: expanded size over the limit")
    try:
        with tarfile.open(fileobj=io.BytesIO(raw), mode="r:") as tf:
            return _read_members(tf)
    except tarfile.TarError as exc:
        raise ArchiveRejected("archive rejected: not a readable tar archive") from exc


def pack_tree(tree: SourceTree) -> bytes:
    """A fresh tar of the tree: fixed owner, modes 0755/0644, mtime 0, GNU format."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w", format=tarfile.GNU_FORMAT) as tf:
        for directory in tree.dirs:
            info = tarfile.TarInfo(directory)
            info.type = tarfile.DIRTYPE
            info.mode = 0o755
            tf.addfile(_owned(info))
        for item in tree.files:
            info = tarfile.TarInfo(item.path)
            info.size = len(item.data)
            info.mode = 0o755 if item.executable else 0o644
            tf.addfile(_owned(info), io.BytesIO(item.data))
    return buf.getvalue()


def _owned(info: tarfile.TarInfo) -> tarfile.TarInfo:
    info.uid = info.gid = OWNER_ID
    info.uname = info.gname = ""
    info.mtime = 0
    return info


def validate_bundle(data: bytes) -> None:
    """Check size and the git bundle header. The bundle itself is only opened by git inside
    a container (`runner.BUNDLE_SCRIPT`), never on this host."""
    if len(data) > MAX_ARCHIVE_BYTES:
        raise ArchiveRejected("archive rejected: archive too large")
    if not data.startswith(_BUNDLE_HEADERS):
        raise ArchiveRejected("archive rejected: not a v2 or v3 git bundle")
