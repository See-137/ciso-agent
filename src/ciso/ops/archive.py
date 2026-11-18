"""Encrypted backup archive format (ADR-0014, blueprint 10.3, 11.1, NFR-007).

Layout, all integers big-endian::

    header   = MAGIC(8) | version(1) | id_len(1) | archive_id | salt(32) | key_id(32)
    record   = type(1) | name_len(2) | name | size(8) | nonce(12) | ciphertext(size) | tag(16)
    archive  = header | member record * N | manifest record | end of file

Every record is AES-256-GCM with a fresh random nonce. The key is HKDF-SHA256 of the
backup secret with the per-archive salt, so no two archives share a key. Associated data:

- member:   archive id, record index, member name, plaintext size;
- manifest: archive id, SHA-256 of the header bytes, number of member records.

So a member cannot be renamed, reordered, resized or moved to another archive, and the
header cannot be edited, without a tag failing. The manifest (names, sizes, SHA-256 of
each plaintext, row counts) is the last record and must be followed by end of file, so a
truncated archive has no valid manifest. `key_id` is an HKDF output of the secret (never
the secret) so a wrong key is reported as such before anything is decrypted.

Every failure to parse or authenticate raises `IntegrityFailure`.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import re
import struct
from collections.abc import Callable
from enum import StrEnum
from pathlib import Path
from typing import BinaryIO, Protocol

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from pydantic import Field, ValidationError

from ciso.common.errors import IntegrityFailure, ValidationFailed
from ciso.common.schemas import FrozenMap, Model, UtcDatetime, canonical_json, sha256_hex

MAGIC = b"CISOBAK\x00"
FORMAT_VERSION = 1
SALT_LEN = 32
KEY_ID_LEN = 32
NONCE_LEN = 12
TAG_LEN = 16
CHUNK = 1 << 20
ARCHIVE_SUFFIX = ".cisobak"
_MEMBER = 1
_MANIFEST = 2
_RECORD_HEAD = struct.Struct(">BH")
_SIZE = struct.Struct(">Q")
_KEY_INFO = b"ciso.ops.backup.v1.archive-key"
_KEY_ID_INFO = b"ciso.ops.backup.v1.key-id"
_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*(/[A-Za-z0-9][A-Za-z0-9._-]*)*$")
_ID_RE = re.compile(r"^[a-z0-9_A-Z]{1,64}$")
_MAX_NAME = 255


class MemberKind(StrEnum):
    SQLITE = "sqlite"
    FILE = "file"


class MemberEntry(Model):
    name: str
    kind: MemberKind
    size: int
    sha256: str
    #: Rows per table, for SQLite members only.
    row_counts: FrozenMap[str, int] = Field(default_factory=dict)


class BackupManifest(Model):
    format_version: int
    archive_id: str
    created_at: UtcDatetime
    created_by: str
    key_id: str
    #: The audit log's id as recorded in the anchor file, when the anchor carries one.
    audit_log_id: str | None = None
    members: tuple[MemberEntry, ...]

    @property
    def file_name(self) -> str:
        return archive_file_name(self.archive_id)

    def member(self, name: str) -> MemberEntry | None:
        return next((m for m in self.members if m.name == name), None)


class RecordSpan(Model):
    """Byte offsets of one record; for tests and diagnostics. Decrypts nothing."""

    kind: str
    name: str
    start: int
    body_start: int
    tag_start: int
    end: int


def archive_file_name(archive_id: str) -> str:
    return f"{archive_id}{ARCHIVE_SUFFIX}"


def check_member_name(name: str) -> str:
    """Relative, forward-slash, no `..`, no leading dot, limited characters."""
    if len(name) > _MAX_NAME or not _NAME_RE.fullmatch(name) or ".." in name.split("/"):
        raise ValidationFailed(f"unsafe archive member name: {name!r}")
    return name


def derive_key(secret: bytes, salt: bytes) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=salt, info=_KEY_INFO).derive(secret)


def key_id(secret: bytes) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=KEY_ID_LEN, salt=None, info=_KEY_ID_INFO).derive(
        secret
    )


def encode_header(archive_id: str, salt: bytes, kid: bytes) -> bytes:
    raw_id = archive_id.encode("ascii")
    if not _ID_RE.fullmatch(archive_id) or len(salt) != SALT_LEN or len(kid) != KEY_ID_LEN:
        raise ValidationFailed("bad archive header fields")
    return MAGIC + bytes([FORMAT_VERSION, len(raw_id)]) + raw_id + salt + kid


def _member_aad(archive_id: str, index: int, name: str, size: int) -> bytes:
    return canonical_json(
        {"type": "member", "archive_id": archive_id, "index": index, "name": name, "size": size}
    ).encode("utf-8")


def _manifest_aad(archive_id: str, header: bytes, count: int) -> bytes:
    return canonical_json(
        {"type": "manifest", "archive_id": archive_id, "header": sha256_hex(header), "count": count}
    ).encode("utf-8")


class ArchiveWriter:
    """Writes records to an open binary file. Holds the derived key; never logs it."""

    def __init__(self, out: BinaryIO, secret: bytes, archive_id: str) -> None:
        self._out = out
        self._archive_id = archive_id
        salt = os.urandom(SALT_LEN)
        self._key = derive_key(secret, salt)
        self.key_id = key_id(secret).hex()
        self.header = encode_header(archive_id, salt, bytes.fromhex(self.key_id))
        self._count = 0
        out.write(self.header)

    def add_member(self, name: str, kind: MemberKind, source: Path) -> MemberEntry:
        check_member_name(name)
        size = source.stat().st_size
        aad = _member_aad(self._archive_id, self._count, name, size)
        with source.open("rb") as handle:
            digest, written = self._record(_MEMBER, name, size, aad, handle)
        if written != size:
            raise IntegrityFailure(f"{name} changed size while it was archived")
        self._count += 1
        return MemberEntry(name=name, kind=kind, size=size, sha256=digest)

    def add_bytes(self, name: str, kind: MemberKind, data: bytes) -> MemberEntry:
        check_member_name(name)
        aad = _member_aad(self._archive_id, self._count, name, len(data))
        digest, _ = self._record(_MEMBER, name, len(data), aad, _BytesSource(data))
        self._count += 1
        return MemberEntry(name=name, kind=kind, size=len(data), sha256=digest)

    def finish(self, manifest: BackupManifest) -> None:
        data = canonical_json(manifest).encode("utf-8")
        aad = _manifest_aad(self._archive_id, self.header, self._count)
        self._record(_MANIFEST, "", len(data), aad, _BytesSource(data))

    def _record(
        self, kind: int, name: str, size: int, aad: bytes, source: _Readable
    ) -> tuple[str, int]:
        raw_name = name.encode("utf-8")
        nonce = os.urandom(NONCE_LEN)
        self._out.write(_RECORD_HEAD.pack(kind, len(raw_name)) + raw_name)
        self._out.write(_SIZE.pack(size) + nonce)
        enc = Cipher(algorithms.AES(self._key), modes.GCM(nonce)).encryptor()
        enc.authenticate_additional_data(aad)
        digest = hashlib.sha256()
        written = 0
        while written < size:
            chunk = source.read(min(CHUNK, size - written))
            if not chunk:
                break
            digest.update(chunk)
            written += len(chunk)
            self._out.write(enc.update(chunk))
        self._out.write(enc.finalize() + enc.tag)
        return digest.hexdigest(), written


class _Readable(Protocol):
    def read(self, n: int, /) -> bytes: ...


class _BytesSource:
    def __init__(self, data: bytes) -> None:
        self._data = data
        self._pos = 0

    def read(self, n: int) -> bytes:
        chunk = self._data[self._pos : self._pos + n]
        self._pos += len(chunk)
        return chunk


#: Called with (index, member name) before a member is decrypted; returns where to write
#: the plaintext, or None to only verify it.
SinkFactory = Callable[[int, str], BinaryIO | None]


def read_archive(path: Path, secret: bytes, open_sink: SinkFactory | None = None) -> BackupManifest:
    """Authenticate every record and the manifest; optionally stream plaintext to sinks.

    Plaintext reaches a sink before that member's tag is checked (GCM streaming), so a
    caller that writes must have verified the archive first and must discard everything
    it wrote if this raises.
    """
    try:
        with path.open("rb") as handle:
            total = os.fstat(handle.fileno()).st_size
            return _read(handle, total, secret, open_sink)
    except OSError as exc:
        raise IntegrityFailure("backup archive cannot be read") from exc


def _read(
    handle: BinaryIO, total: int, secret: bytes, open_sink: SinkFactory | None
) -> BackupManifest:
    header, archive_id, salt, kid = _read_header(handle)
    if not hmac.compare_digest(kid, key_id(secret)):
        raise IntegrityFailure("backup archive was made with a different key")
    key = derive_key(secret, salt)
    seen: list[tuple[str, int, str]] = []
    while True:
        kind, name, size, nonce, tag, body = _read_record_head(handle, total)
        if kind == _MANIFEST:
            aad = _manifest_aad(archive_id, header, len(seen))
            data = _decrypt(handle, key, nonce, tag, aad, size, None)[1]
            if handle.tell() + TAG_LEN != total:
                raise IntegrityFailure("backup archive has data after its manifest")
            return _check_manifest(data or b"", archive_id, kid, seen)
        aad = _member_aad(archive_id, len(seen), name, size)
        sink = open_sink(len(seen), name) if open_sink is not None else None
        try:
            digest, _ = _decrypt(handle, key, nonce, tag, aad, size, sink)
        finally:
            if sink is not None:
                sink.close()
        handle.seek(body + size + TAG_LEN)
        seen.append((name, size, digest))


def _read_header(handle: BinaryIO) -> tuple[bytes, str, bytes, bytes]:
    fixed = handle.read(len(MAGIC) + 2)
    if len(fixed) != len(MAGIC) + 2 or fixed[: len(MAGIC)] != MAGIC:
        raise IntegrityFailure("not a backup archive")
    if fixed[len(MAGIC)] != FORMAT_VERSION:
        raise IntegrityFailure("unsupported backup archive version")
    id_len = fixed[len(MAGIC) + 1]
    rest = handle.read(id_len + SALT_LEN + KEY_ID_LEN)
    if len(rest) != id_len + SALT_LEN + KEY_ID_LEN:
        raise IntegrityFailure("backup archive header is truncated")
    try:
        archive_id = rest[:id_len].decode("ascii")
    except UnicodeDecodeError as exc:
        raise IntegrityFailure("backup archive header is corrupt") from exc
    salt = rest[id_len : id_len + SALT_LEN]
    kid = rest[id_len + SALT_LEN :]
    return fixed + rest, archive_id, salt, kid


def _read_record_head(handle: BinaryIO, total: int) -> tuple[int, str, int, bytes, bytes, int]:
    head = handle.read(_RECORD_HEAD.size)
    if len(head) != _RECORD_HEAD.size:
        raise IntegrityFailure("backup archive is truncated: no manifest")
    kind, name_len = _RECORD_HEAD.unpack(head)
    if kind not in (_MEMBER, _MANIFEST):
        raise IntegrityFailure("backup archive record type is corrupt")
    raw_name = handle.read(name_len)
    fixed = handle.read(_SIZE.size + NONCE_LEN)
    if len(raw_name) != name_len or len(fixed) != _SIZE.size + NONCE_LEN:
        raise IntegrityFailure("backup archive is truncated")
    try:
        name = raw_name.decode("utf-8")
        if kind == _MEMBER:
            check_member_name(name)
    except (UnicodeDecodeError, ValidationFailed) as exc:
        raise IntegrityFailure("backup archive member name is corrupt") from exc
    (size,) = _SIZE.unpack(fixed[: _SIZE.size])
    nonce = fixed[_SIZE.size :]
    body = handle.tell()
    if body + size + TAG_LEN > total:
        raise IntegrityFailure("backup archive is truncated")
    handle.seek(body + size)
    tag = handle.read(TAG_LEN)
    handle.seek(body)
    return kind, name, size, nonce, tag, body


def _decrypt(
    handle: BinaryIO,
    key: bytes,
    nonce: bytes,
    tag: bytes,
    aad: bytes,
    size: int,
    sink: BinaryIO | None,
) -> tuple[str, bytes | None]:
    dec = Cipher(algorithms.AES(key), modes.GCM(nonce, tag)).decryptor()
    dec.authenticate_additional_data(aad)
    digest = hashlib.sha256()
    kept: list[bytes] | None = [] if sink is None and size <= CHUNK * 4 else None
    remaining = size
    while remaining:
        chunk = handle.read(min(CHUNK, remaining))
        if not chunk:
            raise IntegrityFailure("backup archive is truncated")
        remaining -= len(chunk)
        plain = dec.update(chunk)
        digest.update(plain)
        if sink is not None:
            sink.write(plain)
        elif kept is not None:
            kept.append(plain)
    try:
        dec.finalize()
    except InvalidTag as exc:
        raise IntegrityFailure("backup archive failed authentication") from exc
    return digest.hexdigest(), (b"".join(kept) if kept is not None else None)


def _check_manifest(
    data: bytes, archive_id: str, kid: bytes, seen: list[tuple[str, int, str]]
) -> BackupManifest:
    try:
        manifest = BackupManifest.model_validate_json(data)
    except ValidationError as exc:
        raise IntegrityFailure("backup manifest is not valid") from exc
    if manifest.archive_id != archive_id or manifest.key_id != kid.hex():
        raise IntegrityFailure("backup manifest does not belong to this archive")
    if manifest.format_version != FORMAT_VERSION:
        raise IntegrityFailure("backup manifest version is not supported")
    listed = [(m.name, m.size, m.sha256) for m in manifest.members]
    if listed != seen:
        raise IntegrityFailure("backup archive members do not match the manifest")
    return manifest


def describe_layout(path: Path) -> tuple[RecordSpan, ...]:
    """Record offsets of an archive, without decrypting. For tests and diagnostics."""
    spans: list[RecordSpan] = []
    with path.open("rb") as handle:
        total = os.fstat(handle.fileno()).st_size
        header, *_ = _read_header(handle)
        spans.append(RecordSpan(kind="header", name="", start=0, body_start=0,
                                tag_start=len(header), end=len(header)))  # fmt: skip
        while handle.tell() < total:
            start = handle.tell()
            kind, name, size, _nonce, _tag, body = _read_record_head(handle, total)
            end = body + size + TAG_LEN
            label = "member" if kind == _MEMBER else "manifest"
            spans.append(RecordSpan(kind=label, name=name, start=start, body_start=body,
                                    tag_start=body + size, end=end))  # fmt: skip
            handle.seek(end)
    return tuple(spans)
