"""Archive member names and archive ids refuse a trailing newline.

`$` also matches just before a final line feed, so `^...$` with `.match()` accepted
`"db/ops.sqlite\\n"` as a member name (later joined to the restore directory) and
`"bak_1\\n"` as an archive id (later used as a file name).
"""

from __future__ import annotations

import io

import pytest

from ciso.common.errors import ValidationFailed
from ciso.ops.archive import (
    KEY_ID_LEN,
    SALT_LEN,
    ArchiveWriter,
    MemberKind,
    check_member_name,
    encode_header,
)

pytestmark = pytest.mark.resilience

SECRET = b"k" * 32
SALT = b"s" * SALT_LEN
KID = b"i" * KEY_ID_LEN


def test_member_name_with_trailing_newline_is_refused() -> None:
    assert check_member_name("db/ops.sqlite") == "db/ops.sqlite"
    with pytest.raises(ValidationFailed, match="unsafe archive member name"):
        check_member_name("db/ops.sqlite\n")


def test_member_name_with_embedded_newline_is_refused() -> None:
    with pytest.raises(ValidationFailed, match="unsafe archive member name"):
        check_member_name("db/ops\n.sqlite")


def test_writer_refuses_a_member_name_with_trailing_newline_and_writes_no_record() -> None:
    out = io.BytesIO()
    writer = ArchiveWriter(out, SECRET, "bak_test")
    header_only = out.tell()
    with pytest.raises(ValidationFailed, match="unsafe archive member name"):
        writer.add_bytes("evidence/a.txt\n", MemberKind.FILE, b"data")
    assert out.tell() == header_only
    assert writer.add_bytes("evidence/a.txt", MemberKind.FILE, b"data").name == "evidence/a.txt"
    assert out.tell() > header_only


def test_archive_id_with_trailing_newline_is_refused() -> None:
    assert encode_header("bak_test", SALT, KID).endswith(SALT + KID)
    with pytest.raises(ValidationFailed, match="bad archive header fields"):
        encode_header("bak_test\n", SALT, KID)


def test_writer_refuses_an_archive_id_with_trailing_newline_and_writes_nothing() -> None:
    out = io.BytesIO()
    with pytest.raises(ValidationFailed, match="bad archive header fields"):
        ArchiveWriter(out, SECRET, "bak_test\n")
    assert out.tell() == 0
