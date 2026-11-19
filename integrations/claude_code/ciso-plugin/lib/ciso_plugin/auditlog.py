"""Append-only, hash-chained JSON Lines logs in the plugin's per-user data directory.

Each line is one record: `seq`, `at`, the record body, `prev` (the previous line's hash,
64 zeros for the first) and `hash` = SHA-256 of `prev` + the canonical JSON of the line
without `hash`. Editing, removing or reordering a line breaks the chain; `verify` finds
it. The chain is tamper-EVIDENT for whoever reads it later, not tamper-proof: the file
lives in a folder the user can write (README, "Limits").

Writers hold an exclusive lock on a side file while they read the tail and append, so two
hooks running at once (parallel tool calls) cannot fork the chain. A lock that cannot be
taken in time, an unreadable tail or a failed write raises; the hook then blocks.

Never written: command text, prompts, file content, secrets. Callers pass ids, codes,
kinds, hashes and redacted targets only.
"""

from __future__ import annotations

import hashlib
import json
import os
import sys
import time
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Final

from ciso.common.clock import Clock
from ciso.common.ids import new_id
from ciso.common.protocols import AuditEvent, AuditReceipt

GENESIS: Final = "0" * 64
#: Bytes read from the end of the file to find the last record.
TAIL_BYTES: Final = 256 * 1024
#: Longest record line written.
MAX_LINE_BYTES: Final = 64 * 1024
LOCK_ATTEMPTS: Final = 200
LOCK_PAUSE_SECONDS: Final = 0.025


class LogError(Exception):
    """The log could not be read or written. The message names no content."""


def _canonical(value: Mapping[str, Any]) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def record_hash(prev: str, body: Mapping[str, Any]) -> str:
    return hashlib.sha256((prev + _canonical(body)).encode("utf-8")).hexdigest()


@contextmanager
def _locked(path: Path) -> Iterator[None]:
    lock_path = path.with_name(path.name + ".lock")
    fd = os.open(lock_path, os.O_RDWR | os.O_CREAT, 0o600)
    try:
        for _ in range(LOCK_ATTEMPTS):
            if _try_lock(fd):
                break
            time.sleep(LOCK_PAUSE_SECONDS)
        else:
            raise LogError("log is locked by another writer")
        try:
            yield
        finally:
            _unlock(fd)
    finally:
        os.close(fd)


def _try_lock(fd: int) -> bool:
    if sys.platform == "win32":
        import msvcrt

        try:
            os.lseek(fd, 0, os.SEEK_SET)
            msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
        except OSError:
            return False
        return True
    import fcntl

    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        return False
    return True


def _unlock(fd: int) -> None:
    if sys.platform == "win32":
        import msvcrt

        os.lseek(fd, 0, os.SEEK_SET)
        msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)
        return
    import fcntl

    fcntl.flock(fd, fcntl.LOCK_UN)


def _last_record(path: Path) -> dict[str, Any] | None:
    if not path.exists() or path.stat().st_size == 0:
        return None
    with path.open("rb") as handle:
        size = handle.seek(0, os.SEEK_END)
        handle.seek(max(0, size - TAIL_BYTES))
        tail = handle.read()
    if not tail.endswith(b"\n"):
        raise LogError("log does not end with a complete record")
    lines = tail.rstrip(b"\n").split(b"\n")
    try:
        last = json.loads(lines[-1].decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as error:
        raise LogError("last log record is unreadable") from error
    if not isinstance(last, dict) or not isinstance(last.get("hash"), str):
        raise LogError("last log record is malformed")
    return last


@dataclass(frozen=True)
class ChainedLog:
    path: Path
    clock: Clock

    def append(self, body: Mapping[str, Any]) -> dict[str, Any]:
        """Append one record and return it (with `seq`, `at`, `prev`, `hash`)."""
        if {"seq", "at", "prev", "hash"} & set(body):
            raise LogError("record body uses a reserved key")
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with _locked(self.path):
            last = _last_record(self.path)
            prev = GENESIS if last is None else str(last["hash"])
            seq = 1 if last is None else int(last.get("seq", 0)) + 1
            record: dict[str, Any] = {"seq": seq, "at": self.clock.now().isoformat(), **body}
            record["prev"] = prev
            record["hash"] = record_hash(prev, record)
            line = (_canonical(record) + "\n").encode("utf-8")
            if len(line) > MAX_LINE_BYTES:
                raise LogError("log record too large")
            with self.path.open("ab") as handle:
                handle.write(line)
                handle.flush()
                os.fsync(handle.fileno())
        return record


@dataclass(frozen=True)
class ChainReport:
    records: int
    ok: bool
    first_break: int | None = None


def verify(path: Path) -> ChainReport:
    """Re-compute the chain. `first_break` is the 1-based line where it fails."""
    if not path.exists():
        return ChainReport(records=0, ok=True)
    prev = GENESIS
    count = 0
    with path.open("rb") as handle:
        for number, raw in enumerate(handle, start=1):
            count = number
            try:
                record = json.loads(raw.decode("utf-8"))
                body = {k: v for k, v in record.items() if k != "hash"}
                good = (
                    isinstance(record, dict)
                    and record.get("prev") == prev
                    and record_hash(prev, body) == record.get("hash")
                )
            except (UnicodeDecodeError, ValueError, AttributeError):
                good = False
            if not good:
                return ChainReport(records=count, ok=False, first_break=number)
            prev = str(record["hash"])
    return ChainReport(records=count, ok=True)


def read_records(path: Path, limit: int) -> list[dict[str, Any]]:
    """The last `limit` well-formed records (for summaries). Never raises on a bad line."""
    if not path.exists():
        return []
    out: list[dict[str, Any]] = []
    with path.open("rb") as handle:
        for raw in handle:
            try:
                record = json.loads(raw.decode("utf-8"))
            except (UnicodeDecodeError, ValueError):
                continue
            if isinstance(record, dict):
                out.append(record)
    return out[-limit:]


class LocalAuditSink:
    """`AuditSink` for the governance engine: one chained record per event."""

    def __init__(self, log: ChainedLog) -> None:
        self._log = log

    def append(self, event: AuditEvent) -> AuditReceipt:
        record = self._log.append(
            {
                "type": event.action,
                "actor": event.actor_id,
                "outcome": event.outcome.value,
                "target": event.target,
                "correlation": event.correlation_id,
                "details": event.details,
            }
        )
        return AuditReceipt(
            record_id=new_id("aud"),
            seq=int(record["seq"]),
            occurred_at=datetime.fromisoformat(str(record["at"])),
            hash=str(record["hash"]),
        )


class NullAuditSink:
    """For a probe decision that is never the answer (see `decide.py`)."""

    def __init__(self, clock: Clock) -> None:
        self._clock = clock

    def append(self, event: AuditEvent) -> AuditReceipt:
        return AuditReceipt(
            record_id=new_id("aud"), seq=0, occurred_at=self._clock.now(), hash=GENESIS
        )
