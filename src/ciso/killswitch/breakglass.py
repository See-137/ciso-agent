"""Host-local break-glass: engage every kill-switch capability straight in the database.

Usage::

    python -m ciso.killswitch.breakglass --db <path> --reason <text> --operator <name>
        [--key-ref secret://<name>]

For when the API or the identity layer is down (gap G20, ADR-0018, blueprint 11.2). It
bypasses both, so the control here is host access: whoever can run this on the host and
write the database file can stop the platform. That is deliberate. It can only engage;
clearing a flag must go through the audited service.

Checks (review M4): the file must exist and must be the operational database, which
means it has a `schema_version` row for `killswitch`. Nothing is created in any other
file. After writing, every capability is read back through the same check
`KillSwitch.is_blocked` uses; success is reported only if all four read as blocked.

The operator name is typed, not authenticated. It is stored with the flags and queued in
the outbox; the audit record names the fixed `breakglass` identity (anonymous) and
carries the typed name as `unverified_operator`.

With `--key-ref`, the MAC key is resolved from this process's environment
(`CISO_SECRET_<NAME>`). Without it, or if it cannot be resolved, the rows are written
without a MAC: they still read as blocked (an unverifiable row always does), and the
output says so.
"""

from __future__ import annotations

import argparse
import logging
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import TextIO

from sqlalchemy import Engine, select

from ciso.common.clock import Clock, SystemClock
from ciso.common.db import create_db_engine, read_connection, schema_version
from ciso.common.enums import ActorType, KillCapability
from ciso.common.errors import CisoError, ValidationFailed
from ciso.common.protocols import SecretResolver
from ciso.killswitch.integrity import capability_reads_blocked, resolve_key
from ciso.killswitch.models import BREAKGLASS_ACTOR, VIA_BREAKGLASS
from ciso.killswitch.persist import engage_rows, run_write
from ciso.killswitch.rules import require_text
from ciso.vault import EnvSecretStore

logger = logging.getLogger(__name__)


class _Refused(Exception):
    pass


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m ciso.killswitch.breakglass",
        description="Engage every kill-switch capability directly in the operational "
        "database. Host access is the control.",
    )
    parser.add_argument("--db", required=True, type=Path, help="operational database file")
    parser.add_argument("--reason", required=True, help="why the stop is engaged")
    parser.add_argument("--operator", required=True, help="who is engaging it (not verified)")
    parser.add_argument("--key-ref", default=None, help="secret://name of the kill-switch key")
    return parser


def _check_operational(engine: Engine, db_path: Path) -> None:
    try:
        with read_connection(engine) as conn:
            row = conn.execute(
                select(schema_version.c.version).where(schema_version.c.module == "killswitch")
            ).first()
    except Exception as exc:
        raise _Refused(f"{db_path} is not the operational database ({type(exc).__name__})") from exc
    if row is None:
        raise _Refused(f"{db_path} is not the operational database (no killswitch schema)")


def main(
    argv: Sequence[str] | None = None,
    *,
    clock: Clock | None = None,
    secrets: SecretResolver | None = None,
    stdout: TextIO | None = None,
    stderr: TextIO | None = None,
) -> int:
    """Engage all capabilities. Returns 0 only when all four read back as blocked.

    Refusals and failures return 1; argument errors exit with status 2 through argparse.
    """
    out = stdout if stdout is not None else sys.stdout
    err = stderr if stderr is not None else sys.stderr
    args = build_parser().parse_args(argv)
    try:
        reason = require_text(args.reason, "reason")
        operator = require_text(args.operator, "operator")
    except ValidationFailed as exc:
        err.write(f"break-glass refused: {exc}\n")
        return 1
    db_path: Path = args.db
    if not db_path.is_file():
        err.write(f"break-glass refused: database file {db_path} does not exist\n")
        return 1
    key = resolve_key(secrets if secrets is not None else EnvSecretStore(), args.key_ref)
    caps = tuple(KillCapability)
    engine = create_db_engine(db_path)
    try:
        _check_operational(engine, db_path)
        now = (clock or SystemClock()).now()
        run_write(
            engine,
            lambda conn: engage_rows(
                conn, caps, actor_id=BREAKGLASS_ACTOR, actor_type=ActorType.ANONYMOUS,
                reason=reason, via=VIA_BREAKGLASS, operator=operator, now=now, key=key,
            ),
            what="break-glass engage",
            sleep=lambda _seconds: None,
        )  # fmt: skip
        still_clear = [c.value for c in caps if not capability_reads_blocked(engine, key, c)]
    except _Refused as exc:
        err.write(f"break-glass refused: {exc}\n")
        return 1
    except (CisoError, Exception) as exc:
        logger.exception("break-glass engage failed")
        err.write(f"break-glass failed: {type(exc).__name__}: {exc}\n")
        return 1
    finally:
        engine.dispose()
    if still_clear:
        err.write(f"break-glass failed: still reads clear: {', '.join(still_clear)}\n")
        return 1
    names = ", ".join(cap.value for cap in caps)
    mac_note = "rows MAC'd" if key is not None else (
        "key not available here: rows written without a MAC and read as blocked"
    )  # fmt: skip
    out.write(
        f"kill switch engaged for: {names} (operator {operator!r}, unverified); "
        f"{mac_note}; audit queued\n"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
