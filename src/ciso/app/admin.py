"""Host-local administration commands. Never reachable from the API (ADR-0004, ADR-0018).

Usage::

    python -m ciso.app.admin --config <settings.json> bootstrap --name <display name>
    python -m ciso.app.admin --config <settings.json> recover-token --actor <id>
        --operator <name> --reason <text>
    python -m ciso.app.admin --config <settings.json> killswitch-reconcile
    python -m ciso.app.admin --config <settings.json> audit-verify

The control here is host access: whoever can run this on the host with the secret
environment can bootstrap the first administrator (once per database, ever) or issue a
fresh token to an existing administrator who is locked out (review finding F2). Both are
audited by `HostLocalAdmin` with the host-local identity.

A token is written to standard output once, by `sys.stdout.write`, and nowhere else: it is
never logged and never stored (only its hash is). `killswitch-reconcile` reports what the
start-up reconcile found and runs it again; `audit-verify` prints the verification result.

Exit status: 0 success; 1 refused, failed, or a check that did not pass; 2 bad arguments
(from argparse).
"""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path
from typing import IO, TextIO

from ciso.app.container import Container, build_container
from ciso.app.killswitch_startup import MISMATCH, RECONCILE_FAILED, describe_mismatch
from ciso.app.settings import load_settings
from ciso.audit import VerifyStatus
from ciso.common.clock import Clock
from ciso.common.errors import CisoError
from ciso.identity import PRODUCTION_SCRYPT, IssuedToken, ScryptParams

Command = Callable[[Container, argparse.Namespace, TextIO], int]


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="python -m ciso.app.admin")
    parser.add_argument("--config", required=True, type=Path, help="settings JSON file")
    commands = parser.add_subparsers(dest="command", required=True)
    boot = commands.add_parser("bootstrap", help="create the first security_admin, once")
    boot.add_argument("--name", required=True, help="display name of the first administrator")
    recover = commands.add_parser("recover-token", help="new token for a locked-out admin")
    recover.add_argument("--actor", required=True, help="actor id of the administrator")
    recover.add_argument("--operator", required=True, help="person running this at the host")
    recover.add_argument("--reason", required=True, help="why the token is being recovered")
    commands.add_parser("killswitch-reconcile", help="compare flags with the audit log")
    commands.add_parser("audit-verify", help="verify the audit chain, anchor and witness")
    return parser


def _write_token(out: TextIO, issued: IssuedToken) -> None:
    out.write(f"actor_id: {issued.actor_id}\n")
    out.write(f"token_id: {issued.token_id}\n")
    out.write(f"expires_at: {issued.expires_at.isoformat()}\n")
    out.write(f"token: {issued.token}\n")
    out.write("The token is shown once and is not stored. Keep it now.\n")


def _bootstrap(container: Container, args: argparse.Namespace, out: TextIO) -> int:
    result = container.host_local.bootstrap_first_admin(args.name)
    _write_token(out, result.token)
    return 0


def _recover(container: Container, args: argparse.Namespace, out: TextIO) -> int:
    issued = container.host_local.recover_admin_token(args.actor, args.operator, args.reason)
    _write_token(out, issued)
    return 0


def _reconcile(container: Container, args: argparse.Namespace, out: TextIO) -> int:
    at_start = [
        item
        for item in container.readiness().missing
        if item.startswith((MISMATCH, RECONCILE_FAILED))
    ]
    for item in at_start:
        out.write(f"start-up: {item}\n")
    now = container.killswitch.reconcile()
    for mismatch in now:
        out.write(f"now: {describe_mismatch(mismatch)}\n")
    for state in container.killswitch.status():
        reading = "blocked" if state.engaged else "clear"
        out.write(f"{state.capability.value}: {reading}\n")
    if at_start or now:
        out.write("kill-switch flags disagreed with the audit log; see above\n")
        return 1
    out.write("kill-switch flags agree with the audit log\n")
    return 0


def _verify(container: Container, args: argparse.Namespace, out: TextIO) -> int:
    result = container.audit.verify()
    out.write(json.dumps(result.model_dump(mode="json"), sort_keys=True) + "\n")
    return 0 if result.status is VerifyStatus.OK else 1


COMMANDS: Mapping[str, Command] = {
    "bootstrap": _bootstrap,
    "recover-token": _recover,
    "killswitch-reconcile": _reconcile,
    "audit-verify": _verify,
}


def main(
    argv: Sequence[str] | None = None,
    *,
    environ: Mapping[str, str] | None = None,
    clock: Clock | None = None,
    scrypt: ScryptParams = PRODUCTION_SCRYPT,
    stdout: TextIO | None = None,
    stderr: TextIO | None = None,
    log_stream: IO[str] | None = None,
) -> int:
    """Run one command. `environ` is where `secret://` references resolve (default: the
    process environment). Log lines go through the redacting handler to `log_stream`
    (default: standard error); command output goes to `stdout`."""
    out = stdout if stdout is not None else sys.stdout
    err = stderr if stderr is not None else sys.stderr
    args = build_parser().parse_args(argv)
    try:
        settings = load_settings(args.config)
    except CisoError as exc:
        err.write(f"refused: {exc}\n")
        return 1
    with build_container(
        settings, environ=environ, clock=clock, scrypt=scrypt, log_stream=log_stream
    ) as container:
        try:
            return COMMANDS[args.command](container, args, out)
        except CisoError as exc:
            message = container.redactor.redact(str(exc))
            err.write(f"refused: {type(exc).__name__}: {message}\n")
            return 1


if __name__ == "__main__":
    sys.exit(main())
