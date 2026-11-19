"""Command line of the CISO skill's tool. See `skills/ciso/SKILL.md` for how it is run.

    review       --repo DIR [--staged | --range A..B] [--data-dir DIR]
    check        --tool Bash --command TEXT | --tool Write|Edit|Read --path PATH
    audit-setup  --repo DIR [--home] [--data-dir DIR]
    summary      --data-dir DIR [--days N]

Exit 0 with the report on stdout; exit 1 with a one-line reason on stderr.
"""

from __future__ import annotations

import argparse
import os
import secrets
import tempfile
from collections.abc import Sequence
from pathlib import Path
from typing import TextIO

from ciso.common.clock import SystemClock
from ciso_plugin.gitrun import GitError, SafeGit, no_hooks_dir
from ciso_plugin.identity import os_account
from ciso_plugin.settings import SettingsError, git_executable
from ciso_plugin.tools import checkcmd, report, review, setup_audit, summary


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="ciso_tool")
    sub = parser.add_subparsers(dest="command", required=True)
    r = sub.add_parser("review")
    r.add_argument("--repo", required=True)
    group = r.add_mutually_exclusive_group()
    group.add_argument("--staged", action="store_true")
    group.add_argument("--range")
    r.add_argument("--data-dir")
    c = sub.add_parser("check")
    c.add_argument("--tool", default="Bash")
    c.add_argument("--command")
    c.add_argument("--path")
    c.add_argument("--data-dir")
    a = sub.add_parser("audit-setup")
    a.add_argument("--repo", required=True)
    a.add_argument("--home", action="store_true")
    a.add_argument("--data-dir")
    s = sub.add_parser("summary")
    s.add_argument("--data-dir", required=True)
    s.add_argument("--days", type=int, default=30)
    return parser


def _directory(text: str) -> Path:
    path = Path(text)
    if not path.is_absolute() or not path.is_dir():
        raise ValueError("pass an absolute path to an existing folder")
    return path


def _git(repo: Path, data: Path | None) -> SafeGit | None:
    try:
        exe = git_executable(os.environ)
    except SettingsError:
        return None
    base = data if data is not None else Path(tempfile.gettempdir()) / secrets.token_hex(8)
    git = SafeGit(exe, str(repo), no_hooks_dir(base), dict(os.environ))
    probe = git.run("rev-parse", "--show-toplevel")
    return git if probe.returncode == 0 else None


def _review(args: argparse.Namespace, data: Path | None) -> str:
    repo = _directory(args.repo)
    git = _git(repo, data)
    if (args.staged or args.range) and git is None:
        raise ValueError("--staged and --range need a git repository and git")
    if args.staged and git is not None:
        result, scope = review.review_staged(git), f"staged change in {repo.name}"
    elif args.range and git is not None:
        result, scope = review.review_range(git, args.range), f"commits {args.range} in {repo.name}"
    else:
        result, scope = review.review_files(repo, git), f"all files of {repo.name}"
    when = SystemClock().now()
    text = report.render(
        "CISO code review", scope, result.findings, review.coverage_notes(result), when
    )
    saved = report.save(data, "review", text, when)
    return text + (f"\nReport saved: {saved}\n" if saved else "")


def _audit(args: argparse.Namespace, data: Path | None) -> str:
    repo = _directory(args.repo)
    findings = setup_audit.audit_repo(repo)
    scope = f"agent setup of {repo.name}"
    if args.home:
        findings += setup_audit.audit_home(Path.home())
        scope += " and this user's machine configuration"
    notes = [
        "Values (environment, headers, arguments) are scanned, never shown.",
        "Settings delivered by the organization (managed settings) are not audited here.",
    ]
    when = SystemClock().now()
    text = report.render("CISO agent setup audit", scope, findings, notes, when)
    saved = report.save(data, "setup-audit", text, when)
    return text + (f"\nReport saved: {saved}\n" if saved else "")


def run(argv: Sequence[str], plugin_root: Path, out: TextIO, err: TextIO) -> int:
    args = _parser().parse_args(list(argv))
    try:
        data = _directory(args.data_dir) if getattr(args, "data_dir", None) else None
        if args.command == "review":
            text = _review(args, data)
        elif args.command == "audit-setup":
            text = _audit(args, data)
        elif args.command == "summary":
            if data is None:
                raise ValueError("--data-dir is required")
            text = summary.summarise(data, args.days, SystemClock().now())
        else:
            text = checkcmd.check(
                tool=args.tool,
                command=args.command,
                path=args.path,
                plugin_root=plugin_root,
                environ=os.environ,
                clock=SystemClock(),
                account=os_account(),
            )
    except (ValueError, GitError, OSError) as error:
        reason = error.code if isinstance(error, GitError) else str(error)
        err.write(f"ciso_tool: {reason}\n")
        return 1
    out.write(text + "\n")
    return 0
