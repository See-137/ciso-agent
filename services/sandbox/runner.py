"""Running one job: checks in isolated containers, a report in the fixed format.

Order of refusals (each ends the job with every check `error`, before anything runs):
1. a limit is unset (`sandbox.settings_unset`);
2. there is no backend (`sandbox.isolation_unavailable`);
3. the archive is rejected (`sandbox.archive_rejected`);
4. the backend's probe fails or raises (`sandbox.isolation_unavailable`).
A check whose image or rules are unset is `error` on its own. The whole job shares one
wall-time budget; each container gets only what is left.

A tar job: every container receives the tar the sandbox rebuilt (`archive.pack_tree`).
A bundle job: first a git container verifies that the bundle is what the job states
(`verify.verify_bundle`: HEAD, base ancestry, the exact commit set); a mismatch ends the
job with every check `error` `sandbox.range_mismatch` (a bundle job with no git image:
`sandbox.settings_unset`). Then the scanners receive the bundle (history from `base_ref`,
or the whole history); the tests receive the HEAD tree, exported by a git container and
then put through the same archive checks as a tar job. Every bundle container re-checks
that its clone's HEAD is the verified head (`SANDBOX_HEAD`); the report names that head.

The scanners never read configuration from the scanned code (review H3): gitleaks gets the
image's config and an empty ignore file and ignores inline allow comments, and scans a
bundle twice (history in `git` mode and the checked-out tree in `dir` mode, merged into
one `secrets` check); semgrep ignores `nosemgrep` comments and `.semgrepignore` files. The
fixed scripts move the scanners' own files out of the scanned directory, and the bundle
script writes `* diff -export-ignore -export-subst` to `.git/info/attributes`, which
outranks any `.gitattributes` in the tree, so `git log -p` shows every file as text and
`git archive` exports every file as committed.
"""

from __future__ import annotations

import logging
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Final

from services.sandbox.archive import ArchiveRejected, SourceTree, pack_tree, read_tree
from services.sandbox.backend import Backend, ContainerSpec, RunOutcome
from services.sandbox.job import TEST_COMMANDS, ArchiveFormat, CheckId, Job, ProjectType
from services.sandbox.job import detect_project as _detect
from services.sandbox.parsers import (
    parse_gitleaks,
    parse_go_test,
    parse_npm_test,
    parse_pytest,
    parse_semgrep,
)
from services.sandbox.report import (
    CheckReport,
    Report,
    Status,
    error_check,
    finding,
    merge_checks,
)
from services.sandbox.settings import ResolvedLimits, SandboxSettings, SettingsUnset
from services.sandbox.verify import verify_bundle

from ciso.common.activity import Severity
from ciso.common.clock import Clock
from ciso.common.ids import new_id
from services.sandbox import archive

logger = logging.getLogger(__name__)

#: The scanners' own configuration files, moved out of the scanned root before anything
#: runs (defence in depth: the commands already name fixed files from the image).
_SCANNER_FILES: Final = "for f in .gitleaks.toml .gitleaksignore .semgrepignore; do "
#: Unpack the streamed tar into the work dir and run the command words given as arguments.
TAR_SCRIPT: Final = (
    "set -eu; mkdir -p /work/src /work/tmp; tar -x -f - -C /work/src; cd /work/src; "
    + _SCANNER_FILES
    + 'if [ -e "$f" ]; then mv -f -- "$f" "/work/tmp/inert$f"; fi; done; '
    + 'exec "$@"'
)
#: Clone the streamed bundle, check its HEAD is the verified head, override every attribute
#: file in the tree, move the scanner files away (tracked ones marked skip-worktree first,
#: so `git status` stays clean for semgrep's baseline) and run the command words.
BUNDLE_SCRIPT: Final = (
    "set -eu; mkdir -p /work/tmp; cat > /work/tmp/in.bundle; "
    "git clone -q /work/tmp/in.bundle /work/src; cd /work/src; "
    'test "$(git rev-parse HEAD)" = "$SANDBOX_HEAD"; '
    "mkdir -p .git/info; "
    "printf '* diff -export-ignore -export-subst\\n' > .git/info/attributes; "
    + _SCANNER_FILES
    + 'if [ -e "$f" ]; then git update-index --skip-worktree -- "$f" 2>/dev/null || true; '
    + 'mv -f -- "$f" "/work/tmp/inert$f"; fi; done; '
    + 'exec "$@"'
)

_BASE_ENV: Final = (("HOME", "/work"), ("TMPDIR", "/work/tmp"), ("LANG", "C.UTF-8"))
_TEST_ENV: Final = {
    ProjectType.PYTHON: (("PYTHONDONTWRITEBYTECODE", "1"),),
    ProjectType.NODE: (
        ("NPM_CONFIG_CACHE", "/work/tmp/npm"),
        ("NPM_CONFIG_UPDATE_NOTIFIER", "false"),
    ),
    ProjectType.GO: (
        ("GOCACHE", "/work/tmp/gocache"),
        ("GOPATH", "/work/tmp/gopath"),
        ("GOPROXY", "off"),
        ("GOTOOLCHAIN", "local"),
    ),
}
_TEST_PARSERS: Final[dict[ProjectType, Callable[[RunOutcome], CheckReport]]] = {
    ProjectType.PYTHON: parse_pytest,
    ProjectType.NODE: parse_npm_test,
    ProjectType.GO: parse_go_test,
}


@dataclass(frozen=True)
class RunnerHealth:
    usable: bool
    missing: tuple[str, ...]
    backend_reasons: tuple[str, ...]


@dataclass(frozen=True)
class _Plan:
    """What one check needs: image, command, stdin, script, env, parser; or a ready report."""

    check: CheckId
    report: CheckReport | None = None
    image: str = ""
    command: tuple[str, ...] = ()
    stdin: bytes = b""
    script: str = TAR_SCRIPT
    env: tuple[tuple[str, str], ...] = _BASE_ENV
    parse: Callable[[RunOutcome], CheckReport] | None = None


class JobRunner:
    """Runs jobs through a `Backend`. `backend=None` means no isolation: every job fails."""

    def __init__(self, backend: Backend | None, settings: SandboxSettings, clock: Clock) -> None:
        self._backend = backend
        self._settings = settings
        self._clock = clock

    def health(self) -> RunnerHealth:
        missing: list[str] = []
        try:
            self._settings.limits.resolve()
        except SettingsUnset:
            missing.append("limits")
        missing += self._settings.images.missing()
        if self._settings.docker_cli is None:
            missing.append("docker_cli")
        if self._backend is None:
            reasons: tuple[str, ...] = ("no_backend",)
        else:
            try:
                reasons = self._backend.probe(self._settings.images.configured()).reasons
            except Exception as exc:
                logger.warning("backend probe raised %s", type(exc).__name__)
                reasons = ("probe_failed",)
        return RunnerHealth(
            usable=not missing and not reasons, missing=tuple(missing), backend_reasons=reasons
        )

    def run(self, job: Job) -> Report:
        """The report for `job`. Never raises for a job-level failure: it reports `error`."""
        try:
            limits = self._settings.limits.resolve()
        except SettingsUnset as exc:
            return _all(job, "settings_unset", f"limits unset: {', '.join(exc.names)}")
        if self._backend is None:
            return _all(job, "isolation_unavailable", "no isolation backend is configured")
        deadline = self._clock.now() + timedelta(seconds=limits.wall_time_seconds)
        try:
            plans = self._plan(job, self._backend, limits, deadline)
        except ArchiveRejected as exc:
            return _all(job, "archive_rejected", str(exc))
        except _Unusable:
            return _all(job, "isolation_unavailable", "the isolation backend is not usable")
        except _GitUnset:
            return _all(job, "settings_unset", "git image not configured")
        except _RangeMismatch:
            return _all(job, "range_mismatch", "the bundle is not the change the job states")
        checks = _merged(self._execute(p, self._backend, limits, deadline) for p in plans)
        # A tar job carries no head (the job validator refuses one), so it reports none.
        return Report(job_id=job.job_id, head=job.head, checks=checks)

    # --- planning ---------------------------------------------------------------------

    def _plan(
        self, job: Job, backend: Backend, limits: ResolvedLimits, deadline: datetime
    ) -> list[_Plan]:
        bundle = job.archive_format is ArchiveFormat.GIT_BUNDLE
        tree: SourceTree | None = None
        git_image = self._settings.images.git
        if bundle:
            archive.validate_bundle(job.archive)
            if git_image is None:
                raise _GitUnset
        else:
            tree = read_tree(job.archive)
        plans: list[_Plan] = []
        for check in job.checks:
            if check is not CheckId.TESTS:
                plans += self._scanner_plans(check, job, tree)
        wants_tests = CheckId.TESTS in job.checks
        images = [p.image for p in plans if p.report is None]
        test_plan: _Plan | None = None
        if wants_tests and tree is not None:
            test_plan = self._test_plan(tree)
            if test_plan.report is None:
                images.append(test_plan.image)
        if git_image is not None and bundle:
            images.insert(0, git_image)
        _probe(backend, images)
        remaining = self._remaining(deadline)
        if (
            git_image is not None
            and bundle
            and not verify_bundle(job, backend, git_image, limits, remaining)
        ):
            raise _RangeMismatch
        if wants_tests:
            if test_plan is None:
                test_plan = self._bundle_test_plan(job, backend, limits, deadline)
            earlier = set(job.checks[: job.checks.index(CheckId.TESTS)])
            plans.insert(sum(1 for p in plans if p.check in earlier), test_plan)
        return plans

    def _scanner_plans(self, check: CheckId, job: Job, tree: SourceTree | None) -> list[_Plan]:
        """The runs of one scanner check; secrets on a bundle runs twice (merged later)."""
        images = self._settings.images
        stdin = job.archive if tree is None else pack_tree(tree)
        script = BUNDLE_SCRIPT if tree is None else TAR_SCRIPT
        env = _bundle_env(job) if tree is None else _BASE_ENV
        if check is CheckId.SECRETS:
            config, ignore = images.gitleaks_config, images.gitleaks_ignore_file
            if images.gitleaks is None or config is None or ignore is None:
                return [_Plan(check, report=_unset(check, "gitleaks image, config or ignore file"))]
            fixed: tuple[str, ...] = (
                "--config",
                config,
                "--gitleaks-ignore-path",
                ignore,
                "--ignore-gitleaks-allow",
            )
            fixed += ("--report-format", "json", "--report-path", "-")
            fixed += ("--redact", "--no-banner", "--exit-code", "0")
            modes: list[tuple[str, ...]] = [("gitleaks", "dir", ".")]
            if tree is None:
                rng = ("--log-opts", f"{job.base_ref}..HEAD") if job.base_ref else ()
                modes.insert(0, ("gitleaks", "git", ".", *rng))
            gitleaks = images.gitleaks
            return [
                _Plan(check, None, gitleaks, (*m, *fixed), stdin, script, env, parse_gitleaks)
                for m in modes
            ]
        if images.semgrep is None or images.semgrep_config is None:
            return [_Plan(check, report=_unset(check, "semgrep image or rules"))]
        base = ("--baseline-commit", job.base_ref) if tree is None and job.base_ref else ()
        command: tuple[str, ...] = ("semgrep", "scan", "--json", "--config", images.semgrep_config)
        command += ("--disable-nosem", "--x-ignore-semgrepignore-files")
        command += ("--metrics", "off", "--disable-version-check", *base, ".")
        return [_Plan(check, None, images.semgrep, command, stdin, script, env, parse_semgrep)]

    def _test_plan(self, tree: SourceTree) -> _Plan:
        project = _detect(tree.paths())
        if project is ProjectType.NONE:
            note = finding(
                "sandbox.no_test_project", "test", Severity.INFO, "no supported project found"
            )
            skipped = CheckReport(check_id=CheckId.TESTS, status=Status.SKIPPED, findings=(note,))
            return _Plan(CheckId.TESTS, report=skipped)
        image = getattr(self._settings.images, f"{project.value}_tests")
        if image is None:
            return _Plan(CheckId.TESTS, report=_unset(CheckId.TESTS, f"{project} test image"))
        return _Plan(
            CheckId.TESTS, None, image, TEST_COMMANDS[project], pack_tree(tree), TAR_SCRIPT,
            (*_BASE_ENV, *_TEST_ENV[project]), _TEST_PARSERS[project],
        )  # fmt: skip

    def _bundle_test_plan(
        self, job: Job, backend: Backend, limits: ResolvedLimits, deadline: datetime
    ) -> _Plan:
        git_image = self._settings.images.git
        if git_image is None:
            return _Plan(CheckId.TESTS, report=_unset(CheckId.TESTS, "git image"))
        remaining = self._remaining(deadline)
        if remaining <= 0:
            return _Plan(CheckId.TESTS, report=_late(CheckId.TESTS))
        spec = ContainerSpec(
            name=new_id("sbx"),
            image=git_image,
            script=BUNDLE_SCRIPT,
            command=("git", "archive", "--format=tar", "HEAD"),
            env=_bundle_env(job),
            stdin=job.archive,
            limits=limits,
            timeout_seconds=remaining,
            max_output_bytes=archive.MAX_EXPANDED_BYTES,
        )
        outcome = _safe_run(backend, spec)
        if outcome is None or outcome.exit_code != 0:
            failed = error_check(CheckId.TESTS, "prepare_failed", "could not export the tree")
            return _Plan(CheckId.TESTS, report=failed)
        try:
            tree = read_tree(outcome.stdout)
        except ArchiveRejected as exc:
            return _Plan(CheckId.TESTS, report=error_check(CheckId.TESTS, "archive_rejected",
                                                           str(exc)))  # fmt: skip
        return self._test_plan(tree)

    # --- execution --------------------------------------------------------------------

    def _remaining(self, deadline: datetime) -> float:
        return (deadline - self._clock.now()).total_seconds()

    def _execute(
        self, plan: _Plan, backend: Backend, limits: ResolvedLimits, deadline: datetime
    ) -> CheckReport:
        if plan.report is not None:
            return plan.report
        assert plan.parse is not None
        remaining = self._remaining(deadline)
        if remaining <= 0:
            return _late(plan.check)
        spec = ContainerSpec(
            name=new_id("sbx"),
            image=plan.image,
            script=plan.script,
            command=plan.command,
            env=plan.env,
            stdin=plan.stdin,
            limits=limits,
            timeout_seconds=remaining,
            max_output_bytes=limits.output_bytes,
        )
        outcome = _safe_run(backend, spec)
        if outcome is None:
            return error_check(plan.check, "backend_failure", "the isolation backend failed")
        return plan.parse(outcome)


class _Unusable(Exception):
    pass


class _GitUnset(Exception):
    """A bundle job with no git image: the bundle cannot be verified."""


class _RangeMismatch(Exception):
    """The bundle is not the change the job states (`verify.verify_bundle`)."""


def _bundle_env(job: Job) -> tuple[tuple[str, str], ...]:
    """The fixed env plus the verified head every bundle script asserts."""
    if job.head is None:
        raise _RangeMismatch
    return (*_BASE_ENV, ("SANDBOX_HEAD", job.head))


def _merged(reports: Iterable[CheckReport]) -> tuple[CheckReport, ...]:
    """Consecutive reports of the same check become one (`merge_checks`)."""
    out: list[CheckReport] = []
    for report in reports:
        if out and out[-1].check_id == report.check_id:
            out[-1] = merge_checks(out[-1], report)
        else:
            out.append(report)
    return tuple(out)


def _probe(backend: Backend, images: list[str]) -> None:
    try:
        health = backend.probe(tuple(images))
    except Exception as exc:
        logger.warning("backend probe raised %s", type(exc).__name__)
        raise _Unusable from exc
    if not health.usable:
        logger.warning("backend not usable: %s", ",".join(health.reasons))
        raise _Unusable


def _safe_run(backend: Backend, spec: ContainerSpec) -> RunOutcome | None:
    """The outcome, or None when the backend raised (reported as an error by the caller)."""
    try:
        return backend.run(spec)
    except Exception as exc:
        logger.error("backend run of %s raised %s", spec.name, type(exc).__name__)
        return None


def _unset(check: CheckId, what: str) -> CheckReport:
    return error_check(check, "settings_unset", f"{what} not configured")


def _late(check: CheckId) -> CheckReport:
    return error_check(check, "wall_time_exceeded", "the job's wall time ran out before this check")


def _all(job: Job, code: str, message: str) -> Report:
    return Report(
        job_id=job.job_id, checks=tuple(error_check(c, code, message) for c in job.checks)
    )
