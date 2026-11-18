"""Composition root start-up: kill-switch initialise and reconcile, logging, no external path."""

from __future__ import annotations

import dataclasses
import io
import json
import logging
from pathlib import Path

import pytest
from tests.app.helpers import AUDIT_KEY, FAST_SCRYPT, SECRET_ENV, build, provisional

from ciso.app.killswitch_startup import (
    AUDIT_INTEGRITY,
    KILLSWITCH_NOT_INITIALISED,
    MISMATCH,
    RECONCILE_FAILED,
    startup_problems,
)
from ciso.app.logging_lease import ContainerLogFilter
from ciso.common.clock import FixedClock
from ciso.common.enums import ActorType, KillCapability
from ciso.killswitch.integrity import resolve_key
from ciso.killswitch.persist import write_flag
from ciso.observability import RedactingJsonHandler
from ciso.ops import IntegrityStatus, StartupReport, StepOutcome

pytestmark = pytest.mark.unit


def _engage_writes(data: Path, clock: FixedClock) -> None:
    with build(provisional(data), SECRET_ENV, clock=clock) as first:
        boot = first.host_local.bootstrap_first_admin("First Admin")
        admin = first.identity.resolve(boot.actor.id)
        assert admin is not None
        first.killswitch.engage(admin, [KillCapability.WRITES], "drill")


def _clear_flag_behind_the_audit_log(data: Path, clock: FixedClock) -> None:
    """Write a validly MAC'd clear WRITES row without any audit record (a forged release)."""
    settings = provisional(data)
    with build(settings, SECRET_ENV, clock=clock) as c:
        key = resolve_key(c.secret_store, settings.killswitch_key_ref)
        assert key is not None
        with c.operational_engine.begin() as conn:
            write_flag(
                conn, KillCapability.WRITES, engaged=False, changed_by="intruder",
                actor_type=ActorType.HUMAN, reason="quiet release", via="api",
                operator="", now=clock.now(), key=key,
            )  # fmt: skip


class TestKillSwitchStartUp:
    def test_capabilities_read_clear_after_start_up(self, tmp_path: Path) -> None:
        with build(provisional(tmp_path / "d"), SECRET_ENV) as c:
            assert [c.killswitch.is_blocked(cap) for cap in KillCapability] == [False] * len(
                KillCapability
            )
            assert not [m for m in c.readiness().missing if m.startswith(MISMATCH)]

    def test_engaged_state_survives_a_rebuild(self, tmp_path: Path) -> None:
        data = tmp_path / "d"
        _engage_writes(data, FixedClock())
        with build(provisional(data), SECRET_ENV) as second:
            assert second.readiness().ready is True, second.readiness().missing
            assert second.killswitch.is_blocked(KillCapability.WRITES) is True
            assert second.killswitch.is_blocked(KillCapability.ACTIVE_SCANS) is False
            actions = [r.action for r in second.audit.query(limit=100, action_prefix="killswitch.")]
            assert actions[-1] == "killswitch.engage"

    def test_flag_cleared_behind_the_audit_log_is_forced_blocked(self, tmp_path: Path) -> None:
        data, clock = tmp_path / "d", FixedClock()
        _engage_writes(data, clock)
        _clear_flag_behind_the_audit_log(data, clock)
        with build(provisional(data), SECRET_ENV, clock=clock) as c:
            missing = c.readiness().missing
            found = [m for m in missing if m.startswith(MISMATCH)]
            assert len(found) == 1, missing
            assert "writes" in found[0]
            assert "forced to blocked" in found[0]
            assert c.readiness().ready is False
            assert c.killswitch.is_blocked(KillCapability.WRITES) is True
            reconciled = c.audit.query(limit=100, action_prefix="killswitch.engage")
            assert reconciled[-1].actor_id == "system:reconcile"

    def test_reconcile_that_cannot_run_is_missing(self) -> None:
        failed = StepOutcome(name="killswitch_reconcile", status="failed", detail="FailClosed: x")
        problems = startup_problems(report(failed, mismatches=None))
        assert problems == (f"{RECONCILE_FAILED} (could not run: FailClosed: x)",)

    def test_reconcile_is_not_reported_when_initialise_refuses(self) -> None:
        refused = StepOutcome(name="killswitch", status="failed", detail="FailClosed: no key")
        reconcile = StepOutcome(name="killswitch_reconcile", status="failed", detail="no key")
        problems = startup_problems(report(refused, reconcile, mismatches=None))
        assert problems == (KILLSWITCH_NOT_INITIALISED,)

    def test_an_audit_log_that_is_not_ok_is_listed(self) -> None:
        problems = startup_problems(
            report(status=IntegrityStatus.FAILED, reason="hash_mismatch", mismatches=())
        )
        assert problems == (f"{AUDIT_INTEGRITY} (failed: hash_mismatch)",)

    def test_a_clean_report_lists_nothing(self) -> None:
        assert startup_problems(report(mismatches=())) == ()


def report(
    *steps: StepOutcome,
    mismatches: tuple[str, ...] | None,
    status: IntegrityStatus = IntegrityStatus.OK,
    reason: str | None = None,
) -> StartupReport:
    return StartupReport(
        steps=steps,
        audit_status=status,
        audit_reason=reason,
        owed_audit_delivered=0,
        owed_audit_remaining=0,
        killswitch_mismatches=mismatches,
        expired_leases=0,
        awaiting_components=(),
        writes_blocked=status is not IntegrityStatus.OK,
        startup_audited=status is IntegrityStatus.OK,
        startup_audit_note="audited",
    )


def _shared_handler() -> RedactingJsonHandler | None:
    found = [h for h in logging.getLogger().handlers if isinstance(h, RedactingJsonHandler)]
    assert len(found) <= 1
    return found[0] if found else None


class TestLogging:
    def test_registered_secret_never_appears_in_log_output(self, tmp_path: Path) -> None:
        stream = io.StringIO()
        with build(provisional(tmp_path / "d"), SECRET_ENV, stream=stream):
            logging.getLogger("ciso.test").warning("leaking %s now", AUDIT_KEY)
        output = stream.getvalue()
        assert "leaking [REDACTED] now" in output
        assert AUDIT_KEY not in output

    def test_close_removes_the_handler_and_restores_the_level(self, tmp_path: Path) -> None:
        root = logging.getLogger()
        before_handlers, before_level = list(root.handlers), root.level
        stream = io.StringIO()
        c = build(provisional(tmp_path / "d"), SECRET_ENV, stream=stream)
        assert len(root.handlers) == len(before_handlers) + 1
        c.close()
        assert root.handlers == before_handlers
        assert root.level == before_level
        logging.getLogger("ciso.test").warning("after close")
        assert "after close" not in stream.getvalue()

    def test_closing_one_container_keeps_the_other_logging(self, tmp_path: Path) -> None:
        root = logging.getLogger()
        before_handlers, before_level = list(root.handlers), root.level
        stream = io.StringIO()
        env_b = {
            **SECRET_ENV,
            "CISO_SECRET_AUDIT_HMAC_KEY": "second-container-audit-key-77aa-c0ffee",
        }
        a = build(provisional(tmp_path / "a"), SECRET_ENV, stream=stream)
        b = build(provisional(tmp_path / "b"), env_b, stream=io.StringIO())
        handler = _shared_handler()
        assert handler is not None
        assert len([f for f in handler.filters if isinstance(f, ContainerLogFilter)]) == 2
        a.close()
        assert _shared_handler() is handler  # still there for b
        logging.getLogger("ciso.test").warning(
            "b says %s and %s", "second-container-audit-key-77aa-c0ffee", AUDIT_KEY
        )
        b.close()
        output = stream.getvalue()
        assert "b says [REDACTED] and [REDACTED]" in output
        assert "second-container-audit-key-77aa-c0ffee" not in output
        assert root.handlers == before_handlers
        assert root.level == before_level

    def test_extra_fields_and_tracebacks_are_redacted_and_kept(self, tmp_path: Path) -> None:
        stream = io.StringIO()
        with build(provisional(tmp_path / "d"), SECRET_ENV, stream=stream):
            log = logging.getLogger("ciso.test")
            log.warning("with extra", extra={"detail": f"key={AUDIT_KEY}"})
            try:
                raise RuntimeError(f"boom {AUDIT_KEY}")
            except RuntimeError:
                log.exception("failed")
        output = stream.getvalue()
        assert AUDIT_KEY not in output
        records = [json.loads(line) for line in output.splitlines() if line]
        extra = [r for r in records if r["message"] == "with extra"]
        failed = [r for r in records if r["message"] == "failed"]
        assert [r["detail"] for r in extra] == ["key=[REDACTED]"]
        assert len(failed) == 1
        assert "RuntimeError: boom [REDACTED]" in failed[0]["exc_info"]
        assert "exception" not in failed[0]  # no duplicate traceback field

    def test_each_container_adds_its_redactor_and_takes_it_back(self, tmp_path: Path) -> None:
        a = build(provisional(tmp_path / "a"), SECRET_ENV)
        b = build(provisional(tmp_path / "b"), SECRET_ENV)
        handler = _shared_handler()
        assert handler is not None
        assert handler.redactors == (a.redactor, b.redactor)
        b.close()
        assert handler.redactors == (a.redactor,)
        a.close()
        assert _shared_handler() is None

    def test_close_in_creation_order_or_reverse_leaves_nothing(self, tmp_path: Path) -> None:
        root = logging.getLogger()
        before_handlers = list(root.handlers)
        a = build(provisional(tmp_path / "a"), SECRET_ENV)
        b = build(provisional(tmp_path / "b"), SECRET_ENV)
        b.close()
        assert _shared_handler() is not None
        a.close()
        assert root.handlers == before_handlers

    def test_a_handler_installed_by_someone_else_is_left_in_place(self, tmp_path: Path) -> None:
        from ciso.observability import configure_logging, remove_logging
        from ciso.vault import SecretRedactor

        outside = configure_logging(SecretRedactor(), logging.INFO, stream=io.StringIO())
        try:
            with build(provisional(tmp_path / "d"), SECRET_ENV):
                assert _shared_handler() is outside
            assert _shared_handler() is outside
            assert not [f for f in outside.filters if isinstance(f, ContainerLogFilter)]
        finally:
            remove_logging(outside)

    def test_non_propagating_logger_goes_through_the_handler(self, tmp_path: Path) -> None:
        from ciso.app import build_container

        server = logging.getLogger("ciso.test.server")
        server.propagate = False
        stream = io.StringIO()
        try:
            container = build_container(
                provisional(tmp_path / "d"),
                environ=dict(SECRET_ENV),
                clock=FixedClock(),
                log_stream=stream,
                logger_names=("ciso.test.server",),
                scrypt=FAST_SCRYPT,
            )
            with container:
                server.warning("server line with %s", AUDIT_KEY)
            assert "server line with [REDACTED]" in stream.getvalue()
            assert server.handlers == []
        finally:
            server.propagate = True


class TestNoExternalInference:
    def test_no_attribute_method_or_field_names_external(self, tmp_path: Path) -> None:
        with build(provisional(tmp_path / "d"), SECRET_ENV) as c:
            names = set(dir(c)) | {f.name for f in dataclasses.fields(c)}
            assert names, "nothing inspected"
            assert [n for n in names if "external" in n.lower()] == []
            assert c.inference is not None
