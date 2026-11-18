"""Composition root (plan T1.14, G14, G18, G20): wiring, degraded mode, isolation, cleanup."""

from __future__ import annotations

import dataclasses
import shutil
from datetime import timedelta
from pathlib import Path

import pytest
from tests.app.helpers import SECRET_ENV, build, event, provisional

from ciso.app.audit_wiring import ANCHOR_NOT_ISOLATED
from ciso.app.container import HEALTH_UNTIMED, DefaultPolicyContext
from ciso.app.settings import Settings
from ciso.common.clock import FixedClock
from ciso.common.enums import KillCapability
from ciso.common.errors import FailClosed, IntegrityFailure
from ciso.observability import MetricNames
from ciso.observability.health import HealthState

pytestmark = pytest.mark.unit

ANCHOR_SHARED = "audit anchor is stored under the data directory"
NO_WITNESS = "audit log has no witness outside the data directory"
ALL_COMPONENTS = {
    "operational_database",
    "audit_database",
    "killswitch",
    "readiness",
    "integrity",
    "log_records",
    "inference",
    "authentication_audit",
    "audit_integrity",
}


class TestReadyContainer:
    def test_provisional_settings_with_secrets_are_ready(self, tmp_path: Path) -> None:
        with build(provisional(tmp_path / "d"), SECRET_ENV) as c:
            readiness = c.readiness()
            assert readiness.ready is True
            assert readiness.missing == ()
            receipt = c.audit.append(event())
            stored = c.audit.query(limit=100, action_prefix="test.")
            assert [r.seq for r in stored] == [receipt.seq]

    def test_two_containers_on_two_directories_are_independent(self, tmp_path: Path) -> None:
        sa, sb = provisional(tmp_path / "a"), provisional(tmp_path / "b")
        with build(sa, SECRET_ENV) as a, build(sb, SECRET_ENV) as b:
            a.audit.append(event(1))
            a.audit.append(event(2))
            b.audit.append(event(3))
            targets_a = [r.target for r in a.audit.query(limit=100, action_prefix="test.")]
            targets_b = [r.target for r in b.audit.query(limit=100, action_prefix="test.")]
            assert targets_a == ["asset:1", "asset:2"]
            assert targets_b == ["asset:3"]
            assert a.audit.log_id != b.audit.log_id
            assert a.audit is not b.audit
            assert a.operational_engine is not b.operational_engine
            assert sa.operational_db.is_file()
            assert sb.audit_db.is_file()
            assert sa.operational_db.parent == tmp_path / "a" / "db"

    def test_close_releases_the_database_files(self, tmp_path: Path) -> None:
        data = tmp_path / "d"
        c = build(provisional(data), SECRET_ENV)
        c.audit.append(event())
        assert c.killswitch.is_blocked(KillCapability.WRITES) is False
        c.close()
        c.close()  # idempotent
        shutil.rmtree(data)  # fails on Windows if a handle is still open
        assert not data.exists()

    def test_container_is_frozen(self, tmp_path: Path) -> None:
        with (
            build(provisional(tmp_path / "d"), SECRET_ENV) as c,
            pytest.raises(dataclasses.FrozenInstanceError),
        ):
            c.audit = None  # type: ignore[misc]

    def test_ready_container_health(self, tmp_path: Path) -> None:
        with build(provisional(tmp_path / "d"), SECRET_ENV) as c:
            report = c.health.aggregate()
            states = {comp.name: comp for comp in report.components}
            assert set(states) == ALL_COMPONENTS
            # No witness can be wired (no cadence or key setting): integrity is degraded,
            # so overall is degraded; everything else is healthy.
            integrity = states.pop("integrity")
            assert integrity.state is HealthState.DEGRADED
            assert NO_WITNESS in integrity.reason
            assert {comp.state for comp in states.values()} == {HealthState.HEALTHY}
            assert report.overall is HealthState.DEGRADED

    def test_unknown_component_makes_overall_not_healthy(self, tmp_path: Path) -> None:
        with build(provisional(tmp_path / "d"), SECRET_ENV) as c:

            def broken() -> object:
                raise RuntimeError("probe failed")

            c.health.register("probe", broken)  # type: ignore[arg-type]
            assert c.health.aggregate().overall is HealthState.UNKNOWN


class TestSafetyKnobs:
    def test_token_and_lease_lifetimes_reach_the_services(self, tmp_path: Path) -> None:
        settings = provisional(tmp_path / "d")
        clock = FixedClock()
        ttl = settings.safety.max_token_ttl_seconds
        lease = settings.safety.queue_lease_seconds
        assert ttl is not None
        assert lease is not None
        with build(settings, SECRET_ENV, clock=clock) as c:
            boot = c.host_local.bootstrap_first_admin("First Admin")
            assert boot.token.expires_at == clock.now() + timedelta(seconds=ttl)
            c.queue.enqueue("test.kind", {"n": 1}, source="test", event_id="e1")
            job = c.queue.lease(["test.kind"], "worker-1")
            assert job is not None
            assert job.lease_expires_at == clock.now() + timedelta(seconds=lease)

    def test_unset_knobs_stay_unset(self, tmp_path: Path) -> None:
        with build(Settings(data_dir=tmp_path / "d")) as c:
            c.queue.enqueue("test.kind", {"n": 1}, source="test", event_id="e1")
            with pytest.raises(FailClosed):
                c.queue.lease(["test.kind"], "worker-1")

    def test_health_timeout_comes_from_settings(self, tmp_path: Path) -> None:
        with build(provisional(tmp_path / "a"), SECRET_ENV) as timed:
            assert HEALTH_UNTIMED not in timed.readiness().warnings
            states = {comp.state for comp in timed.health.aggregate().components}
            assert HealthState.UNKNOWN not in states
        untimed_settings = provisional(tmp_path / "b", health_check_timeout_seconds=None)
        with build(untimed_settings, SECRET_ENV) as untimed:
            assert HEALTH_UNTIMED in untimed.readiness().warnings
            report = untimed.health.aggregate()
            assert {comp.state for comp in report.components} == {HealthState.UNKNOWN}

    def test_metrics_series_cap_comes_from_settings(self, tmp_path: Path) -> None:
        settings = provisional(tmp_path / "d", metrics_max_series_per_metric=2)
        with build(settings, SECRET_ENV) as c:
            for kind in ("a", "b", "c"):
                c.metrics.inc(MetricNames.QUEUE_DEAD_LETTERS, labels={"kind": kind})
            assert c.metrics.value(MetricNames.QUEUE_DEAD_LETTERS, {"kind": "b"}) == 1
            assert c.metrics.value(MetricNames.QUEUE_DEAD_LETTERS, {"kind": "c"}) == 0
            assert c.metrics.rejected_series == 1

    def test_killswitch_claim_timeout_comes_from_settings(self, tmp_path: Path) -> None:
        from ciso.killswitch.tables import killswitch_pending_audit as outbox

        settings = provisional(tmp_path / "d")
        timeout = settings.safety.killswitch_claim_timeout_seconds
        assert timeout is not None
        clock = FixedClock()
        with build(settings, SECRET_ENV, clock=clock) as c:
            boot = c.host_local.bootstrap_first_admin("First Admin")
            admin = c.identity.resolve(boot.actor.id)
            assert admin is not None
            c.killswitch.engage(admin, [KillCapability.WRITES], "drill")
            # Simulate a deliverer that claimed the record and died.
            with c.operational_engine.begin() as conn:
                conn.execute(
                    outbox.update().values(
                        delivered_at=None, claimed_by="dead-worker", claimed_at=clock.now()
                    )
                )
            assert c.killswitch.retry_pending_audit() == 0  # claim still fresh
            clock.advance(seconds=timeout + 1)
            assert c.killswitch.retry_pending_audit() == 1  # stale claim taken over
            assert c.killswitch.pending_audit() == ()

    def test_dead_letter_reaches_the_metric(self, tmp_path: Path) -> None:
        settings = provisional(tmp_path / "d", queue_max_attempts=1)
        with build(settings, SECRET_ENV) as c:
            c.queue.enqueue("test.kind", {"n": 1}, source="test", event_id="e1")
            job = c.queue.lease(["test.kind"], "worker-1")
            assert job is not None
            assert c.metrics.value(MetricNames.QUEUE_DEAD_LETTERS, {"kind": "test.kind"}) == 0
            c.queue.fail(job.job_id, "worker-1", RuntimeError("boom"))
            assert c.metrics.value(MetricNames.QUEUE_DEAD_LETTERS, {"kind": "test.kind"}) == 1


class TestDegradedContainer:
    def test_default_settings_list_what_is_missing(self, tmp_path: Path) -> None:
        with build(Settings(data_dir=tmp_path / "d")) as c:
            readiness = c.readiness()
            assert readiness.ready is False
            assert "audit_hmac_key_ref" in readiness.missing
            assert "killswitch_key_ref" in readiness.missing
            assert "safety.max_token_ttl_seconds" in readiness.missing
            # The default anchor is outside the database directory: not refused, warned.
            assert ANCHOR_NOT_ISOLATED not in readiness.missing
            assert ANCHOR_SHARED in readiness.warnings

    def test_default_settings_audit_append_refuses(self, tmp_path: Path) -> None:
        with build(Settings(data_dir=tmp_path / "d")) as c, pytest.raises(FailClosed):
            c.audit.append(event())

    def test_default_settings_block_every_capability(self, tmp_path: Path) -> None:
        with build(Settings(data_dir=tmp_path / "d")) as c:
            assert all(c.killswitch.is_blocked(cap) for cap in KillCapability)
            assert any(item.startswith("killswitch (") for item in c.readiness().missing)

    def test_default_anchor_with_keys_builds_and_appends(self, tmp_path: Path) -> None:
        settings = provisional(tmp_path / "d", isolated_anchor=False)
        assert settings.audit_anchor == tmp_path / "d" / "anchor" / "audit-head.json"
        with build(settings, SECRET_ENV) as c:
            readiness = c.readiness()
            assert readiness.ready is True, readiness.missing
            assert ANCHOR_SHARED in readiness.warnings
            receipt = c.audit.append(event())
            assert [r.seq for r in c.audit.query(limit=10, action_prefix="test.")] == [receipt.seq]
            assert settings.audit_anchor.is_file()
            states = {comp.name: comp for comp in c.health.aggregate().components}
            assert states["integrity"].state is HealthState.DEGRADED
            assert ANCHOR_SHARED in states["integrity"].reason
            assert states["audit_database"].state is HealthState.HEALTHY

    def test_anchor_inside_the_database_directory_is_refused(self, tmp_path: Path) -> None:
        data = tmp_path / "d"
        settings = provisional(data).model_copy(
            update={"audit_anchor_path": data / "db" / "anchor" / "head.json"}
        )
        with build(settings, SECRET_ENV) as c:
            assert ANCHOR_NOT_ISOLATED in c.readiness().missing
            with pytest.raises(FailClosed):
                c.audit.append(event())
            states = {comp.name: comp.state for comp in c.health.aggregate().components}
            assert states["audit_database"] is HealthState.UNHEALTHY

    def test_set_but_unresolvable_ref_is_missing_and_refuses(self, tmp_path: Path) -> None:
        with build(provisional(tmp_path / "d"), environ={}) as c:
            missing = c.readiness().missing
            assert "audit_hmac_key_ref (unresolvable)" in missing
            assert "killswitch_key_ref (unresolvable)" in missing
            assert "evidence_key_ref (unresolvable)" in missing
            with pytest.raises(FailClosed):
                c.audit.append(event())

    def test_degraded_audit_reads_unhealthy_and_overall_is_not_healthy(
        self, tmp_path: Path
    ) -> None:
        with build(Settings(data_dir=tmp_path / "d")) as c:
            report = c.health.aggregate()
            states = {comp.name: comp.state for comp in report.components}
            # Default settings have no health timeout: every component reads unknown.
            assert states["audit_database"] is HealthState.UNKNOWN
            assert report.overall is not HealthState.HEALTHY
        timed = Settings(data_dir=tmp_path / "e").model_copy(
            update={"safety": provisional(tmp_path / "e").safety}
        )
        with build(timed) as c:
            states = {comp.name: comp.state for comp in c.health.aggregate().components}
            assert states["audit_database"] is HealthState.UNHEALTHY
            assert states["readiness"] is HealthState.DEGRADED


class TestAuditIdentity:
    def test_wiped_audit_database_is_not_reinitialised(self, tmp_path: Path) -> None:
        settings = provisional(tmp_path / "d")
        with build(settings, SECRET_ENV) as first:
            original = first.audit.log_id
        for path in (settings.audit_db, *settings.audit_db.parent.glob("audit.db-*")):
            path.unlink()
        assert not settings.audit_db.exists()
        with build(settings, SECRET_ENV) as c:
            missing = c.readiness().missing
            assert any(item.startswith("audit_log_wiped") for item in missing), missing
            states = {comp.name: comp for comp in c.health.aggregate().components}
            assert states["audit_database"].state is HealthState.UNHEALTHY
            assert "wiped" in states["audit_database"].reason
            with pytest.raises((FailClosed, IntegrityFailure)):
                c.audit.append(event())
            assert c.audit.log_id in (None, original)  # never a fresh identity

    def test_rebuild_on_intact_directory_is_ready(self, tmp_path: Path) -> None:
        data = tmp_path / "d"
        with build(provisional(data), SECRET_ENV):
            pass
        with build(provisional(data), SECRET_ENV) as c:
            assert c.readiness().ready is True


class TestPolicyWiring:
    def test_ruleset_is_the_loaded_default(self, tmp_path: Path) -> None:
        with build(provisional(tmp_path / "d"), SECRET_ENV) as c:
            assert c.policy.ruleset.deny_all is False
            assert c.policy.ruleset.version

    def test_default_context_has_the_four_refusing_answers(self, tmp_path: Path) -> None:
        from ciso.policy import EnvelopeScope, PolicyContext

        with build(provisional(tmp_path / "d"), SECRET_ENV) as c:
            ctx: PolicyContext = c.policy_context
            assert isinstance(c.policy_context, DefaultPolicyContext)
            scope = EnvelopeScope.model_construct()
            assert ctx.is_channel_approved("any") is False
            assert ctx.playbook_status("any.op", scope) is None
            assert dict(ctx.fact_freshness(("fact:1",))) == {}
            assert not hasattr(c.policy_context, "actor_is_active")
