"""Audit witness wiring in the composition root (ADR-0013, review C1; M1 fix pass items 1, 3, 7).

A witness is built only when its path, key and cadence are all set. Anything less leaves the
log unwitnessed and is an integrity warning, so the `integrity` health component reads
healthy only when the anchor and the witness are both configured outside the data directory.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
from tests.app.helpers import SECRET_ENV, build, event, provisional
from tests.fakes.core import FakeSecrets

from ciso.app.settings import Settings
from ciso.audit import FileHeadWitness, VerifyStatus
from ciso.common.errors import FailClosed, IntegrityFailure
from ciso.observability.health import HealthState
from ciso.vault import MIN_KEY_BYTES

pytestmark = pytest.mark.unit

WITNESS_REF = "secret://audit_witness_key"
WITNESS_KEY = "witness-key-for-container-tests-3d5e"
ENV = {**SECRET_ENV, "CISO_SECRET_AUDIT_WITNESS_KEY": WITNESS_KEY}
NO_WITNESS = "audit log has no witness outside the data directory"
HALF_SET = "audit witness path is set but its key or cadence is not"
WITNESS_INSIDE = "audit witness is stored under the data directory"


def witnessed(tmp_path: Path, **overrides: Any) -> Settings:
    """Provisional settings with anchor and witness outside the data directory."""
    base = provisional(tmp_path / "d")
    update: dict[str, Any] = {
        "audit_witness_path": tmp_path / "witness" / "heads.jsonl",
        "audit_witness_key_ref": WITNESS_REF,
    }
    safety = overrides.pop("safety", None)
    update.update(overrides)
    if safety is not None:
        update["safety"] = base.safety.model_copy(update=safety)
    return base.model_copy(update=update)


def states(container: Any) -> dict[str, Any]:
    return {comp.name: comp for comp in container.health.aggregate().components}


class TestFullyConfigured:
    def test_integrity_is_healthy_and_appends_are_witnessed(self, tmp_path: Path) -> None:
        settings = witnessed(tmp_path)
        with build(settings, ENV) as c:
            assert c.readiness().ready is True
            assert c.readiness().warnings == ()
            integrity = states(c)["integrity"]
            assert integrity.state is HealthState.HEALTHY, integrity.reason
            assert isinstance(c.witness, FileHeadWitness)
            assert c.witness.path == settings.audit_witness_path
            before = len(c.witness.path.read_text(encoding="utf-8").splitlines())
            c.audit.append(event(1))
            c.audit.append(event(2))
            after = len(c.witness.path.read_text(encoding="utf-8").splitlines())
            assert after - before == 2  # cadence 1: one line per append
            result = c.audit.verify()
            assert result.status is VerifyStatus.OK
            assert result.witnessed is True

    def test_cadence_comes_from_settings(self, tmp_path: Path) -> None:
        every = 3
        settings = witnessed(tmp_path, safety={"audit_witness_every": every})
        with build(settings, ENV) as c:
            assert c.witness is not None
            published = []
            for n in range(2 * every):
                receipt = c.audit.append(event(n))
                latest = c.witness.latest(c.audit.log_id or "")
                published.append(latest is not None and latest.seq == receipt.seq)
        assert published.count(True) == 2  # exactly every third append was published

    def test_witness_size_is_readable(self, tmp_path: Path) -> None:
        with build(witnessed(tmp_path), ENV) as c:
            assert c.witness is not None
            before = c.witness.size_bytes()
            c.audit.append(event())
            assert c.witness.size_bytes() > before
            assert c.witness.size_bytes() == c.witness.path.stat().st_size

    def test_witness_size_of_a_missing_file_is_zero(self, tmp_path: Path) -> None:
        missing = FileHeadWitness(tmp_path / "none" / "heads.jsonl", FakeSecrets(), WITNESS_REF)
        assert missing.size_bytes() == 0

    def test_witness_key_is_registered_with_the_redactor(self, tmp_path: Path) -> None:
        with build(witnessed(tmp_path), ENV) as c:
            assert c.redactor.redact(f"x {WITNESS_KEY} y") == "x [REDACTED] y"


class TestNotFullyConfigured:
    def test_nothing_set_is_an_unwitnessed_integrity_warning(self, tmp_path: Path) -> None:
        with build(provisional(tmp_path / "d"), SECRET_ENV) as c:
            assert c.witness is None
            assert NO_WITNESS in c.readiness().warnings
            assert states(c)["integrity"].state is HealthState.DEGRADED
            c.audit.append(event())
            assert c.audit.verify().witnessed is False

    @pytest.mark.parametrize("unset", ["key", "cadence"])
    def test_path_without_key_or_cadence_builds_no_witness(
        self, tmp_path: Path, unset: str
    ) -> None:
        if unset == "key":
            settings = witnessed(tmp_path, audit_witness_key_ref=None)
        else:
            settings = witnessed(tmp_path, safety={"audit_witness_every": None})
        with build(settings, ENV) as c:
            assert c.witness is None
            assert HALF_SET in c.readiness().warnings
            integrity = states(c)["integrity"]
            assert integrity.state is HealthState.DEGRADED
            assert HALF_SET in integrity.reason
            c.audit.append(event())
            assert c.audit.verify().witnessed is False
        assert settings.audit_witness_path is not None
        assert not settings.audit_witness_path.exists()

    def test_witness_under_the_data_directory_is_a_warning(self, tmp_path: Path) -> None:
        settings = witnessed(tmp_path, audit_witness_path=tmp_path / "d" / "w" / "heads.jsonl")
        with build(settings, ENV) as c:
            assert WITNESS_INSIDE in c.readiness().warnings
            assert states(c)["integrity"].state is HealthState.DEGRADED
            c.audit.append(event())
            assert c.audit.verify().witnessed is True  # still wired, just not isolated

    def test_witness_inside_the_database_directory_refuses_the_log(self, tmp_path: Path) -> None:
        settings = witnessed(tmp_path)
        inside = settings.audit_db.parent / "heads.jsonl"
        with build(settings.model_copy(update={"audit_witness_path": inside}), ENV) as c:
            assert c.readiness().ready is False
            assert any("audit_witness_path" in m for m in c.readiness().missing)
            with pytest.raises(FailClosed):
                c.audit.append(event())


class TestWitnessKey:
    def test_unresolvable_witness_key_is_missing_and_appends_refuse(self, tmp_path: Path) -> None:
        with build(witnessed(tmp_path), SECRET_ENV) as c:
            assert "audit_witness_key_ref (unresolvable)" in c.readiness().missing
            with pytest.raises((FailClosed, IntegrityFailure)):
                c.audit.append(event())

    def test_short_witness_key_is_missing_and_appends_refuse(self, tmp_path: Path) -> None:
        env = {**SECRET_ENV, "CISO_SECRET_AUDIT_WITNESS_KEY": "w" * (MIN_KEY_BYTES - 1)}
        with build(witnessed(tmp_path), env) as c:
            assert f"audit_witness_key_ref (shorter than {MIN_KEY_BYTES} bytes)" in (
                c.readiness().missing
            )
            with pytest.raises((FailClosed, IntegrityFailure)):
                c.audit.append(event())

    def test_32_byte_witness_key_is_ready(self, tmp_path: Path) -> None:
        env = {**SECRET_ENV, "CISO_SECRET_AUDIT_WITNESS_KEY": "w" * MIN_KEY_BYTES}
        with build(witnessed(tmp_path), env) as c:
            assert c.readiness().ready is True
            c.audit.append(event())
            assert c.audit.verify().witnessed is True

    def test_short_audit_key_is_reported_as_too_short(self, tmp_path: Path) -> None:
        env = {**ENV, "CISO_SECRET_AUDIT_HMAC_KEY": "h" * (MIN_KEY_BYTES - 1)}
        with build(witnessed(tmp_path), env) as c:
            assert f"audit_hmac_key_ref (shorter than {MIN_KEY_BYTES} bytes)" in (
                c.readiness().missing
            )
            with pytest.raises(FailClosed):
                c.audit.append(event())
