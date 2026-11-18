"""Host-local admin command line (`ciso.app.admin`), run in-process through `main(argv)`."""

from __future__ import annotations

import io
import json
from pathlib import Path

import pytest
from tests.app.helpers import FAST_SCRYPT, SECRET_ENV, build, provisional

from ciso.app.admin import main
from ciso.app.settings import Settings
from ciso.common.clock import FixedClock
from ciso.common.enums import ActorType, KillCapability
from ciso.killswitch.integrity import resolve_key
from ciso.killswitch.persist import write_flag

pytestmark = pytest.mark.unit


class Run:
    """One installation on disk and a way to call `main` against it."""

    def __init__(self, tmp_path: Path, settings: Settings | None = None) -> None:
        self.settings = settings or provisional(tmp_path / "d")
        self.config = tmp_path / "settings.json"
        self.config.write_text(json.dumps(self.settings.model_dump(mode="json")), encoding="utf-8")
        self.clock = FixedClock()
        self.logs = io.StringIO()

    def __call__(self, *argv: str) -> tuple[int, str, str]:
        out, err = io.StringIO(), io.StringIO()
        code = main(
            ["--config", str(self.config), *argv],
            environ=dict(SECRET_ENV),
            clock=self.clock,
            scrypt=FAST_SCRYPT,
            stdout=out,
            stderr=err,
            log_stream=self.logs,
        )
        return code, out.getvalue(), err.getvalue()


def _field(output: str, name: str) -> str:
    (line,) = [ln for ln in output.splitlines() if ln.startswith(f"{name}: ")]
    return line.split(": ", 1)[1]


class TestBootstrap:
    def test_bootstrap_prints_a_working_token_once_and_never_logs_it(self, tmp_path: Path) -> None:
        run = Run(tmp_path)
        code, out, err = run("bootstrap", "--name", "First Admin")
        assert code == 0, err
        token = _field(out, "token")
        actor_id = _field(out, "actor_id")
        assert out.count(token) == 1
        assert token not in run.logs.getvalue()
        assert run.logs.getvalue(), "nothing was logged, so the check above proves nothing"
        with build(run.settings, SECRET_ENV, clock=run.clock) as c:
            principal = c.authenticator.authenticate(token)
            assert principal.actor_id == actor_id
            records = c.audit.query(limit=10, action_prefix="identity.bootstrap")
            assert [r.outcome.value for r in records] == ["attempt", "success"]
            assert all(token not in r.model_dump_json() for r in records)

    def test_second_bootstrap_is_refused(self, tmp_path: Path) -> None:
        run = Run(tmp_path)
        assert run("bootstrap", "--name", "First Admin")[0] == 0
        code, out, err = run("bootstrap", "--name", "Second Admin")
        assert code == 1
        assert out == ""
        assert "Conflict" in err

    def test_bootstrap_without_keys_is_refused(self, tmp_path: Path) -> None:
        run = Run(tmp_path, Settings(data_dir=tmp_path / "d"))
        code, out, err = run("bootstrap", "--name", "First Admin")
        assert code == 1
        assert "token" not in out
        assert err.startswith("refused:")

    def test_missing_arguments_exit_2(self, tmp_path: Path) -> None:
        run = Run(tmp_path)
        with pytest.raises(SystemExit) as raised:
            run("bootstrap")
        assert raised.value.code == 2

    def test_unreadable_config_is_refused(self, tmp_path: Path) -> None:
        err = io.StringIO()
        code = main(["--config", str(tmp_path / "absent.json"), "audit-verify"], stderr=err)
        assert code == 1
        assert "settings file not found" in err.getvalue()


class TestRecoverToken:
    def test_recovered_token_authenticates_and_names_the_operator(self, tmp_path: Path) -> None:
        run = Run(tmp_path)
        _, boot_out, _ = run("bootstrap", "--name", "First Admin")
        actor_id = _field(boot_out, "actor_id")
        code, out, err = run(
            "recover-token", "--actor", actor_id, "--operator", "Night Operator",
            "--reason", "token expired",
        )  # fmt: skip
        assert code == 0, err
        token = _field(out, "token")
        assert token != _field(boot_out, "token")
        assert token not in run.logs.getvalue()
        with build(run.settings, SECRET_ENV, clock=run.clock) as c:
            assert c.authenticator.authenticate(token).actor_id == actor_id
            (success,) = c.audit.query(
                limit=10, action_prefix="identity.recover_admin_token", outcome=None
            )[-1:]
            assert success.details["operator"] == "Night Operator"

    def test_unknown_actor_is_refused(self, tmp_path: Path) -> None:
        run = Run(tmp_path)
        run("bootstrap", "--name", "First Admin")
        code, out, err = run(
            "recover-token", "--actor", "act_nobody", "--operator", "Op", "--reason", "why"
        )
        assert code == 1
        assert out == ""
        assert "AuthorizationError" in err


class TestKillSwitchReconcile:
    def test_consistent_flags_exit_0(self, tmp_path: Path) -> None:
        run = Run(tmp_path)
        code, out, _ = run("killswitch-reconcile")
        assert code == 0
        assert "flags agree with the audit log" in out
        assert f"{KillCapability.WRITES.value}: clear" in out

    def test_forged_clear_flag_is_reported_and_forced_blocked(self, tmp_path: Path) -> None:
        run = Run(tmp_path)
        _, boot_out, _ = run("bootstrap", "--name", "First Admin")
        actor_id = _field(boot_out, "actor_id")
        with build(run.settings, SECRET_ENV, clock=run.clock) as c:
            admin = c.identity.resolve(actor_id)
            assert admin is not None
            c.killswitch.engage(admin, [KillCapability.WRITES], "drill")
            key = resolve_key(c.secret_store, run.settings.killswitch_key_ref)
            with c.operational_engine.begin() as conn:
                write_flag(
                    conn, KillCapability.WRITES, engaged=False, changed_by="intruder",
                    actor_type=ActorType.HUMAN, reason="quiet", via="api", operator="",
                    now=run.clock.now(), key=key,
                )  # fmt: skip
        code, out, _ = run("killswitch-reconcile")
        assert code == 1
        assert "start-up: killswitch_mismatch (writes:" in out
        assert f"{KillCapability.WRITES.value}: blocked" in out


class TestAuditVerify:
    def test_intact_log_verifies_ok(self, tmp_path: Path) -> None:
        run = Run(tmp_path)
        run("bootstrap", "--name", "First Admin")
        code, out, _ = run("audit-verify")
        assert code == 0
        result = json.loads(out)
        assert result["status"] == "ok"
        assert result["checked"] >= 2
        assert result["witnessed"] is False

    def test_tampered_log_exits_1(self, tmp_path: Path) -> None:
        run = Run(tmp_path)
        run("bootstrap", "--name", "First Admin")
        with build(run.settings, SECRET_ENV, clock=run.clock) as c, c.audit_engine.begin() as conn:
            conn.exec_driver_sql("DROP TRIGGER audit_record_no_update")
            conn.exec_driver_sql("UPDATE audit_record SET target = 'forged' WHERE seq = 1")
        code, out, _ = run("audit-verify")
        assert code == 1
        assert json.loads(out)["status"] == "failed"
