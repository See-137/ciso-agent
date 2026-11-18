"""Alert triggers, delivery failure kept pending, retry, and the directory sink."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from sqlalchemy import Engine, select
from tests.findings.conftest import NOW, MakeService, action, decision, inspection

from ciso.common.activity import Phase, Severity, Verdict
from ciso.common.errors import ValidationFailed
from ciso.findings import (
    Alert,
    AlertSink,
    AlertStatus,
    AlertTrigger,
    DirectoryAlertSink,
    FindingsService,
    InMemoryAlertSink,
)
from ciso.findings.tables import alert as alert_table

pytestmark = pytest.mark.unit


# --- which events alert ----------------------------------------------------------------


def test_before_deny_alerts(svc: FindingsService, sink: InMemoryAlertSink) -> None:
    out = svc.record(decision(Verdict.DENY), action(), None, decision_id="dec_1")
    (a,) = out.alerts
    assert a.trigger is AlertTrigger.BEFORE_DENY
    assert a.finding_id == out.findings[0].finding_id
    assert a.status is AlertStatus.DELIVERED
    assert a.attempts == 1
    assert [d.alert_id for d in sink.delivered] == [a.alert_id]
    assert a.delivered_at is not None


def test_after_deny_of_medium_does_not_alert(svc: FindingsService) -> None:
    out = svc.record(decision(Verdict.DENY), action(phase=Phase.AFTER), None, decision_id="dec_1")
    assert out.findings
    assert out.alerts == ()


def test_ask_does_not_alert(svc: FindingsService) -> None:
    assert svc.record(decision(Verdict.ASK), action(), None, decision_id="dec_1").alerts == ()


def test_every_before_deny_alerts_even_when_deduped(svc: FindingsService) -> None:
    svc.record(decision(Verdict.DENY), action(), None, decision_id="dec_1")
    out = svc.record(
        decision(Verdict.DENY, action_id="act_2"), action("act_2"), None, decision_id="dec_2"
    )
    assert out.created == ()
    assert len(out.alerts) == 1
    assert out.alerts[0].decision_id == "dec_2"


@pytest.mark.parametrize("level", [Severity.HIGH, Severity.CRITICAL])
def test_new_severe_finding_alerts_even_when_allowed(svc: FindingsService, level: Severity) -> None:
    out = svc.record(
        decision(Verdict.ALLOW), action(), inspection(("secrets.token", level)), decision_id="d1"
    )
    (a,) = out.alerts
    assert a.trigger is AlertTrigger.SEVERE_FINDING
    assert a.severity is level
    assert a.recommendation == "Remove the credential and rotate it."


def test_medium_finding_does_not_alert(svc: FindingsService) -> None:
    out = svc.record(
        decision(Verdict.ALLOW),
        action(),
        inspection(("deps.vulnerable", Severity.MEDIUM)),
        decision_id="dec_1",
    )
    assert out.alerts == ()


def test_repeat_of_a_severe_finding_does_not_alert_again(svc: FindingsService) -> None:
    result = inspection(("secrets.token", Severity.HIGH))
    svc.record(decision(Verdict.ALLOW), action(), result, decision_id="dec_1")
    out = svc.record(
        decision(Verdict.ALLOW, action_id="act_2"),
        action("act_2"),
        inspection(("secrets.token", Severity.HIGH), action_id="act_2"),
        decision_id="dec_2",
    )
    assert out.alerts == ()


def test_raise_into_high_alerts(svc: FindingsService) -> None:
    svc.record(
        decision(Verdict.ALLOW),
        action(),
        inspection(("deps.vulnerable", Severity.MEDIUM)),
        decision_id="dec_1",
    )
    out = svc.record(
        decision(Verdict.ALLOW, action_id="act_2"),
        action("act_2"),
        inspection(("deps.vulnerable", Severity.HIGH), action_id="act_2"),
        decision_id="dec_2",
    )
    assert [a.trigger for a in out.alerts] == [AlertTrigger.SEVERE_FINDING]


def test_before_deny_with_critical_inspection_alerts_twice(svc: FindingsService) -> None:
    out = svc.record(
        decision(Verdict.DENY),
        action(),
        inspection(("secrets.token", Severity.CRITICAL)),
        decision_id="dec_1",
    )
    assert sorted(a.trigger.value for a in out.alerts) == ["before_deny", "severe_finding"]


# --- delivery failure ------------------------------------------------------------------


class BrokenSink:
    def __init__(self) -> None:
        self.calls = 0

    def deliver(self, alert: Alert) -> None:
        self.calls += 1
        raise OSError("disk full: secret path /x")


def test_delivery_failure_keeps_alert_pending_and_does_not_block(
    make_service: MakeService, engine: Engine
) -> None:
    svc = make_service(alert_sink=BrokenSink())
    out = svc.record(decision(Verdict.DENY), action(), None, decision_id="dec_1")
    (a,) = out.alerts
    assert a.status is AlertStatus.PENDING
    assert a.attempts == 1
    assert a.last_failure == "OSError"
    with engine.connect() as conn:
        row = conn.execute(select(alert_table)).one()
    assert (row.status, row.attempts, row.last_failure) == ("pending", 1, "OSError")


def test_deliver_pending_retries_until_delivered(
    make_service: MakeService, sink: InMemoryAlertSink
) -> None:
    broken = BrokenSink()
    svc = make_service(alert_sink=broken)
    svc.record(decision(Verdict.DENY), action(), None, decision_id="dec_1")
    still = svc.deliver_pending()
    assert len(still) == 1
    assert still[0].attempts == 2
    assert broken.calls == 2
    fixed = make_service(alert_sink=sink)
    assert fixed.deliver_pending() == ()
    assert len(sink.delivered) == 1
    assert fixed.deliver_pending() == ()
    assert len(sink.delivered) == 1


def test_pending_alerts_listed_for_admin(make_service: MakeService) -> None:
    svc = make_service(alert_sink=BrokenSink())
    svc.record(decision(Verdict.DENY), action(), None, decision_id="dec_1")
    assert len(svc.list_alerts("human_admin", AlertStatus.PENDING)) == 1
    assert svc.list_alerts("human_admin", AlertStatus.DELIVERED) == ()


def test_in_memory_sink_can_fail(sink: InMemoryAlertSink) -> None:
    assert isinstance(sink, AlertSink)
    sink.fail = True
    with pytest.raises(OSError, match="set to fail"):
        sink.deliver(_alert())


# --- directory sink --------------------------------------------------------------------


def _alert(alert_id: str = "alt_01KAAAAAAAAAAAAAAAAAAAAAAA") -> Alert:
    return Alert(
        alert_id=alert_id,
        trigger=AlertTrigger.BEFORE_DENY,
        finding_id="fnd_01KAAAAAAAAAAAAAAAAAAAAAAA",
        decision_id="dec_1",
        severity=Severity.HIGH,
        title="deny by rule: push_protected_branch",
        person_ref="person:p_emp",
        repository="repo-a",
        branch="main",
        recommendation="Open a pull request.",
        created_at=NOW,
    )


def test_directory_sink_writes_one_json_file(tmp_path: Path) -> None:
    out = tmp_path / "alerts"
    out.mkdir()
    sink = DirectoryAlertSink(out)
    a = _alert()
    sink.deliver(a)
    files = list(out.iterdir())
    assert [f.name for f in files] == [f"{a.alert_id}.json"]
    assert json.loads(files[0].read_text(encoding="utf-8")) == a.payload()


def test_directory_sink_redelivery_of_same_alert_is_idempotent(tmp_path: Path) -> None:
    sink = DirectoryAlertSink(tmp_path)
    sink.deliver(_alert())
    sink.deliver(_alert())
    assert len(list(tmp_path.iterdir())) == 1


def test_directory_sink_never_overwrites_a_different_file(tmp_path: Path) -> None:
    sink = DirectoryAlertSink(tmp_path)
    a = _alert()
    target = tmp_path / f"{a.alert_id}.json"
    target.write_text("{}", encoding="utf-8")
    with pytest.raises(FileExistsError):
        sink.deliver(a)
    assert target.read_text(encoding="utf-8") == "{}"
    assert [p.name for p in tmp_path.iterdir()] == [target.name]


@pytest.mark.parametrize(
    "bad_id", ["../escape", "alt_..", "x/y", "alt_01KAAAAAAAAAAAAAAAAAAAAAA\\"]
)
def test_directory_sink_refuses_ids_that_could_escape(tmp_path: Path, bad_id: str) -> None:
    inner = tmp_path / "alerts"
    inner.mkdir()
    sink = DirectoryAlertSink(inner)
    with pytest.raises(ValidationFailed):
        sink.deliver(_alert().model_copy(update={"alert_id": bad_id}))
    assert list(tmp_path.iterdir()) == [inner]
    assert list(inner.iterdir()) == []


def test_directory_sink_needs_an_existing_directory(tmp_path: Path) -> None:
    with pytest.raises(ValidationFailed):
        DirectoryAlertSink(tmp_path / "missing")
    file = tmp_path / "f"
    file.write_text("x", encoding="utf-8")
    with pytest.raises(ValidationFailed):
        DirectoryAlertSink(file)


def test_directory_sink_leaves_no_temp_file_on_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    sink = DirectoryAlertSink(tmp_path)

    def boom(src: object, dst: object) -> None:
        raise OSError("link failed")

    monkeypatch.setattr("ciso.findings.alerts.os.link", boom)
    with pytest.raises(OSError, match="link failed"):
        sink.deliver(_alert())
    assert list(tmp_path.iterdir()) == []


def test_service_with_directory_sink_end_to_end(make_service: MakeService, tmp_path: Path) -> None:
    svc = make_service(alert_sink=DirectoryAlertSink(tmp_path))
    out = svc.record(decision(Verdict.DENY), action(), None, decision_id="dec_1")
    (a,) = out.alerts
    body = (tmp_path / f"{a.alert_id}.json").read_text(encoding="utf-8")
    assert "SUPERSECRET" not in body
    assert json.loads(body)["decision_id"] == "dec_1"
