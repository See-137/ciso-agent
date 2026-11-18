"""NFR-012, NFR-018: redacted structured logs, metrics registry, no-false-healthy health."""

from __future__ import annotations

import io
import json
import logging
import threading
import time
from collections.abc import Iterator
from concurrent.futures import ThreadPoolExecutor
from typing import Any

import pytest
from tests.fakes.core import FakeRedactor

import ciso.observability as observability
from ciso.common.clock import FixedClock
from ciso.common.errors import Conflict, ValidationFailed
from ciso.common.protocols import Redactor
from ciso.observability import (
    PREDEFINED_COUNTERS,
    CheckResult,
    HealthRegistry,
    HealthState,
    MetricNames,
    MetricsRegistry,
    RedactingJsonHandler,
    configure_logging,
    dropped_records_check,
    remove_logging,
)
from ciso.vault import SecretRedactor

pytestmark = pytest.mark.unit

SECRET = "s3cr3t-token-value-123"
NAMED = "ciso.test.nonpropagating"


def real_redactor() -> SecretRedactor:
    redactor = SecretRedactor()
    assert redactor.register(SECRET) is True
    return redactor


@pytest.fixture(params=["fake", "real"])
def redactor(request: pytest.FixtureRequest) -> Redactor:
    return FakeRedactor(SECRET) if request.param == "fake" else real_redactor()


@pytest.fixture
def stream() -> io.StringIO:
    return io.StringIO()


@pytest.fixture(autouse=True)
def restore_logging() -> Iterator[None]:
    """No test leaves root or named logger state changed."""
    root = logging.getLogger()
    named = logging.getLogger(NAMED)
    before = (root.level, list(root.handlers), list(named.handlers), named.propagate)
    yield
    root.setLevel(before[0])
    root.handlers[:] = before[1]
    named.handlers[:] = before[2]
    named.propagate = before[3]


def strict_loads(text: str) -> Any:
    def refuse(token: str) -> Any:
        raise ValueError(f"invalid JSON constant {token}")

    return json.loads(text, parse_constant=refuse)


def lines(stream: io.StringIO) -> list[dict[str, Any]]:
    return [strict_loads(line) for line in stream.getvalue().splitlines() if line]


def metrics() -> MetricsRegistry:
    return MetricsRegistry(max_series_per_metric=50)


# -- logs ------------------------------------------------------------------------------


def test_log_line_is_json_with_core_fields(redactor: Redactor, stream: io.StringIO) -> None:
    configure_logging(redactor, logging.INFO, stream=stream)
    logging.getLogger("ciso.test").info("hello %s", "world", extra={"job": "j1"})
    (record,) = lines(stream)
    assert record["message"] == "hello world"
    assert record["level"] == "INFO"
    assert record["logger"] == "ciso.test"
    assert record["job"] == "j1"


def test_secret_in_message_is_redacted(redactor: Redactor, stream: io.StringIO) -> None:
    configure_logging(redactor, logging.INFO, stream=stream)
    logging.getLogger("ciso.test").warning(f"token is {SECRET} ok")
    assert SECRET not in stream.getvalue()
    assert lines(stream)[0]["message"] == "token is [REDACTED] ok"


def test_secret_in_args_is_redacted(redactor: Redactor, stream: io.StringIO) -> None:
    configure_logging(redactor, logging.INFO, stream=stream)
    logging.getLogger("ciso.test").warning("token %s and %s", SECRET, {"k": SECRET})
    assert SECRET not in stream.getvalue()
    assert "[REDACTED]" in lines(stream)[0]["message"]


def test_secret_in_extra_is_redacted(redactor: Redactor, stream: io.StringIO) -> None:
    configure_logging(redactor, logging.INFO, stream=stream)
    logging.getLogger("ciso.test").warning(
        "event", extra={"header": f"Bearer {SECRET}", "nested": {"a": [SECRET]}, "n": 3}
    )
    assert SECRET not in stream.getvalue()
    record = lines(stream)[0]
    assert "[REDACTED]" in record["header"]
    assert record["nested"] == {"a": ["[REDACTED]"]}
    assert record["n"] == 3


def test_secret_in_object_repr_and_traceback_is_redacted(
    redactor: Redactor, stream: io.StringIO
) -> None:
    class Odd:
        def __repr__(self) -> str:
            return f"Odd({SECRET})"

    configure_logging(redactor, logging.INFO, stream=stream)
    log = logging.getLogger("ciso.test")
    log.warning("odd", extra={"obj": Odd()})
    try:
        raise RuntimeError(f"bad {SECRET}")
    except RuntimeError:
        log.exception("failed")
    assert SECRET not in stream.getvalue()
    assert len(lines(stream)) == 2
    assert "RuntimeError" in lines(stream)[1]["exc_info"]


def test_nan_and_infinity_never_produce_invalid_json(stream: io.StringIO) -> None:
    configure_logging(FakeRedactor(SECRET), logging.INFO, stream=stream)
    logging.getLogger("ciso.test").info(
        "numbers", extra={"a": float("nan"), "b": float("inf"), "c": [float("-inf")], "d": 1.5}
    )
    (record,) = lines(stream)  # strict_loads rejects bare NaN / Infinity
    assert record["a"] == "nan"
    assert record["b"] == "inf"
    assert record["c"] == ["-inf"]
    assert record["d"] == 1.5


def test_records_below_level_are_not_emitted(stream: io.StringIO) -> None:
    configure_logging(FakeRedactor(SECRET), logging.INFO, stream=stream)
    logging.getLogger("ciso.test").debug("quiet")
    assert stream.getvalue() == ""


class BrokenRedactor(FakeRedactor):
    def redact(self, text: str) -> str:
        raise RuntimeError("redactor down")


def test_redactor_failure_drops_the_record_and_surfaces_it(stream: io.StringIO) -> None:
    registry = metrics()
    handler = configure_logging(BrokenRedactor(), logging.INFO, stream=stream, metrics=registry)
    assert isinstance(handler, RedactingJsonHandler)
    check = dropped_records_check(handler)
    assert check().state is HealthState.HEALTHY
    logging.getLogger("ciso.test").warning(f"leak {SECRET}")
    assert stream.getvalue() == ""
    assert handler.dropped == 1
    assert registry.value(MetricNames.LOG_RECORDS_DROPPED) == 1
    unhealthy = check()
    assert unhealthy.state is HealthState.UNHEALTHY
    assert unhealthy.reason == "1 log records dropped"


def test_dropped_check_makes_the_aggregate_unhealthy(stream: io.StringIO) -> None:
    handler = configure_logging(BrokenRedactor(), logging.INFO, stream=stream)
    assert isinstance(handler, RedactingJsonHandler)
    health = HealthRegistry(FixedClock(), check_timeout_seconds=2, redactor=FakeRedactor())
    health.register("logging", dropped_records_check(handler))
    assert health.aggregate().overall is HealthState.HEALTHY
    logging.getLogger("ciso.test").warning("x")
    assert health.aggregate().overall is HealthState.UNHEALTHY


def test_configure_twice_adds_one_handler_and_one_line(stream: io.StringIO) -> None:
    root = logging.getLogger()
    first = configure_logging(FakeRedactor(SECRET), logging.INFO, stream=stream)
    second = configure_logging(FakeRedactor(SECRET), logging.WARNING, stream=io.StringIO())
    assert second is first
    ours = [h for h in root.handlers if isinstance(h, RedactingJsonHandler)]
    assert ours == [first]
    logging.getLogger("ciso.test").warning("once")
    assert len(lines(stream)) == 1
    assert first.level == logging.WARNING  # the later call's level applies


def test_second_call_can_supply_the_metrics_registry(stream: io.StringIO) -> None:
    registry = metrics()
    handler = configure_logging(BrokenRedactor(), logging.INFO, stream=stream)
    configure_logging(BrokenRedactor(), logging.INFO, metrics=registry)
    logging.getLogger("ciso.test").warning("x")
    assert isinstance(handler, RedactingJsonHandler)
    assert registry.value(MetricNames.LOG_RECORDS_DROPPED) == 1


def test_non_propagating_logger_bypasses_redaction_unless_named(
    redactor: Redactor, stream: io.StringIO
) -> None:
    foreign = io.StringIO()
    named = logging.getLogger(NAMED)
    named.propagate = False
    named.setLevel(logging.INFO)
    named.addHandler(logging.StreamHandler(foreign))

    configure_logging(redactor, logging.INFO, stream=stream)  # root only
    named.warning("access %s", SECRET)
    assert SECRET in foreign.getvalue()  # the hole this feature closes
    assert stream.getvalue() == ""

    foreign.truncate(0)
    foreign.seek(0)
    configure_logging(redactor, logging.INFO, logger_names=[NAMED])
    named.warning("access %s", SECRET)
    assert foreign.getvalue() == ""  # the foreign handler is gone
    assert SECRET not in stream.getvalue()
    (record,) = lines(stream)
    assert record["logger"] == NAMED
    assert record["message"] == "access [REDACTED]"


def test_naming_a_propagating_logger_removes_foreign_handlers_without_duplicates(
    redactor: Redactor, stream: io.StringIO
) -> None:
    foreign = io.StringIO()
    named = logging.getLogger(NAMED)
    named.propagate = True
    named.setLevel(logging.INFO)
    named.addHandler(logging.StreamHandler(foreign))
    configure_logging(redactor, logging.INFO, stream=stream, logger_names=[NAMED])
    configure_logging(redactor, logging.INFO, stream=stream, logger_names=[NAMED])
    named.warning("access %s", SECRET)
    assert foreign.getvalue() == ""
    assert len(lines(stream)) == 1  # reaches the root handler once, not twice
    assert SECRET not in stream.getvalue()


def test_remove_logging_restores_handlers(stream: io.StringIO) -> None:
    root = logging.getLogger()
    named = logging.getLogger(NAMED)
    named.propagate = False
    before = (list(root.handlers), list(named.handlers))
    handler = configure_logging(
        FakeRedactor(SECRET), logging.INFO, stream=stream, logger_names=[NAMED]
    )
    assert handler in root.handlers
    assert handler in named.handlers
    remove_logging(handler, [NAMED])
    assert (list(root.handlers), list(named.handlers)) == before


# -- metrics ---------------------------------------------------------------------------


def test_predefined_counter_names_exist() -> None:
    reg = metrics()
    expected = {
        MetricNames.POLICY_DECISIONS,
        MetricNames.BROKER_EXECUTIONS,
        MetricNames.INFERENCE_CALLS,
        MetricNames.CONNECTOR_SYNCS,
        MetricNames.AUDIT_APPENDS,
        MetricNames.KILLSWITCH_BLOCKED_READS,
        MetricNames.LOG_RECORDS_DROPPED,
        MetricNames.QUEUE_DEAD_LETTERS,
    }
    assert set(PREDEFINED_COUNTERS) == expected
    assert len(expected) == 8
    for name in expected:
        assert reg.value(name) == 0


def test_counters_increment_per_label_set() -> None:
    reg = metrics()
    reg.inc(MetricNames.POLICY_DECISIONS, labels={"outcome": "allow"})
    reg.inc(MetricNames.POLICY_DECISIONS, labels={"outcome": "allow"})
    reg.inc(MetricNames.POLICY_DECISIONS, 3, {"outcome": "deny"})
    assert reg.value(MetricNames.POLICY_DECISIONS, {"outcome": "allow"}) == 2
    assert reg.value(MetricNames.POLICY_DECISIONS, {"outcome": "deny"}) == 3
    assert reg.value(MetricNames.POLICY_DECISIONS, {"outcome": "hold"}) == 0
    reg.inc(MetricNames.AUDIT_APPENDS)
    assert reg.value(MetricNames.AUDIT_APPENDS) == 1
    reg.inc(MetricNames.CONNECTOR_SYNCS, labels={"a": "1", "b": "2"})
    assert reg.value(MetricNames.CONNECTOR_SYNCS, {"b": "2", "a": "1"}) == 1  # order irrelevant


def test_label_names_may_equal_parameter_names() -> None:
    reg = metrics()
    reg.declare_gauge("depth")
    reg.inc(MetricNames.INFERENCE_CALLS, labels={"name": "m", "amount": "5", "labels": "x"})
    reg.set_gauge("depth", 4, {"value": "v", "name": "n"})
    assert reg.value(MetricNames.INFERENCE_CALLS, {"name": "m", "amount": "5", "labels": "x"}) == 1
    assert reg.gauge("depth", {"value": "v", "name": "n"}) == 4


def test_unknown_counter_bad_amount_and_bad_labels_are_refused() -> None:
    reg = metrics()
    with pytest.raises(ValidationFailed):
        reg.inc("policy_decison_total", labels={"outcome": "allow"})  # typo creates nothing
    with pytest.raises(ValidationFailed):
        reg.inc(MetricNames.AUDIT_APPENDS, -1)
    with pytest.raises(ValidationFailed):
        reg.inc(MetricNames.AUDIT_APPENDS, 1.5)  # type: ignore[arg-type]
    with pytest.raises(ValidationFailed):
        reg.inc(MetricNames.AUDIT_APPENDS, labels={"k": 1})  # type: ignore[dict-item]


def test_gauges_set_and_overwrite() -> None:
    reg = metrics()
    reg.declare_gauge("queue_depth")
    reg.set_gauge("queue_depth", 5, {"queue": "main"})
    reg.set_gauge("queue_depth", 2, {"queue": "main"})
    assert reg.gauge("queue_depth", {"queue": "main"}) == 2
    assert reg.gauge("queue_depth", {"queue": "other"}) is None
    with pytest.raises(ValidationFailed):
        reg.set_gauge("undeclared", 1)


def test_snapshot_is_json_serialisable_and_complete() -> None:
    reg = metrics()
    reg.declare_gauge("g")
    reg.inc(MetricNames.INFERENCE_CALLS, 2, {"result": "ok"})
    reg.set_gauge("g", 1.5, {"q": "a"})
    snap = json.loads(json.dumps(reg.snapshot()))
    assert snap["counters"][MetricNames.INFERENCE_CALLS] == [
        {"labels": {"result": "ok"}, "value": 2}
    ]
    assert snap["gauges"]["g"] == [{"labels": {"q": "a"}, "value": 1.5}]
    assert snap["rejected_series"] == 0


def test_series_cap_refuses_new_label_sets_but_keeps_existing() -> None:
    reg = MetricsRegistry(max_series_per_metric=2)
    reg.inc(MetricNames.POLICY_DECISIONS, labels={"outcome": "a"})
    reg.inc(MetricNames.POLICY_DECISIONS, labels={"outcome": "b"})
    reg.inc(MetricNames.POLICY_DECISIONS, labels={"outcome": "c"})  # refused
    reg.inc(MetricNames.POLICY_DECISIONS, labels={"outcome": "a"})  # still counts
    assert reg.value(MetricNames.POLICY_DECISIONS, {"outcome": "c"}) == 0
    assert reg.value(MetricNames.POLICY_DECISIONS, {"outcome": "a"}) == 2
    assert reg.rejected_series == 1
    assert len(reg.snapshot()["counters"][MetricNames.POLICY_DECISIONS]) == 2
    reg.inc(MetricNames.INFERENCE_CALLS, labels={"result": "x"})  # another metric has its own cap
    assert reg.value(MetricNames.INFERENCE_CALLS, {"result": "x"}) == 1


def test_series_cap_applies_to_gauges() -> None:
    reg = MetricsRegistry(max_series_per_metric=1)
    reg.declare_gauge("g")
    reg.set_gauge("g", 1, {"a": "1"})
    reg.set_gauge("g", 2, {"a": "2"})
    assert reg.gauge("g", {"a": "2"}) is None
    assert reg.rejected_series == 1


def test_no_cap_configured_allows_only_the_first_series() -> None:
    reg = MetricsRegistry(max_series_per_metric=None)
    reg.inc(MetricNames.AUDIT_APPENDS)
    reg.inc(MetricNames.AUDIT_APPENDS)
    assert reg.value(MetricNames.AUDIT_APPENDS) == 2
    reg.inc(MetricNames.POLICY_DECISIONS, labels={"outcome": "a"})
    reg.inc(MetricNames.POLICY_DECISIONS, labels={"outcome": "b"})
    assert reg.value(MetricNames.POLICY_DECISIONS, {"outcome": "a"}) == 1
    assert reg.value(MetricNames.POLICY_DECISIONS, {"outcome": "b"}) == 0
    assert reg.rejected_series == 1


@pytest.mark.parametrize("bad", [0, -1, True, 2.5, "3"])
def test_bad_series_cap_is_refused(bad: Any) -> None:
    with pytest.raises(ValidationFailed):
        MetricsRegistry(max_series_per_metric=bad)


def test_counters_are_exact_under_threads() -> None:
    reg = metrics()
    threads, per_thread = 8, 2000

    def work(i: int) -> None:
        for _ in range(per_thread):
            reg.inc(MetricNames.POLICY_DECISIONS, labels={"outcome": "allow"})
            reg.inc(MetricNames.POLICY_DECISIONS, labels={"outcome": f"t{i}"})

    with ThreadPoolExecutor(max_workers=threads) as pool:
        list(pool.map(work, range(threads)))
    assert reg.value(MetricNames.POLICY_DECISIONS, {"outcome": "allow"}) == threads * per_thread
    for i in range(threads):
        assert reg.value(MetricNames.POLICY_DECISIONS, {"outcome": f"t{i}"}) == per_thread


def test_public_names_are_exported() -> None:
    for name in observability.__all__:
        assert hasattr(observability, name), name
    assert {"HealthRegistry", "MetricsRegistry", "configure_logging"} <= set(observability.__all__)


# -- health ----------------------------------------------------------------------------


def registry(clock: FixedClock, redactor: Redactor | None = None, timeout: float | None = 2) -> Any:
    return HealthRegistry(clock, check_timeout_seconds=timeout, redactor=redactor or FakeRedactor())


def ok(state: HealthState = HealthState.HEALTHY, reason: str = "fine") -> Any:
    return lambda: CheckResult(state=state, reason=reason)


def boom() -> CheckResult:
    raise RuntimeError(f"secret detail {SECRET}")


def test_empty_registry_is_unknown_not_healthy(clock: FixedClock) -> None:
    report = registry(clock).aggregate()
    assert report.overall is HealthState.UNKNOWN
    assert report.components == ()


def test_all_healthy_is_healthy(clock: FixedClock) -> None:
    reg = registry(clock)
    reg.register("db", ok())
    reg.register("queue", ok())
    report = reg.aggregate()
    assert report.overall is HealthState.HEALTHY
    assert {c.name: c.state for c in report.components} == {
        "db": HealthState.HEALTHY,
        "queue": HealthState.HEALTHY,
    }
    assert report.components[0].checked_at == clock.now()
    assert isinstance(report.components, tuple)


def test_report_cannot_be_appended_to(clock: FixedClock) -> None:
    reg = registry(clock)
    reg.register("db", ok())
    report = reg.aggregate()
    assert not hasattr(report.components, "append")


def test_one_unknown_is_not_healthy(clock: FixedClock) -> None:
    reg = registry(clock)
    reg.register("db", ok())
    reg.register("audit", ok(HealthState.UNKNOWN, "no signal"))
    report = reg.aggregate()
    assert report.overall is HealthState.UNKNOWN
    assert {c.name: c.state for c in report.components}["audit"] is HealthState.UNKNOWN


def test_raising_check_is_unknown_and_does_not_leak_message(clock: FixedClock) -> None:
    reg = registry(clock)
    reg.register("db", ok())
    reg.register("flaky", boom)
    report = reg.aggregate()
    assert report.overall is HealthState.UNKNOWN
    flaky = next(c for c in report.components if c.name == "flaky")
    assert flaky.state is HealthState.UNKNOWN
    assert "RuntimeError" in flaky.reason
    assert SECRET not in flaky.reason


def test_one_unhealthy_makes_overall_unhealthy(clock: FixedClock) -> None:
    reg = registry(clock)
    reg.register("db", ok())
    reg.register("audit", ok(HealthState.UNHEALTHY, "chain broken"))
    reg.register("odd", boom)
    assert reg.aggregate().overall is HealthState.UNHEALTHY


def test_degraded_only_is_degraded(clock: FixedClock) -> None:
    reg = registry(clock)
    reg.register("db", ok())
    reg.register("conn", ok(HealthState.DEGRADED, "quota"))
    assert reg.aggregate().overall is HealthState.DEGRADED


def test_invalid_check_result_is_unknown(clock: FixedClock) -> None:
    reg = registry(clock)
    reg.register("bad", lambda: "healthy")  # type: ignore[arg-type,return-value]
    report = reg.aggregate()
    assert report.overall is HealthState.UNKNOWN
    assert report.components[0].state is HealthState.UNKNOWN


def test_duplicate_and_empty_registration_are_refused(clock: FixedClock) -> None:
    reg = registry(clock)
    reg.register("db", ok())
    with pytest.raises(Conflict):
        reg.register("db", ok())
    with pytest.raises(ValidationFailed):
        reg.register(" ", ok())


def test_state_follows_check_over_time(clock: FixedClock) -> None:
    state = {"value": HealthState.HEALTHY}
    reg = registry(clock)
    reg.register("db", lambda: CheckResult(state=state["value"], reason="x"))
    assert reg.aggregate().overall is HealthState.HEALTHY
    state["value"] = HealthState.UNHEALTHY
    clock.advance(seconds=5)
    report = reg.aggregate()
    assert report.overall is HealthState.UNHEALTHY
    assert report.components[0].checked_at == clock.now()


def test_hung_check_is_unknown_and_aggregate_returns_on_time(clock: FixedClock) -> None:
    release = threading.Event()

    def hung() -> CheckResult:
        release.wait(10)
        return CheckResult(state=HealthState.HEALTHY, reason="late")

    reg = registry(clock, timeout=0.2)
    reg.register("fast", ok())
    for i in range(3):  # several hung checks must not add up
        reg.register(f"hung{i}", hung)
    started = time.monotonic()
    try:
        report = reg.aggregate()
        elapsed = time.monotonic() - started
    finally:
        release.set()
    assert elapsed < 2.0
    assert report.overall is HealthState.UNKNOWN
    states = {c.name: c.state for c in report.components}
    assert states["fast"] is HealthState.HEALTHY
    assert states["hung0"] is HealthState.UNKNOWN
    hung_reason = next(c.reason for c in report.components if c.name == "hung0")
    assert "exceeded" in hung_reason


def test_no_timeout_configured_means_checks_are_not_run(clock: FixedClock) -> None:
    ran: list[str] = []

    def check() -> CheckResult:
        ran.append("x")
        return CheckResult(state=HealthState.HEALTHY)

    reg = registry(clock, timeout=None)
    reg.register("db", check)
    report = reg.aggregate()
    assert ran == []
    assert report.overall is HealthState.UNKNOWN
    assert report.components[0].state is HealthState.UNKNOWN
    assert "no time limit" in report.components[0].reason


@pytest.mark.parametrize("bad", [0, -1, float("nan"), float("inf"), True, "2"])
def test_bad_timeout_is_refused(clock: FixedClock, bad: Any) -> None:
    with pytest.raises(ValidationFailed):
        registry(clock, timeout=bad)


def test_reason_is_redacted(clock: FixedClock, redactor: Redactor) -> None:
    reg = registry(clock, redactor)
    reg.register("db", ok(HealthState.DEGRADED, f"connect failed with {SECRET}"))
    report = reg.aggregate()
    assert SECRET not in report.components[0].reason
    assert "[REDACTED]" in report.components[0].reason


def test_reason_is_withheld_when_redaction_fails(clock: FixedClock) -> None:
    reg = registry(clock, BrokenRedactor())
    reg.register("db", ok(HealthState.DEGRADED, f"has {SECRET}"))
    component = reg.aggregate().components[0]
    assert component.state is HealthState.DEGRADED
    assert component.reason == "reason withheld: redaction failed"


def test_register_and_aggregate_race_without_errors(clock: FixedClock) -> None:
    reg = registry(clock, timeout=5)
    reg.register("seed", ok())
    errors: list[BaseException] = []
    stop = threading.Event()

    def aggregate() -> None:
        try:
            while not stop.is_set():
                reg.aggregate()
        except BaseException as exc:
            errors.append(exc)

    readers = [threading.Thread(target=aggregate) for _ in range(3)]
    for t in readers:
        t.start()
    try:
        for i in range(200):
            reg.register(f"c{i}", ok())
    finally:
        stop.set()
        for t in readers:
            t.join(20)
    assert errors == []
    assert len(reg.aggregate().components) == 201
