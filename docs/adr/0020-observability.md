# ADR-0020: Observability (structured logging, in-process metrics, health aggregate; no exporter chosen)
Status: Proposed (reversible default; owner approval pending)
Date: 2026-11-17
Revised: 2026-11-18 (health time limit, logging coverage, dropped-record component, series cap)
Blueprint refs: §3 (register item "Technology stack", DEFERRED), §5.1 #14, §7.2, §8.3, §10.3, §11.1, §13.4, FR-032, NFR-012, NFR-018, OD-01, OD-17; plan gap G18

## Context
The BP asks for "metrics/logs/traces for API, connectors, model inference, workflows, policy decisions and execution" (NFR-012), for audit and observability to cover connector health and service health (§5.1 #14), and for recovery "without silent loss or false 'healthy' status" (NFR-018). A connector failure "must not be misreported as 'no risk found'" (§7.2). Sensitive prompt and response logging must be minimized (§8.3, §11.1). The original design had no observability module and no health aggregation (plan gap G18). The BP selects no logging, metrics or monitoring product, and what the company already runs is unknown.

## Options considered

| Option | Gains | Costs | Security impact |
|---|---|---|---|
| Structured logging with the standard library, passed through the redactor; an in-process metrics registry; a health aggregate in which any unknown component makes the whole not healthy; no exporter | No product assumed; no new dependency; no outbound connection; the "no false healthy" rule is testable now | Metrics live in memory and are lost at restart; no history, dashboards or alerting; no traces | Log records are redacted before they are written. Nothing leaves the host |
| A metrics and tracing library with an exporter to a collector (product not chosen) | History, dashboards, alerting, distributed traces | Assumes a collector and a host that are not decided (OD-01); needs an outbound or local network path, while the network allowlist is empty | Telemetry can carry sensitive names and identifiers to another system; that system must be protected too |
| Use the audit log as the only record of operations | One store | Mixes operational noise into the security record; if the audit log is down, nothing can say so | Weakens both the audit log and operational visibility; rejected |
| No observability until Phase 0 | Nothing to build | A stopped connector or a dead queue would be invisible | Fails NFR-018; rejected |

## Default chosen for the local build
`ciso.observability` (`logs.py`, `metrics.py`, `health.py`) provides three things, and `ciso.app` wires them:
- **Logging.** `configure_logging` attaches one redacting handler to the root logger of the standard library. It writes one JSON object per record to a stream (standard error unless another is given). The message, arguments, extra fields and exception text are redacted, and the finished line is redacted once more. A record that cannot be made safe is dropped and counted: losing a line is preferred to emitting an unredacted one. Prompt bodies are not logged. The call is idempotent, and containers share the one handler through a lease, so closing one container does not remove the handler another still uses. The handler is removed only when the last holder lets go, and only if a container put it there.
- **Loggers that do not propagate.** A library logger with its own handler and `propagate` off never reaches the root handler. `configure_logging` takes their names, removes their other handlers and attaches the redacting one. The API names the web server's own loggers (its main, error and access loggers) and switches the server's own logging configuration and access log off. A test shows that a non-propagating logger leaks unless it is named, and that naming it fixes it.
- **Dropped records.** The count is on the handler, is exported as a counter (`ciso_log_records_dropped_total`) and is read by a health component, `log_records`, which reports unhealthy once anything has been dropped. The handler does not print its own failures to standard error, since that would be another unredacted channel.
- **Metrics.** `MetricsRegistry` holds counters and gauges with label sets, in memory, safe to share between threads. Seven counters are predefined: policy decisions, broker executions, inference calls, connector syncs, audit appends, kill-switch blocked reads and dropped log records. The composition root declares two more: dead-lettered jobs, labelled by job kind, and an authentication-audit-failure gauge. Incrementing a name that was not declared raises, so a typo cannot create a second series. A label may have any name. Each metric holds at most `metrics_max_series_per_metric` label sets (a safety setting, ADR-0019); a new label set past the cap is refused, counted and logged once, so user-controlled labels cannot grow memory without bound. The snapshot is JSON-serialisable.
- **Health.** `HealthRegistry` runs one check per registered component and reports the worst state, ranked unhealthy, unknown, degraded, healthy. The whole is healthy only when at least one component is registered and every one reports healthy. With no components it is unknown. A check that raises, returns something that is not a result, or runs past its time limit counts as unknown. The limit is `health_check_timeout_seconds`; with it unset no check is run and every component, and so the whole, is unknown. Checks run side by side in daemon threads and the report returns at the limit. Registration and aggregation are safe against each other. Reason texts are redacted, and withheld if redaction fails.
- Components registered by the composition root: operational database, audit database (with the anchor state), kill switch, readiness (what is missing), integrity (warnings such as an unwitnessed log), log records, inference (abandoned calls) and authentication audit failures. The start-up sequence in `ciso.ops` registers more, including the audit integrity state; it is not wired yet (ADR-0014).

No exporter, collector or dashboard product is chosen.

Weaknesses of this default:
- Nobody is told when health changes. An operator learns it only by asking the API. The BP's alerts for power state (§10.3) and connector health (§13.4) are not met.
- Metrics do not survive a restart, so there is no trend and no way to compare today with last week.
- NFR-012 lists traces. There are none; the correlation id on audit records is the only link across steps.
- A process cannot report that it is dead. Detecting that needs a check from outside the process (ADR-0015).
- The aggregate knows only the components that are registered. A component that was never wired in is absent, not unknown; there is no list of expected components.
- A check that overruns its limit is reported as unknown, but its thread cannot be killed and keeps running until it returns. A check that hangs for ever leaks one thread per poll. Checks must be quick and own their input and output time limits.
- A counter that reads zero does not show that nothing happened; it may never have been wired. Each counter needs a test that drives the event and reads a positive count.
- Only records that reach this handler are redacted. Another handler on the root logger, or a library logger that was not named when logging was configured, writes unredacted output. A logging traceback fix is in progress.
- Redaction has the limits described in ADR-0008: it removes values it knows and shapes it recognises.
- Where log output is stored, who may read it and how long it is kept are not decided (OD-17).
- A view that is "not healthy" whenever anything is unknown will be not healthy often during setup. Operators may learn to ignore it.
- The metric cap protects memory, and a metric that hits it silently loses new series apart from one counter and one log line.

## Why this default is reversible
Seam: the `ciso.observability` package. Modules log through the standard library, receive a `MetricsRegistry` and register a check with the `HealthRegistry`; none imports a monitoring product. An exporter is an addition that reads the registry and the log stream. Adding one means choosing a product, adding its client to the network allowlist and deciding which fields may leave the host.

## Evidence needed to make this final
- Which monitoring and alerting tools the company already runs, and who watches them (Phase 0 checklist PRD-07, HST-14).
- Who must be told about a failure, through which channel, including outside office hours (ORG-10).
- The approved host and whether an outside liveness check is possible (OD-01).
- Retention and access rules for logs and model traces (OD-17).
- Which signals operators actually use once the platform runs against real sources (FR-032).

## Consequences
- Health and counters are meant to be read through the API in the local build; there is no other consumer.
- Alerting is a known gap and must be closed before the platform is relied on to notice its own failures.
- Metric names and labels must never carry secret values or personal data; this is a review rule, since the registry cannot tell.
